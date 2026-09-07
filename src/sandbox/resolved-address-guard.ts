/**
 * Resolved-address guard for hostname destinations.
 *
 * The domain allowlist decides by name, but whoever controls a permitted
 * name's DNS records (or any label under a permitted wildcard) decides what
 * that name resolves to. Without a check on the resolved address, an
 * allow-listed name can be pointed at the loopback interface, a link-local
 * address, or address space the embedder considers private, and the proxy
 * will dial it. This module wraps `dns.lookup` so a direct dial resolves
 * once, drops denied addresses, and connects to a surviving one — the
 * address that passed the check is the address dialed, with no second
 * resolution in between.
 *
 * Scope: hostnames only. An IP literal on the allowlist is an explicit
 * choice and is never re-judged here. The reserved loopback names
 * (`localhost` and anything under `.localhost`, RFC 6761) may resolve to
 * loopback — that is what allow-listing them asks for — but to nothing else
 * in the denied set. Connections routed through a parent proxy or a MITM
 * socket are not resolved locally at all; that hop resolves the name and is
 * responsible for its own address policy.
 */

import { lookup as dnsLookup } from 'node:dns'
import type { LookupAddress, LookupAllOptions } from 'node:dns'
import { BlockList, isIP } from 'node:net'
import type { LookupFunction } from 'node:net'
import { logForDebugging } from '../utils/debug.js'

/**
 * Destinations an allow-listed hostname may not resolve to unless the
 * embedder carves them out. IPv4 entries also cover their IPv4-mapped IPv6
 * form (see {@link unmapIPv4}). Private-use ranges (RFC 1918, ULA, CGNAT)
 * are deliberately absent: allow-listing an intranet hostname is legitimate,
 * so those are opt-in via `network.deniedResolvedAddresses`.
 */
export const DEFAULT_DENIED_RESOLVED_ADDRESSES: readonly string[] = [
  '0.0.0.0/8', // "this host on this network"; connects to the local host on common stacks
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local, incl. cloud instance-metadata endpoints
  '224.0.0.0/4', // multicast
  '255.255.255.255', // limited broadcast
  '::', // unspecified; connects to the local host on common stacks
  '::1', // loopback
  'fe80::/10', // link-local
  'ff00::/8', // multicast
]

/** `X-Proxy-Error` tag and response body used when a dial is refused here. */
export const RESOLVED_ADDRESS_DENIED_TAG = 'blocked-by-resolved-address'
export const RESOLVED_ADDRESS_DENIED_BODY =
  'Connection blocked: destination resolved to a denied address'

export type AddressRange = {
  address: string
  prefix: number
  family: 'ipv4' | 'ipv6'
}

/**
 * Parse an IP literal or CIDR range (`10.0.0.0/8`, `fc00::/7`, `::1`).
 * Returns undefined for anything else; IPv6 is unbracketed.
 */
export function parseAddressRange(entry: string): AddressRange | undefined {
  const slash = entry.indexOf('/')
  const ip = slash === -1 ? entry : entry.slice(0, slash)
  const fam = isIP(ip)
  if (!fam) return undefined
  const max = fam === 6 ? 128 : 32
  let prefix = max
  if (slash !== -1) {
    const raw = entry.slice(slash + 1)
    if (!/^\d{1,3}$/.test(raw) || Number(raw) > max) return undefined
    prefix = Number(raw)
  }
  return { address: ip, prefix, family: fam === 6 ? 'ipv6' : 'ipv4' }
}

/** Whether `entry` is an IP literal or CIDR range this module accepts. */
export function isValidAddressRange(entry: string): boolean {
  return parseAddressRange(entry) !== undefined
}

/**
 * Build a BlockList from IP/CIDR entries. Throws on a malformed entry — the
 * config schema validates with {@link isValidAddressRange} first, so a throw
 * here means a caller bypassed it.
 */
export function buildAddressSet(entries: readonly string[]): BlockList {
  const list = new BlockList()
  for (const entry of entries) {
    const range = parseAddressRange(entry)
    if (!range) {
      throw new Error(
        `Invalid IP address or CIDR range: ${JSON.stringify(entry)}`,
      )
    }
    // Single addresses via addAddress: some runtimes mis-evaluate
    // full-length (/32, /128) subnet rules.
    if (range.prefix === (range.family === 'ipv6' ? 128 : 32)) {
      list.addAddress(range.address, range.family)
    } else list.addSubnet(range.address, range.prefix, range.family)
  }
  return list
}

/**
 * An IPv4-mapped IPv6 address (`::ffff:127.0.0.1`, `::ffff:7f00:1`) as its
 * dotted-quad IPv4 form; anything else unchanged. Lets IPv4 rules judge the
 * mapped spelling without relying on the runtime's BlockList to cross-match
 * families.
 */
export function unmapIPv4(address: string): string {
  if (isIP(address) !== 6) return address
  let canonical: string
  try {
    canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1)
  } catch {
    return address
  }
  const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonical)
  if (!m) return address
  const hi = parseInt(m[1]!, 16)
  const lo = parseInt(m[2]!, 16)
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`
}

/** BlockList membership for an address string of either family. */
export function addressInSet(list: BlockList, address: string): boolean {
  const addr = unmapIPv4(address)
  const fam = isIP(addr)
  return fam !== 0 && list.check(addr, fam === 6 ? 'ipv6' : 'ipv4')
}

const LOOPBACK = buildAddressSet(['127.0.0.0/8', '::1'])

/** True for an IPv4/IPv6 loopback literal (including v4-mapped forms). */
export function isLoopbackAddress(address: string): boolean {
  return addressInSet(LOOPBACK, address)
}

/** `localhost` and names under `.localhost` (RFC 6761 §6.3). */
export function isLoopbackName(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, '')
  return h === 'localhost' || h.endsWith('.localhost')
}

export class ResolvedAddressDeniedError extends Error {
  readonly code = 'ERR_SRT_RESOLVED_ADDRESS_DENIED'
  /** Parenthetical for the violation line, e.g. `resolved to denied address 127.0.0.1`. */
  readonly reason: string
  constructor(
    readonly hostname: string,
    readonly addresses: readonly string[],
  ) {
    const reason = `resolved to denied address ${addresses.join(', ')}`
    super(`connection to ${hostname} refused: ${reason}`)
    this.name = 'ResolvedAddressDeniedError'
    this.reason = reason
  }
}

export function isResolvedAddressDenied(
  err: unknown,
): err is ResolvedAddressDeniedError {
  return (
    err instanceof ResolvedAddressDeniedError ||
    (err as { code?: unknown } | null)?.code ===
      'ERR_SRT_RESOLVED_ADDRESS_DENIED'
  )
}

export type Resolver = (
  hostname: string,
  options: LookupAllOptions,
  callback: (
    err: NodeJS.ErrnoException | null,
    addresses: LookupAddress[],
  ) => void,
) => void

export interface ResolvedAddressGuardOptions {
  /** Extra denied IPs/CIDRs, in addition to {@link DEFAULT_DENIED_RESOLVED_ADDRESSES}. */
  denied?: readonly string[]
  /** Carve-outs: a resolved address in one of these is permitted even if it is also in the denied set. */
  allowed?: readonly string[]
  /** Name resolver; defaults to `dns.lookup`. Test seam. */
  resolve?: Resolver
}

export interface ResolvedAddressGuard {
  /**
   * Whether a connection to `hostname` may use resolved `address`. Always
   * true when `hostname` is itself an IP literal.
   */
  permits(hostname: string, address: string): boolean
  /**
   * Drop-in `lookup` for `net.connect` / `http(s).request`: resolves via the
   * configured resolver, removes addresses `permits` rejects, and fails with
   * {@link ResolvedAddressDeniedError} when none remain.
   */
  lookup: LookupFunction
}

export function createResolvedAddressGuard(
  opts: ResolvedAddressGuardOptions = {},
): ResolvedAddressGuard {
  const denied = buildAddressSet([
    ...DEFAULT_DENIED_RESOLVED_ADDRESSES,
    ...(opts.denied ?? []),
  ])
  const allowed = buildAddressSet(opts.allowed ?? [])
  const resolve: Resolver = opts.resolve ?? dnsLookup

  const permits = (hostname: string, address: string): boolean => {
    if (isIP(hostname)) return true
    if (!isIP(address)) return false
    if (addressInSet(allowed, address)) return true
    if (isLoopbackName(hostname) && addressInSet(LOOPBACK, address)) {
      return true
    }
    return !addressInSet(denied, address)
  }

  const lookup: LookupFunction = (hostname, options, callback) => {
    const literalFamily = isIP(hostname)
    if (literalFamily) {
      // Runtimes skip `lookup` for literals; mirror dns.lookup for any that don't.
      if (options.all) {
        callback(null, [{ address: hostname, family: literalFamily }])
      } else callback(null, hostname, literalFamily)
      return
    }
    resolve(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) {
        callback(err, [])
        return
      }
      const survivors = addresses.filter(a => permits(hostname, a.address))
      if (survivors.length < addresses.length) {
        const dropped = addresses
          .filter(a => !survivors.includes(a))
          .map(a => a.address)
        if (survivors.length === 0) {
          logForDebugging(
            `Refusing to dial ${hostname}: resolved to denied address ${dropped.join(', ')}`,
            { level: 'error' },
          )
          callback(new ResolvedAddressDeniedError(hostname, dropped), [])
          return
        }
        logForDebugging(
          `Skipping denied address(es) for ${hostname}: ${dropped.join(', ')}`,
        )
      }
      const first = survivors[0]
      if (!first) {
        const none: NodeJS.ErrnoException = new Error(
          `getaddrinfo ENOTFOUND ${hostname}`,
        )
        none.code = 'ENOTFOUND'
        callback(none, [])
      } else if (options.all) callback(null, survivors)
      else callback(null, first.address, first.family)
    })
  }

  return { permits, lookup }
}
