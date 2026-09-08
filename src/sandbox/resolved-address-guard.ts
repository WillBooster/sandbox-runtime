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
 * choice and is never re-judged here; conversely, a name may resolve to a
 * denied address only when that address (and port) is itself allow-listed,
 * so reaching it by name grants nothing the literal entry did not. The
 * reserved loopback names (`localhost` and anything under `.localhost`,
 * RFC 6761) resolve to loopback — that is what allow-listing them asks for —
 * and to nothing else. Connections routed through a parent proxy or a MITM
 * socket are not resolved locally at all; that hop resolves the name and is
 * responsible for its own address policy.
 */

import { lookup as dnsLookup } from 'node:dns'
import type { LookupAddress, LookupAllOptions } from 'node:dns'
import { BlockList, isIP } from 'node:net'
import type { LookupFunction } from 'node:net'
import { networkInterfaces } from 'node:os'
import { logForDebugging } from '../utils/debug.js'
import {
  addRange,
  addressInSet,
  isLoopbackAddress,
  isLoopbackName,
  LOOPBACK_RANGES,
} from './address.js'

/**
 * Destinations an allow-listed hostname may not resolve to. Addresses
 * assigned to this host's own interfaces are denied too (see
 * {@link localInterfaceAddresses}), since a service bound to 0.0.0.0 answers
 * on those exactly as on loopback. Private-use ranges (RFC 1918, ULA, CGNAT)
 * are deliberately absent: allow-listing an intranet hostname is legitimate,
 * so those are opt-in via `network.deniedResolvedAddresses`.
 */
export const DEFAULT_DENIED_RESOLVED_ADDRESSES: readonly string[] = [
  ...LOOPBACK_RANGES,
  '0.0.0.0/8', // "this host on this network"; connects to the local host on common stacks
  '169.254.0.0/16', // link-local, incl. cloud instance-metadata endpoints
  '224.0.0.0/4', // multicast
  '255.255.255.255', // limited broadcast
  '100.100.100.200', // instance-metadata endpoint outside link-local (Alibaba Cloud)
  '::', // unspecified; connects to the local host on common stacks
  'fe80::/10', // link-local
  'ff00::/8', // multicast
  'fd00:ec2::254', // instance-metadata endpoint outside link-local (EC2 IPv6)
]

/** Unicast addresses currently assigned to this host's network interfaces. */
export function localInterfaceAddresses(): string[] {
  let byInterface: ReturnType<typeof networkInterfaces>
  try {
    byInterface = networkInterfaces()
  } catch {
    // Interface enumeration is unavailable in some restricted environments;
    // the fixed denied set still applies.
    return []
  }
  return Object.values(byInterface)
    .flat()
    .flatMap(i => (i ? [i.address] : []))
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
    super(`Connection to ${hostname} blocked: ${reason}`)
    this.name = 'ResolvedAddressDeniedError'
    this.reason = reason
  }
}

export function isResolvedAddressDenied(
  err: unknown,
): err is ResolvedAddressDeniedError {
  return err instanceof ResolvedAddressDeniedError
}

export type Resolver = (
  hostname: string,
  options: LookupAllOptions,
  callback: (
    err: NodeJS.ErrnoException | null,
    addresses: LookupAddress[],
  ) => void,
) => void

/**
 * An IP literal or CIDR range, optionally restricted to one destination
 * port. A bare string is shorthand for `{ range }` (any port).
 */
export type AddressRule = string | { range: string; port?: number }

export interface ResolvedAddressGuardOptions {
  /** Denied in addition to {@link DEFAULT_DENIED_RESOLVED_ADDRESSES} and this host's own addresses. */
  denied?: readonly AddressRule[]
  /**
   * Addresses (and ports) a name MAY resolve to even though they are denied —
   * the manager passes the allowlist's own IP-literal entries, so a name
   * reaches nothing a literal entry does not already permit.
   */
  allowed?: readonly AddressRule[]
  /** Name resolver; defaults to `dns.lookup`. Test seam. */
  resolve?: Resolver
  /** This host's interface addresses; defaults to {@link localInterfaceAddresses}, read per lookup. Test seam. */
  localAddresses?: () => readonly string[]
}

export interface ResolvedAddressGuard {
  /**
   * Whether a connection to `hostname:port` may use resolved `address`.
   * Always true when `hostname` is itself an IP literal.
   */
  permits(hostname: string, address: string, port: number): boolean
  /**
   * `lookup` for a `net.connect` / `http(s).request` to `port`: resolves via
   * the configured resolver, removes addresses `permits` rejects, and fails
   * with {@link ResolvedAddressDeniedError} when none remain.
   */
  lookupFor(port: number): LookupFunction
}

/** Port-scoped BlockLists: `anyPort` plus one list per port-qualified rule. */
type RuleSet = { anyPort: BlockList; byPort: Map<number, BlockList> }

function buildRuleSet(rules: readonly AddressRule[]): RuleSet {
  const set: RuleSet = { anyPort: new BlockList(), byPort: new Map() }
  for (const rule of rules) {
    const { range, port } =
      typeof rule === 'string' ? { range: rule, port: undefined } : rule
    let list = port === undefined ? set.anyPort : set.byPort.get(port)
    if (!list) set.byPort.set(port!, (list = new BlockList()))
    if (!addRange(list, range)) {
      throw new Error(
        `Invalid IP address or CIDR range: ${JSON.stringify(range)}`,
      )
    }
  }
  return set
}

function inRuleSet(set: RuleSet, address: string, port: number): boolean {
  const forPort = set.byPort.get(port)
  return (
    addressInSet(set.anyPort, address) ||
    (forPort !== undefined && addressInSet(forPort, address))
  )
}

export function createResolvedAddressGuard(
  opts: ResolvedAddressGuardOptions = {},
): ResolvedAddressGuard {
  const denied = buildRuleSet([
    ...DEFAULT_DENIED_RESOLVED_ADDRESSES,
    ...(opts.denied ?? []),
  ])
  const allowed = buildRuleSet(opts.allowed ?? [])
  const resolve: Resolver = opts.resolve ?? dnsLookup
  /** This host's addresses right now; a malformed entry from the seam is skipped. */
  const localSet = (): BlockList => {
    const list = new BlockList()
    for (const a of (opts.localAddresses ?? localInterfaceAddresses)()) {
      addRange(list, a)
    }
    return list
  }

  const judge = (
    hostname: string,
    address: string,
    port: number,
    local: BlockList,
  ): boolean => {
    if (isIP(hostname)) return true
    if (!isIP(address)) return false
    if (inRuleSet(allowed, address, port)) return true
    if (isLoopbackName(hostname)) return isLoopbackAddress(address)
    return !inRuleSet(denied, address, port) && !addressInSet(local, address)
  }

  const lookupFor =
    (port: number): LookupFunction =>
    (hostname, options, callback) => {
      resolve(hostname, { ...options, all: true }, (err, addresses) => {
        if (err) {
          callback(err, [])
          return
        }
        const local = localSet()
        const kept: LookupAddress[] = []
        const dropped: string[] = []
        for (const a of addresses) {
          if (judge(hostname, a.address, port, local)) kept.push(a)
          else dropped.push(a.address)
        }
        const first = kept[0]
        if (!first) {
          // An empty answer without an error is possible from some resolvers.
          const none: NodeJS.ErrnoException = dropped.length
            ? new ResolvedAddressDeniedError(hostname, dropped)
            : Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), {
                code: 'ENOTFOUND',
              })
          callback(none, [])
          return
        }
        if (dropped.length) {
          logForDebugging(
            `Skipping denied address(es) for ${hostname}: ${dropped.join(', ')}`,
          )
        }
        if (options.all) callback(null, kept)
        else callback(null, first.address, first.family)
      })
    }

  return {
    permits: (hostname, address, port) =>
      judge(hostname, address, port, localSet()),
    lookupFor,
  }
}
