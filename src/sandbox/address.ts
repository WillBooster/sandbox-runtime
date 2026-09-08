/**
 * IP-literal / CIDR helpers over `net.BlockList`, shared by the
 * resolved-address guard, the parent-proxy NO_PROXY matcher and config
 * validation.
 */

import { BlockList, isIP } from 'node:net'

/** Loopback in both families (BlockList matches IPv4-mapped forms against the IPv4 rule). */
export const LOOPBACK_RANGES: readonly string[] = ['127.0.0.0/8', '::1']

export type AddressFamily = 'ipv4' | 'ipv6'

/** BlockList family of an address string, or undefined if it is not an IP. */
export function ipFamily(address: string): AddressFamily | undefined {
  const fam = isIP(address)
  return fam === 4 ? 'ipv4' : fam === 6 ? 'ipv6' : undefined
}

export type AddressRange = {
  address: string
  prefix: number
  family: AddressFamily
}

/**
 * Parse an IP literal or CIDR range (`10.0.0.0/8`, `fc00::/7`, `::1`).
 * Returns undefined for anything else; IPv6 is unbracketed.
 */
export function parseAddressRange(entry: string): AddressRange | undefined {
  const slash = entry.indexOf('/')
  const address = slash === -1 ? entry : entry.slice(0, slash)
  const family = ipFamily(address)
  if (!family) return undefined
  const max = family === 'ipv6' ? 128 : 32
  let prefix = max
  if (slash !== -1) {
    const raw = entry.slice(slash + 1)
    if (!/^\d{1,3}$/.test(raw) || Number(raw) > max) return undefined
    prefix = Number(raw)
  }
  return { address, prefix, family }
}

/** Add an IP literal or CIDR range to `list`; false (list untouched) if malformed. */
export function addRange(list: BlockList, entry: string): boolean {
  const range = parseAddressRange(entry)
  if (!range) return false
  list.addSubnet(range.address, range.prefix, range.family)
  return true
}

/**
 * Build a BlockList from IP/CIDR entries. Throws on a malformed entry — the
 * config schema validates first, so a throw here means a caller bypassed it.
 */
export function buildAddressSet(entries: readonly string[]): BlockList {
  const list = new BlockList()
  for (const entry of entries) {
    if (!addRange(list, entry)) {
      throw new Error(
        `Invalid IP address or CIDR range: ${JSON.stringify(entry)}`,
      )
    }
  }
  return list
}

/**
 * BlockList membership for an address string of either family. IPv4 rules
 * also match the IPv4-mapped IPv6 spelling (BlockList does that itself);
 * an IPv6 zone id (`fe80::1%en0`) is dropped first because a zoned address
 * is a non-match on some runtimes.
 */
export function addressInSet(list: BlockList, address: string): boolean {
  const pct = address.indexOf('%')
  const addr = pct === -1 ? address : address.slice(0, pct)
  const family = ipFamily(addr)
  return family !== undefined && list.check(addr, family)
}

const LOOPBACK = buildAddressSet(LOOPBACK_RANGES)

/** True for an IPv4/IPv6 loopback literal (including v4-mapped forms). */
export function isLoopbackAddress(address: string): boolean {
  return addressInSet(LOOPBACK, address)
}

/** `localhost` and names under `.localhost` (RFC 6761 §6.3). */
export function isLoopbackName(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, '')
  return h === 'localhost' || h.endsWith('.localhost')
}
