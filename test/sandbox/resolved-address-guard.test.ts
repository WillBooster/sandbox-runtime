import { connect, createServer as createTcpServer } from 'node:net'
import type { AddressInfo, Server as TcpServer, Socket } from 'node:net'
import { createServer as createHttpServer } from 'node:http'
import type { Server as HttpServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import type { LookupAddress } from 'node:dns'
import { once } from 'node:events'
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import {
  createResolvedAddressGuard,
  DEFAULT_DENIED_RESOLVED_ADDRESSES,
  isResolvedAddressDenied,
  isValidAddressRange,
  parseAddressRange,
  RESOLVED_ADDRESS_DENIED_TAG,
  ResolvedAddressDeniedError,
  type Resolver,
} from '../../src/sandbox/resolved-address-guard.js'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createSocksProxyServer } from '../../src/sandbox/socks-proxy.js'
import { SandboxRuntimeConfigSchema } from '../../src/sandbox/sandbox-config.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

/**
 * The domain allowlist matches by name; these tests pin what happens when a
 * permitted name resolves somewhere the allowlist never meant — loopback,
 * link-local, or an embedder-listed private range — and that explicit IP
 * literals and the reserved `localhost` names are left alone.
 */

/** Resolver stub: answers from a fixed table, ENOTFOUND otherwise. */
function fakeResolver(table: Record<string, string[]>): Resolver & {
  calls: string[]
} {
  const calls: string[] = []
  const resolve: Resolver = (hostname, _opts, cb) => {
    calls.push(hostname)
    const addrs = table[hostname]
    if (!addrs) {
      const err: NodeJS.ErrnoException = new Error(
        `getaddrinfo ENOTFOUND ${hostname}`,
      )
      err.code = 'ENOTFOUND'
      cb(err, [])
      return
    }
    cb(
      null,
      addrs.map(
        (address): LookupAddress => ({
          address,
          family: address.includes(':') ? 6 : 4,
        }),
      ),
    )
  }
  return Object.assign(resolve, { calls })
}

function lookupAll(
  guard: ReturnType<typeof createResolvedAddressGuard>,
  hostname: string,
): Promise<LookupAddress[]> {
  return new Promise((resolve, reject) => {
    guard.lookup(hostname, { all: true }, (err, addresses) => {
      if (err) reject(err)
      else resolve(addresses as LookupAddress[])
    })
  })
}

describe('resolved-address-guard: parseAddressRange', () => {
  it('accepts IPv4/IPv6 literals and CIDR ranges', () => {
    expect(parseAddressRange('10.0.0.0/8')).toEqual({
      address: '10.0.0.0',
      prefix: 8,
      family: 'ipv4',
    })
    expect(parseAddressRange('192.0.2.7')).toEqual({
      address: '192.0.2.7',
      prefix: 32,
      family: 'ipv4',
    })
    expect(parseAddressRange('fc00::/7')).toEqual({
      address: 'fc00::',
      prefix: 7,
      family: 'ipv6',
    })
    expect(parseAddressRange('::1')?.prefix).toBe(128)
  })

  it('rejects hostnames, bad prefixes and bracketed IPv6', () => {
    for (const bad of [
      'example.com',
      '10.0.0.0/33',
      '10.0.0.0/',
      '10.0.0.0/x',
      'fc00::/129',
      '[::1]',
      '',
      '300.1.1.1',
    ]) {
      expect(isValidAddressRange(bad)).toBe(false)
    }
  })
})

describe('resolved-address-guard: permits', () => {
  const guard = createResolvedAddressGuard()

  it('denies the built-in set for a hostname, including v4-mapped forms', () => {
    for (const addr of [
      '127.0.0.1',
      '127.255.255.254',
      '::1',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
      '0.0.0.0',
      '169.254.169.254',
      '::ffff:169.254.169.254',
      '224.0.0.1',
      '239.255.255.250',
      '255.255.255.255',
      '::',
      'fe80::1',
      'febf::1',
      'ff02::1',
    ]) {
      expect(guard.permits('api.example.com', addr)).toBe(false)
    }
  })

  it('permits public and (by default) private-use addresses for a hostname', () => {
    for (const addr of [
      '192.0.2.10',
      '198.51.100.1',
      '2001:db8::1',
      '10.0.0.5',
      '172.16.0.1',
      '192.168.1.1',
      'fd00::1',
      '100.64.0.1',
    ]) {
      expect(guard.permits('api.example.com', addr)).toBe(true)
    }
  })

  it('never re-judges an IP-literal destination', () => {
    expect(guard.permits('127.0.0.1', '127.0.0.1')).toBe(true)
    expect(guard.permits('::1', '::1')).toBe(true)
    expect(guard.permits('169.254.169.254', '169.254.169.254')).toBe(true)
  })

  it('lets localhost names resolve to loopback but nothing else in the set', () => {
    expect(guard.permits('localhost', '127.0.0.1')).toBe(true)
    expect(guard.permits('localhost', '::1')).toBe(true)
    expect(guard.permits('LOCALHOST.', '127.0.0.1')).toBe(true)
    expect(guard.permits('app.dev.localhost', '127.0.0.1')).toBe(true)
    expect(guard.permits('localhost', '169.254.169.254')).toBe(false)
    expect(guard.permits('notlocalhost', '127.0.0.1')).toBe(false)
    expect(guard.permits('localhost.example.com', '127.0.0.1')).toBe(false)
  })

  it('applies embedder-configured denied ranges (and their v4-mapped twins)', () => {
    const g = createResolvedAddressGuard({
      denied: ['10.0.0.0/8', '192.168.0.0/16', 'fc00::/7'],
    })
    expect(g.permits('intranet.example.com', '10.1.2.3')).toBe(false)
    expect(g.permits('intranet.example.com', '::ffff:10.1.2.3')).toBe(false)
    expect(g.permits('intranet.example.com', '192.168.1.1')).toBe(false)
    expect(g.permits('intranet.example.com', 'fd12:3456::1')).toBe(false)
    expect(g.permits('intranet.example.com', '172.16.0.1')).toBe(true)
    expect(g.permits('intranet.example.com', '192.0.2.10')).toBe(true)
    // Built-ins still apply alongside the extras.
    expect(g.permits('intranet.example.com', '127.0.0.1')).toBe(false)
  })

  it('allowed carve-outs win over the denied set', () => {
    const g = createResolvedAddressGuard({ allowed: ['127.0.0.1'] })
    expect(g.permits('myapp.test', '127.0.0.1')).toBe(true)
    expect(g.permits('myapp.test', '127.0.0.2')).toBe(false)
    expect(g.permits('myapp.test', '::1')).toBe(false)
  })

  it('throws on a malformed entry (schema validates first)', () => {
    expect(() => createResolvedAddressGuard({ denied: ['nope/8'] })).toThrow(
      /Invalid IP address or CIDR range/,
    )
    expect(() => createResolvedAddressGuard({ allowed: ['[::1]'] })).toThrow()
  })

  it('exports the documented default set', () => {
    expect(DEFAULT_DENIED_RESOLVED_ADDRESSES).toContain('127.0.0.0/8')
    expect(DEFAULT_DENIED_RESOLVED_ADDRESSES).toContain('169.254.0.0/16')
    expect(DEFAULT_DENIED_RESOLVED_ADDRESSES).not.toContain('10.0.0.0/8')
  })
})

describe('resolved-address-guard: lookup', () => {
  it('fails with ResolvedAddressDeniedError when every address is denied', async () => {
    const resolve = fakeResolver({ 'evil.example.com': ['127.0.0.1', '::1'] })
    const guard = createResolvedAddressGuard({ resolve })
    const err = await lookupAll(guard, 'evil.example.com').catch(e => e)
    expect(err).toBeInstanceOf(ResolvedAddressDeniedError)
    expect(isResolvedAddressDenied(err)).toBe(true)
    expect(err.code).toBe('ERR_SRT_RESOLVED_ADDRESS_DENIED')
    expect(err.reason).toBe('resolved to denied address 127.0.0.1, ::1')
    expect(err.hostname).toBe('evil.example.com')
  })

  it('returns only the surviving addresses, in resolver order', async () => {
    const resolve = fakeResolver({
      'mixed.example.com': ['169.254.169.254', '2001:db8::5', '192.0.2.10'],
    })
    const guard = createResolvedAddressGuard({ resolve })
    expect(await lookupAll(guard, 'mixed.example.com')).toEqual([
      { address: '2001:db8::5', family: 6 },
      { address: '192.0.2.10', family: 4 },
    ])
  })

  it('supports the single-address callback form', async () => {
    const resolve = fakeResolver({
      'mixed.example.com': ['127.0.0.1', '192.0.2.10'],
    })
    const guard = createResolvedAddressGuard({ resolve })
    const got = await new Promise<[string, number | undefined]>((res, rej) =>
      guard.lookup('mixed.example.com', {}, (err, address, family) =>
        err ? rej(err) : res([address as string, family]),
      ),
    )
    expect(got).toEqual(['192.0.2.10', 4])
  })

  it('passes IP literals through without consulting the resolver', async () => {
    const resolve = fakeResolver({})
    const guard = createResolvedAddressGuard({ resolve })
    expect(await lookupAll(guard, '127.0.0.1')).toEqual([
      { address: '127.0.0.1', family: 4 },
    ])
    expect(resolve.calls).toEqual([])
  })

  it('propagates resolver errors unchanged', async () => {
    const guard = createResolvedAddressGuard({ resolve: fakeResolver({}) })
    const err = await lookupAll(guard, 'nx.example.com').catch(e => e)
    expect(err.code).toBe('ENOTFOUND')
    expect(isResolvedAddressDenied(err)).toBe(false)
  })
})

describe('resolved-address-guard: config schema', () => {
  const base = {
    network: { allowedDomains: ['*.example.com'], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }

  it('accepts deniedResolvedAddresses / allowedResolvedAddresses', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...base,
      network: {
        ...base.network,
        deniedResolvedAddresses: ['10.0.0.0/8', 'fc00::/7', '192.0.2.1'],
        allowedResolvedAddresses: ['127.0.0.1'],
      },
    })
    expect(r.success).toBe(true)
  })

  it('rejects a malformed range with a pointed message', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...base,
      network: { ...base.network, deniedResolvedAddresses: ['10.0.0.0/33'] },
    })
    expect(r.success).toBe(false)
    if (!r.success) {
      expect(r.error.issues[0]?.message).toContain(
        'Invalid IP address or CIDR range',
      )
    }
  })
})

// ---------------------------------------------------------------------------
// Proxy-level: the guard's lookup wired into the real HTTP / SOCKS servers.
// A local HTTP server on 127.0.0.1 stands in for "whatever is listening on
// loopback"; the fake resolver points allow-listed names at it.
// ---------------------------------------------------------------------------

describe('resolved-address-guard: through the proxy servers', () => {
  let upstream: HttpServer
  let upstreamPort: number
  let upstreamHits: string[]
  let denials: Array<{ host: string; port: number; reason: string }>
  const closers: Array<() => Promise<unknown> | unknown> = []

  beforeEach(async () => {
    upstreamHits = []
    denials = []
    upstream = createHttpServer((req, res) => {
      upstreamHits.push(`${req.method} ${req.url} host=${req.headers.host}`)
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end('upstream-ok')
    })
    upstream.listen(0, '127.0.0.1')
    await once(upstream, 'listening')
    upstreamPort = (upstream.address() as { port: number }).port
  })

  afterEach(async () => {
    for (const c of closers.splice(0)) await c()
    upstream.close()
  })

  const resolve = fakeResolver({
    'rebind.example.com': ['127.0.0.1'],
    'metadata.example.com': ['169.254.169.254'],
    'intranet.example.com': ['127.0.0.1'],
    'devbox.example.com': ['127.0.0.1'],
    localhost: ['127.0.0.1'],
  })

  async function startHttpProxy(
    guard = createResolvedAddressGuard({ resolve }),
  ): Promise<number> {
    const proxy = createHttpProxyServer({
      filter: () => true,
      lookup: guard.lookup,
      onDirectDialDenied: info => denials.push(info),
    })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    closers.push(
      () =>
        new Promise(r => {
          proxy.closeAllConnections?.()
          proxy.close(() => r(undefined))
        }),
    )
    return (proxy.address() as { port: number }).port
  }

  async function rawExchange(
    proxyPort: number,
    payload: string,
  ): Promise<string> {
    const sock = connect({ host: '127.0.0.1', port: proxyPort })
    await once(sock, 'connect')
    sock.write(payload)
    let buf = ''
    sock.on('data', d => (buf += d.toString('latin1')))
    await Promise.race([
      once(sock, 'close'),
      once(sock, 'end').then(() => sock.destroy()),
    ])
    return buf
  }

  it('plain HTTP: allow-listed name resolving to loopback is refused with 403, upstream untouched', async () => {
    const proxyPort = await startHttpProxy()
    const resp = await rawExchange(
      proxyPort,
      `GET http://rebind.example.com:${upstreamPort}/secret HTTP/1.1\r\n` +
        `Host: rebind.example.com:${upstreamPort}\r\nConnection: close\r\n\r\n`,
    )
    expect(resp.startsWith('HTTP/1.1 403')).toBe(true)
    expect(resp).toContain(`X-Proxy-Error: ${RESOLVED_ADDRESS_DENIED_TAG}`)
    expect(resp).toContain('resolved to a denied address')
    expect(upstreamHits).toEqual([])
    expect(denials).toEqual([
      {
        host: 'rebind.example.com',
        port: upstreamPort,
        reason: 'resolved to denied address 127.0.0.1',
        encodedCommand: undefined,
      },
    ])
  })

  it('plain HTTP: an allow-listed IP literal is still dialed', async () => {
    const proxyPort = await startHttpProxy()
    const resp = await rawExchange(
      proxyPort,
      `GET http://127.0.0.1:${upstreamPort}/ok HTTP/1.1\r\n` +
        `Host: 127.0.0.1:${upstreamPort}\r\nConnection: close\r\n\r\n`,
    )
    expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
    expect(resp).toContain('upstream-ok')
    expect(denials).toEqual([])
  })

  it('plain HTTP: "localhost" may resolve to loopback', async () => {
    const proxyPort = await startHttpProxy()
    const resp = await rawExchange(
      proxyPort,
      `GET http://localhost:${upstreamPort}/ok HTTP/1.1\r\n` +
        `Host: localhost:${upstreamPort}\r\nConnection: close\r\n\r\n`,
    )
    expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
    expect(upstreamHits).toEqual([`GET /ok host=localhost:${upstreamPort}`])
  })

  it('plain HTTP: a permitted resolution dials the resolved address with the Host header preserved', async () => {
    const proxyPort = await startHttpProxy(
      createResolvedAddressGuard({ resolve, allowed: ['127.0.0.1'] }),
    )
    const resp = await rawExchange(
      proxyPort,
      `GET http://devbox.example.com:${upstreamPort}/app HTTP/1.1\r\n` +
        `Host: devbox.example.com:${upstreamPort}\r\nConnection: close\r\n\r\n`,
    )
    expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
    expect(upstreamHits).toEqual([
      `GET /app host=devbox.example.com:${upstreamPort}`,
    ])
    expect(resolve.calls).toContain('devbox.example.com')
  })

  it('plain HTTP: an embedder-configured range is refused too', async () => {
    const proxyPort = await startHttpProxy(
      createResolvedAddressGuard({
        resolve: fakeResolver({ 'intranet.example.com': ['10.20.30.40'] }),
        denied: ['10.0.0.0/8'],
      }),
    )
    const resp = await rawExchange(
      proxyPort,
      `GET http://intranet.example.com/ HTTP/1.1\r\nHost: intranet.example.com\r\nConnection: close\r\n\r\n`,
    )
    expect(resp.startsWith('HTTP/1.1 403')).toBe(true)
    expect(denials[0]?.reason).toBe('resolved to denied address 10.20.30.40')
  })

  it('CONNECT: allow-listed name resolving to loopback gets 403 instead of a tunnel', async () => {
    const proxyPort = await startHttpProxy()
    const resp = await rawExchange(
      proxyPort,
      `CONNECT rebind.example.com:${upstreamPort} HTTP/1.1\r\nHost: rebind.example.com:${upstreamPort}\r\n\r\n`,
    )
    expect(resp.startsWith('HTTP/1.1 403')).toBe(true)
    expect(resp).toContain(`X-Proxy-Error: ${RESOLVED_ADDRESS_DENIED_TAG}`)
    expect(denials.map(d => `${d.host}:${d.port}`)).toEqual([
      `rebind.example.com:${upstreamPort}`,
    ])
  })

  it('CONNECT: link-local (metadata-style) resolution is refused', async () => {
    const proxyPort = await startHttpProxy()
    const resp = await rawExchange(
      proxyPort,
      `CONNECT metadata.example.com:80 HTTP/1.1\r\nHost: metadata.example.com:80\r\n\r\n`,
    )
    expect(resp.startsWith('HTTP/1.1 403')).toBe(true)
    expect(denials[0]?.reason).toBe(
      'resolved to denied address 169.254.169.254',
    )
  })

  it('CONNECT: an allow-listed IP literal still tunnels', async () => {
    const proxyPort = await startHttpProxy()
    const sock = connect({ host: '127.0.0.1', port: proxyPort })
    await once(sock, 'connect')
    sock.write(
      `CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`,
    )
    const [first] = (await once(sock, 'data')) as [Buffer]
    expect(first.toString()).toContain('200 Connection Established')
    sock.write(
      `GET /tunnelled HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\nConnection: close\r\n\r\n`,
    )
    let buf = ''
    sock.on('data', d => (buf += d.toString()))
    await once(sock, 'close')
    expect(buf).toContain('upstream-ok')
    expect(denials).toEqual([])
  })

  // --- SOCKS -------------------------------------------------------------

  async function startSocks(
    guard = createResolvedAddressGuard({ resolve }),
  ): Promise<number> {
    const wrapper = createSocksProxyServer({
      filter: () => true,
      lookup: guard.lookup,
      onDirectDialDenied: info => denials.push(info),
    })
    const tcp: TcpServer = createTcpServer((s: Socket) =>
      wrapper.handleConnection(s),
    )
    tcp.listen(0, '127.0.0.1')
    await once(tcp, 'listening')
    closers.push(async () => {
      await wrapper.close()
      tcp.close()
    })
    return (tcp.address() as { port: number }).port
  }

  /** No-auth greeting, then CONNECT; resolves with the reply's REP byte. */
  async function socksConnect(
    socksPort: number,
    dest:
      | { type: 'domain'; host: string; port: number }
      | { type: 'ipv4'; host: string; port: number },
  ): Promise<{ rep: number; sock: Socket }> {
    const sock = connect({ host: '127.0.0.1', port: socksPort })
    await once(sock, 'connect')
    sock.write(Buffer.from([0x05, 0x01, 0x00]))
    const [method] = (await once(sock, 'data')) as [Buffer]
    expect([...method]).toEqual([0x05, 0x00])
    const portBytes = Buffer.from([(dest.port >> 8) & 0xff, dest.port & 0xff])
    const addr =
      dest.type === 'domain'
        ? Buffer.concat([
            Buffer.from([0x03, dest.host.length]),
            Buffer.from(dest.host, 'utf8'),
          ])
        : Buffer.from([0x01, ...dest.host.split('.').map(Number)])
    sock.write(
      Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, portBytes]),
    )
    const [reply] = (await once(sock, 'data')) as [Buffer]
    return { rep: reply[1]!, sock }
  }

  it('SOCKS: allow-listed name resolving to loopback gets "not allowed by ruleset"', async () => {
    const socksPort = await startSocks()
    const { rep, sock } = await socksConnect(socksPort, {
      type: 'domain',
      host: 'rebind.example.com',
      port: upstreamPort,
    })
    sock.destroy()
    expect(rep).toBe(0x02)
    expect(denials).toEqual([
      {
        host: 'rebind.example.com',
        port: upstreamPort,
        reason: 'resolved to denied address 127.0.0.1',
        encodedCommand: undefined,
      },
    ])
  })

  it('SOCKS: an IP-literal destination is still granted', async () => {
    const socksPort = await startSocks()
    const { rep, sock } = await socksConnect(socksPort, {
      type: 'ipv4',
      host: '127.0.0.1',
      port: upstreamPort,
    })
    expect(rep).toBe(0x00)
    sock.write(
      `GET /via-socks HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\nConnection: close\r\n\r\n`,
    )
    let buf = ''
    sock.on('data', d => (buf += d.toString()))
    await once(sock, 'close')
    expect(buf).toContain('upstream-ok')
    expect(denials).toEqual([])
  })

  it('SOCKS: a permitted resolution is dialed at the resolved address', async () => {
    const socksPort = await startSocks(
      createResolvedAddressGuard({ resolve, allowed: ['127.0.0.0/8'] }),
    )
    const { rep, sock } = await socksConnect(socksPort, {
      type: 'domain',
      host: 'devbox.example.com',
      port: upstreamPort,
    })
    expect(rep).toBe(0x00)
    sock.write(
      `GET /via-socks-name HTTP/1.1\r\nHost: devbox.example.com\r\nConnection: close\r\n\r\n`,
    )
    let buf = ''
    sock.on('data', d => (buf += d.toString()))
    await once(sock, 'close')
    expect(buf).toContain('upstream-ok')
    expect(upstreamHits).toEqual([
      'GET /via-socks-name host=devbox.example.com',
    ])
  })
})

// ---------------------------------------------------------------------------
// TLS-terminated leg: the upstream https.request gets the same lookup. Driven
// with curl (a real CONNECT-through-proxy client). The positive case relies
// on the runtime verifying the upstream certificate against the hostname,
// not the resolved IP, when a custom lookup is used — true for Node and for
// Bun >= 1.3.11.
// ---------------------------------------------------------------------------

describe('resolved-address-guard: TLS-terminated upstream leg', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  const UP_HOST = 'devbox.example.com'
  let upstream: ReturnType<typeof createHttpsServer>
  let upstreamPort: number
  let denials: Array<{ host: string; port: number; reason: string }>
  const closers: Array<() => Promise<unknown>> = []

  beforeEach(async () => {
    denials = []
    // Leaf for the HOSTNAME, served on 127.0.0.1: a request that reaches it
    // verified proves the upstream leg dialed the resolved address while
    // keeping SNI/verification on the name.
    const leaf = mintLeafCert(ca, UP_HOST)
    const leafOnly = leaf.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: leafOnly, key: leaf.keyPem },
      (req, res) => {
        res.writeHead(200, { 'x-upstream-host': String(req.headers.host) })
        res.end('tls-upstream-ok')
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port
    closers.push(() => new Promise(r => upstream.close(() => r(undefined))))
  })

  afterEach(async () => {
    for (const c of closers.splice(0)) await c()
  })

  async function startTerminatingProxy(
    guard: ReturnType<typeof createResolvedAddressGuard>,
  ): Promise<number> {
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      lookup: guard.lookup,
      onDirectDialDenied: info => denials.push(info),
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    closers.push(
      () =>
        new Promise(r => {
          proxy.closeAllConnections?.()
          proxy.close(() => r(undefined))
        }),
    )
    return (proxy.address() as AddressInfo).port
  }

  async function curl(
    proxyPort: number,
    url: string,
  ): Promise<{ exit: number; out: string }> {
    const child = spawn('curl', [
      '-sS',
      '--proxy',
      `http://127.0.0.1:${proxyPort}`,
      '--cacert',
      CA_CERT,
      '--max-time',
      '10',
      '-D',
      '-',
      url,
    ])
    let out = ''
    child.stdout.setEncoding('utf8').on('data', c => (out += c))
    child.stderr.resume()
    await new Promise<void>(r => child.stdout.once('end', () => r()))
    const exit = await new Promise<number>(r =>
      child.on('close', code => r(code ?? 1)),
    )
    return { exit, out }
  }

  it('hostname resolving to loopback: 403 inside the terminated session, upstream untouched', async () => {
    const proxyPort = await startTerminatingProxy(
      createResolvedAddressGuard({
        resolve: fakeResolver({ [UP_HOST]: ['127.0.0.1'] }),
      }),
    )
    const r = await curl(proxyPort, `https://${UP_HOST}:${upstreamPort}/secret`)
    expect(r.out).toContain('HTTP/1.1 403')
    expect(r.out.toLowerCase()).toContain(
      `x-proxy-error: ${RESOLVED_ADDRESS_DENIED_TAG}`,
    )
    expect(r.out).not.toContain('tls-upstream-ok')
    expect(denials).toEqual([
      {
        host: UP_HOST,
        port: upstreamPort,
        reason: 'resolved to denied address 127.0.0.1',
        encodedCommand: undefined,
      },
    ])
  })

  it('permitted resolution: dials the resolved address, verifies the certificate against the name', async () => {
    const resolve = fakeResolver({ [UP_HOST]: ['127.0.0.1'] })
    const proxyPort = await startTerminatingProxy(
      createResolvedAddressGuard({ resolve, allowed: ['127.0.0.1'] }),
    )
    const r = await curl(proxyPort, `https://${UP_HOST}:${upstreamPort}/app`)
    expect(r.exit).toBe(0)
    expect(r.out).toContain('HTTP/1.1 200')
    expect(r.out).toContain('tls-upstream-ok')
    expect(r.out).toContain(`x-upstream-host: ${UP_HOST}:${upstreamPort}`)
    expect(resolve.calls).toContain(UP_HOST)
    expect(denials).toEqual([])
  })
})
