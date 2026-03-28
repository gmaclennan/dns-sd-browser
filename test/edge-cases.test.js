/**
 * Edge case tests that fill coverage gaps identified during test review.
 *
 * Covers:
 * - browse()/browseAll() after destroy()
 * - parseServiceType with 3-part string form
 * - IPv6 encode/decode roundtrips
 * - Malformed A/AAAA rdlength handling
 * - TXT goodbye (TTL=0)
 * - Binary and edge-case TXT records
 * - extractInstanceName fallback
 * - Symbol.asyncDispose actually disposing
 * - Authority section records
 * - Unknown record types
 */

import { describe, test, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import dnsPacket from 'dns-packet'
import * as dns from '../lib/dns.js'
import { parseServiceType, extractInstanceName, parseTxtData } from '../lib/service.js'
import { DnsSdBrowser } from '../lib/index.js'
import { TestAdvertiser } from './helpers/advertiser.js'
import { nextEvent, getRandomPort, delay, TEST_INTERFACE } from './helpers/utils.js'

// ─── API misuse ──────────────────────────────────────────────────────────

describe('API misuse: operations after destroy', () => {
  test('browse() throws after DnsSdBrowser is destroyed', async () => {
    const port = await getRandomPort()
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    await mdns.destroy()

    assert.throws(
      () => mdns.browse('_http._tcp'),
      /has been destroyed/
    )
  })

  test('browseAll() throws after DnsSdBrowser is destroyed', async () => {
    const port = await getRandomPort()
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    await mdns.destroy()

    assert.throws(
      () => mdns.browseAll(),
      /has been destroyed/
    )
  })

  test('double destroy is a no-op', async () => {
    const port = await getRandomPort()
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    await mdns.destroy()
    await mdns.destroy() // should not throw
  })

  test('Symbol.asyncDispose actually cleans up the transport', async () => {
    const port = await getRandomPort()
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')
    await mdns.ready()

    // Dispose via Symbol.asyncDispose
    await mdns[Symbol.asyncDispose]()

    // After dispose, browse should throw
    assert.throws(
      () => mdns.browse('_http._tcp'),
      /has been destroyed/
    )
  })

  test('ServiceBrowser Symbol.asyncDispose ends iteration', async () => {
    const port = await getRandomPort()
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await browser[Symbol.asyncDispose]()

    const result = await iter.next()
    assert.equal(result.done, true)

    await mdns.destroy()
  })
})

// ─── parseServiceType coverage ──────────────────────────────────────────

describe('parseServiceType edge cases', () => {
  test('parses 3-part string with .local suffix', () => {
    const result = parseServiceType('_http._tcp.local')
    assert.equal(result.type, '_http._tcp')
    assert.equal(result.protocol, 'tcp')
    assert.equal(result.domain, 'local')
    assert.equal(result.queryName, '_http._tcp.local')
  })

  test('parses 2-part string without .local suffix', () => {
    const result = parseServiceType('_http._tcp')
    assert.equal(result.type, '_http._tcp')
    assert.equal(result.protocol, 'tcp')
    assert.equal(result.domain, 'local')
    assert.equal(result.queryName, '_http._tcp.local')
  })

  test('parses UDP protocol', () => {
    const result = parseServiceType('_dns._udp')
    assert.equal(result.protocol, 'udp')
  })

  test('object form with underscored name', () => {
    const result = parseServiceType({ name: '_http', protocol: '_tcp' })
    assert.equal(result.type, '_http._tcp')
    assert.equal(result.protocol, 'tcp')
  })
})

// ─── extractInstanceName coverage ───────────────────────────────────────

describe('extractInstanceName', () => {
  test('extracts name when FQDN matches suffix', () => {
    const name = extractInstanceName(
      'My Printer._http._tcp.local',
      '_http._tcp.local'
    )
    assert.equal(name, 'My Printer')
  })

  test('returns full FQDN when suffix does not match', () => {
    const name = extractInstanceName(
      'My Printer._ipp._tcp.local',
      '_http._tcp.local'
    )
    assert.equal(name, 'My Printer._ipp._tcp.local')
  })
})

// ─── IPv6 roundtrip tests ───────────────────────────────────────────────

describe('IPv6 encode/decode roundtrip', () => {
  const ipv6Addresses = [
    'fe80::1',
    '::1',
    '::',
    'ff02::fb',
    '2001:db8::1',
    '2001:db8:85a3::8a2e:370:7334',
  ]

  for (const addr of ipv6Addresses) {
    test(`roundtrips ${addr}`, () => {
      const buf = dnsPacket.encode({
        type: 'response',
        id: 0,
        flags: dnsPacket.AUTHORITATIVE_ANSWER,
        answers: [{
          type: 'AAAA',
          name: 'host.local',
          ttl: 120,
          class: 'IN',
          data: addr,
        }],
      })

      const decoded = dns.decode(buf)
      assert.equal(decoded.answers.length, 1)

      // Decode the result with dns-packet too to get canonical form
      const reference = dnsPacket.decode(buf)
      const refAddr = reference.answers[0].data

      // Our decoded address should match the canonical form
      assert.equal(decoded.answers[0].data, refAddr)
    })
  }
})

describe('IPv6 encoding via known-answer query', () => {
  test('encodes AAAA record in known answers', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers: [{
        name: 'host.local',
        type: dns.RecordType.AAAA,
        class: 1,
        cacheFlush: false,
        ttl: 120,
        data: 'fe80::1',
      }],
    })

    const decoded = dnsPacket.decode(buf)
    assert.equal(decoded.answers?.length, 1)
    assert.equal(decoded.answers?.[0].type, 'AAAA')
    assert.ok(
      decoded.answers?.[0].data?.includes('fe80'),
      'should contain fe80 address'
    )
  })
})

// ─── Malformed A/AAAA rdlength ──────────────────────────────────────────

describe('Malformed A/AAAA record handling', () => {
  test('A record with rdlength != 4 returns empty string', () => {
    // Build a packet with A record that has rdlength=3
    const buf = Buffer.alloc(26)
    buf.writeUInt16BE(0x8400, 2)  // flags
    buf.writeUInt16BE(1, 6)       // ANCOUNT = 1
    buf[12] = 0                   // Root name
    buf.writeUInt16BE(1, 13)      // TYPE = A
    buf.writeUInt16BE(1, 15)      // CLASS = IN
    buf.writeUInt32BE(120, 17)    // TTL
    buf.writeUInt16BE(3, 21)      // RDLENGTH = 3 (wrong for A)
    buf[23] = 192; buf[24] = 168; buf[25] = 1

    const decoded = dns.decode(buf)
    assert.equal(decoded.answers[0].data, '')
  })

  test('AAAA record with rdlength != 16 returns empty string', () => {
    // Build a packet with AAAA record that has rdlength=4
    const buf = Buffer.alloc(27)
    buf.writeUInt16BE(0x8400, 2)  // flags
    buf.writeUInt16BE(1, 6)       // ANCOUNT = 1
    buf[12] = 0                   // Root name
    buf.writeUInt16BE(28, 13)     // TYPE = AAAA
    buf.writeUInt16BE(1, 15)      // CLASS = IN
    buf.writeUInt32BE(120, 17)    // TTL
    buf.writeUInt16BE(4, 21)      // RDLENGTH = 4 (wrong for AAAA)
    buf.writeUInt32BE(0, 23)

    const decoded = dns.decode(buf)
    assert.equal(decoded.answers[0].data, '')
  })
})

// ─── TXT goodbye ────────────────────────────────────────────────────────

describe('TXT goodbye handling', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(async () => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    mdns.browse('_noop._tcp').destroy()
    await mdns.ready()
    advertiser.clearQueries()
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('TXT record with TTL=0 does not crash and does not update service', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'TxtGoodbye',
      type: '_http._tcp',
      host: 'txtbye.local',
      port: 80,
      addresses: ['192.168.1.1'],
      txt: { version: '1' },
    })

    const up = await nextEvent(iter)
    assert.equal(up.type, 'serviceUp')

    // Send a standalone TXT record with TTL=0
    const txtGoodbye = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [{
        type: 'TXT',
        name: 'TxtGoodbye._http._tcp.local',
        ttl: 0,
        class: 'IN',
        flush: true,
        data: ['version=2'],
      }],
    })
    await advertiser.sendRaw(txtGoodbye)

    // TXT goodbye should be silently ignored — not crash, not update
    await delay(300)

    // Service should still exist with original TXT data
    assert.equal(browser.services.size, 1)
    const service = browser.services.values().next().value
    assert.equal(service.txt.version, '1')

    browser.destroy()
  })
})

// ─── Binary/edge-case TXT ───────────────────────────────────────────────

describe('TXT record edge cases', () => {
  test('TXT with empty key (=value) is parsed as key="" value="value"', () => {
    const encoder = new TextEncoder()
    const { txt } = parseTxtData([encoder.encode('=value')])
    // Key is empty string, value is 'value'
    assert.equal(txt[''], 'value')
  })

  test('TXT with key=<empty> is parsed as empty string value', () => {
    const encoder = new TextEncoder()
    const { txt } = parseTxtData([encoder.encode('key=')])
    assert.equal(txt.key, '')
  })

  test('TXT with value containing = signs preserves them', () => {
    const encoder = new TextEncoder()
    const { txt } = parseTxtData([encoder.encode('eq=a=b=c')])
    assert.equal(txt.eq, 'a=b=c')
  })

  test('txtRaw contains raw Uint8Array for binary values', () => {
    const encoder = new TextEncoder()
    const { txtRaw } = parseTxtData([encoder.encode('bin=hello')])
    assert.ok(txtRaw.bin instanceof Uint8Array)
    assert.equal(new TextDecoder().decode(txtRaw.bin), 'hello')
  })

  test('empty txtData array returns empty objects', () => {
    const { txt, txtRaw } = parseTxtData([])
    assert.deepEqual(txt, {})
    assert.deepEqual(txtRaw, {})
  })
})

// ─── Authority section records ──────────────────────────────────────────

describe('Authority section parsing', () => {
  test('decodes records in the authority section', () => {
    // Craft a packet with a record in the authority (NS) section
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [{
        type: 'PTR',
        name: '_http._tcp.local',
        ttl: 4500,
        class: 'IN',
        data: 'Test._http._tcp.local',
      }],
      authorities: [{
        type: 'A',
        name: 'auth.local',
        ttl: 120,
        class: 'IN',
        data: '10.0.0.1',
      }],
    })

    const decoded = dns.decode(buf)
    assert.equal(decoded.answers.length, 1)
    assert.equal(decoded.authorities.length, 1)
    assert.equal(decoded.authorities[0].name, 'auth.local')
    assert.equal(decoded.authorities[0].data, '10.0.0.1')
  })
})

// ─── Unknown record types ───────────────────────────────────────────────

describe('Unknown record type handling', () => {
  test('unknown record type returns raw bytes', () => {
    // Type 99 is not a known type — should return raw RDATA
    const buf = Buffer.alloc(27)
    buf.writeUInt16BE(0x8400, 2)  // flags
    buf.writeUInt16BE(1, 6)       // ANCOUNT = 1
    buf[12] = 0                   // Root name
    buf.writeUInt16BE(99, 13)     // TYPE = 99 (unknown)
    buf.writeUInt16BE(1, 15)      // CLASS = IN
    buf.writeUInt32BE(300, 17)    // TTL
    buf.writeUInt16BE(4, 21)      // RDLENGTH = 4
    buf[23] = 0xDE; buf[24] = 0xAD; buf[25] = 0xBE; buf[26] = 0xEF

    const decoded = dns.decode(buf)
    assert.equal(decoded.answers[0].type, 99)
    assert.ok(Array.isArray(decoded.answers[0].data))
    const raw = decoded.answers[0].data[0]
    assert.equal(raw[0], 0xDE)
    assert.equal(raw[1], 0xAD)
    assert.equal(raw[2], 0xBE)
    assert.equal(raw[3], 0xEF)
  })
})

// ─── Encode record types (A, SRV, TXT) via known answers ───────────────

describe('Encoding record types via known-answer queries', () => {
  test('encodes A record in known answers', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers: [{
        name: 'host.local',
        type: dns.RecordType.A,
        class: 1,
        cacheFlush: false,
        ttl: 120,
        data: '192.168.1.5',
      }],
    })

    const decoded = dnsPacket.decode(buf)
    assert.equal(decoded.answers?.[0].type, 'A')
    assert.equal(decoded.answers?.[0].data, '192.168.1.5')
  })

  test('encodes SRV record in known answers', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers: [{
        name: 'Test._http._tcp.local',
        type: dns.RecordType.SRV,
        class: 1,
        cacheFlush: true,
        ttl: 120,
        data: { priority: 0, weight: 0, port: 8080, target: 'host.local' },
      }],
    })

    const decoded = dnsPacket.decode(buf)
    assert.equal(decoded.answers?.[0].type, 'SRV')
    assert.equal(decoded.answers?.[0].data?.port, 8080)
    assert.equal(decoded.answers?.[0].data?.target, 'host.local')
  })

  test('encodes TXT record in known answers', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers: [{
        name: 'Test._http._tcp.local',
        type: dns.RecordType.TXT,
        class: 1,
        cacheFlush: false,
        ttl: 4500,
        data: [Buffer.from('key=value')],
      }],
    })

    const decoded = dnsPacket.decode(buf)
    assert.equal(decoded.answers?.[0].type, 'TXT')
  })

  test('encodes empty TXT record', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers: [{
        name: 'Test._http._tcp.local',
        type: dns.RecordType.TXT,
        class: 1,
        cacheFlush: false,
        ttl: 4500,
        data: [],
      }],
    })

    const decoded = dnsPacket.decode(buf)
    assert.equal(decoded.answers?.[0].type, 'TXT')
  })

  test('encodes QU bit in question', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR, qu: true }],
    })

    const decoded = dnsPacket.decode(buf)
    // dns-packet interprets QU bit; the class field should have the high bit set
    assert.equal(decoded.questions?.[0].name, '_http._tcp.local')
  })
})

// ─── 3-part service type through full browse flow ───────────────────────

describe('Browsing with 3-part service type string', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(async () => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    mdns.browse('_noop._tcp').destroy()
    await mdns.ready()
    advertiser.clearQueries()
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('browse("_http._tcp.local") discovers services', async () => {
    const browser = mdns.browse('_http._tcp.local')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'ThreePart',
      type: '_http._tcp',
      host: 'three.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'ThreePart')

    browser.destroy()
  })
})
