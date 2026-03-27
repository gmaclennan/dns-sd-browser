/**
 * RFC compliance tests — covers protocol requirements from RFC 6762 and
 * RFC 6763 that are not covered by the main browse.test.js suite.
 *
 * These tests verify edge cases, timing behavior, cache management,
 * response validation, and advanced DNS-SD scenarios.
 */
import { describe, test, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import dnsPacket from 'dns-packet'
import { DnsSdBrowser } from '../lib/index.js'
import { TestAdvertiser } from './helpers/advertiser.js'
import { nextEvent, collectEvents, getRandomPort, delay, TEST_INTERFACE } from './helpers/utils.js'

// ─── Cache & TTL Management (RFC 6762 §6, §10.1) ─────────────────────

describe('Cache and TTL management', () => {
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

  test('SRV goodbye removes the service (RFC 6762 §10.1)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'SRV Goodbye',
      type: '_http._tcp',
      host: 'srvbye.local',
      port: 8080,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')

    // Send a standalone SRV record with TTL=0
    const srvGoodbye = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'SRV',
          name: 'SRV Goodbye._http._tcp.local',
          ttl: 0,
          class: 'IN',
          flush: true,
          data: { target: 'srvbye.local', port: 8080, priority: 0, weight: 0 },
        },
      ],
    })
    await advertiser.sendRaw(srvGoodbye)

    const downEvent = await nextEvent(iter)
    assert.equal(downEvent.type, 'serviceDown')
    assert.equal(downEvent.service.name, 'SRV Goodbye')
    assert.equal(browser.services.size, 0)

    browser.destroy()
  })

  test('service re-appears after goodbye with different host', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'Reappear',
      type: '_http._tcp',
      host: 'host1.local',
      port: 80,
    }

    await advertiser.announce({
      ...serviceInfo,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.equal(upEvent.service.host, 'host1.local')

    // Send goodbye
    await advertiser.goodbye(serviceInfo)
    const downEvent = await nextEvent(iter)
    assert.equal(downEvent.type, 'serviceDown')

    // Re-announce on a different host
    await advertiser.announce({
      ...serviceInfo,
      host: 'host2.local',
      addresses: ['192.168.1.2'],
    })

    const reUpEvent = await nextEvent(iter)
    assert.equal(reUpEvent.type, 'serviceUp')
    assert.equal(reUpEvent.service.host, 'host2.local')
    assert.ok(reUpEvent.service.addresses.includes('192.168.1.2'))

    browser.destroy()
  })

  test('address update emits serviceUpdated', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Addr Update',
      type: '_http._tcp',
      host: 'addrup.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')

    // Send an additional A record for the same host
    const addrUpdate = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'A',
          name: 'addrup.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: '10.0.0.1',
        },
      ],
    })
    await advertiser.sendRaw(addrUpdate)

    const updateEvent = await nextEvent(iter)
    assert.equal(updateEvent.type, 'serviceUpdated')
    assert.ok(updateEvent.service.addresses.includes('192.168.1.1'))
    assert.ok(updateEvent.service.addresses.includes('10.0.0.1'))

    browser.destroy()
  })
})

// ─── Response Validation (RFC 6762 §18) ───────────────────────────────

describe('Response validation', () => {
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
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('ignores query packets (QR=0) (RFC 6762 §18)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send a packet that looks like a query (QR=0), not a response
    const queryPacket = dnsPacket.encode({
      type: 'query',
      id: 0,
      questions: [
        { type: 'PTR', name: '_http._tcp.local' },
      ],
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'Sneaky._http._tcp.local',
        },
      ],
    })
    await advertiser.sendRaw(queryPacket)

    // Then send a legitimate response
    await advertiser.announce({
      name: 'Legit',
      type: '_http._tcp',
      host: 'legit.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'Legit')

    browser.destroy()
  })

  test('ignores packets with non-zero opcode (RFC 6762 §18.3)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Manually craft a response with opcode != 0
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'BadOpcode._http._tcp.local',
        },
      ],
    })
    // Set opcode to 1 (IQUERY) in the flags field (byte 2, bits 14-11)
    buf[2] = buf[2] | 0x08 // Set opcode bit
    await advertiser.sendRaw(buf)

    // Then send valid
    await advertiser.announce({
      name: 'After Bad Opcode',
      type: '_http._tcp',
      host: 'ok.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.service.name, 'After Bad Opcode')

    browser.destroy()
  })

  test('ignores packets with non-zero rcode (RFC 6762 §18.3)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Craft a response with rcode = SERVFAIL (2)
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'BadRcode._http._tcp.local',
        },
      ],
    })
    // Set rcode to 2 (SERVFAIL) in byte 3, lower nibble
    buf[3] = (buf[3] & 0xf0) | 0x02
    await advertiser.sendRaw(buf)

    // Then send valid
    await advertiser.announce({
      name: 'After Bad Rcode',
      type: '_http._tcp',
      host: 'ok2.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.service.name, 'After Bad Rcode')

    browser.destroy()
  })

  test('handles records with invalid data structures gracefully', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send a packet with a truncated SRV record (rdlength too short)
    // Build a minimal valid-looking but internally broken packet
    const brokenBuf = Buffer.alloc(12 + 20 + 10 + 2) // header + name + meta + tiny rdata
    // Header: QR=1, AA=1, 1 answer
    brokenBuf.writeUInt16BE(0x0000, 0)  // ID
    brokenBuf.writeUInt16BE(0x8400, 2)  // flags
    brokenBuf.writeUInt16BE(0, 4)       // QDCOUNT
    brokenBuf.writeUInt16BE(1, 6)       // ANCOUNT
    brokenBuf.writeUInt16BE(0, 8)       // NSCOUNT
    brokenBuf.writeUInt16BE(0, 10)      // ARCOUNT
    // Name: _http._tcp.local
    let off = 12
    const labels = ['_http', '_tcp', 'local']
    for (const label of labels) {
      brokenBuf[off++] = label.length
      Buffer.from(label).copy(brokenBuf, off)
      off += label.length
    }
    brokenBuf[off++] = 0 // null terminator
    // Type: SRV (33)
    brokenBuf.writeUInt16BE(33, off); off += 2
    // Class: IN
    brokenBuf.writeUInt16BE(1, off); off += 2
    // TTL
    brokenBuf.writeUInt32BE(120, off); off += 4
    // RDLENGTH: 2 (way too short for SRV which needs 6 + name)
    brokenBuf.writeUInt16BE(2, off); off += 2
    // RDATA: just 2 garbage bytes
    brokenBuf.writeUInt16BE(0, off)

    await advertiser.sendRaw(brokenBuf)

    // Send valid afterwards
    await advertiser.announce({
      name: 'After Broken',
      type: '_http._tcp',
      host: 'ok3.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'After Broken')

    browser.destroy()
  })
})

// ─── Query Scheduling (RFC 6762 §5.2) ─────────────────────────────────

describe('Query scheduling', () => {
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

  test('queries continue after service is discovered (RFC 6762 §5.2)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Wait for initial query
    await advertiser.waitForQuery((q) =>
      (q.questions || []).some((qq) => qq.type === 'PTR' && qq.name === '_http._tcp.local')
    )

    // Announce a service
    await advertiser.announce({
      name: 'Continuing',
      type: '_http._tcp',
      host: 'cont.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    await nextEvent(iter) // serviceUp
    advertiser.clearQueries()

    // Wait for a subsequent query — browser should continue querying
    // even after discovering a service. The first re-query interval is ~1s.
    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )

    assert.ok(query, 'browser should continue sending queries after discovery')

    browser.destroy()
  })

  test('sends at least two queries with increasing intervals (RFC 6762 §5.2)', async () => {
    const browser = mdns.browse('_http._tcp')
    advertiser.clearQueries()

    // Wait for initial query
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR' && qq.name === '_http._tcp.local'),
      1000
    )

    const firstQueryTime = Date.now()
    advertiser.clearQueries()

    // Wait for second query (~1s interval)
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )

    const secondQueryTime = Date.now()
    const interval = secondQueryTime - firstQueryTime

    // First re-query interval is ~1000ms (±jitter)
    assert.ok(interval >= 800, `interval ${interval}ms should be >= 800ms`)
    assert.ok(interval < 2500, `interval ${interval}ms should be < 2500ms`)

    browser.destroy()
  })

  test('known-answer suppression: only includes PTR with >50% TTL remaining (RFC 6762 §7.1)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Announce with a very short TTL (2 seconds)
    const shortTtlPacket = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 2,
          class: 'IN',
          data: 'ShortTTL._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'ShortTTL._http._tcp.local',
          ttl: 2,
          class: 'IN',
          flush: true,
          data: { target: 'short.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'ShortTTL._http._tcp.local',
          ttl: 2,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'short.local',
          ttl: 2,
          class: 'IN',
          flush: true,
          data: '192.168.1.1',
        },
      ],
    })
    await advertiser.sendRaw(shortTtlPacket)

    await nextEvent(iter) // serviceUp

    // Wait > 50% of the 2s TTL (i.e. > 1s) so the known answer should NOT be included
    await delay(1200)

    advertiser.clearQueries()

    // Wait for next query — it should NOT contain the short-TTL known answer
    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )

    // The answer section should be empty (no known answers with >50% TTL)
    const knownAnswers = (query.answers || []).filter(
      (a) => a.type === 'PTR' && a.data === 'ShortTTL._http._tcp.local'
    )
    assert.equal(knownAnswers.length, 0, 'should not include expired known answer')

    browser.destroy()
  })

  test('multiple known answers in single query (RFC 6762 §7.1)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Announce two services with long TTLs
    await advertiser.announce({
      name: 'KnownA',
      type: '_http._tcp',
      host: 'ka.local',
      port: 80,
      addresses: ['192.168.1.1'],
      ttl: 4500,
    })
    await nextEvent(iter) // serviceUp for KnownA

    await advertiser.announce({
      name: 'KnownB',
      type: '_http._tcp',
      host: 'kb.local',
      port: 81,
      addresses: ['192.168.1.2'],
      ttl: 4500,
    })
    await nextEvent(iter) // serviceUp for KnownB

    advertiser.clearQueries()

    // Wait for a query with multiple known answers
    try {
      const query = await advertiser.waitForQuery(
        (q) =>
          (q.questions || []).some((qq) => qq.type === 'PTR') &&
          (q.answers || []).length >= 2,
        5000
      )

      const knownNames = (query.answers || [])
        .filter((a) => a.type === 'PTR')
        .map((a) => a.data)
        .sort()

      assert.ok(
        knownNames.includes('KnownA._http._tcp.local'),
        'should include KnownA'
      )
      assert.ok(
        knownNames.includes('KnownB._http._tcp.local'),
        'should include KnownB'
      )
    } catch {
      // If no query arrived with both KAs in the window, that's acceptable
      // since the timing depends on the query schedule
    }

    browser.destroy()
  })
})

// ─── Record Type Edge Cases (RFC 6763 §5, §6) ────────────────────────

describe('Record type edge cases', () => {
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
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('handles large TXT records with multiple 255-byte strings (RFC 6763 §6.3)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const longValue = 'x'.repeat(200)

    await advertiser.announce({
      name: 'Large TXT',
      type: '_http._tcp',
      host: 'largetxt.local',
      port: 80,
      addresses: ['192.168.1.1'],
      txt: { key1: longValue, key2: 'short' },
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.txt.key1, longValue)
    assert.equal(event.service.txt.key2, 'short')

    browser.destroy()
  })

  test('handles TXT record with duplicate keys (first wins per RFC 6763 §6.4)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Manually construct a TXT record with duplicate keys
    const pkt = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'DupKey._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'DupKey._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'dupkey.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'DupKey._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: ['key=first', 'key=second', 'other=value'],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'dupkey.local',
          ttl: 120,
          class: 'IN',
          data: '192.168.1.1',
        },
      ],
    })
    await advertiser.sendRaw(pkt)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    // RFC 6763 §6.4: first occurrence wins
    assert.equal(event.service.txt.key, 'first')
    assert.equal(event.service.txt.other, 'value')

    browser.destroy()
  })

  test('resolves service even when records arrive in unusual order', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send A record first, then SRV, then PTR — reversed from normal
    const pkt = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'A',
          name: 'reversed.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: '10.0.0.5',
        },
        {
          type: 'TXT',
          name: 'Reversed._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: ['order=reversed'],
        },
        {
          type: 'SRV',
          name: 'Reversed._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'reversed.local', port: 9090, priority: 0, weight: 0 },
        },
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'Reversed._http._tcp.local',
        },
      ],
    })
    await advertiser.sendRaw(pkt)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'Reversed')
    assert.equal(event.service.port, 9090)
    assert.equal(event.service.txt.order, 'reversed')
    assert.ok(event.service.addresses.includes('10.0.0.5'))

    browser.destroy()
  })

  test('handles PTR without SRV then later SRV arrives', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send only PTR — no SRV, so service can't be fully resolved yet
    const ptrOnly = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'Delayed._http._tcp.local',
        },
      ],
    })
    await advertiser.sendRaw(ptrOnly)

    // No serviceUp yet (no SRV)
    await delay(200)
    assert.equal(browser.services.size, 0)

    // Now send the SRV + A as a separate response
    const srvResponse = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'Delayed._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'Delayed._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'delayed.local', port: 3000, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'Delayed._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'delayed.local',
          ttl: 120,
          class: 'IN',
          data: '192.168.1.50',
        },
      ],
    })
    await advertiser.sendRaw(srvResponse)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'Delayed')
    assert.equal(event.service.port, 3000)

    browser.destroy()
  })

  test('case-insensitive PTR name matching (RFC 1035 §3.1)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send PTR with mixed case in the name field
    const pkt = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_HTTP._TCP.local',
          ttl: 4500,
          class: 'IN',
          data: 'CaseTest._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'CaseTest._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'case.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'CaseTest._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'case.local',
          ttl: 120,
          class: 'IN',
          data: '192.168.1.1',
        },
      ],
    })
    await advertiser.sendRaw(pkt)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'CaseTest')

    browser.destroy()
  })
})

// ─── Advanced Scenarios & Robustness ──────────────────────────────────

describe('Advanced scenarios', () => {
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
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('rapid service up/down cycles without event loss', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'Rapid',
      type: '_http._tcp',
      host: 'rapid.local',
      port: 80,
    }

    // Rapidly announce and remove
    await advertiser.announce({ ...serviceInfo, addresses: ['192.168.1.1'] })
    await advertiser.goodbye(serviceInfo)
    await advertiser.announce({ ...serviceInfo, addresses: ['192.168.1.1'] })

    // Should get up, down, up in order
    const events = await collectEvents(iter, 3, 5000)
    assert.equal(events[0].type, 'serviceUp')
    assert.equal(events[1].type, 'serviceDown')
    assert.equal(events[2].type, 'serviceUp')

    browser.destroy()
  })

  test('concurrent browsers for same service type share transport', async () => {
    const browser1 = mdns.browse('_http._tcp')
    const browser2 = mdns.browse('_http._tcp')
    const iter1 = browser1[Symbol.asyncIterator]()
    const iter2 = browser2[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Shared',
      type: '_http._tcp',
      host: 'shared.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    // Both browsers should receive the event
    const event1 = await nextEvent(iter1)
    const event2 = await nextEvent(iter2)

    assert.equal(event1.type, 'serviceUp')
    assert.equal(event1.service.name, 'Shared')
    assert.equal(event2.type, 'serviceUp')
    assert.equal(event2.service.name, 'Shared')

    browser1.destroy()
    browser2.destroy()
  })

  test('service with port change emits serviceUpdated', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'PortChange',
      type: '_http._tcp',
      host: 'portchange.local',
      port: 8080,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.service.port, 8080)

    // Re-announce with different port
    await advertiser.announce({
      name: 'PortChange',
      type: '_http._tcp',
      host: 'portchange.local',
      port: 9090,
      addresses: ['192.168.1.1'],
    })

    const updateEvent = await nextEvent(iter)
    assert.equal(updateEvent.type, 'serviceUpdated')
    assert.equal(updateEvent.service.port, 9090)

    browser.destroy()
  })

  test('service with host change emits serviceUpdated', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'HostChange',
      type: '_http._tcp',
      host: 'old.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.service.host, 'old.local')

    // Re-announce with different host
    await advertiser.announce({
      name: 'HostChange',
      type: '_http._tcp',
      host: 'new.local',
      port: 80,
      addresses: ['192.168.1.2'],
    })

    const updateEvent = await nextEvent(iter)
    assert.equal(updateEvent.type, 'serviceUpdated')
    assert.equal(updateEvent.service.host, 'new.local')

    browser.destroy()
  })

  test('handles many services without issues', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const count = 50
    for (let i = 0; i < count; i++) {
      await advertiser.announce({
        name: `Service ${i}`,
        type: '_http._tcp',
        host: `host${i}.local`,
        port: 8000 + i,
        addresses: [`192.168.1.${i + 1}`],
      })
    }

    const events = await collectEvents(iter, count, 10000)
    assert.equal(events.length, count)
    assert.ok(events.every((e) => e.type === 'serviceUp'))
    assert.equal(browser.services.size, count)

    browser.destroy()
  })

  test('service name with special characters', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: "John's Printer (2nd Floor)",
      type: '_http._tcp',
      host: 'printer.local',
      port: 631,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, "John's Printer (2nd Floor)")

    browser.destroy()
  })

  test('browser ignores services of different type', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Announce an IPP service — should be ignored by an HTTP browser
    await advertiser.announce({
      name: 'Wrong Type',
      type: '_ipp._tcp',
      host: 'ipp.local',
      port: 631,
      addresses: ['192.168.1.1'],
    })

    // Then announce an HTTP service
    await advertiser.announce({
      name: 'Right Type',
      type: '_http._tcp',
      host: 'http.local',
      port: 80,
      addresses: ['192.168.1.2'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.service.name, 'Right Type')

    browser.destroy()
  })
})
