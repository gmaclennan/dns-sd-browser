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
import { setOpcode, setRcode, setQUBitOnFirstQuestion } from './helpers/dns-packet-utils.js'

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

  test('address update without cache-flush merges addresses', async () => {
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

    // Send an additional A record WITHOUT cache-flush — should merge
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
          flush: false,
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

  test('address update with cache-flush replaces addresses (RFC 6762 §10.2)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Addr Flush',
      type: '_http._tcp',
      host: 'addrflush.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.ok(upEvent.service.addresses.includes('192.168.1.1'))

    // Wait >1s so the old address is outside the cache-flush grace period
    await delay(1100)

    // Send an A record WITH cache-flush — should replace, not merge
    const addrUpdate = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'A',
          name: 'addrflush.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: '10.0.0.2',
        },
      ],
    })
    await advertiser.sendRaw(addrUpdate)

    const updateEvent = await nextEvent(iter)
    assert.equal(updateEvent.type, 'serviceUpdated')
    // Old address should be flushed, only new one present
    assert.deepEqual(updateEvent.service.addresses, ['10.0.0.2'])

    browser.destroy()
  })

  test('cache-flush within 1s grace period merges addresses (RFC 6762 §10.2)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Addr Grace',
      type: '_http._tcp',
      host: 'addrgrace.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.ok(upEvent.service.addresses.includes('192.168.1.1'))

    // Immediately send a cache-flush address update (within 1 second)
    // Per RFC 6762 §10.2, the old address should be kept because it was
    // received less than 1 second ago (grace period for multi-packet bursts)
    const addrUpdate = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'A',
          name: 'addrgrace.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: '10.0.0.3',
        },
      ],
    })
    await advertiser.sendRaw(addrUpdate)

    const updateEvent = await nextEvent(iter)
    assert.equal(updateEvent.type, 'serviceUpdated')
    // Both addresses should be present — old one kept due to grace period
    assert.ok(updateEvent.service.addresses.includes('192.168.1.1'),
      'old address should be kept within 1s grace period')
    assert.ok(updateEvent.service.addresses.includes('10.0.0.3'),
      'new address should be added')

    browser.destroy()
  })

  test('TXT goodbye (TTL=0) is silently ignored — service remains unchanged', async () => {
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

    assert.equal(browser.services.size, 1)
    const service = browser.services.values().next().value
    assert.equal(service.txt.version, '1')

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
    setOpcode(buf, 1) // IQUERY
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

  test('accepts packets with non-zero rcode (RFC 6762 §18.11 — lenient)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Craft a full service announcement with rcode = SERVFAIL (2).
    // Per RFC 6762 §18.11, receivers SHOULD silently ignore the rcode field.
    // Some buggy advertisers set non-zero rcodes in otherwise valid responses.
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
        {
          type: 'SRV',
          name: 'BadRcode._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'rcode.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'BadRcode._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'rcode.local',
          ttl: 120,
          class: 'IN',
          data: '192.168.1.1',
        },
      ],
    })
    setRcode(buf, 2) // SERVFAIL
    await advertiser.sendRaw(buf)

    // The packet should still be processed despite the non-zero rcode
    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'BadRcode')

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

    // First re-query interval is ~1000ms (±jitter).
    // Use generous bounds to avoid flakes under CI load.
    assert.ok(interval >= 500, `interval ${interval}ms should be >= 500ms`)
    assert.ok(interval < 5000, `interval ${interval}ms should be < 5000ms`)

    browser.destroy()
  })

  test('known-answer suppression: only includes PTR with >50% TTL remaining (RFC 6762 §7.1)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Announce a service with a SHORT TTL (4 seconds) — will drop below 50%
    const mkShortTtlPacket = (ttl) => dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl,
          class: 'IN',
          data: 'ShortTTL._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'ShortTTL._http._tcp.local',
          ttl,
          class: 'IN',
          flush: true,
          data: { target: 'short.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'ShortTTL._http._tcp.local',
          ttl,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'short.local',
          ttl,
          class: 'IN',
          flush: true,
          data: '192.168.1.1',
        },
      ],
    })

    // Also announce a LONG-TTL service — should always appear as known answer
    await advertiser.announce({
      name: 'LongTTL',
      type: '_http._tcp',
      host: 'long.local',
      port: 81,
      addresses: ['192.168.1.2'],
      ttl: 4500,
    })
    await nextEvent(iter) // serviceUp for LongTTL

    await advertiser.sendRaw(mkShortTtlPacket(4))
    await nextEvent(iter) // serviceUp for ShortTTL

    // Wait > 50% of the 4s TTL (i.e. > 2s) so the short-TTL known answer
    // drops below the 50% threshold, but the service hasn't fully expired.
    await delay(2500)

    // Verify the short-TTL service still exists (hasn't expired yet)
    assert.equal(browser.services.size, 2, 'both services should still exist')

    advertiser.clearQueries()

    // Wait for next query — it should include LongTTL but NOT ShortTTL
    const query = await advertiser.waitForQuery(
      (q) =>
        (q.questions || []).some((qq) => qq.type === 'PTR') &&
        (q.answers || []).some(
          (a) => a.type === 'PTR' && a.data === 'LongTTL._http._tcp.local'
        ),
      10000
    )

    // The long-TTL service should be included as a known answer
    const longKA = (query.answers || []).find(
      (a) => a.type === 'PTR' && a.data === 'LongTTL._http._tcp.local'
    )
    assert.ok(longKA, 'should include long-TTL known answer')

    // The short-TTL service should NOT be included (below 50% TTL)
    const shortKA = (query.answers || []).find(
      (a) => a.type === 'PTR' && a.data === 'ShortTTL._http._tcp.local'
    )
    assert.equal(shortKA, undefined, 'should not include short-TTL known answer below 50%')

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

    // Wait for a query with multiple known answers.
    // After both services are discovered, the next re-query (~1s interval)
    // should include both PTR records as known answers.
    const query = await advertiser.waitForQuery(
      (q) =>
        (q.questions || []).some((qq) => qq.type === 'PTR') &&
        (q.answers || []).length >= 2,
      10000
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

  test('goodbye followed by rapid re-announce cancels the goodbye (RFC 6762 §10.1)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'Rapid',
      type: '_http._tcp',
      host: 'rapid.local',
      port: 80,
    }

    // Announce, then goodbye, then re-announce quickly
    await advertiser.announce({ ...serviceInfo, addresses: ['192.168.1.1'] })
    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')

    // Goodbye schedules removal after 1 second per RFC 6762 §10.1
    await advertiser.goodbye(serviceInfo)
    // Re-announce within the 1-second window cancels the pending goodbye
    await advertiser.announce({ ...serviceInfo, addresses: ['192.168.1.1'] })

    // Wait past the 1-second goodbye window
    await delay(1500)

    // Service should still be alive — the re-announce cancelled the goodbye
    assert.equal(browser.services.size, 1, 'service should still exist after cancelled goodbye')

    browser.destroy()
  })

  test('goodbye removes service after 1-second delay (RFC 6762 §10.1)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'DelayedGoodbye',
      type: '_http._tcp',
      host: 'delayed.local',
      port: 80,
    }

    await advertiser.announce({ ...serviceInfo, addresses: ['192.168.1.1'] })
    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')

    await advertiser.goodbye(serviceInfo)

    // Service should still exist immediately after goodbye
    assert.equal(browser.services.size, 1, 'service should persist for 1 second after goodbye')

    // After the 1-second delay, the service should be removed
    const downEvent = await nextEvent(iter, 3000)
    assert.equal(downEvent.type, 'serviceDown')
    assert.equal(downEvent.service.name, 'DelayedGoodbye')
    assert.equal(browser.services.size, 0)

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

// ─── Duplicate Question Suppression (RFC 6762 §7.3) ────────────────────

describe('Duplicate question suppression (RFC 6762 §7.3)', () => {
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

  test('suppresses next query when another host sends matching QM query with sufficient known answers', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Announce a service so the browser has a known PTR record
    await advertiser.announce({
      name: 'Suppression Test',
      type: '_http._tcp',
      host: 'suppress.local',
      port: 8080,
      addresses: ['192.168.1.50'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.equal(upEvent.service.name, 'Suppression Test')

    // Wait for two browser queries so we're well into the QM phase.
    // After the initial QU query (queryIndex 0→1), next interval is 2s.
    // After that fires (queryIndex 1→2), next interval is 4s.
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )
    advertiser.clearQueries()
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      5000
    )

    // Now queryIndex=2, next unsuppressed interval is ~4s.
    // Wait 200ms past the loopback guard so the browser doesn't
    // mistake our injected query for its own.
    await delay(200)
    advertiser.clearQueries()

    await advertiser.sendQuery({
      questions: [{ type: 'PTR', name: '_http._tcp.local', class: 'IN' }],
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'Suppression Test._http._tcp.local',
        },
      ],
    })

    // Allow suppression to take effect
    await delay(100)
    advertiser.clearQueries()
    const measureStart = Date.now()

    // Wait for the next query from the browser.
    const nextQuery = await advertiser.waitForQuery(
      (q) => (q.questions || []).some(
        (qq) => qq.type === 'PTR' && qq.name === '_http._tcp.local'
      ),
      15000
    )
    const elapsed = Date.now() - measureStart

    assert.ok(nextQuery, 'should eventually receive a query')
    // Without suppression, the next query would fire at the current ~4s
    // interval (~3.7s from measureStart). With suppression, queryIndex
    // advances to 3 and the interval becomes ~8s (~7.7s from measureStart).
    // Assert the delay exceeds the unsuppressed interval, proving
    // suppression pushed the schedule forward. Use a generous lower bound
    // to account for CI timing jitter.
    assert.ok(
      elapsed >= 4000,
      `Expected suppressed query to be delayed beyond the normal ~4s interval; got ${elapsed}ms`
    )

    browser.destroy()
  })

  test('does NOT suppress when incoming query has insufficient known answers', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Announce two services so the browser knows about both
    await advertiser.announce({
      name: 'Service A',
      type: '_http._tcp',
      host: 'a.local',
      port: 8080,
      addresses: ['192.168.1.51'],
    })
    const ev1 = await nextEvent(iter)
    assert.equal(ev1.type, 'serviceUp')

    await advertiser.announce({
      name: 'Service B',
      type: '_http._tcp',
      host: 'b.local',
      port: 8081,
      addresses: ['192.168.1.52'],
    })
    const ev2 = await nextEvent(iter)
    assert.equal(ev2.type, 'serviceUp')

    // Wait for a scheduled QM query so we're past the initial QU phase.
    // After this fires (queryIndex 1→2), next interval is ~4s.
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )

    // Wait past the loopback guard so the browser processes our query
    await delay(200)
    advertiser.clearQueries()
    const measureStart = Date.now()

    // Send a QM query that only covers one of the two known services
    // (insufficient known answers — should NOT suppress)
    await advertiser.sendQuery({
      questions: [{ type: 'PTR', name: '_http._tcp.local', class: 'IN' }],
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'Service A._http._tcp.local',
        },
        // Service B is missing from the known answers
      ],
    })

    // The browser should NOT suppress — its next query should arrive on the
    // normal ~4s schedule. If suppression incorrectly fired, the interval
    // would jump to ~8s.
    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some(
        (qq) => qq.type === 'PTR' && qq.name === '_http._tcp.local'
      ),
      7000
    )
    const elapsed = Date.now() - measureStart

    assert.ok(query, 'browser should still send query when known answers are insufficient')
    // Normal interval is ~4s. If suppression incorrectly fired it would be ~8s.
    // Assert the query arrived within the normal interval window.
    // Use a generous upper bound for CI jitter.
    assert.ok(
      elapsed < 8000,
      `Expected query on normal schedule (~4s); got ${elapsed}ms — suppression may have incorrectly fired`
    )

    browser.destroy()
  })

  test('does NOT suppress for QU (unicast) queries', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'QU Test',
      type: '_http._tcp',
      host: 'qutest.local',
      port: 8080,
      addresses: ['192.168.1.53'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')

    // Wait for one QM query so we're past initial QU phase.
    // After this fires (queryIndex 1→2), next interval is ~4s.
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )

    await delay(200)
    advertiser.clearQueries()
    const measureStart = Date.now()

    // Send a QU query with sufficient known answers. RFC 6762 §7.3
    // suppression applies only to QM questions, so this should NOT suppress.
    // Encode as a normal query, then set the QU bit (high bit of class field)
    // in the raw buffer since dns-packet doesn't support numeric class values.
    const quBuf = dnsPacket.encode({
      type: 'query',
      id: 0,
      flags: 0,
      questions: [{ type: 'PTR', name: '_http._tcp.local', class: 'IN' }],
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'QU Test._http._tcp.local',
        },
      ],
    })
    setQUBitOnFirstQuestion(quBuf)
    await advertiser.sendRaw(quBuf)

    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some(
        (qq) => qq.type === 'PTR' && qq.name === '_http._tcp.local'
      ),
      7000
    )
    const elapsed = Date.now() - measureStart

    assert.ok(query, 'browser should still send query after QU query from another host')
    // Use a generous upper bound for CI jitter.
    assert.ok(
      elapsed < 8000,
      `Expected query on normal schedule (~4s); got ${elapsed}ms — QU query should not suppress`
    )

    browser.destroy()
  })
})

// ─── Cache flush on failure indication (RFC 6762 §10.4) ─────────────

describe('Cache flush on failure indication', () => {
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

  test('reconfirm() removes service if no response within timeout (RFC 6762 §10.4)', async () => {
    const RECONFIRM_TIMEOUT = 500
    const browser = mdns.browse('_http._tcp', { reconfirmTimeoutMs: RECONFIRM_TIMEOUT })
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Stale Service',
      type: '_http._tcp',
      host: 'stale.local',
      port: 8080,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.equal(upEvent.service.name, 'Stale Service')

    // Request reconfirmation — no response will be sent
    browser.reconfirm('Stale Service._http._tcp.local')

    // Service should be removed after the reconfirmation timeout
    const downEvent = await nextEvent(iter, RECONFIRM_TIMEOUT + 2000)
    assert.equal(downEvent.type, 'serviceDown')
    assert.equal(downEvent.service.name, 'Stale Service')
    assert.equal(browser.services.size, 0)

    browser.destroy()
  })

  test('reconfirm() keeps service if response is received (RFC 6762 §10.4)', async () => {
    const RECONFIRM_TIMEOUT = 500
    const browser = mdns.browse('_http._tcp', { reconfirmTimeoutMs: RECONFIRM_TIMEOUT })
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Alive Service',
      type: '_http._tcp',
      host: 'alive.local',
      port: 8080,
      addresses: ['192.168.1.2'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.equal(upEvent.service.name, 'Alive Service')

    // Request reconfirmation
    browser.reconfirm('Alive Service._http._tcp.local')

    // Re-announce to prove the service is still alive
    await advertiser.announce({
      name: 'Alive Service',
      type: '_http._tcp',
      host: 'alive.local',
      port: 8080,
      addresses: ['192.168.1.2'],
    })

    // Wait past the reconfirmation timeout
    await delay(RECONFIRM_TIMEOUT + 200)

    // Service should still be present — it was reconfirmed
    assert.equal(browser.services.size, 1)
    assert.ok(browser.services.has('Alive Service._http._tcp.local'))

    browser.destroy()
  })

  test('reconfirm() on unknown FQDN is a no-op (RFC 6762 §10.4)', async () => {
    const browser = mdns.browse('_http._tcp', { reconfirmTimeoutMs: 500 })

    // Should not throw or cause any issues
    browser.reconfirm('Nonexistent._http._tcp.local')

    // Verify no services were affected
    assert.equal(browser.services.size, 0)

    browser.destroy()
  })
})

// ─── Passive Observation of Failures / POOF (RFC 6762 §10.5) ─────────

describe('Passive Observation of Failures (POOF) — RFC 6762 §10.5', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  // Use short timeouts for testing
  const POOF_TIMEOUT_MS = 3000
  const POOF_RESPONSE_WAIT_MS = 500

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

  test('flushes cached record after 2+ unanswered queries within timeout window', async () => {
    const browser = mdns.browse('_http._tcp', {
      poofTimeoutMs: POOF_TIMEOUT_MS,
      poofResponseWaitMs: POOF_RESPONSE_WAIT_MS,
    })
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'POOF Target',
      type: '_http._tcp',
      host: 'poof.local',
      port: 8080,
      addresses: ['192.168.1.50'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.equal(browser.services.size, 1)

    // Simulate another host querying (query 1)
    await advertiser.sendQuery({
      questions: [{ type: 'PTR', name: '_http._tcp.local', class: 'IN' }],
    })
    await delay(POOF_RESPONSE_WAIT_MS + 200)
    assert.equal(browser.services.size, 1, 'should still exist after 1 unanswered query')

    // Simulate another host querying (query 2) — triggers POOF flush
    await advertiser.sendQuery({
      questions: [{ type: 'PTR', name: '_http._tcp.local', class: 'IN' }],
    })
    await delay(POOF_RESPONSE_WAIT_MS + 200)

    const downEvent = await nextEvent(iter, 2000)
    assert.equal(downEvent.type, 'serviceDown')
    assert.equal(downEvent.service.name, 'POOF Target')
    assert.equal(browser.services.size, 0)

    browser.destroy()
  })

  test('does NOT flush record when a response is seen after the query', async () => {
    const browser = mdns.browse('_http._tcp', {
      poofTimeoutMs: POOF_TIMEOUT_MS,
      poofResponseWaitMs: POOF_RESPONSE_WAIT_MS,
    })
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'POOF Survivor',
      type: '_http._tcp',
      host: 'survivor.local',
      port: 9090,
      addresses: ['192.168.1.60'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')

    // Query 1 — respond before timer expires
    await advertiser.sendQuery({
      questions: [{ type: 'PTR', name: '_http._tcp.local', class: 'IN' }],
    })
    await delay(100)
    await advertiser.announce({
      name: 'POOF Survivor',
      type: '_http._tcp',
      host: 'survivor.local',
      port: 9090,
      addresses: ['192.168.1.60'],
    })
    await delay(POOF_RESPONSE_WAIT_MS + 200)

    // Query 2 — respond before timer expires
    await advertiser.sendQuery({
      questions: [{ type: 'PTR', name: '_http._tcp.local', class: 'IN' }],
    })
    await delay(100)
    await advertiser.announce({
      name: 'POOF Survivor',
      type: '_http._tcp',
      host: 'survivor.local',
      port: 9090,
      addresses: ['192.168.1.60'],
    })
    await delay(POOF_RESPONSE_WAIT_MS + 200)

    // Service should still be present — responses were observed
    assert.equal(browser.services.size, 1)

    browser.destroy()
  })

  test('QU (unicast-response) queries do not trigger POOF flush', async () => {
    const browser = mdns.browse('_http._tcp', {
      poofTimeoutMs: POOF_TIMEOUT_MS,
      poofResponseWaitMs: POOF_RESPONSE_WAIT_MS,
    })
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'QU POOF Test',
      type: '_http._tcp',
      host: 'qutest.local',
      port: 8080,
      addresses: ['192.168.1.70'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')

    // Send QU queries (unicast-response bit set) — these may get unicast
    // replies we can't observe, so POOF must not count them as unanswered.
    // Encode a normal IN-class query and set the QU bit via helper.
    const quQuery = dnsPacket.encode({
      type: 'query',
      id: 0,
      flags: 0,
      questions: [{ type: 'PTR', name: '_http._tcp.local', class: 'IN' }],
    })
    setQUBitOnFirstQuestion(quQuery)
    await advertiser.sendRaw(quQuery)
    await delay(POOF_RESPONSE_WAIT_MS + 200)

    await advertiser.sendRaw(quQuery)
    await delay(POOF_RESPONSE_WAIT_MS + 200)

    // Service should still be present — QU queries must not trigger POOF
    assert.equal(browser.services.size, 1)

    browser.destroy()
  })
})

// ─── Case-insensitive DNS name matching (RFC 1035 §3.1) ─────────────

describe('Case-insensitive DNS name matching (RFC 1035 §3.1)', () => {
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

  test('resolves SRV record with different casing than PTR data', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send a raw packet where the PTR data uses mixed case but SRV name
    // uses lowercase — this tests case-insensitive matching on SRV lookup
    const packet = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      questions: [],
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'My Service._http._tcp.local',
        },
        {
          type: 'SRV',
          // Different casing than the PTR data
          name: 'my service._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'myhost.local', port: 8080, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'my service._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: ['key=val'],
        },
      ],
      additionals: [
        {
          type: 'A',
          // Different casing on the host too
          name: 'MyHost.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: '192.168.1.100',
        },
      ],
    })

    await advertiser.sendRaw(packet)
    const event = await nextEvent(iter)

    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.port, 8080)
    assert.equal(event.service.host, 'myhost.local')
    // The A record with "MyHost.local" should match "myhost.local" case-insensitively
    assert.ok(
      event.service.addresses.includes('192.168.1.100'),
      `Expected addresses to include 192.168.1.100 but got: ${event.service.addresses}`
    )

    browser.destroy()
  })

  test('matches TXT updates with different casing on known service', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // First announce normally
    await advertiser.announce({
      name: 'CaseTest',
      type: '_http._tcp',
      host: 'casehost.local',
      port: 9090,
      addresses: ['10.0.0.1'],
      txt: { version: '1' },
    })

    const up = await nextEvent(iter)
    assert.equal(up.type, 'serviceUp')

    // Now send a TXT update with different casing on the name
    const txtUpdate = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      questions: [],
      answers: [
        {
          type: 'TXT',
          // Lowercase instead of the original mixed case
          name: 'casetest._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: ['version=2'],
        },
      ],
    })

    await advertiser.sendRaw(txtUpdate)
    const updated = await nextEvent(iter)
    assert.equal(updated.type, 'serviceUpdated')
    assert.equal(updated.service.txt.version, '2')

    browser.destroy()
  })
})
