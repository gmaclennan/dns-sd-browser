/**
 * Tests for features from the CONTRIBUTING.md "Known Gaps" list:
 * - TTL-based cache expiration
 * - QU bit on initial queries
 * - Subtype browsing
 * - TC (truncated) bit handling
 * - IPv6 multicast (best-effort — depends on host support)
 */

import { describe, test, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import dnsPacket from 'dns-packet'
import { DnsSdBrowser } from '../lib/index.js'
import { TestAdvertiser } from './helpers/advertiser.js'
import { nextEvent, getRandomPort, delay, TEST_INTERFACE } from './helpers/utils.js'
import { QU_CLASS, QM_CLASS, setTCBit } from './helpers/dns-packet-utils.js'

// ─── TTL-based cache expiration ─────────────────────────────────────────

describe('TTL-based cache expiration', () => {
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

  test('service is removed when PTR TTL expires', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Announce with a very short TTL (1 second)
    const pkt = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 1,
          class: 'IN',
          data: 'ShortLived._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'ShortLived._http._tcp.local',
          ttl: 1,
          class: 'IN',
          flush: true,
          data: { target: 'short.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'ShortLived._http._tcp.local',
          ttl: 1,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'short.local',
          ttl: 1,
          class: 'IN',
          flush: true,
          data: '192.168.1.1',
        },
      ],
    })
    await advertiser.sendRaw(pkt)

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.equal(upEvent.service.name, 'ShortLived')
    assert.equal(browser.services.size, 1)

    // Wait for TTL to expire. The TTL check is scheduled precisely based on
    // the soonest-expiring record, so with a 1s TTL the service should be
    // removed within ~2s (1s TTL + 1s minimum check delay clamp).
    const downEvent = await nextEvent(iter, 5000)
    assert.equal(downEvent.type, 'serviceDown')
    assert.equal(downEvent.service.name, 'ShortLived')
    assert.equal(browser.services.size, 0)

    browser.destroy()
  })

  test('service with refreshed TTL is not expired', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Also announce a short-TTL service that we do NOT refresh — it should
    // expire, proving that TTL expiration is working. This serves as a
    // positive control: if both services survive, the test is inconclusive.
    const mkPacket = (name, host, ttl) => dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl,
          class: 'IN',
          data: `${name}._http._tcp.local`,
        },
        {
          type: 'SRV',
          name: `${name}._http._tcp.local`,
          ttl,
          class: 'IN',
          flush: true,
          data: { target: `${host}.local`, port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: `${name}._http._tcp.local`,
          ttl,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: `${host}.local`,
          ttl,
          class: 'IN',
          data: '192.168.1.1',
        },
      ],
    })

    // Announce both with 2s TTL
    await advertiser.sendRaw(mkPacket('Refreshed', 'refresh', 2))
    const upEvent1 = await nextEvent(iter)
    assert.equal(upEvent1.type, 'serviceUp')
    assert.equal(upEvent1.service.name, 'Refreshed')

    await advertiser.sendRaw(mkPacket('NotRefreshed', 'norefresh', 2))
    const upEvent2 = await nextEvent(iter)
    assert.equal(upEvent2.type, 'serviceUp')
    assert.equal(upEvent2.service.name, 'NotRefreshed')

    // Refresh ONLY the first service's TTL before it expires
    await delay(1000)
    await advertiser.sendRaw(mkPacket('Refreshed', 'refresh', 4500))

    // Wait for the un-refreshed service to expire — this proves TTL
    // expiration is working and the refreshed service survived intentionally
    const downEvent = await nextEvent(iter, 5000)
    assert.equal(downEvent.type, 'serviceDown')
    assert.equal(downEvent.service.name, 'NotRefreshed')

    // The refreshed service should still be alive
    assert.ok(
      browser.services.has('Refreshed._http._tcp.local'),
      'refreshed service should still exist'
    )

    browser.destroy()
  })
})

// ─── QU bit on initial queries ──────────────────────────────────────────

describe('QU bit on initial queries (RFC 6762 §5.4)', () => {
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

  test('first query has QU bit set', async () => {
    const browser = mdns.browse('_http._tcp')

    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR' && qq.name === '_http._tcp.local'),
      3000
    )

    // The first query should have the QU (unicast-response) bit set.
    // dns-packet decodes the QU bit (high bit of class field) as 'UNKNOWN_32769'
    // (0x8001 = IN class with QU bit set).
    const question = query.questions?.find((q) => q.type === 'PTR')
    assert.ok(question, 'should have PTR question')
    assert.equal(question?.class, QU_CLASS, 'first query should have QU bit set')

    browser.destroy()
  })

  test('subsequent queries do not have QU bit set', async () => {
    const browser = mdns.browse('_http._tcp')

    // Wait for initial query
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )
    advertiser.clearQueries()

    // Wait for second query (~1s later)
    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      5000
    )

    const question = query.questions?.find((q) => q.type === 'PTR')
    assert.ok(question, 'should have PTR question')
    // Subsequent queries should NOT have QU bit — class should be IN
    assert.equal(question?.class, QM_CLASS, 'subsequent query should not have QU bit (class should be IN)')

    browser.destroy()
  })
})

// ─── Subtype browsing ───────────────────────────────────────────────────

describe('Subtype browsing (RFC 6763 §7.1)', () => {
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

  test('queries the _subtype._sub._type._proto.domain name', async () => {
    const browser = mdns.browse('_http._tcp', { subtype: '_printer' })

    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some(
        (qq) => qq.type === 'PTR' && qq.name === '_printer._sub._http._tcp.local'
      ),
      3000
    )

    assert.ok(query, 'should send query for subtype')

    browser.destroy()
  })

  test('discovers services via subtype PTR records', async () => {
    const browser = mdns.browse('_http._tcp', { subtype: '_printer' })
    const iter = browser[Symbol.asyncIterator]()

    // Send a response to the subtype query
    const pkt = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_printer._sub._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'My Printer._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'My Printer._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'printer.local', port: 631, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'My Printer._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: ['ty=HP LaserJet'],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'printer.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: '192.168.1.50',
        },
      ],
    })
    await advertiser.sendRaw(pkt)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'My Printer')
    assert.equal(event.service.port, 631)
    assert.equal(event.service.txt.ty, 'HP LaserJet')

    browser.destroy()
  })

  test('auto-prefixes underscore on subtype', async () => {
    const browser = mdns.browse('_http._tcp', { subtype: 'printer' })

    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some(
        (qq) => qq.type === 'PTR' && qq.name === '_printer._sub._http._tcp.local'
      ),
      3000
    )

    assert.ok(query, 'should auto-prefix underscore on subtype')

    browser.destroy()
  })

  test('populates subtypes array from subtype PTR records', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // First, announce the service normally
    await advertiser.announce({
      name: 'SubtypeSvc',
      type: '_http._tcp',
      host: 'sub.local',
      port: 80,
      addresses: ['10.0.0.1'],
    })

    const up = await nextEvent(iter)
    assert.equal(up.type, 'serviceUp')
    assert.deepEqual(up.service.subtypes, [])

    // Now send a subtype PTR record linking this service to _printer subtype
    const subtypePkt = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [{
        type: 'PTR',
        name: '_printer._sub._http._tcp.local',
        ttl: 4500,
        class: 'IN',
        data: 'SubtypeSvc._http._tcp.local',
      }],
    })
    await advertiser.sendRaw(subtypePkt)

    const updated = await nextEvent(iter)
    assert.equal(updated.type, 'serviceUpdated')
    assert.deepEqual(updated.service.subtypes, ['_printer'])

    browser.destroy()
  })
})

// ─── TC bit handling ────────────────────────────────────────────────────

describe('TC (truncated) bit handling (RFC 6762 §18.5)', () => {
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

  test('re-queries with QU bit when receiving truncated response', async () => {
    const browser = mdns.browse('_http._tcp')

    // Wait for initial query to arrive
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )
    advertiser.clearQueries()

    // Send a truncated response (TC bit set)
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
          data: 'Truncated._http._tcp.local',
        },
      ],
    })
    setTCBit(buf)
    await advertiser.sendRaw(buf)

    // The browser should re-query with QU bit set.
    const retryQuery = await advertiser.waitForQuery(
      (q) => (q.questions || []).some(
        (qq) => qq.type === 'PTR' && qq.name === '_http._tcp.local' && qq.class === QU_CLASS
      ),
      5000
    )

    assert.ok(retryQuery, 'should re-query with QU bit after truncated response')

    browser.destroy()
  })

  test('still processes partial records from truncated response', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send a truncated response that does contain a complete service
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
          data: 'Partial._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'Partial._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'partial.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'Partial._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'partial.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: '10.0.0.1',
        },
      ],
    })
    setTCBit(buf)
    await advertiser.sendRaw(buf)

    // Should still process the complete records from the truncated packet
    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'Partial')

    browser.destroy()
  })
})

// ─── IPv6 multicast ─────────────────────────────────────────────────────

/**
 * Check if IPv6 UDP sockets are available on this host.
 * @returns {Promise<boolean>}
 */
async function hasIPv6() {
  const { createSocket } = await import('node:dgram')
  return new Promise((resolve) => {
    const s = createSocket({ type: 'udp6', reuseAddr: true })
    s.on('error', () => { resolve(false) })
    s.bind(0, () => {
      try {
        s.addMembership('FF02::FB')
        s.dropMembership('FF02::FB')
      } catch {
        s.close(() => resolve(false))
        return
      }
      s.close(() => resolve(true))
    })
  })
}

// ─── Network rejoin ────────────────────────────────────────────────────

describe('Network rejoin (mdns.rejoin())', () => {
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

  test('flushes existing services as serviceDown and accepts new ones', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Announce a service
    await advertiser.announce({
      name: 'Rejoin Test',
      type: '_http._tcp',
      host: 'rejoin.local',
      port: 80,
      addresses: ['10.0.0.1'],
    })

    const up = await nextEvent(iter)
    assert.equal(up.type, 'serviceUp')
    assert.equal(up.service.name, 'Rejoin Test')
    assert.equal(browser.services.size, 1)

    // Simulate network change — rejoin
    mdns.rejoin()

    // Should get serviceDown for the old service
    const down = await nextEvent(iter)
    assert.equal(down.type, 'serviceDown')
    assert.equal(down.service.name, 'Rejoin Test')
    assert.equal(browser.services.size, 0)

    // Re-announce the service (simulates advertiser responding on new network)
    await advertiser.announce({
      name: 'Rejoin Test',
      type: '_http._tcp',
      host: 'rejoin.local',
      port: 80,
      addresses: ['10.0.0.2'],
    })

    // Should re-discover as a fresh serviceUp
    const reUp = await nextEvent(iter, 5000)
    assert.equal(reUp.type, 'serviceUp')
    assert.equal(reUp.service.name, 'Rejoin Test')
    assert.deepEqual(reUp.service.addresses, ['10.0.0.2'])
    assert.equal(browser.services.size, 1)

    browser.destroy()
  })

  test('rejoin on destroyed browser is a no-op', async () => {
    const browser = mdns.browse('_http._tcp')
    browser.destroy()

    // Should not throw
    mdns.rejoin()
  })

  test('rejoin before any browse is a no-op', async () => {
    const fresh = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    // Should not throw
    fresh.rejoin()
    await fresh.destroy()
  })

  test('re-sends initial query with QU bit after rejoin', async () => {
    const browser = mdns.browse('_http._tcp')

    // Wait for initial query
    await advertiser.waitForQuery(
      (q) => (q.questions || []).some((qq) => qq.type === 'PTR'),
      3000
    )
    advertiser.clearQueries()

    // Rejoin — should restart query schedule from the beginning
    mdns.rejoin()

    // The first query after rejoin should have the QU bit set
    const query = await advertiser.waitForQuery(
      (q) => (q.questions || []).some(
        (qq) => qq.type === 'PTR' && qq.name === '_http._tcp.local'
      ),
      3000
    )

    const question = query.questions?.find((q) => q.type === 'PTR')
    assert.ok(question, 'should have PTR question')
    assert.equal(question?.class, QU_CLASS, 'first query after rejoin should have QU bit set')

    browser.destroy()
  })
})

// When TEST_IPV6=1 is set (e.g. in CI), the IPv6 test must not be skipped.
// Otherwise, skip gracefully on hosts without IPv6.
const runIPv6Tests = process.env.TEST_IPV6 === '1' || await hasIPv6()

describe('IPv6 multicast support', () => {
  test('transport starts successfully regardless of IPv6 availability', async () => {
    // This test validates that the IPv6 socket failure doesn't prevent startup.
    // On systems without IPv6, the transport should fall back to IPv4 only.
    const port = await getRandomPort()
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')

    // If IPv6 blocked startup, ready() would hang or throw
    await mdns.ready()

    browser.destroy()
    await mdns.destroy()
  })

  test('discovers service announced via IPv6 multicast', { skip: !runIPv6Tests && 'IPv6 not available on this host' }, async () => {
    const { createSocket } = await import('node:dgram')
    const dnsPacketMod = (await import('dns-packet')).default

    const port = await getRandomPort()
    const mdns = new DnsSdBrowser({ port })
    const browser = mdns.browse('_http._tcp')
    await mdns.ready()
    const iter = browser[Symbol.asyncIterator]()

    // Create an IPv6 advertiser that sends to FF02::FB on the test port
    const sock6 = createSocket({ type: 'udp6', reuseAddr: true })
    try {
      await new Promise((resolve, reject) => {
        sock6.on('error', reject)
        sock6.bind(port, () => {
          try {
            sock6.addMembership('FF02::FB')
            sock6.setMulticastLoopback(true)
            sock6.removeListener('error', reject)
            resolve(undefined)
          } catch (err) {
            reject(err)
          }
        })
      })

      // Send a service announcement over IPv6
      const pkt = dnsPacketMod.encode({
        type: 'response',
        id: 0,
        flags: dnsPacketMod.AUTHORITATIVE_ANSWER,
        answers: [
          {
            type: 'PTR',
            name: '_http._tcp.local',
            ttl: 4500,
            class: 'IN',
            data: 'IPv6Svc._http._tcp.local',
          },
          {
            type: 'SRV',
            name: 'IPv6Svc._http._tcp.local',
            ttl: 120,
            class: 'IN',
            flush: true,
            data: { target: 'v6host.local', port: 8080, priority: 0, weight: 0 },
          },
          {
            type: 'TXT',
            name: 'IPv6Svc._http._tcp.local',
            ttl: 4500,
            class: 'IN',
            flush: true,
            data: ['via=ipv6'],
          },
        ],
        additionals: [
          {
            type: 'AAAA',
            name: 'v6host.local',
            ttl: 120,
            class: 'IN',
            flush: true,
            data: '::1',
          },
        ],
      })

      await new Promise((resolve, reject) => {
        sock6.send(pkt, 0, pkt.length, port, 'FF02::FB', (err) => {
          if (err) reject(err)
          else resolve(undefined)
        })
      })

      const event = await nextEvent(iter, 5000)
      assert.equal(event.type, 'serviceUp')
      assert.equal(event.service.name, 'IPv6Svc')
      assert.equal(event.service.txt.via, 'ipv6')
      assert.ok(
        event.service.addresses.some((a) => a.includes('::1')),
        `Expected an IPv6 address but got: ${event.service.addresses}`
      )
    } finally {
      browser.destroy()
      await mdns.destroy()
      await new Promise((resolve) => sock6.close(resolve))
    }
  })
})
