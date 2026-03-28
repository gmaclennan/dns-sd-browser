/**
 * Tests for advertiser leniency — verifies the browser handles common
 * real-world quirks and bugs in DNS-SD advertisers gracefully.
 *
 * These test patterns seen in ciao, avahi, python-zeroconf, multicast-dns,
 * and other implementations.
 */

import { describe, test, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import dnsPacket from 'dns-packet'
import { DnsSdBrowser } from '../lib/index.js'
import { TestAdvertiser } from './helpers/advertiser.js'
import { nextEvent, getRandomPort, delay, TEST_INTERFACE } from './helpers/utils.js'

describe('Advertiser leniency: split responses', () => {
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

  test('resolves service when PTR arrives first, SRV arrives in a separate packet', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Packet 1: PTR only — no SRV, can't resolve yet
    const ptrOnly = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [{
        type: 'PTR',
        name: '_http._tcp.local',
        ttl: 4500,
        class: 'IN',
        data: 'Split._http._tcp.local',
      }],
    })
    await advertiser.sendRaw(ptrOnly)

    await delay(100)
    assert.equal(browser.services.size, 0, 'service should be pending, not resolved')

    // Packet 2: SRV + TXT + A without PTR — this should resolve the pending service
    const srvOnly = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'SRV',
          name: 'Split._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'split.local', port: 8080, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'Split._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: ['source=split'],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'split.local',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '10.0.0.1',
      }],
    })
    await advertiser.sendRaw(srvOnly)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'Split')
    assert.equal(event.service.port, 8080)
    assert.equal(event.service.txt.source, 'split')

    browser.destroy()
  })

  test('resolves service when all records arrive in separate packets', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Packet 1: PTR only
    await advertiser.sendRaw(dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [{
        type: 'PTR',
        name: '_http._tcp.local',
        ttl: 4500,
        class: 'IN',
        data: 'FullSplit._http._tcp.local',
      }],
    }))
    await delay(50)

    // Packet 2: SRV only — should resolve the service (no TXT = empty TXT)
    await advertiser.sendRaw(dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [{
        type: 'SRV',
        name: 'FullSplit._http._tcp.local',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: { target: 'fullsplit.local', port: 3000, priority: 0, weight: 0 },
      }],
    }))

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'FullSplit')
    assert.equal(event.service.port, 3000)
    assert.deepEqual(event.service.txt, {})

    // Packet 3: A record arrives later — should emit serviceUpdated
    await advertiser.sendRaw(dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [{
        type: 'A',
        name: 'fullsplit.local',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '10.0.0.2',
      }],
    }))

    const update = await nextEvent(iter)
    assert.equal(update.type, 'serviceUpdated')
    assert.ok(update.service.addresses.includes('10.0.0.2'))

    browser.destroy()
  })
})

describe('Advertiser leniency: non-zero rcode', () => {
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

  test('processes response with rcode=NXDOMAIN (3)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

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
          data: 'NxDomain._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'NxDomain._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'nx.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'NxDomain._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'nx.local',
        ttl: 120,
        class: 'IN',
        data: '10.0.0.1',
      }],
    })
    // Set rcode to 3 (NXDOMAIN)
    buf[3] = (buf[3] & 0xf0) | 0x03
    await advertiser.sendRaw(buf)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'NxDomain')

    browser.destroy()
  })
})

describe('Advertiser leniency: records in authority section', () => {
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

  test('uses A record from authority section for address resolution', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Put the A record in the authority section instead of additionals
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
          data: 'AuthSvc._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'AuthSvc._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'auth.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'AuthSvc._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      authorities: [{
        type: 'A',
        name: 'auth.local',
        ttl: 120,
        class: 'IN',
        data: '10.0.0.99',
      }],
    })
    await advertiser.sendRaw(buf)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'AuthSvc')
    assert.ok(
      event.service.addresses.includes('10.0.0.99'),
      'should pick up A record from authority section'
    )

    browser.destroy()
  })
})

describe('Advertiser leniency: missing records', () => {
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

  test('resolves service with no TXT record (empty TXT)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send PTR + SRV + A but NO TXT record at all
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
          data: 'NoTxt._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'NoTxt._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'notxt.local', port: 9090, priority: 0, weight: 0 },
        },
      ],
      additionals: [{
        type: 'A',
        name: 'notxt.local',
        ttl: 120,
        class: 'IN',
        data: '10.0.0.1',
      }],
    })
    await advertiser.sendRaw(pkt)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'NoTxt')
    assert.deepEqual(event.service.txt, {})

    browser.destroy()
  })

  test('resolves service with no A/AAAA records (empty addresses)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send PTR + SRV + TXT but NO address records
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
          data: 'NoAddr._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'NoAddr._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'noaddr.local', port: 8080, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'NoAddr._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
    })
    await advertiser.sendRaw(pkt)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'NoAddr')
    assert.deepEqual(event.service.addresses, [])

    browser.destroy()
  })

  test('handles non-zero packet ID', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Some legacy implementations use non-zero IDs
    const pkt = dnsPacket.encode({
      type: 'response',
      id: 42,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'NonZeroId._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'NonZeroId._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'nzid.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'NonZeroId._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'nzid.local',
        ttl: 120,
        class: 'IN',
        data: '192.168.1.1',
      }],
    })
    await advertiser.sendRaw(pkt)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'NonZeroId')

    browser.destroy()
  })

  test('handles SRV with port 0', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Port Zero',
      type: '_http._tcp',
      host: 'pz.local',
      port: 0,
      addresses: ['10.0.0.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.port, 0)

    browser.destroy()
  })

  test('handles response without AA bit', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Craft a response without the AA (authoritative) bit
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: 0, // No AA bit
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'NoAA._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'NoAA._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'noaa.local', port: 80, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'NoAA._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'noaa.local',
        ttl: 120,
        class: 'IN',
        data: '10.0.0.1',
      }],
    })
    // Ensure QR bit is set (response) but AA is not
    buf[2] = 0x80 // QR=1, AA=0, opcode=0
    buf[3] = 0x00 // rcode=0
    await advertiser.sendRaw(buf)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'NoAA')

    browser.destroy()
  })
})
