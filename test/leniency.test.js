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

// ─── Android NSD quirks ──────────────────────────────────────────────────────
// Tests for specific mDNS advertising quirks found in Android's NsdManager
// implementation across versions 7–14+. Android uses mdnsd (Apple
// mDNSResponder fork) on Android 7–12 and a Java-based mDNS stack on 13+.

describe('Advertiser leniency: Android NSD quirks', () => {
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

  test('handles shared "Android.local" hostname from multiple devices', async () => {
    // Android 7–12 hardcodes the mDNS hostname to "Android.local" for all
    // devices (AOSP mDNSPosix.c: GetUserSpecifiedRFC1034ComputerName).
    // Two different services from different devices share the same SRV target.
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Device A announces service with Android.local → 192.168.1.10
    await advertiser.sendRaw(dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'DeviceA._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'DeviceA._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'Android.local', port: 8080, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'DeviceA._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: ['id=device-a'],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'Android.local',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '192.168.1.10',
      }],
    }))

    const eventA = await nextEvent(iter)
    assert.equal(eventA.type, 'serviceUp')
    assert.equal(eventA.service.name, 'DeviceA')
    assert.equal(eventA.service.host, 'Android.local')
    assert.ok(eventA.service.addresses.includes('192.168.1.10'))

    // Device B announces a different service also using Android.local → 192.168.1.20
    await advertiser.sendRaw(dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'DeviceB._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'DeviceB._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'Android.local', port: 9090, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'DeviceB._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: ['id=device-b'],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'Android.local',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '192.168.1.20',
      }],
    }))

    const eventB = await nextEvent(iter)
    assert.equal(eventB.type, 'serviceUp')
    assert.equal(eventB.service.name, 'DeviceB')
    assert.equal(eventB.service.port, 9090)
    assert.ok(eventB.service.addresses.includes('192.168.1.20'))

    browser.destroy()
  })

  test('handles empty TXT record (single null byte RDATA per RFC 6763 §6.1)', async () => {
    // Android sends a single \x00 byte as RDATA when no TXT attributes are set.
    // This is the RFC-mandated encoding for "no TXT data" (a single empty string).
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Manually build a packet with TXT RDATA = [0x00] (single zero-length string)
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
          data: 'EmptyTxt._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'EmptyTxt._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'android.local', port: 8080, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'EmptyTxt._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          // dns-packet encodes [''] as a single \x00 byte (zero-length string)
          data: [''],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'android.local',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '10.0.0.1',
      }],
    })
    await advertiser.sendRaw(pkt)

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'EmptyTxt')
    assert.deepEqual(event.service.txt, {})

    browser.destroy()
  })

  test('handles Android setAttribute(key, null) producing "key=" on wire', async () => {
    // Android's NsdServiceInfo.setAttribute(key, null) always writes "key=" on
    // the wire (with the = sign) instead of just "key" (boolean flag). Per RFC
    // 6763 §6.4, "key=" means empty string value, which is what the browser
    // should parse it as.
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.sendRaw(dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'NullAttr._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'NullAttr._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: { target: 'android.local', port: 5000, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'NullAttr._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          // Android writes "key=" for null values, "normal=value" for string values
          data: ['available=', 'name=MyDevice'],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'android.local',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '10.0.0.2',
      }],
    }))

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    // "available=" should be parsed as key with empty string value (not boolean)
    assert.equal(event.service.txt.available, '')
    assert.equal(event.service.txt.name, 'MyDevice')

    browser.destroy()
  })

  test('handles service name with conflict resolution suffix "MyService (2)"', async () => {
    // When Android detects a service name conflict on the network, it appends
    // " (N)" to the name (e.g. "MyService" → "MyService (2)"). The parentheses
    // and spaces are valid in DNS-SD instance names (RFC 6763 §4.1.1).
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'MyService (2)',
      type: '_http._tcp',
      host: 'android.local',
      port: 3000,
      addresses: ['10.0.0.3'],
      txt: { id: 'conflict-resolved' },
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'MyService (2)')
    assert.equal(event.service.port, 3000)
    assert.equal(event.service.txt.id, 'conflict-resolved')

    browser.destroy()
  })

  test('handles service flickering (goodbye then quick re-announcement)', async () => {
    // Android NSD sometimes signals onServiceLost() then shortly re-announces.
    // The browser's 1-second goodbye grace period should absorb this flicker.
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const svc = {
      name: 'Flicker',
      type: '_http._tcp',
      host: 'android.local',
      port: 7070,
      addresses: ['10.0.0.4'],
    }

    // Initial announcement
    await advertiser.announce(svc)
    const up = await nextEvent(iter)
    assert.equal(up.type, 'serviceUp')
    assert.equal(up.service.name, 'Flicker')

    // Goodbye immediately followed by re-announcement (within 1-second grace)
    await advertiser.goodbye(svc)
    await delay(100) // well within the 1-second grace period
    await advertiser.announce(svc)

    // Should NOT receive serviceDown because the re-announcement cancels the goodbye.
    // Verify the service is still in the map after the grace period expires.
    await delay(1500)
    assert.ok(
      browser.services.has('Flicker._http._tcp.local'),
      'service should still exist after flicker — goodbye was cancelled by re-announcement'
    )

    browser.destroy()
  })

  test('handles long hostname from newer Android devices (40+ bytes)', async () => {
    // Android 13+ (Java mDNS stack) can advertise hostnames with 40+ bytes,
    // e.g. a UUID-based hostname like "Android_<UUID>.local".
    const longHost = 'Android_25101c8afe6a479387b1d63318378d56.local'
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'LongHost',
      type: '_http._tcp',
      host: longHost,
      port: 4000,
      addresses: ['10.0.0.5'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.host, longHost)
    assert.equal(event.service.port, 4000)

    browser.destroy()
  })

  test('handles 75-minute TTL (Android NSD default)', async () => {
    // Android NSD uses a 75-minute (4500 second) TTL for PTR and TXT records.
    // This is unusually long but valid. The browser should accept it.
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.sendRaw(dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'LongTTL._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'LongTTL._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: { target: 'android.local', port: 6000, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'LongTTL._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [{
        type: 'A',
        name: 'android.local',
        ttl: 4500,
        class: 'IN',
        flush: true,
        data: '10.0.0.6',
      }],
    }))

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'LongTTL')
    assert.ok(browser.services.has('LongTTL._http._tcp.local'))

    browser.destroy()
  })

  test('handles mixed-case hostname in SRV vs A record (Android.local vs android.local)', async () => {
    // Android's mdnsd advertises "Android.local" (capitalized) in the SRV target,
    // but the A record name may use different casing depending on the source.
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.sendRaw(dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'CaseHost._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'CaseHost._http._tcp.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          // SRV target uses capital "A"
          data: { target: 'Android.local', port: 8888, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'CaseHost._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
      additionals: [{
        type: 'A',
        // A record name uses lowercase
        name: 'android.local',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '192.168.1.50',
      }],
    }))

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'CaseHost')
    // The A record with "android.local" should match SRV target "Android.local"
    assert.ok(
      event.service.addresses.includes('192.168.1.50'),
      'address should be resolved despite hostname case mismatch between SRV and A record'
    )

    browser.destroy()
  })
})
