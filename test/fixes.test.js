import { describe, test, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import dnsPacket from 'dns-packet'
import * as dns from '../lib/dns.js'
import { parseTxtData } from '../lib/service.js'
import { DnsSdBrowser } from '../lib/index.js'
import { ServiceBrowser } from '../lib/browser.js'
import { TestAdvertiser } from './helpers/advertiser.js'
import { nextEvent, getRandomPort, delay, TEST_INTERFACE } from './helpers/utils.js'

describe('Fix: case-insensitive DNS name matching (RFC 1035 §3.1)', () => {
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

describe('Fix: decodeName throws on malformed input', () => {
  test('throws on pointer loop instead of returning partial data', () => {
    const buf = Buffer.alloc(30)
    buf.writeUInt16BE(0, 0)       // ID
    buf.writeUInt16BE(0x8400, 2)  // Flags: QR=1, AA=1
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    buf.writeUInt16BE(0, 6)
    buf.writeUInt16BE(0, 8)
    buf.writeUInt16BE(0, 10)
    // Self-referencing pointer at offset 12
    buf.writeUInt16BE(0xC00C, 12)
    buf.writeUInt16BE(1, 14)      // QTYPE = A
    buf.writeUInt16BE(1, 16)      // QCLASS = IN

    assert.throws(() => dns.decode(buf), /too many compression pointers/)
  })

  test('throws on oversized label length', () => {
    const buf = Buffer.alloc(30)
    buf.writeUInt16BE(0, 0)       // ID
    buf.writeUInt16BE(0x8400, 2)  // Flags
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    buf.writeUInt16BE(0, 6)
    buf.writeUInt16BE(0, 8)
    buf.writeUInt16BE(0, 10)
    // Label length 64 (exceeds MAX_LABEL_LENGTH of 63)
    buf[12] = 64
    // Fill with garbage
    buf.fill(0x41, 13, 30)

    assert.throws(() => dns.decode(buf), /label length/)
  })
})

describe('Fix: parseTxtData uses O(n) duplicate detection', () => {
  test('first key wins for case-insensitive duplicates', () => {
    const encoder = new TextEncoder()
    const entries = [
      encoder.encode('Key=first'),
      encoder.encode('KEY=second'),
      encoder.encode('key=third'),
    ]
    const { txt } = parseTxtData(entries)
    assert.equal(txt.Key, 'first')
    assert.equal(Object.keys(txt).length, 1)
  })

  test('handles boolean flags with duplicate detection', () => {
    const encoder = new TextEncoder()
    const entries = [
      encoder.encode('Flag'),
      encoder.encode('flag=not-a-flag'),
    ]
    const { txt } = parseTxtData(entries)
    assert.equal(txt.Flag, true)
    assert.equal(Object.keys(txt).length, 1)
  })
})

describe('Fix: single-consumer async iterator enforcement', () => {
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

  test('throws when creating a second concurrent iterator', () => {
    const browser = mdns.browse('_http._tcp')
    // First iterator is fine
    const iter1 = browser[Symbol.asyncIterator]()
    // Second should throw
    assert.throws(
      () => browser[Symbol.asyncIterator](),
      /single concurrent async iterator/
    )
    browser.destroy()
  })

  test('allows a new iterator after the previous one ends', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter1 = browser[Symbol.asyncIterator]()

    // End the first iterator via return()
    await iter1.return()

    // A new browser is needed since return() destroys the browser.
    // So let's test with a fresh browser that we destroy and re-iterate.
    const browser2 = mdns.browse('_http._tcp')
    const iter2 = browser2[Symbol.asyncIterator]()

    // Destroy ends the iterator, allowing a new one
    browser2.destroy()
    const result = await iter2.next()
    assert.equal(result.done, true)

    // After the iterator ends (done=true), we should be able to create a new one
    // (though it will immediately return done since browser is destroyed)
    const iter3 = browser2[Symbol.asyncIterator]()
    const result2 = await iter3.next()
    assert.equal(result2.done, true)
  })
})

describe('Fix: transport start error surfacing', () => {
  test('ready() surfaces the underlying transport error', async () => {
    // Use a port that requires elevated privileges to reliably cause a bind error.
    // On Linux, binding to a well-known port (< 1024) as non-root should fail.
    // If it doesn't fail (e.g. running as root), skip the test.
    const mdns = new DnsSdBrowser({ port: 1 })

    // Trigger start
    mdns.browse('_http._tcp').destroy()

    // Give the start promise time to settle
    await new Promise((r) => setTimeout(r, 200))

    try {
      await mdns.ready()
      // If ready() didn't throw, the port bind succeeded (running as root) — skip
    } catch (err) {
      // The error should be the real bind error, not a generic message
      assert.ok(err instanceof Error)
      assert.ok(
        err.message.includes('EACCES') || err.message.includes('EADDRINUSE') || err.message.includes('EPERM'),
        `Expected a bind error but got: ${err.message}`
      )
    } finally {
      await mdns.destroy()
    }
  })
})
