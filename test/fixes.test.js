import { describe, test, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import dnsPacket from 'dns-packet'
import * as dns from '../lib/dns.js'
import { parseTxtData, parseServiceType, extractInstanceName } from '../lib/service.js'
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

  test('does not throw on 127 pointer hops followed by a null terminator', () => {
    // 127 pointer hops + null terminator = 128 iterations of the decode loop.
    // Each pointer consumes one iteration (with continue), then the null
    // terminator consumes the 128th iteration and breaks. This exercises the
    // exact boundary of the maxJumps counter.
    const chainLen = 127
    const dataOffset = 12 + chainLen * 2 // where the null terminator lives
    const bufLen = dataOffset + 1 + 4    // null + QTYPE + QCLASS
    const buf = Buffer.alloc(bufLen)

    buf.writeUInt16BE(0, 0)       // ID
    buf.writeUInt16BE(0x8400, 2)  // Flags: QR=1, AA=1
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    buf.writeUInt16BE(0, 6)
    buf.writeUInt16BE(0, 8)
    buf.writeUInt16BE(0, 10)

    // Write 127 pointers: offset 12 -> 14 -> 16 -> ... -> dataOffset
    for (let i = 0; i < chainLen; i++) {
      const off = 12 + i * 2
      const target = (i < chainLen - 1) ? 12 + (i + 1) * 2 : dataOffset
      buf.writeUInt16BE(0xC000 | target, off)
    }

    // At dataOffset: null terminator (root name ".")
    buf[dataOffset] = 0
    buf.writeUInt16BE(1, dataOffset + 1) // QTYPE = A
    buf.writeUInt16BE(1, dataOffset + 3) // QCLASS = IN

    // Should decode successfully — not throw
    const pkt = dns.decode(buf)
    assert.equal(pkt.questions[0].name, '')
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

describe('Fix: parseTxtData duplicate handling and edge cases', () => {
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

  test('TXT string beginning with = (missing key) is silently ignored per RFC 6763 §6.4', () => {
    const encoder = new TextEncoder()
    const { txt } = parseTxtData([encoder.encode('=value')])
    assert.deepEqual(txt, {})
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

describe('Fix: parseServiceType validation', () => {
  test('rejects null/undefined service type object', () => {
    assert.throws(() => parseServiceType(null), /non-empty "name" property/)
  })

  test('rejects service type object with empty name', () => {
    assert.throws(() => parseServiceType({ name: '' }), /non-empty "name" property/)
  })

  test('rejects non-string, non-object service type', () => {
    assert.throws(() => parseServiceType(123), /non-empty string/)
  })

  test('rejects empty string service type', () => {
    assert.throws(() => parseServiceType(''), /non-empty string/)
  })
})

describe('Fix: parseServiceType edge cases', () => {
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

  test('object form with underscored name and protocol', () => {
    const result = parseServiceType({ name: '_http', protocol: '_tcp' })
    assert.equal(result.type, '_http._tcp')
    assert.equal(result.protocol, 'tcp')
  })

  test('single-label string defaults protocol to tcp', () => {
    const result = parseServiceType('_http')
    assert.equal(result.type, '_http')
    assert.equal(result.protocol, 'tcp')
    assert.equal(result.queryName, '_http.local')
  })
})

describe('Fix: extractInstanceName', () => {
  test('extracts name when FQDN matches suffix', () => {
    const name = extractInstanceName(
      'My Printer._http._tcp.local',
      '_http._tcp.local'
    )
    assert.equal(name, 'My Printer')
  })

  test('returns full FQDN when suffix does not match (fallback)', () => {
    const name = extractInstanceName(
      'My Printer._ipp._tcp.local',
      '_http._tcp.local'
    )
    assert.equal(name, 'My Printer._ipp._tcp.local')
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

  test('existing iterator throws after destroy', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    browser.destroy()
    await assert.rejects(iter.next(), /Browser has been destroyed/)
  })

  test('creating a new iterator after destroy throws', () => {
    const browser = mdns.browse('_http._tcp')
    browser.destroy()

    assert.throws(
      () => browser[Symbol.asyncIterator](),
      /Browser has been destroyed/
    )
  })
})

describe('Fix: ready() before browse() throws', () => {
  test('throws when ready() is called before any browse()', async () => {
    const mdns = new DnsSdBrowser()
    await assert.rejects(
      () => mdns.ready(),
      /Cannot call ready\(\) before browse\(\)/
    )
    await mdns.destroy()
  })
})

describe('Fix: browse() with pre-aborted signal', () => {
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

  test('browse() with already-aborted signal is immediately destroyed', async () => {
    const controller = new AbortController()
    controller.abort()

    const browser = mdns.browse('_http._tcp', { signal: controller.signal })

    // Browser is destroyed synchronously — creating an iterator should throw
    assert.throws(
      () => browser[Symbol.asyncIterator](),
      /Browser has been destroyed/
    )
  })
})

describe('Fix: transport start error surfacing', () => {
  test('ready() surfaces the underlying transport error', async (t) => {
    // Use a port that requires elevated privileges to reliably cause a bind error.
    // On Linux, binding to a well-known port (< 1024) as non-root should fail.
    const mdns = new DnsSdBrowser({ port: 1 })

    // Trigger start
    mdns.browse('_http._tcp').destroy()

    // Give the start promise time to settle
    await new Promise((r) => setTimeout(r, 200))

    let threw = false
    try {
      await mdns.ready()
      // If ready() didn't throw, the port bind succeeded (e.g. running as root)
    } catch (err) {
      threw = true
      // The error should be the real bind error, not a generic message
      assert.ok(err instanceof Error)
      assert.ok(
        err.message.includes('EACCES') || err.message.includes('EADDRINUSE') || err.message.includes('EPERM'),
        `Expected a bind error but got: ${err.message}`
      )
    } finally {
      await mdns.destroy()
    }

    if (!threw) {
      t.skip('port 1 bind succeeded (likely running as root)')
    }
  })
})
