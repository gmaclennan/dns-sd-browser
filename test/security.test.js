/**
 * Security regression tests for dns-sd-browser.
 *
 * These tests verify defenses against vulnerability patterns found in
 * historical CVEs for Avahi and Apple mDNSResponder. While this is a
 * memory-safe JavaScript library (no buffer overflows), the logic-level
 * attack patterns still apply: resource exhaustion, malformed packet
 * handling, and DNS parsing edge cases.
 *
 * References:
 * - CVE-2006-6870: Avahi infinite loop via self-referencing compression pointer
 * - CVE-2011-1002: Avahi crash on empty mDNS packet
 * - CVE-2023-38469: Avahi assertion on oversized TXT record
 * - CVE-2023-38472: Avahi assertion in rdata_parse on malformed records
 * - CVE-2025-59529: Avahi unlimited connections / resource exhaustion
 * - CVE-2015-7987/7988: mDNSResponder buffer overflow in name decompression
 * - CVE-2017-6519: Avahi mDNS amplification
 */

import { describe, test, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import dnsPacket from 'dns-packet'
import * as dns from '../lib/dns.js'
import { DnsSdBrowser } from '../lib/index.js'
import { TestAdvertiser } from './helpers/advertiser.js'
import { nextEvent, getRandomPort, delay, TEST_INTERFACE } from './helpers/utils.js'

// ─── DNS Packet Parsing Security ─────────────────────────────────────────

describe('Security: malformed packet rejection (CVE-2011-1002, CVE-2023-38472)', () => {
  test('rejects empty packet', () => {
    assert.throws(() => dns.decode(Buffer.alloc(0)), /too short/)
  })

  test('rejects packet shorter than DNS header', () => {
    assert.throws(() => dns.decode(Buffer.alloc(6)), /too short/)
    assert.throws(() => dns.decode(Buffer.alloc(11)), /too short/)
  })

  test('accepts minimal 12-byte header', () => {
    const buf = Buffer.alloc(12)
    buf.writeUInt16BE(0x8400, 2) // QR=1, AA=1
    const packet = dns.decode(buf)
    assert.equal(packet.answers.length, 0)
  })

  test('rejects packet with excessive record counts', () => {
    const buf = Buffer.alloc(12)
    buf.writeUInt16BE(0x8400, 2) // flags
    buf.writeUInt16BE(100, 4)    // QDCOUNT = 100
    buf.writeUInt16BE(100, 6)    // ANCOUNT = 100
    buf.writeUInt16BE(100, 8)    // NSCOUNT = 100
    // Total = 300 > 256 limit
    assert.throws(() => dns.decode(buf), /records/)
  })

  test('rejects truncated resource record', () => {
    // Craft a packet that claims 1 answer but has no data after the header
    const buf = Buffer.alloc(14)
    buf.writeUInt16BE(0x8400, 2) // QR=1, AA=1
    buf.writeUInt16BE(1, 6)      // ANCOUNT = 1
    buf[12] = 0                  // Root name (1 byte)
    // Only 1 byte of record data — need 10 for type+class+ttl+rdlength
    assert.throws(() => dns.decode(buf), /truncated|beyond buffer/)
  })

  test('rejects RDATA that overflows packet boundary', () => {
    const buf = Buffer.alloc(25)
    buf.writeUInt16BE(0x8400, 2)  // flags
    buf.writeUInt16BE(1, 6)       // ANCOUNT = 1
    buf[12] = 0                   // Root name
    buf.writeUInt16BE(1, 13)      // TYPE = A
    buf.writeUInt16BE(1, 15)      // CLASS = IN
    buf.writeUInt32BE(300, 17)    // TTL
    buf.writeUInt16BE(100, 21)    // RDLENGTH = 100 (way beyond buffer)
    assert.throws(() => dns.decode(buf), /overflows/)
  })
})

describe('Security: DNS name compression attacks (CVE-2006-6870, CVE-2015-7987)', () => {
  test('rejects self-referencing pointer (infinite loop)', () => {
    const buf = Buffer.alloc(18)
    buf.writeUInt16BE(0x8400, 2)
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    buf.writeUInt16BE(0xC00C, 12) // Pointer to itself
    buf.writeUInt16BE(1, 14)      // QTYPE
    buf.writeUInt16BE(1, 16)      // QCLASS
    assert.throws(() => dns.decode(buf), /too many compression pointers/)
  })

  test('rejects pointer targeting beyond buffer', () => {
    const buf = Buffer.alloc(18)
    buf.writeUInt16BE(0x8400, 2)
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    // Pointer to offset 0xFF00 — way beyond the 18-byte buffer
    buf.writeUInt16BE(0xCF00, 12)
    buf.writeUInt16BE(1, 14)
    buf.writeUInt16BE(1, 16)
    assert.throws(() => dns.decode(buf), /pointer offset.*beyond buffer/)
  })

  test('rejects label that extends beyond buffer', () => {
    const buf = Buffer.alloc(18)
    buf.writeUInt16BE(0x8400, 2)
    buf.writeUInt16BE(1, 4)
    buf[12] = 50                  // Label claims 50 bytes, but only ~5 remain
    assert.throws(() => dns.decode(buf), /beyond buffer/)
  })

  test('rejects DNS name exceeding 253 character limit', () => {
    // Build a packet with a very long name: 4 labels of 63 chars each = 255 chars
    // We need 4 * (1 + 63) + 1 = 257 bytes just for the name
    const name63 = 'a'.repeat(63)
    const longName = `${name63}.${name63}.${name63}.${name63}`
    assert.ok(longName.length > 253) // 255 chars

    // Try to decode a packet containing this name
    const labels = longName.split('.')
    const parts = [Buffer.alloc(12)] // header
    parts[0].writeUInt16BE(0x8400, 2) // flags
    parts[0].writeUInt16BE(1, 4)       // QDCOUNT = 1
    for (const label of labels) {
      const lenBuf = Buffer.alloc(1)
      lenBuf[0] = label.length
      parts.push(lenBuf, Buffer.from(label))
    }
    parts.push(Buffer.from([0])) // null terminator
    parts.push(Buffer.alloc(4))  // QTYPE + QCLASS

    const buf = Buffer.concat(parts)
    assert.throws(() => dns.decode(buf), /maximum length/)
  })

  test('rejects oversized label (> 63 bytes)', () => {
    const buf = Buffer.alloc(80)
    buf.writeUInt16BE(0x8400, 2)
    buf.writeUInt16BE(1, 4)
    buf[12] = 64 // Label length 64 > max 63
    buf.fill(0x41, 13, 77) // 64 bytes of 'A'
    assert.throws(() => dns.decode(buf), /label length/)
  })
})

describe('Security: SRV record validation (CVE-2023-38472)', () => {
  test('rejects SRV record with RDATA too short', () => {
    // Build a response with SRV record that has rdlength < 7
    const buf = Buffer.alloc(30)
    buf.writeUInt16BE(0x8400, 2)  // flags
    buf.writeUInt16BE(1, 6)       // ANCOUNT = 1
    buf[12] = 0                   // Root name
    buf.writeUInt16BE(33, 13)     // TYPE = SRV (33)
    buf.writeUInt16BE(1, 15)      // CLASS = IN
    buf.writeUInt32BE(300, 17)    // TTL
    buf.writeUInt16BE(4, 21)      // RDLENGTH = 4 (too short for SRV)
    assert.throws(() => dns.decode(buf), /SRV.*too short/)
  })
})

describe('Security: TXT record boundary check (CVE-2023-38469)', () => {
  test('rejects TXT string that exceeds RDATA boundary', () => {
    // Build a response with a TXT record where string length exceeds rdlength
    const buf = Buffer.alloc(30)
    buf.writeUInt16BE(0x8400, 2)  // flags
    buf.writeUInt16BE(1, 6)       // ANCOUNT = 1
    buf[12] = 0                   // Root name
    buf.writeUInt16BE(16, 13)     // TYPE = TXT (16)
    buf.writeUInt16BE(1, 15)      // CLASS = IN
    buf.writeUInt32BE(300, 17)    // TTL
    buf.writeUInt16BE(3, 21)      // RDLENGTH = 3
    buf[23] = 10                  // TXT string claims 10 bytes, but only 2 remain in RDATA
    buf[24] = 0x41                // 'A'
    buf[25] = 0x42                // 'B'
    assert.throws(() => dns.decode(buf), /TXT.*boundary/)
  })

  test('accepts valid TXT record', () => {
    const packet = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [{
        type: 'TXT',
        name: 'test._http._tcp.local',
        ttl: 4500,
        class: 'IN',
        data: ['key=value', 'flag'],
      }],
    })
    const decoded = dns.decode(packet)
    assert.equal(decoded.answers.length, 1)
    assert.equal(decoded.answers[0].type, dns.RecordType.TXT)
  })
})

// ─── Resource Exhaustion Defense ─────────────────────────────────────────

describe('Security: resource exhaustion defense (CVE-2025-59529)', () => {
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

  test('service count is bounded under flood of unique services', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Flood with 1100 unique services (above the 1024 limit)
    const batchSize = 50
    for (let batch = 0; batch < 22; batch++) {
      const promises = []
      for (let i = 0; i < batchSize; i++) {
        const n = batch * batchSize + i
        promises.push(advertiser.announce({
          name: `FloodService-${n}`,
          type: '_http._tcp',
          host: `host-${n}.local`,
          port: 8080 + n,
          addresses: [`10.0.${Math.floor(n / 256)}.${n % 256}`],
        }))
      }
      await Promise.all(promises)
      // Small delay to let packets be processed
      await delay(20)
    }

    // Allow processing time
    await delay(200)

    // The service count should be capped at MAX_SERVICES (1024)
    assert.ok(
      browser.services.size <= 1024,
      `Expected at most 1024 services but found ${browser.services.size}`
    )

    browser.destroy()
  })

  test('malformed packets from network do not crash the browser', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // Send various malformed packets — none should crash the process
    const malformedPackets = [
      Buffer.alloc(0),                     // empty
      Buffer.alloc(4),                     // too short
      Buffer.from([0xff, 0xff, 0xff]),     // garbage
      (() => {                             // self-referencing pointer
        const b = Buffer.alloc(18)
        b.writeUInt16BE(0x8400, 2)
        b.writeUInt16BE(1, 4)
        b.writeUInt16BE(0xC00C, 12)
        b.writeUInt16BE(1, 14)
        b.writeUInt16BE(1, 16)
        return b
      })(),
    ]

    for (const pkt of malformedPackets) {
      await advertiser.sendRaw(pkt)
    }

    // Now send a valid service — it should work fine after the malformed packets
    await advertiser.announce({
      name: 'ValidService',
      type: '_http._tcp',
      host: 'valid.local',
      port: 9999,
      addresses: ['10.0.0.1'],
    })

    const event = await nextEvent(iter, 5000)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'ValidService')

    browser.destroy()
  })
})
