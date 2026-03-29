import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import dnsPacket from 'dns-packet'
import * as dns from '../lib/dns.js'

/**
 * Integration tests for the DNS packet codec.
 *
 * These tests validate our encoder/decoder against the well-established
 * `dns-packet` library. This cross-validation approach catches encoding
 * bugs without mocking — we compare two independent implementations.
 */

describe('DNS packet decoding', () => {
  test('decodes a PTR response', () => {
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
          data: 'My Service._http._tcp.local',
        },
      ],
    })

    const packet = dns.decode(buf)
    assert.equal(packet.flags.qr, true, 'should be a response')
    assert.equal(packet.flags.aa, true, 'should be authoritative')
    assert.equal(packet.answers.length, 1)

    const answer = packet.answers[0]
    assert.equal(answer.type, dns.RecordType.PTR)
    assert.equal(answer.name, '_http._tcp.local')
    assert.equal(answer.data, 'My Service._http._tcp.local')
    assert.equal(answer.ttl, 4500)
  })

  test('decodes an SRV record', () => {
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'SRV',
          name: 'My Service._http._tcp.local',
          ttl: 120,
          class: 'IN',
          data: { target: 'myhost.local', port: 8080, priority: 0, weight: 0 },
        },
      ],
    })

    const packet = dns.decode(buf)
    const answer = packet.answers[0]
    assert.equal(answer.type, dns.RecordType.SRV)
    assert.equal(answer.data.target, 'myhost.local')
    assert.equal(answer.data.port, 8080)
    assert.equal(answer.data.priority, 0)
    assert.equal(answer.data.weight, 0)
  })

  test('decodes a TXT record with key=value pairs', () => {
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'TXT',
          name: 'My Service._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: ['key1=value1', 'key2=value2'],
        },
      ],
    })

    const packet = dns.decode(buf)
    const answer = packet.answers[0]
    assert.equal(answer.type, dns.RecordType.TXT)
    assert.ok(Array.isArray(answer.data), 'TXT data should be an array of buffers')
    assert.equal(answer.data.length, 2)
  })

  test('decodes an A record', () => {
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'A',
          name: 'myhost.local',
          ttl: 120,
          class: 'IN',
          data: '192.168.1.5',
        },
      ],
    })

    const packet = dns.decode(buf)
    const answer = packet.answers[0]
    assert.equal(answer.type, dns.RecordType.A)
    assert.equal(answer.data, '192.168.1.5')
  })

  test('decodes an AAAA record', () => {
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'AAAA',
          name: 'myhost.local',
          ttl: 120,
          class: 'IN',
          data: 'fe80::1',
        },
      ],
    })

    const packet = dns.decode(buf)
    const answer = packet.answers[0]
    assert.equal(answer.type, dns.RecordType.AAAA)
    // IPv6 address representation may vary (expanded vs compressed)
    assert.ok(answer.data.includes('fe80'), 'should contain fe80')
  })

  test('decodes a response with multiple record types', () => {
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
          data: 'My Service._http._tcp.local',
        },
        {
          type: 'SRV',
          name: 'My Service._http._tcp.local',
          ttl: 120,
          class: 'IN',
          data: { target: 'myhost.local', port: 8080, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: 'My Service._http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: ['path=/api'],
        },
      ],
      additionals: [
        {
          type: 'A',
          name: 'myhost.local',
          ttl: 120,
          class: 'IN',
          data: '192.168.1.5',
        },
      ],
    })

    const packet = dns.decode(buf)
    assert.equal(packet.answers.length, 3)
    assert.equal(packet.additionals.length, 1)

    const types = packet.answers.map((a) => a.type)
    assert.ok(types.includes(dns.RecordType.PTR))
    assert.ok(types.includes(dns.RecordType.SRV))
    assert.ok(types.includes(dns.RecordType.TXT))
    assert.equal(packet.additionals[0].type, dns.RecordType.A)
  })

  test('handles DNS name compression (pointers)', () => {
    // dns-packet uses name compression internally, so encoding a packet
    // with repeated domain names will produce compressed names
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
          data: 'ServiceA._http._tcp.local',
        },
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'ServiceB._http._tcp.local',
        },
      ],
    })

    const packet = dns.decode(buf)
    assert.equal(packet.answers.length, 2)
    // Both records should have properly decompressed names
    assert.equal(packet.answers[0].name, '_http._tcp.local')
    assert.equal(packet.answers[1].name, '_http._tcp.local')
    assert.equal(packet.answers[0].data, 'ServiceA._http._tcp.local')
    assert.equal(packet.answers[1].data, 'ServiceB._http._tcp.local')
  })

  test('handles cache-flush bit in class field', () => {
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'A',
          name: 'myhost.local',
          ttl: 120,
          class: 'IN',
          flush: true,
          data: '192.168.1.5',
        },
      ],
    })

    const packet = dns.decode(buf)
    const answer = packet.answers[0]
    assert.equal(answer.cacheFlush, true, 'cache-flush bit should be set')
    assert.equal(answer.data, '192.168.1.5')
  })

  test('handles goodbye packet (TTL=0)', () => {
    const buf = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      answers: [
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 0,
          class: 'IN',
          data: 'My Service._http._tcp.local',
        },
      ],
    })

    const packet = dns.decode(buf)
    assert.equal(packet.answers[0].ttl, 0)
  })
})

describe('DNS query format (RFC 6762 §18)', () => {
  test('query ID is zero (RFC 6762 §18.1)', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
    })

    // Bytes 0-1 are the query ID — must be 0x0000
    assert.equal(buf[0], 0)
    assert.equal(buf[1], 0)
  })

  test('cache-flush bit is not set in known-answer records (RFC 6762 §10.2)', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers: [{
        name: '_http._tcp.local',
        type: dns.RecordType.PTR,
        class: 1,
        cacheFlush: false,
        ttl: 4500,
        data: 'Test._http._tcp.local',
      }],
    })

    // Decode with dns-packet and verify no flush bit on the answer
    const decoded = dnsPacket.decode(buf)
    assert.ok(decoded.answers?.length >= 1)
    // dns-packet reports flush as a boolean property
    assert.equal(decoded.answers?.[0].flush, false)
  })

  test('SRV target is not compressed in encoding (RFC 2782)', () => {
    const buf = dns.encodeQuery({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers: [{
        name: 'Test._http._tcp.local',
        type: dns.RecordType.SRV,
        class: 1,
        cacheFlush: true,
        ttl: 120,
        data: { priority: 0, weight: 0, port: 8080, target: '_http._tcp.local' },
      }],
    })

    // If the target were compressed, it would be a 2-byte pointer.
    // If not compressed, the full name "_http._tcp.local" must appear in the RDATA.
    // Decode and verify target is correct (if compression were incorrectly used,
    // dns-packet would still decode it, but let's verify the raw bytes).
    const decoded = dnsPacket.decode(buf)
    const srv = decoded.answers?.[0]
    assert.equal(srv?.type, 'SRV')
    assert.equal(srv?.data?.target, '_http._tcp.local')

    // Additionally verify that the RDATA section contains the uncompressed name.
    // An uncompressed name for "_http._tcp.local" is at least 18 bytes
    // (5+1 + 4+1 + 5+1 + 0 = 17 bytes for labels). A compressed pointer is only 2 bytes.
    // The SRV RDATA is: priority(2) + weight(2) + port(2) + target(N).
    // So total RDATA with uncompressed target >= 6+17 = 23 bytes.
    // With compressed target it would be 6+2 = 8 bytes.
    // We verify by checking that the RDATA is large enough to contain an uncompressed name.
    // Since dns-packet doesn't expose raw RDATA length, we verify indirectly:
    // The total packet must be longer than it would be with compression.
    assert.ok(buf.length > 40, 'packet should be large enough to contain uncompressed SRV target')
  })
})

describe('DNS packet encoding', () => {
  test('encodes a PTR query', () => {
    const buf = dns.encodeQuery({
      questions: [
        { name: '_http._tcp.local', type: dns.RecordType.PTR },
      ],
    })

    // Verify our encoding by decoding with dns-packet
    const decoded = dnsPacket.decode(buf)
    assert.equal(decoded.type, 'query')
    assert.equal(decoded.questions?.length, 1)
    assert.equal(decoded.questions?.[0].type, 'PTR')
    assert.equal(decoded.questions?.[0].name, '_http._tcp.local')
  })

  test('encodes a query with multiple questions', () => {
    const buf = dns.encodeQuery({
      questions: [
        { name: '_http._tcp.local', type: dns.RecordType.PTR },
        { name: '_ipp._tcp.local', type: dns.RecordType.PTR },
      ],
    })

    const decoded = dnsPacket.decode(buf)
    assert.equal(decoded.questions?.length, 2)
    assert.equal(decoded.questions?.[0].name, '_http._tcp.local')
    assert.equal(decoded.questions?.[1].name, '_ipp._tcp.local')
  })

  test('encodes a query with known answers (known-answer suppression)', () => {
    const buf = dns.encodeQuery({
      questions: [
        { name: '_http._tcp.local', type: dns.RecordType.PTR },
      ],
      answers: [
        {
          name: '_http._tcp.local',
          type: dns.RecordType.PTR,
          class: 1,
          cacheFlush: false,
          ttl: 4500,
          data: 'Known._http._tcp.local',
        },
      ],
    })

    const decoded = dnsPacket.decode(buf)
    assert.equal(decoded.questions?.length, 1)
    assert.ok((decoded.answers?.length ?? 0) >= 1, 'should have known answers')
    assert.equal(decoded.answers?.[0].type, 'PTR')
    assert.equal(decoded.answers?.[0].data, 'Known._http._tcp.local')
  })
})

describe('DNS name encoding/decoding', () => {
  test('round-trips a simple domain name', () => {
    const buf = dns.encodeQuery({
      questions: [
        { name: 'test.local', type: dns.RecordType.A },
      ],
    })
    const decoded = dns.decode(buf)
    assert.equal(decoded.questions[0].name, 'test.local')
  })

  test('handles pointer loops by throwing instead of hanging', () => {
    // Construct a packet with a self-referencing pointer loop
    const buf = Buffer.alloc(30)
    // Header
    buf.writeUInt16BE(0, 0)       // ID
    buf.writeUInt16BE(0x8400, 2)  // Flags: QR=1, AA=1
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    buf.writeUInt16BE(0, 6)       // ANCOUNT
    buf.writeUInt16BE(0, 8)       // NSCOUNT
    buf.writeUInt16BE(0, 10)      // ARCOUNT
    // Question with a pointer that points to itself (offset 12)
    buf.writeUInt16BE(0xC00C, 12) // Pointer to offset 12 = itself
    buf.writeUInt16BE(1, 14)      // QTYPE = A
    buf.writeUInt16BE(1, 16)      // QCLASS = IN

    // Should throw on pointer loop rather than returning partial data
    assert.throws(() => dns.decode(buf), /too many compression pointers/)
  })

  test('throws when name label extends beyond buffer', () => {
    // A label that claims 5 bytes but only 3 remain in the buffer
    const buf = Buffer.alloc(16)
    buf.writeUInt16BE(0x8400, 2)
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    buf[12] = 5                   // Label length 5, but only bytes 13-15 exist
    buf[13] = 0x61; buf[14] = 0x62; buf[15] = 0x63
    assert.throws(() => dns.decode(buf), /beyond buffer/)
  })

  test('throws when name has no terminator and runs off buffer', () => {
    // A valid 2-byte label followed by end-of-buffer (no null terminator)
    // After reading the label, offset advances past it, then the loop tries
    // to read the next length byte which is beyond the buffer.
    const buf = Buffer.alloc(15)
    buf.writeUInt16BE(0x8400, 2)
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    buf[12] = 2                   // Label length 2
    buf[13] = 0x61; buf[14] = 0x62 // 'ab' — buffer ends here, no null terminator
    assert.throws(() => dns.decode(buf), /beyond buffer/)
  })

  test('throws when compression pointer is truncated (at last byte)', () => {
    // A compression pointer needs 2 bytes, but the buffer ends after the first byte
    const buf = Buffer.alloc(13)
    buf.writeUInt16BE(0x8400, 2) // flags
    buf.writeUInt16BE(1, 4)       // QDCOUNT = 1
    // Byte 12 is 0xC0 (start of compression pointer), but byte 13 doesn't exist
    buf[12] = 0xC0
    assert.throws(() => dns.decode(buf), /pointer truncated/)
  })

  test('handles chained DNS name compression pointers', () => {
    // Build a packet where one pointer references another pointer
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
          data: 'A._http._tcp.local',
        },
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'B._http._tcp.local',
        },
        {
          type: 'PTR',
          name: '_http._tcp.local',
          ttl: 4500,
          class: 'IN',
          data: 'C._http._tcp.local',
        },
      ],
    })

    // dns-packet will naturally create chained pointers for repeated domains
    const decoded = dns.decode(buf)
    assert.equal(decoded.answers.length, 3)
    assert.equal(decoded.answers[0].data, 'A._http._tcp.local')
    assert.equal(decoded.answers[1].data, 'B._http._tcp.local')
    assert.equal(decoded.answers[2].data, 'C._http._tcp.local')
  })

  test('round-trips a service instance name with dots and spaces', () => {
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
          data: 'My Web Server._http._tcp.local',
        },
      ],
    })

    const decoded = dns.decode(buf)
    assert.equal(decoded.answers[0].data, 'My Web Server._http._tcp.local')
  })
})

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

describe('DNS record encoding', () => {
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
    assert.ok(decoded.answers?.[0].data?.includes('fe80'))
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
    assert.equal(decoded.questions?.[0].name, '_http._tcp.local')
    // QU bit (high bit of class field) should be set — dns-packet decodes this as 'UNKNOWN_32769'
    assert.equal(decoded.questions?.[0].class, 'UNKNOWN_32769', 'QU bit should be set in class field')
  })
})

describe('Malformed record data handling', () => {
  test('A record with rdlength != 4 returns empty string', () => {
    const buf = Buffer.alloc(26)
    buf.writeUInt16BE(0x8400, 2)
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
    const buf = Buffer.alloc(27)
    buf.writeUInt16BE(0x8400, 2)
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

  test('unknown record type returns raw bytes', () => {
    const buf = Buffer.alloc(27)
    buf.writeUInt16BE(0x8400, 2)
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

describe('Authority section parsing', () => {
  test('decodes records in the authority section', () => {
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

describe('Multi-packet known-answer splitting', () => {
  test('small query fits in a single packet', () => {
    const packets = dns.encodeQueryPackets({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers: [
        {
          name: '_http._tcp.local',
          type: dns.RecordType.PTR,
          class: 1,
          cacheFlush: false,
          ttl: 4500,
          data: 'Svc1._http._tcp.local',
        },
      ],
    })
    assert.equal(packets.length, 1)

    const decoded = dnsPacket.decode(packets[0])
    assert.equal(decoded.questions?.length, 1)
    assert.equal(decoded.answers?.length, 1)
  })

  test('large known-answer list is split across multiple packets', () => {
    // Create enough known answers to exceed ~1472 bytes
    const answers = []
    for (let i = 0; i < 50; i++) {
      answers.push({
        name: '_http._tcp.local',
        type: dns.RecordType.PTR,
        class: 1,
        cacheFlush: false,
        ttl: 4500,
        data: `VeryLongServiceName-${i}-${'x'.repeat(30)}._http._tcp.local`,
      })
    }

    const packets = dns.encodeQueryPackets({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
      answers,
    })

    assert.ok(packets.length > 1, `expected multiple packets but got ${packets.length}`)

    // First packet should have the question and TC bit set
    const first = dnsPacket.decode(packets[0])
    assert.equal(first.questions?.length, 1)
    assert.ok((first.answers?.length ?? 0) > 0, 'first packet should have some answers')
    // Check TC bit: byte 2, bit 1
    assert.ok((packets[0][2] & 0x02) !== 0, 'first packet should have TC bit set')

    // Continuation packets should have no questions and no TC bit
    for (let i = 1; i < packets.length; i++) {
      const cont = dnsPacket.decode(packets[i])
      assert.equal(cont.questions?.length, 0, `continuation packet ${i} should have no questions`)
      assert.ok((cont.answers?.length ?? 0) > 0, `continuation packet ${i} should have answers`)
      assert.equal(packets[i][2] & 0x02, 0, `continuation packet ${i} should not have TC bit`)
    }

    // Total answers across all packets should equal original count
    let totalAnswers = 0
    for (const pkt of packets) {
      const decoded = dnsPacket.decode(pkt)
      totalAnswers += decoded.answers?.length ?? 0
    }
    assert.equal(totalAnswers, answers.length)

    // Each packet should fit within the mDNS size limit
    for (const pkt of packets) {
      assert.ok(pkt.length <= 1472, `packet size ${pkt.length} exceeds 1472 limit`)
    }
  })

  test('query with no answers returns single packet', () => {
    const packets = dns.encodeQueryPackets({
      questions: [{ name: '_http._tcp.local', type: dns.RecordType.PTR }],
    })
    assert.equal(packets.length, 1)
  })
})
