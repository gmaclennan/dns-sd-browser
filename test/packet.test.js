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
