/**
 * DNS packet encoder/decoder for mDNS.
 *
 * Implements the subset of DNS wire format (RFC 1035) needed for DNS-SD
 * browsing over mDNS (RFC 6762, RFC 6763). Handles DNS name compression,
 * the mDNS cache-flush bit, and all record types used by DNS-SD:
 * PTR, SRV, TXT, A, AAAA.
 *
 * @module
 */

/** @enum {number} */
export const RecordType = /** @type {const} */ ({
  A: 1,
  PTR: 12,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  ANY: 255,
})

/** DNS class IN */
const CLASS_IN = 1

/** mDNS cache-flush bit — high bit of the class field (RFC 6762 §10.2) */
const CACHE_FLUSH_BIT = 0x8000

/** DNS name pointer mask — two highest bits set (RFC 1035 §4.1.4) */
const POINTER_MASK = 0xc0

/** Maximum DNS name label length */
const MAX_LABEL_LENGTH = 63

/**
 * @typedef {object} DnsFlags
 * @property {boolean} qr - true for response, false for query
 * @property {number} opcode
 * @property {boolean} aa - Authoritative Answer
 * @property {boolean} tc - Truncated
 * @property {boolean} rd - Recursion Desired
 * @property {boolean} ra - Recursion Available
 * @property {number} rcode - Response code
 */

/**
 * @typedef {object} DnsQuestion
 * @property {string} name
 * @property {number} type - RecordType value
 * @property {boolean} [qu] - QU (unicast-response) bit (RFC 6762 §5.4)
 */

/**
 * @typedef {object} SrvData
 * @property {number} priority
 * @property {number} weight
 * @property {number} port
 * @property {string} target
 */

/**
 * @typedef {object} DnsRecord
 * @property {string} name
 * @property {number} type - RecordType value
 * @property {number} class - Usually 1 (IN)
 * @property {boolean} cacheFlush - mDNS cache-flush bit
 * @property {number} ttl
 * @property {string | SrvData | Uint8Array[]} data - Type-specific data
 */

/**
 * @typedef {object} DnsPacket
 * @property {number} id
 * @property {DnsFlags} flags
 * @property {DnsQuestion[]} questions
 * @property {DnsRecord[]} answers
 * @property {DnsRecord[]} authorities
 * @property {DnsRecord[]} additionals
 */

/**
 * Decode a DNS packet from a buffer.
 * @param {Uint8Array} buf
 * @returns {DnsPacket}
 */
export function decode(buf) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  let offset = 0

  // Header (RFC 1035 §4.1.1) — 12 bytes
  const id = view.getUint16(offset)
  offset += 2

  const flagBits = view.getUint16(offset)
  offset += 2

  const flags = {
    qr: (flagBits & 0x8000) !== 0,
    opcode: (flagBits >> 11) & 0xf,
    aa: (flagBits & 0x0400) !== 0,
    tc: (flagBits & 0x0200) !== 0,
    rd: (flagBits & 0x0100) !== 0,
    ra: (flagBits & 0x0080) !== 0,
    rcode: flagBits & 0x000f,
  }

  const qdcount = view.getUint16(offset)
  offset += 2
  const ancount = view.getUint16(offset)
  offset += 2
  const nscount = view.getUint16(offset)
  offset += 2
  const arcount = view.getUint16(offset)
  offset += 2

  const questions = []
  for (let i = 0; i < qdcount; i++) {
    const { name, offset: newOffset } = decodeName(buf, offset)
    offset = newOffset
    const qtype = view.getUint16(offset)
    offset += 2
    const qclassBits = view.getUint16(offset)
    offset += 2
    const qu = (qclassBits & CACHE_FLUSH_BIT) !== 0
    questions.push({ name, type: qtype, qu })
  }

  const answers = decodeRecords(buf, view, offset, ancount)
  offset = answers.newOffset
  const authorities = decodeRecords(buf, view, offset, nscount)
  offset = authorities.newOffset
  const additionals = decodeRecords(buf, view, offset, arcount)

  return {
    id,
    flags,
    questions,
    answers: answers.records,
    authorities: authorities.records,
    additionals: additionals.records,
  }
}

/**
 * Decode N resource records starting at the given offset.
 * @param {Uint8Array} buf
 * @param {DataView} view
 * @param {number} offset
 * @param {number} count
 * @returns {{ records: DnsRecord[], newOffset: number }}
 */
function decodeRecords(buf, view, offset, count) {
  const records = []
  for (let i = 0; i < count; i++) {
    const { name, offset: nameEnd } = decodeName(buf, offset)
    offset = nameEnd

    const type = view.getUint16(offset)
    offset += 2
    const classBits = view.getUint16(offset)
    offset += 2
    const cacheFlush = (classBits & CACHE_FLUSH_BIT) !== 0
    const rrClass = classBits & ~CACHE_FLUSH_BIT

    const ttl = view.getUint32(offset)
    offset += 4
    const rdlength = view.getUint16(offset)
    offset += 2

    const data = decodeRecordData(buf, view, offset, type, rdlength)
    offset += rdlength

    records.push({ name, type, class: rrClass, cacheFlush, ttl, data })
  }
  return { records, newOffset: offset }
}

/**
 * Decode record-type-specific data (RDATA).
 * @param {Uint8Array} buf
 * @param {DataView} view
 * @param {number} offset - Start of RDATA
 * @param {number} type - Record type
 * @param {number} rdlength - Length of RDATA
 * @returns {string | SrvData | Uint8Array[]}
 */
function decodeRecordData(buf, view, offset, type, rdlength) {
  switch (type) {
    case RecordType.A: {
      if (rdlength !== 4) return ''
      return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`
    }

    case RecordType.AAAA: {
      if (rdlength !== 16) return ''
      const parts = []
      for (let i = 0; i < 16; i += 2) {
        parts.push(view.getUint16(offset + i).toString(16))
      }
      return compressIPv6(parts.join(':'))
    }

    case RecordType.PTR: {
      const { name } = decodeName(buf, offset)
      return name
    }

    case RecordType.SRV: {
      const priority = view.getUint16(offset)
      const weight = view.getUint16(offset + 2)
      const port = view.getUint16(offset + 4)
      const { name: target } = decodeName(buf, offset + 6)
      return { priority, weight, port, target }
    }

    case RecordType.TXT: {
      return decodeTxtData(buf, offset, rdlength)
    }

    default: {
      // Return raw bytes for unknown record types
      return [buf.slice(offset, offset + rdlength)]
    }
  }
}

/**
 * Decode TXT record data into an array of Uint8Array strings.
 * Each string is length-prefixed (RFC 1035 §3.3.14).
 * @param {Uint8Array} buf
 * @param {number} offset
 * @param {number} rdlength
 * @returns {Uint8Array[]}
 */
function decodeTxtData(buf, offset, rdlength) {
  const strings = []
  const end = offset + rdlength
  while (offset < end) {
    const len = buf[offset]
    offset += 1
    if (len === 0) {
      // Empty string — represents an empty TXT record (RFC 6763 §6.1)
      continue
    }
    strings.push(buf.slice(offset, offset + len))
    offset += len
  }
  return strings
}

/**
 * Decode a DNS name from the buffer, handling compression pointers.
 * @param {Uint8Array} buf
 * @param {number} offset
 * @returns {{ name: string, offset: number }}
 */
function decodeName(buf, offset) {
  const labels = []
  let jumped = false
  let returnOffset = offset

  // Guard against infinite loops from malicious pointer chains
  let maxJumps = 128
  while (maxJumps-- > 0) {
    if (offset >= buf.length) break

    const len = buf[offset]

    if (len === 0) {
      // End of name
      if (!jumped) returnOffset = offset + 1
      break
    }

    if ((len & POINTER_MASK) === POINTER_MASK) {
      // Compressed name pointer (RFC 1035 §4.1.4)
      if (!jumped) returnOffset = offset + 2
      const pointerOffset = ((len & ~POINTER_MASK) << 8) | buf[offset + 1]
      offset = pointerOffset
      jumped = true
      continue
    }

    // Regular label
    if (len > MAX_LABEL_LENGTH) break

    offset += 1
    const label = new TextDecoder().decode(buf.slice(offset, offset + len))
    labels.push(label)
    offset += len

    // Track return position through each label when not following pointers
    if (!jumped) returnOffset = offset
  }

  return { name: labels.join('.'), offset: returnOffset }
}

/**
 * Compress an IPv6 address string (collapse longest run of :0: groups).
 * @param {string} addr - Fully expanded IPv6 (8 groups of hex)
 * @returns {string}
 */
function compressIPv6(addr) {
  const parts = addr.split(':').map((p) => p.replace(/^0+/, '') || '0')
  // Find longest run of consecutive '0' groups
  let bestStart = -1
  let bestLen = 0
  let curStart = -1
  let curLen = 0
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '0') {
      if (curStart === -1) curStart = i
      curLen++
      if (curLen > bestLen) {
        bestStart = curStart
        bestLen = curLen
      }
    } else {
      curStart = -1
      curLen = 0
    }
  }

  if (bestLen < 2) return parts.join(':')

  const before = parts.slice(0, bestStart).join(':')
  const after = parts.slice(bestStart + bestLen).join(':')
  return `${before}::${after}`
}

// ─── Encoding ───────────────────────────────────────────────────────────

/**
 * @typedef {object} QueryOptions
 * @property {DnsQuestion[]} questions
 * @property {DnsRecord[]} [answers] - Known answers for suppression (RFC 6762 §7.1)
 */

/**
 * Encode an mDNS query packet.
 * @param {QueryOptions} options
 * @returns {Buffer}
 */
export function encodeQuery({ questions, answers = [] }) {
  /** @type {Map<string, number>} - Name compression table: name → offset */
  const compressionTable = new Map()

  // Header — 12 bytes
  const header = Buffer.alloc(12)
  // ID = 0 for mDNS queries (RFC 6762 §18.1)
  header.writeUInt16BE(0, 0)
  // Flags = 0 for standard query
  header.writeUInt16BE(0, 2)
  // QDCOUNT
  header.writeUInt16BE(questions.length, 4)
  // ANCOUNT (known answers for suppression)
  header.writeUInt16BE(answers.length, 6)
  // NSCOUNT
  header.writeUInt16BE(0, 8)
  // ARCOUNT
  header.writeUInt16BE(0, 10)

  const parts = [header]
  let currentOffset = 12

  // Encode questions
  for (const q of questions) {
    const nameBytes = encodeName(q.name, compressionTable, currentOffset)
    const qFooter = Buffer.alloc(4)
    qFooter.writeUInt16BE(q.type, 0)
    // QU bit in the class field for mDNS unicast-response
    qFooter.writeUInt16BE(q.qu ? (CLASS_IN | CACHE_FLUSH_BIT) : CLASS_IN, 2)

    parts.push(nameBytes, qFooter)
    currentOffset += nameBytes.length + 4
  }

  // Encode known answers
  for (const record of answers) {
    const recordBytes = encodeRecord(record, compressionTable, currentOffset)
    parts.push(recordBytes)
    currentOffset += recordBytes.length
  }

  return Buffer.concat(parts)
}

/**
 * Encode a single resource record.
 * @param {DnsRecord} record
 * @param {Map<string, number>} compressionTable
 * @param {number} currentOffset
 * @returns {Buffer}
 */
function encodeRecord(record, compressionTable, currentOffset) {
  const nameBytes = encodeName(record.name, compressionTable, currentOffset)
  currentOffset += nameBytes.length

  const rdata = encodeRecordData(record, compressionTable, currentOffset + 10)

  const meta = Buffer.alloc(10)
  meta.writeUInt16BE(record.type, 0)
  const classBits = (record.class || CLASS_IN) | (record.cacheFlush ? CACHE_FLUSH_BIT : 0)
  meta.writeUInt16BE(classBits, 2)
  meta.writeUInt32BE(record.ttl, 4)
  meta.writeUInt16BE(rdata.length, 8)

  return Buffer.concat([nameBytes, meta, rdata])
}

/**
 * Encode record-type-specific data.
 * @param {DnsRecord} record
 * @param {Map<string, number>} compressionTable
 * @param {number} rdataOffset
 * @returns {Buffer}
 */
function encodeRecordData(record, compressionTable, rdataOffset) {
  switch (record.type) {
    case RecordType.A: {
      const data = /** @type {string} */ (record.data)
      const parts = data.split('.').map(Number)
      return Buffer.from(parts)
    }

    case RecordType.AAAA: {
      const data = /** @type {string} */ (record.data)
      return encodeIPv6(data)
    }

    case RecordType.PTR: {
      const data = /** @type {string} */ (record.data)
      return encodeName(data, compressionTable, rdataOffset)
    }

    case RecordType.SRV: {
      const data = /** @type {SrvData} */ (record.data)
      const header = Buffer.alloc(6)
      header.writeUInt16BE(data.priority, 0)
      header.writeUInt16BE(data.weight, 2)
      header.writeUInt16BE(data.port, 4)
      // SRV target MUST NOT use name compression (RFC 2782)
      const targetBytes = encodeName(data.target, new Map(), rdataOffset + 6)
      return Buffer.concat([header, targetBytes])
    }

    case RecordType.TXT: {
      const data = /** @type {Uint8Array[]} */ (record.data)
      if (data.length === 0) return Buffer.from([0])
      const parts = data.map((s) => {
        const len = Buffer.alloc(1)
        len[0] = s.length
        return Buffer.concat([len, s])
      })
      return Buffer.concat(parts)
    }

    default:
      return Buffer.alloc(0)
  }
}

/**
 * Encode a DNS name with compression.
 * @param {string} name
 * @param {Map<string, number>} compressionTable
 * @param {number} currentOffset
 * @returns {Buffer}
 */
function encodeName(name, compressionTable, currentOffset) {
  const labels = name.split('.')
  const parts = []

  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.')

    // Check if this suffix is already in the compression table
    const pointer = compressionTable.get(suffix)
    if (pointer !== undefined) {
      const ptrBuf = Buffer.alloc(2)
      ptrBuf.writeUInt16BE(0xc000 | pointer, 0)
      parts.push(ptrBuf)
      return Buffer.concat(parts)
    }

    // Store this suffix position for future compression
    compressionTable.set(suffix, currentOffset)

    const label = labels[i]
    const encoded = Buffer.from(label, 'utf-8')
    const lenBuf = Buffer.alloc(1)
    lenBuf[0] = encoded.length
    parts.push(lenBuf, encoded)
    currentOffset += 1 + encoded.length
  }

  // Null terminator
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

/**
 * Encode an IPv6 address to a 16-byte buffer.
 * @param {string} addr
 * @returns {Buffer}
 */
function encodeIPv6(addr) {
  const buf = Buffer.alloc(16)
  // Expand :: shorthand
  let fullAddr = addr
  if (fullAddr.includes('::')) {
    const [left, right] = fullAddr.split('::')
    const leftParts = left ? left.split(':') : []
    const rightParts = right ? right.split(':') : []
    const missing = 8 - leftParts.length - rightParts.length
    const middle = Array(missing).fill('0')
    fullAddr = [...leftParts, ...middle, ...rightParts].join(':')
  }

  const parts = fullAddr.split(':')
  for (let i = 0; i < 8; i++) {
    const val = parseInt(parts[i] || '0', 16)
    buf.writeUInt16BE(val, i * 2)
  }
  return buf
}
