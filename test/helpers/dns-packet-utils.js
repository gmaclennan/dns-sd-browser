/**
 * Helpers for manipulating raw DNS packet buffers in tests.
 *
 * These abstract away dns-packet encoding details so that tests don't
 * depend on specific byte offsets or internal string representations.
 */

/**
 * The string that dns-packet uses to represent the QU (unicast-response)
 * bit in the class field (IN class 0x0001 | QU bit 0x8000 = 0x8001).
 *
 * Centralised here so that if dns-packet changes its representation,
 * only this constant needs updating.
 */
export const QU_CLASS = 'UNKNOWN_32769'

/**
 * The standard multicast class string used by dns-packet.
 */
export const QM_CLASS = 'IN'

/**
 * Set the TC (truncated) bit in a DNS packet buffer.
 * TC is bit 9 of the flags field (byte 2, bit 1).
 * @param {Buffer} buf - Encoded DNS packet
 * @returns {Buffer} The same buffer, mutated
 */
export function setTCBit(buf) {
  buf[2] = buf[2] | 0x02
  return buf
}

/**
 * Force QR=1 (response) and AA=0 in a DNS packet buffer,
 * preserving all other flag bits (opcode, TC, RD, RA, Z, AD, CD, rcode).
 * @param {Buffer} buf - Encoded DNS packet
 * @returns {Buffer} The same buffer, mutated
 */
export function setResponseNoAA(buf) {
  buf[2] = (buf[2] | 0x80) & ~0x04 // QR=1, AA=0, preserve opcode/TC/RD
  // buf[3] left untouched — preserves RA/Z/AD/CD/rcode
  return buf
}

/**
 * Set a non-zero opcode in a DNS packet buffer.
 * @param {Buffer} buf - Encoded DNS packet
 * @param {number} opcode - Opcode value (1-15)
 * @returns {Buffer} The same buffer, mutated
 */
export function setOpcode(buf, opcode) {
  buf[2] = (buf[2] & 0x87) | ((opcode & 0x0f) << 3)
  return buf
}

/**
 * Set the rcode field in a DNS packet buffer.
 * @param {Buffer} buf - Encoded DNS packet
 * @param {number} rcode - Response code (0-15)
 * @returns {Buffer} The same buffer, mutated
 */
export function setRcode(buf, rcode) {
  buf[3] = (buf[3] & 0xf0) | (rcode & 0x0f)
  return buf
}

/**
 * Set the QU (unicast-response) bit on the first question in a DNS packet.
 * Scans past the DNS header and question name to find the class field,
 * then sets the high bit.
 * @param {Buffer} buf - Encoded DNS packet (must contain at least one question)
 * @returns {Buffer} The same buffer, mutated
 */
export function setQUBitOnFirstQuestion(buf) {
  // Skip 12-byte DNS header, then scan past the question name
  let offset = 12
  while (buf[offset] !== 0) {
    offset += 1 + buf[offset] // label length + label data
  }
  offset++ // skip null terminator
  // offset now points at QTYPE (2 bytes), then QCLASS (2 bytes)
  const classOffset = offset + 2
  buf.writeUInt16BE(buf.readUInt16BE(classOffset) | 0x8000, classOffset)
  return buf
}
