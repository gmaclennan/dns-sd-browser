/**
 * Minimal pcap-format reader for mDNS golden-replay tests.
 *
 * Supports classic pcap (not pcapng), Ethernet / Linux-cooked / BSD-loopback
 * link types, IPv4 + IPv6, UDP only. Returns the UDP payload of every
 * packet whose source or destination port is 5353 (mDNS).
 *
 * Reference: https://www.tcpdump.org/manpages/pcap-savefile.5.txt
 *
 * @module
 */

const PCAP_GLOBAL_HEADER_LEN = 24
const PCAP_RECORD_HEADER_LEN = 16
const MDNS_PORT = 5353
const PROTO_UDP = 17

const LINK_TYPE_ETHERNET = 1
const LINK_TYPE_NULL = 0
const LINK_TYPE_RAW = 101
const LINK_TYPE_LINUX_SLL = 113

/**
 * Extract every mDNS UDP payload from a pcap buffer.
 * @param {Uint8Array} buf
 * @returns {Uint8Array[]}
 */
export function extractMdnsPayloads(buf) {
  if (buf.byteLength < PCAP_GLOBAL_HEADER_LEN) {
    throw new Error(`pcap: file too short (${buf.byteLength} bytes)`)
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  const magic = view.getUint32(0, false)

  /** @type {boolean} */ let littleEndian
  if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) littleEndian = false
  else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) littleEndian = true
  else throw new Error(`pcap: unrecognised magic 0x${magic.toString(16)}`)

  const linkType = view.getUint32(20, littleEndian)

  /** @type {Uint8Array[]} */
  const payloads = []
  let offset = PCAP_GLOBAL_HEADER_LEN

  while (offset + PCAP_RECORD_HEADER_LEN <= buf.byteLength) {
    const inclLen = view.getUint32(offset + 8, littleEndian)
    offset += PCAP_RECORD_HEADER_LEN

    if (offset + inclLen > buf.byteLength) break

    const frame = buf.subarray(offset, offset + inclLen)
    offset += inclLen

    const payload = extractMdnsFromFrame(frame, linkType)
    if (payload) payloads.push(payload)
  }

  return payloads
}

/**
 * Walk a single link-layer frame down to its mDNS UDP payload.
 * Returns null if the frame isn't UDP/5353.
 * @param {Uint8Array} frame
 * @param {number} linkType
 * @returns {Uint8Array | null}
 */
function extractMdnsFromFrame(frame, linkType) {
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
  let off = 0
  /** 0x0800 = IPv4, 0x86dd = IPv6 */
  let ethertype

  if (linkType === LINK_TYPE_ETHERNET) {
    if (frame.byteLength < 14) return null
    ethertype = view.getUint16(12, false)
    off = 14
    // Strip stacked VLAN tags
    while (ethertype === 0x8100 || ethertype === 0x88a8) {
      if (off + 4 > frame.byteLength) return null
      ethertype = view.getUint16(off + 2, false)
      off += 4
    }
  } else if (linkType === LINK_TYPE_NULL) {
    // BSD loopback: 4-byte address-family in host byte order. Both
    // endiannesses appear in the wild, so accept either.
    if (frame.byteLength < 4) return null
    const family = view.getUint32(0, true)
    if (family === 2 || family === 0x02000000) ethertype = 0x0800
    else if (family === 24 || family === 28 || family === 30) ethertype = 0x86dd
    else return null
    off = 4
  } else if (linkType === LINK_TYPE_RAW) {
    if (frame.byteLength < 1) return null
    const ipVer = (frame[0] >> 4) & 0xf
    ethertype = ipVer === 4 ? 0x0800 : ipVer === 6 ? 0x86dd : 0
  } else if (linkType === LINK_TYPE_LINUX_SLL) {
    if (frame.byteLength < 16) return null
    ethertype = view.getUint16(14, false)
    off = 16
  } else {
    return null
  }

  /** offset of the IP header's payload (i.e. start of UDP header) */
  let udpOff
  if (ethertype === 0x0800) {
    if (frame.byteLength < off + 20) return null
    const ihl = (frame[off] & 0x0f) * 4
    const proto = frame[off + 9]
    if (proto !== PROTO_UDP) return null
    udpOff = off + ihl
  } else if (ethertype === 0x86dd) {
    if (frame.byteLength < off + 40) return null
    // Skip-extension-headers handling is omitted: mDNS captures don't
    // typically use IPv6 extension headers, and unknown nh values just
    // mean we drop the packet.
    const nh = frame[off + 6]
    if (nh !== PROTO_UDP) return null
    udpOff = off + 40
  } else {
    return null
  }

  if (frame.byteLength < udpOff + 8) return null
  const srcPort = view.getUint16(udpOff, false)
  const dstPort = view.getUint16(udpOff + 2, false)
  if (srcPort !== MDNS_PORT && dstPort !== MDNS_PORT) return null
  const udpLen = view.getUint16(udpOff + 4, false)
  // udpLen includes the 8-byte UDP header. Clamp to what we actually have.
  const payloadLen = Math.max(0, Math.min(udpLen - 8, frame.byteLength - udpOff - 8))

  return frame.subarray(udpOff + 8, udpOff + 8 + payloadLen)
}
