/**
 * mDNS transport layer — manages the UDP multicast socket.
 *
 * Handles binding to the mDNS port, joining/leaving the multicast group,
 * sending queries, and dispatching received packets to registered handlers.
 * Multiple ServiceBrowsers share a single transport instance via the
 * DnsSdBrowser class.
 *
 * @module
 */

import { createSocket } from 'node:dgram'
import { MDNS_ADDRESS, MDNS_PORT, MDNS_TTL } from './constants.js'
import * as dns from './dns.js'

/**
 * @callback PacketHandler
 * @param {dns.DnsPacket} packet
 * @returns {void}
 */

export class MdnsTransport {
  /** @type {import('node:dgram').Socket | null} */
  #socket = null
  #port
  #interface
  /** @type {Set<PacketHandler>} */
  #handlers = new Set()
  #bound = false

  /**
   * @param {object} [options]
   * @param {number} [options.port] - mDNS port (default 5353)
   * @param {string} [options.interface] - Network interface IP to bind to
   */
  constructor(options = {}) {
    this.#port = options.port ?? MDNS_PORT
    this.#interface = options.interface
  }

  /**
   * Start the transport: bind socket and join multicast group.
   * @returns {Promise<void>}
   */
  async start() {
    if (this.#bound) return

    return new Promise((resolve, reject) => {
      this.#socket = createSocket({ type: 'udp4', reuseAddr: true })

      this.#socket.on('error', (err) => {
        if (!this.#bound) {
          reject(err)
        }
        // After binding, log but don't crash (transient errors are normal)
      })

      this.#socket.on('message', (msg) => {
        try {
          const packet = dns.decode(msg)
          // Only process response packets (QR bit set)
          // mDNS queries from other hosts are not relevant to a browser
          if (!packet.flags.qr) return
          // Ignore packets with non-zero opcode or rcode (RFC 6762 §18.3)
          if (packet.flags.opcode !== 0 || packet.flags.rcode !== 0) return

          for (const handler of this.#handlers) {
            handler(packet)
          }
        } catch {
          // Silently ignore malformed packets (RFC 6762 §18)
        }
      })

      this.#socket.bind(this.#port, () => {
        const socket = /** @type {import('node:dgram').Socket} */ (this.#socket)
        try {
          const iface = this.#interface || '0.0.0.0'
          socket.addMembership(MDNS_ADDRESS, iface)
          socket.setMulticastLoopback(true)
          socket.setMulticastTTL(MDNS_TTL)
          if (this.#interface) {
            socket.setMulticastInterface(this.#interface)
          }
        } catch {
          // Multicast setup can fail on some interfaces — continue anyway.
          // The socket can still receive unicast responses.
        }
        this.#bound = true
        resolve()
      })
    })
  }

  /**
   * Send an mDNS query.
   * @param {dns.QueryOptions} queryOptions
   * @returns {Promise<void>}
   */
  async sendQuery(queryOptions) {
    if (!this.#socket || !this.#bound) {
      throw new Error('Transport not started')
    }

    const buf = dns.encodeQuery(queryOptions)

    return new Promise((resolve, reject) => {
      const socket = /** @type {import('node:dgram').Socket} */ (this.#socket)
      socket.send(buf, 0, buf.length, this.#port, MDNS_ADDRESS, (err) => {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  /**
   * Register a handler for incoming mDNS response packets.
   * @param {PacketHandler} handler
   */
  addHandler(handler) {
    this.#handlers.add(handler)
  }

  /**
   * Remove a previously registered handler.
   * @param {PacketHandler} handler
   */
  removeHandler(handler) {
    this.#handlers.delete(handler)
  }

  /**
   * Close the socket and clean up.
   * @returns {Promise<void>}
   */
  async destroy() {
    this.#handlers.clear()
    return new Promise((resolve) => {
      if (this.#socket) {
        this.#socket.close(() => resolve())
        this.#socket = null
        this.#bound = false
      } else {
        resolve()
      }
    })
  }
}
