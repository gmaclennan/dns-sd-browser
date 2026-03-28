/**
 * mDNS transport layer — manages the UDP multicast sockets.
 *
 * Handles binding to the mDNS port, joining/leaving multicast groups for
 * both IPv4 (224.0.0.251) and IPv6 (FF02::FB), sending queries, and
 * dispatching received packets to registered handlers.
 * Multiple ServiceBrowsers share a single transport instance via the
 * DnsSdBrowser class.
 *
 * @module
 */

import { createSocket } from 'node:dgram'
import { MDNS_ADDRESS, MDNS_ADDRESS_V6, MDNS_PORT, MDNS_TTL } from './constants.js'
import * as dns from './dns.js'

/**
 * @callback PacketHandler
 * @param {dns.DnsPacket} packet
 * @returns {void}
 */

export class MdnsTransport {
  /** @type {import('node:dgram').Socket | null} */
  #socket4 = null
  /** @type {import('node:dgram').Socket | null} */
  #socket6 = null
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
   * Start the transport: bind sockets and join multicast groups.
   * Always binds IPv4. Attempts IPv6 but does not fail if unavailable.
   * @returns {Promise<void>}
   */
  async start() {
    if (this.#bound) return

    // Always start IPv4
    await this.#startIPv4()

    // Attempt IPv6 — non-fatal if it fails (e.g. no IPv6 on the host)
    try {
      await this.#startIPv6()
    } catch {
      // IPv6 not available on this host — IPv4-only mode
    }
  }

  /**
   * Bind the IPv4 socket and join the multicast group.
   * @returns {Promise<void>}
   */
  async #startIPv4() {
    return new Promise((resolve, reject) => {
      this.#socket4 = createSocket({ type: 'udp4', reuseAddr: true })

      this.#socket4.on('error', (err) => {
        if (!this.#bound) {
          reject(err)
        }
        // After binding, log but don't crash (transient errors are normal)
      })

      this.#socket4.on('message', (msg) => this.#onMessage(msg))

      this.#socket4.bind(this.#port, () => {
        const socket = /** @type {import('node:dgram').Socket} */ (this.#socket4)
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
   * Bind the IPv6 socket and join the multicast group.
   * @returns {Promise<void>}
   */
  async #startIPv6() {
    return new Promise((resolve, reject) => {
      this.#socket6 = createSocket({ type: 'udp6', reuseAddr: true })

      this.#socket6.on('error', (err) => {
        // IPv6 socket errors are always non-fatal — clean up and resolve/reject
        // to avoid hanging the Promise. This covers EAFNOSUPPORT (no IPv6 on host),
        // EADDRINUSE, and any other bind errors.
        if (this.#socket6) {
          try { this.#socket6.close() } catch { /* ignore */ }
          this.#socket6 = null
        }
        reject(err)
      })

      this.#socket6.on('message', (msg) => this.#onMessage(msg))

      this.#socket6.bind(this.#port, () => {
        const socket = /** @type {import('node:dgram').Socket} */ (this.#socket6)
        try {
          socket.addMembership(MDNS_ADDRESS_V6)
          socket.setMulticastLoopback(true)
          socket.setMulticastTTL(MDNS_TTL)
        } catch {
          // IPv6 multicast setup failed — close the socket, fall back to IPv4 only
          socket.close()
          this.#socket6 = null
        }
        resolve()
      })
    })
  }

  /**
   * Handle an incoming message from either socket.
   * @param {Buffer} msg
   */
  #onMessage(msg) {
    try {
      const packet = dns.decode(msg)
      // Only process response packets (QR bit set)
      // mDNS queries from other hosts are not relevant to a browser
      if (!packet.flags.qr) return
      // Ignore packets with non-zero opcode (RFC 6762 §18.3)
      if (packet.flags.opcode !== 0) return
      // Note: rcode is intentionally NOT checked. RFC 6762 §18.11 says
      // receivers SHOULD silently ignore the rcode field, and some buggy
      // advertisers set non-zero rcodes in otherwise valid responses.

      for (const handler of this.#handlers) {
        handler(packet)
      }
    } catch {
      // Silently ignore malformed packets (RFC 6762 §18)
    }
  }

  /**
   * Send an mDNS query on IPv4 (and IPv6 if available).
   * @param {dns.QueryOptions} queryOptions
   * @returns {Promise<void>}
   */
  async sendQuery(queryOptions) {
    if (!this.#socket4 || !this.#bound) {
      throw new Error('Transport not started')
    }

    // Encode into one or more packets (splits known answers if too large)
    const packets = dns.encodeQueryPackets(queryOptions)

    for (const buf of packets) {
      // Send on IPv4
      await this.#sendOn(this.#socket4, buf, MDNS_ADDRESS)

      // Also send on IPv6 if available
      if (this.#socket6) {
        try {
          await this.#sendOn(this.#socket6, buf, MDNS_ADDRESS_V6)
        } catch {
          // IPv6 send failure is non-fatal
        }
      }
    }
  }

  /**
   * Send a buffer on a specific socket.
   * @param {import('node:dgram').Socket} socket
   * @param {Buffer} buf
   * @param {string} address
   * @returns {Promise<void>}
   */
  #sendOn(socket, buf, address) {
    return new Promise((resolve, reject) => {
      socket.send(buf, 0, buf.length, this.#port, address, (err) => {
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
   * Close all sockets and clean up.
   * @returns {Promise<void>}
   */
  async destroy() {
    this.#handlers.clear()
    const promises = []

    if (this.#socket4) {
      promises.push(new Promise((resolve) => {
        this.#socket4.close(() => resolve())
      }))
      this.#socket4 = null
    }

    if (this.#socket6) {
      promises.push(new Promise((resolve) => {
        this.#socket6.close(() => resolve())
      }))
      this.#socket6 = null
    }

    this.#bound = false

    if (promises.length > 0) {
      await Promise.all(promises)
    }
  }
}
