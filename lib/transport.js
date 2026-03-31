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
  /** @type {Set<PacketHandler>} */
  #queryHandlers = new Set()
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
      /* c8 ignore next 2 -- IPv6 start failure requires OS-level IPv6 unavailability, which is hard to replicate in tests but expected in some environments */
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

      /* c8 ignore next 5 -- IPv4 socket error requires OS-level bind failure */
      this.#socket4.on('error', (err) => {
        if (!this.#bound) {
          reject(err)
        }
        // After binding, log but don't crash (transient errors are normal)
      })

      this.#socket4.on('message', (msg, rinfo) => this.#onMessage(msg, rinfo))

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
        /* c8 ignore start -- multicast setup failure requires specific OS/interface conditions */
        } catch {
          // Multicast setup can fail on some interfaces — continue anyway.
          // The socket can still receive unicast responses.
        }
        /* c8 ignore stop */
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
        /* c8 ignore start -- hard to replicate IPv6 bind errors in tests, but they are expected in some environments */
        // IPv6 socket errors are always non-fatal — clean up and resolve/reject
        // to avoid hanging the Promise. This covers EAFNOSUPPORT (no IPv6 on host),
        // EADDRINUSE, and any other bind errors.
        if (this.#socket6) {
          try { this.#socket6.close() } catch { /* ignore */ }
          this.#socket6 = null
        }
        reject(err)
        /* c8 ignore stop */
      })

      this.#socket6.on('message', (msg, rinfo) => this.#onMessage(msg, rinfo))

      /* c8 ignore next 13 -- IPv6 bind/multicast requires IPv6 availability */
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
   * @param {import('node:dgram').RemoteInfo} rinfo
   */
  #onMessage(msg, rinfo) {
    try {
      // RFC 6762 §11: Source address check (defense-in-depth).
      // All packets received on our multicast socket are inherently local-link
      // per RFC 6762 §11 ("packets received via link-local multicast are
      // necessarily deemed to have originated on the local link"). However, we
      // reject clearly invalid source addresses as a defensive measure.
      if (rinfo.address === '0.0.0.0' || rinfo.address === '::') return

      // RFC 6762 §6: source UDP port in all mDNS traffic MUST be 5353.
      // Silently ignore packets from other ports.
      if (rinfo.port !== this.#port) return

      const packet = dns.decode(msg)
      // Ignore packets with non-zero opcode (RFC 6762 §18.3)
      if (packet.flags.opcode !== 0) return

      if (!packet.flags.qr) {
        // Query packet (QR=0) — dispatch to query handlers for
        // duplicate question suppression (RFC 6762 §7.3) and
        // Passive Observation of Failures (RFC 6762 §10.5)
        for (const handler of this.#queryHandlers) {
          try {
            handler(packet)
          /* c8 ignore start -- handler error isolation is defensive */
          } catch {
            // Isolate handler failures so one bad handler can't break others
          }
          /* c8 ignore stop */
        }
        return
      }

      // Response packet (QR=1)
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
    /* c8 ignore next 3 -- guard requires calling sendQuery before start() */
    if (!this.#socket4 || !this.#bound) {
      throw new Error('Transport not started')
    }

    // Encode into one or more packets (splits known answers if too large)
    const packets = dns.encodeQueryPackets(queryOptions)

    for (const buf of packets) {
      // Send on IPv4
      await this.#sendOn(this.#socket4, buf, MDNS_ADDRESS)

      // Also send on IPv6 if available
      /* c8 ignore next 7 -- IPv6 send path requires IPv6 socket availability */
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
   * Register a handler for incoming mDNS query packets (QR=0).
   * Used for duplicate question suppression (RFC 6762 §7.3) and
   * Passive Observation of Failures (RFC 6762 §10.5).
   * @param {PacketHandler} handler
   */
  addQueryHandler(handler) {
    this.#queryHandlers.add(handler)
  }

  /**
   * Remove a previously registered query handler.
   * @param {PacketHandler} handler
   */
  removeQueryHandler(handler) {
    this.#queryHandlers.delete(handler)
  }

  /**
   * Re-join multicast groups on existing sockets.
   *
   * Call this after a network interface change (e.g. WiFi reconnect,
   * Ethernet re-plug). The OS drops multicast group membership when an
   * interface goes down; this method re-establishes it so the socket
   * can receive multicast responses again.
   */
  rejoinMulticast() {
    if (this.#socket4) {
      try {
        const iface = this.#interface || '0.0.0.0'
        // Drop first to avoid EADDRINUSE if membership somehow survived
        try { this.#socket4.dropMembership(MDNS_ADDRESS, iface) } catch { /* ignore */ }
        this.#socket4.addMembership(MDNS_ADDRESS, iface)
        if (this.#interface) {
          this.#socket4.setMulticastInterface(this.#interface)
        }
      /* c8 ignore start -- multicast re-join failure requires OS/interface conditions */
      } catch {
        // Multicast re-join failed — interface may not be fully up yet
      }
      /* c8 ignore stop */
    }

    /* c8 ignore next 8 -- IPv6 rejoin requires IPv6 socket availability */
    if (this.#socket6) {
      try {
        try { this.#socket6.dropMembership(MDNS_ADDRESS_V6) } catch { /* ignore */ }
        this.#socket6.addMembership(MDNS_ADDRESS_V6)
      } catch {
        // IPv6 multicast re-join failed — non-fatal
      }
    }
  }

  /**
   * Close all sockets and clean up.
   * @returns {Promise<void>}
   */
  async destroy() {
    this.#handlers.clear()
    this.#queryHandlers.clear()
    const promises = []

    if (this.#socket4) {
      const s4 = this.#socket4
      this.#socket4 = null
      promises.push(/** @type {Promise<void>} */ (new Promise((resolve) => {
        s4.close(() => resolve())
      })))
    }

    /* c8 ignore next 7 -- IPv6 socket cleanup requires IPv6 availability */
    if (this.#socket6) {
      const s6 = this.#socket6
      this.#socket6 = null
      promises.push(/** @type {Promise<void>} */ (new Promise((resolve) => {
        s6.close(() => resolve())
      })))
    }

    this.#bound = false

    if (promises.length > 0) {
      await Promise.all(promises)
    }
  }
}
