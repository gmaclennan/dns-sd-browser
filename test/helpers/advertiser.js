import { createSocket } from 'node:dgram'
import dnsPacket from 'dns-packet'

const MDNS_ADDRESS = '224.0.0.251'

/**
 * A test mDNS responder that can announce and remove services.
 * Uses the `dns-packet` package (independent of our implementation) to
 * construct spec-compliant mDNS response packets. This lets us do true
 * end-to-end tests against known-good packet encoding.
 */
export class TestAdvertiser {
  /** @type {import('node:dgram').Socket | null} */
  #socket = null
  #port
  #interface

  /**
   * @param {object} options
   * @param {number} options.port - mDNS port to use
   * @param {string} [options.interface='127.0.0.1'] - Network interface
   */
  constructor({ port, interface: iface = '127.0.0.1' }) {
    this.#port = port
    this.#interface = iface
    /** @type {dnsPacket.Packet[]} */
    this.receivedQueries = []
  }

  /** Bind socket and join multicast group. */
  async start() {
    return new Promise((resolve, reject) => {
      this.#socket = createSocket({ type: 'udp4', reuseAddr: true })
      this.#socket.on('error', reject)
      this.#socket.bind(this.#port, () => {
        const socket = /** @type {import('node:dgram').Socket} */ (this.#socket)
        socket.addMembership(MDNS_ADDRESS, this.#interface)
        socket.setMulticastLoopback(true)
        socket.setMulticastInterface(this.#interface)
        socket.setMulticastTTL(255)

        // Capture incoming queries for test assertions
        socket.on('message', (msg) => {
          try {
            const packet = dnsPacket.decode(msg)
            if (packet.type === 'query') {
              this.receivedQueries.push(packet)
            }
          } catch {
            // Ignore malformed packets
          }
        })

        socket.removeListener('error', reject)
        resolve(undefined)
      })
    })
  }

  /** Close the socket. */
  async stop() {
    return new Promise((resolve) => {
      if (this.#socket) {
        this.#socket.close(() => resolve(undefined))
        this.#socket = null
      } else {
        resolve(undefined)
      }
    })
  }

  /**
   * Send an mDNS response announcing a service.
   * Constructs a full set of DNS-SD records: PTR, SRV, TXT, and A/AAAA.
   *
   * @param {object} service
   * @param {string} service.name - Instance name (e.g. "My Web Server")
   * @param {string} service.type - Service type (e.g. "_http._tcp")
   * @param {string} [service.domain='local'] - Domain
   * @param {string} service.host - Target hostname (e.g. "myhost.local")
   * @param {number} service.port - Port number
   * @param {string[]} [service.addresses=[]] - IPv4 addresses
   * @param {string[]} [service.addressesv6=[]] - IPv6 addresses
   * @param {Record<string, string | boolean>} [service.txt={}] - TXT key-value pairs
   * @param {string[]} [service.subtypes=[]] - Service subtypes
   * @param {number} [service.ttl=4500] - Record TTL in seconds
   */
  async announce(service) {
    const {
      name,
      type,
      domain = 'local',
      host,
      port,
      addresses = [],
      addressesv6 = [],
      txt = {},
      subtypes = [],
      ttl = 4500,
    } = service

    const serviceFqdn = `${name}.${type}.${domain}`
    const serviceType = `${type}.${domain}`

    // Build TXT strings from key-value pairs
    const txtStrings = Object.entries(txt).map(([k, v]) =>
      v === true ? k : `${k}=${v}`
    )

    /** @type {dnsPacket.Answer[]} */
    const answers = [
      // PTR: _http._tcp.local -> My Service._http._tcp.local
      {
        type: 'PTR',
        name: serviceType,
        ttl,
        class: 'IN',
        data: serviceFqdn,
      },
      // SRV: My Service._http._tcp.local -> myhost.local:8080
      {
        type: 'SRV',
        name: serviceFqdn,
        ttl: 120,
        class: 'IN',
        flush: true,
        data: { target: host, port, priority: 0, weight: 0 },
      },
      // TXT: My Service._http._tcp.local -> key=value pairs
      {
        type: 'TXT',
        name: serviceFqdn,
        ttl,
        class: 'IN',
        flush: true,
        data: txtStrings.length > 0 ? txtStrings : [''],
      },
    ]

    // Subtype PTR records
    for (const subtype of subtypes) {
      answers.push({
        type: 'PTR',
        name: `${subtype}._sub.${serviceType}`,
        ttl,
        class: 'IN',
        data: serviceFqdn,
      })
    }

    /** @type {dnsPacket.Answer[]} */
    const additionals = []

    // A records for each IPv4 address
    for (const addr of addresses) {
      additionals.push({
        type: 'A',
        name: host,
        ttl: 120,
        class: 'IN',
        flush: true,
        data: addr,
      })
    }

    // AAAA records for each IPv6 address
    for (const addr of addressesv6) {
      additionals.push({
        type: 'AAAA',
        name: host,
        ttl: 120,
        class: 'IN',
        flush: true,
        data: addr,
      })
    }

    const packet = dnsPacket.encode({
      type: 'response',
      id: 0,
      // QR=1 (response), AA=1 (authoritative)
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      questions: [],
      answers,
      additionals,
    })

    await this.#send(packet)
  }

  /**
   * Send a goodbye packet (TTL=0) for a service.
   * @param {object} service
   * @param {string} service.name
   * @param {string} service.type
   * @param {string} [service.domain='local']
   * @param {string} service.host
   * @param {number} service.port
   */
  async goodbye(service) {
    const { name, type, domain = 'local', host, port } = service
    const serviceFqdn = `${name}.${type}.${domain}`
    const serviceType = `${type}.${domain}`

    const packet = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      questions: [],
      answers: [
        {
          type: 'PTR',
          name: serviceType,
          ttl: 0,
          class: 'IN',
          data: serviceFqdn,
        },
        {
          type: 'SRV',
          name: serviceFqdn,
          ttl: 0,
          class: 'IN',
          flush: true,
          data: { target: host, port, priority: 0, weight: 0 },
        },
        {
          type: 'TXT',
          name: serviceFqdn,
          ttl: 0,
          class: 'IN',
          flush: true,
          data: [''],
        },
      ],
    })

    await this.#send(packet)
  }

  /**
   * Send an updated TXT record for a service.
   * @param {object} service
   * @param {string} service.name
   * @param {string} service.type
   * @param {string} [service.domain='local']
   * @param {Record<string, string | boolean>} txt - New TXT data
   */
  async updateTxt(service, txt) {
    const { name, type, domain = 'local' } = service
    const serviceFqdn = `${name}.${type}.${domain}`

    const txtStrings = Object.entries(txt).map(([k, v]) =>
      v === true ? k : `${k}=${v}`
    )

    const packet = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      questions: [],
      answers: [
        {
          type: 'TXT',
          name: serviceFqdn,
          ttl: 4500,
          class: 'IN',
          flush: true,
          data: txtStrings.length > 0 ? txtStrings : [''],
        },
      ],
    })

    await this.#send(packet)
  }

  /**
   * Send a service type enumeration PTR record (RFC 6763 §9).
   * Announces that a given service type exists on the network.
   * @param {string} serviceType - e.g. "_http._tcp"
   * @param {string} [domain='local']
   */
  async announceServiceType(serviceType, domain = 'local') {
    const packet = dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.AUTHORITATIVE_ANSWER,
      questions: [],
      answers: [
        {
          type: 'PTR',
          name: `_services._dns-sd._udp.${domain}`,
          ttl: 4500,
          class: 'IN',
          data: `${serviceType}.${domain}`,
        },
      ],
    })
    await this.#send(packet)
  }

  /**
   * Send a raw DNS packet buffer.
   * @param {Buffer} buf
   * @returns {Promise<void>}
   */
  async sendRaw(buf) {
    return this.#send(buf)
  }

  /**
   * Wait until a query matching the predicate is received.
   * @param {(query: dnsPacket.Packet) => boolean} predicate
   * @param {number} [timeoutMs=3000]
   * @returns {Promise<dnsPacket.Packet>}
   */
  async waitForQuery(predicate, timeoutMs = 3000) {
    // Check already-received queries first
    const existing = this.receivedQueries.find(predicate)
    if (existing) return existing

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup()
        reject(new Error('Timed out waiting for matching query'))
      }, timeoutMs)

      const check = () => {
        const match = this.receivedQueries.find(predicate)
        if (match) {
          cleanup()
          resolve(match)
        }
      }

      // Poll for new queries (the socket 'message' handler pushes to receivedQueries)
      const interval = setInterval(check, 50)

      const cleanup = () => {
        clearTimeout(timer)
        clearInterval(interval)
      }
    })
  }

  /** Clear recorded queries. */
  clearQueries() {
    this.receivedQueries.length = 0
  }

  /**
   * @param {Buffer | Uint8Array} buf
   * @returns {Promise<void>}
   */
  #send(buf) {
    return new Promise((resolve, reject) => {
      if (!this.#socket) {
        reject(new Error('Advertiser not started'))
        return
      }
      this.#socket.send(buf, 0, buf.length, this.#port, MDNS_ADDRESS, (err) => {
        if (err) reject(err)
        else resolve()
      })
    })
  }
}
