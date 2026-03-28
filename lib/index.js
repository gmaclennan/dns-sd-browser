/**
 * dns-sd-browser — Spec-compliant DNS-SD browser over mDNS for Node.js.
 *
 * Discovers services advertised via DNS-SD (RFC 6763) over Multicast DNS
 * (RFC 6762). Designed as a complementary browser to the ciao advertiser.
 *
 * @example
 * ```js
 * import { DnsSdBrowser } from 'dns-sd-browser'
 *
 * const mdns = new DnsSdBrowser()
 * const browser = mdns.browse('_http._tcp')
 *
 * for await (const event of browser) {
 *   if (event.type === 'serviceUp') {
 *     console.log(`Found: ${event.service.name} at ${event.service.host}:${event.service.port}`)
 *   }
 * }
 * ```
 *
 * @module
 */

import { MdnsTransport } from './transport.js'
import { ServiceBrowser } from './browser.js'
import { parseServiceType } from './service.js'
import { SERVICE_TYPE_ENUMERATION, DEFAULT_DOMAIN } from './constants.js'

export { ServiceBrowser } from './browser.js'

/**
 * @typedef {import('./service.js').Service} Service
 * @typedef {import('./browser.js').BrowseEvent} BrowseEvent
 */

export class DnsSdBrowser {
  /** @type {MdnsTransport} */
  #transport
  /** @type {Set<ServiceBrowser>} */
  #browsers = new Set()
  #started = false
  #destroyed = false
  /** @type {Promise<void> | null} */
  #startPromise = null
  /** @type {Error | null} */
  #startError = null

  /**
   * @param {object} [options]
   * @param {number} [options.port=5353] - mDNS port
   * @param {string} [options.interface] - Network interface IP to bind to
   */
  constructor(options = {}) {
    this.#transport = new MdnsTransport({
      port: options.port,
      interface: options.interface,
    })
  }

  /**
   * Start browsing for a specific service type.
   *
   * Returns a ServiceBrowser that is an async iterable yielding BrowseEvents
   * as services appear, disappear, or update on the network.
   *
   * @param {string | { name: string, protocol?: string }} serviceType
   *   Service type to browse for. Either a string like "_http._tcp" or
   *   an object like `{ name: 'http', protocol: 'tcp' }`.
   * @param {object} [options]
   * @param {AbortSignal} [options.signal] - Signal to cancel browsing
   * @param {string} [options.subtype] - Browse a service subtype (RFC 6763 §7.1).
   *   e.g. `browse('_http._tcp', { subtype: '_printer' })` queries
   *   `_printer._sub._http._tcp.local`.
   * @returns {ServiceBrowser}
   */
  browse(serviceType, options = {}) {
    if (this.#destroyed) {
      throw new Error('DnsSdBrowser has been destroyed')
    }

    const parsed = parseServiceType(serviceType)

    // Build subtype query name if requested (RFC 6763 §7.1)
    let queryName = parsed.queryName
    if (options.subtype) {
      const sub = options.subtype.startsWith('_') ? options.subtype : `_${options.subtype}`
      queryName = `${sub}._sub.${parsed.type}.${parsed.domain}`
    }

    this.#ensureStarted()

    const browser = new ServiceBrowser(this.#transport, {
      queryName,
      serviceType: parsed.type,
      domain: parsed.domain,
      protocol: parsed.protocol,
      signal: options.signal,
      onDestroy: () => this.#browsers.delete(browser),
    })

    this.#browsers.add(browser)
    return browser
  }

  /**
   * Browse for all service types on the network.
   *
   * Queries `_services._dns-sd._udp.local` (RFC 6763 §9) to discover
   * which service types are being advertised.
   *
   * @param {object} [options]
   * @param {AbortSignal} [options.signal]
   * @returns {ServiceBrowser}
   */
  browseAll(options = {}) {
    if (this.#destroyed) {
      throw new Error('DnsSdBrowser has been destroyed')
    }

    this.#ensureStarted()

    const browser = new ServiceBrowser(this.#transport, {
      queryName: SERVICE_TYPE_ENUMERATION,
      serviceType: '_services._dns-sd._udp',
      domain: DEFAULT_DOMAIN,
      protocol: 'udp',
      isTypeEnumeration: true,
      signal: options.signal,
      onDestroy: () => this.#browsers.delete(browser),
    })

    this.#browsers.add(browser)
    return browser
  }

  /**
   * Stop all browsers and close the mDNS transport.
   * @returns {Promise<void>}
   */
  async destroy() {
    if (this.#destroyed) return
    this.#destroyed = true

    for (const browser of this.#browsers) {
      browser.destroy()
    }
    this.#browsers.clear()

    // Wait for the transport to finish starting before closing it,
    // to avoid closing a socket that is still in the process of binding.
    if (this.#startPromise) {
      await this.#startPromise.catch(() => {})
    }

    await this.#transport.destroy()
  }

  /** @returns {Promise<void>} */
  async [Symbol.asyncDispose]() {
    return this.destroy()
  }

  /**
   * Returns a promise that resolves when the mDNS transport is ready
   * to send and receive packets. Useful for tests or when you need
   * to ensure the socket is bound before external interaction.
   *
   * Note: the transport is started lazily on the first `browse()` or
   * `browseAll()` call. Calling `ready()` before any browse will throw.
   * @returns {Promise<void>}
   */
  async ready() {
    if (!this.#startPromise) {
      throw new Error('Cannot call ready() before browse() or browseAll() — transport not started')
    }
    await this.#startPromise
    if (this.#startError) throw this.#startError
  }

  /** Start the transport if not already started. */
  #ensureStarted() {
    if (!this.#started) {
      this.#started = true
      this.#startPromise = this.#transport.start().catch((err) => {
        this.#startError = err
      })
    }
  }
}
