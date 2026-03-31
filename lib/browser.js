/**
 * ServiceBrowser — discovers DNS-SD services via mDNS and exposes them
 * as an async iterable stream of events.
 *
 * Implements continuous querying per RFC 6762 §5.2:
 * - Sends an initial query immediately
 * - Repeats at increasing intervals (1s, 2s, 4s, …) up to 60 minutes
 * - Includes known answers for suppression (RFC 6762 §7.1)
 *
 * @module
 */

import { RecordType } from './dns.js'
import { parseTxtData, extractInstanceName } from './service.js'
import { SERVICE_TYPE_ENUMERATION } from './constants.js'

/**
 * @typedef {import('./service.js').Service} Service
 * @typedef {import('./dns.js').DnsPacket} DnsPacket
 * @typedef {import('./dns.js').DnsRecord} DnsRecord
 * @typedef {import('./transport.js').MdnsTransport} MdnsTransport
 */

/**
 * @typedef {{ type: 'serviceUp', service: Service }
 *         | { type: 'serviceDown', service: Service }
 *         | { type: 'serviceUpdated', service: Service }} BrowseEvent
 */

/**
 * Resolves a promise externally — used for the async iterator's event queue.
 * @template T
 * @typedef {object} Deferred
 * @property {Promise<T>} promise
 * @property {(value: T) => void} resolve
 * @property {(reason?: unknown) => void} reject
 */

/**
 * @template T
 * @returns {Deferred<T>}
 */
function createDeferred() {
  /** @type {(value: T) => void} */
  let resolve
  /** @type {(reason?: unknown) => void} */
  let reject
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  // @ts-ignore — assigned in Promise constructor
  return { promise, resolve, reject }
}

// Query interval schedule per RFC 6762 §5.2:
// Start at 1s, double each time, cap at 1 hour (3600s)
const QUERY_INTERVALS_MS = [
  1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 120_000, 240_000,
  480_000, 960_000, 1_920_000, 3_600_000,
]

/**
 * Maximum number of services a single browser will track.
 * Prevents memory exhaustion from an attacker flooding the multicast group
 * with unique service names (analogous to CVE-2025-59529 in Avahi).
 */
const MAX_SERVICES = 1024

/**
 * Maximum number of events buffered before the oldest are dropped.
 * Prevents memory exhaustion when events are produced faster than consumed.
 */
const MAX_EVENT_BUFFER = 4096

/**
 * Minimum TTL check delay (ms). Even if a record claims TTL=0,
 * we won't schedule a check sooner than this to avoid busy-looping.
 */
const MIN_TTL_CHECK_DELAY_MS = 1_000

/**
 * TTL refresh thresholds per RFC 6762 §5.2.
 * Queries are sent at 80%, 85%, 90%, and 95% of TTL (with 2% jitter each).
 * If no answer is received by 100%, the record is removed.
 */
const TTL_REFRESH_THRESHOLDS = [0.80, 0.85, 0.90, 0.95]

export class ServiceBrowser {
  /** @type {MdnsTransport} */
  #transport
  #queryName
  #serviceType
  #domain
  #protocol
  #destroyed = false
  /** When true, this is a service type enumeration browser (browseAll) */
  #isTypeEnumeration = false

  /**
   * Currently discovered services, keyed by FQDN.
   * @type {Map<string, Service>}
   */
  services = new Map()

  /** @type {BrowseEvent[]} - Buffered events waiting for a consumer */
  #eventBuffer = []

  /** @type {Deferred<void> | null} - Resolves when a new event is buffered */
  #eventSignal = null

  /** @type {ReturnType<typeof setTimeout> | null} */
  #queryTimer = null
  #queryIndex = 0

  /** @type {AbortSignal | undefined} */
  #signal

  /** @type {(() => void) | null} */
  #abortHandler = null

  /** Whether an async iterator is currently active (single-consumer enforcement) */
  #iterating = false

  /**
   * Timestamp of the last query we sent, used to ignore our own loopback
   * queries in duplicate question suppression (RFC 6762 §7.3).
   * @type {number}
   */
  #lastQuerySentAt = 0

  /**
   * If set, the iterator throws this instead of returning done: true,
   * matching the Node.js convention (events.on, Readable, setInterval).
   * @type {any}
   */
  #destroyReason = undefined

  /**
   * Tracks PTR records we've received, mapping service FQDN → TTL.
   * Used for known-answer suppression and TTL-based expiration.
   * @type {Map<string, { ttl: number, receivedAt: number }>}
   */
  #knownPtrRecords = new Map()

  /**
   * FQDNs we've seen via PTR but couldn't resolve (no SRV yet).
   * When a standalone SRV arrives later, we re-attempt resolution.
   * @type {Set<string>}
   */
  #pendingFqdns = new Set()

  /**
   * Pending goodbye timers, keyed by FQDN.
   * Per RFC 6762 §10.1, goodbye records (TTL=0) schedule removal after 1 second
   * rather than removing immediately, giving the advertiser a window to correct
   * an accidental goodbye.
   * @type {Map<string, ReturnType<typeof setTimeout>>}
   */
  #pendingGoodbyes = new Map()

  /**
   * Per-address receive timestamps for cache-flush grace period (RFC 6762 §10.2).
   * When cache-flush is set, records received more than 1 second ago are flushed,
   * but records received within the last 1 second are kept to allow multi-packet
   * announcement bursts.
   * @type {Map<string, Map<string, number>>} - serviceFqdn → (address → receivedAt)
   */
  #addressTimestamps = new Map()

  /** @type {ReturnType<typeof setInterval> | null} */
  #ttlCheckTimer = null

  /** @type {(() => void) | null} */
  #onDestroy = null

  /**
   * Pending reconfirmation state, keyed by FQDN (RFC 6762 §10.4).
   * Each entry holds the timers for the verification queries and
   * the final flush timeout.
   * @type {Map<string, { timers: ReturnType<typeof setTimeout>[], startedAt: number }>}
   */
  #pendingReconfirms = new Map()

  /** Timeout (ms) for reconfirmation before flushing. Default 10s per RFC 6762 §10.4. */
  #reconfirmTimeoutMs = 10_000

  /**
   * POOF state: tracks queries from other hosts that mention our cached records.
   * Per RFC 6762 §10.5, after 2+ unanswered queries within the timeout window,
   * the record should be flushed from the cache.
   * @type {Map<string, { queryCount: number, firstSeenAt: number, pendingQueries: number }>}
   */
  #poofTracking = new Map()

  /** @type {Map<string, ReturnType<typeof setTimeout>>} */
  #poofTimers = new Map()

  /** Timeout (ms) for POOF window per RFC 6762 §10.5. */
  #poofTimeoutMs = 10_000

  /** Delay (ms) to wait for a response before counting query as unanswered. */
  #poofResponseWaitMs = 2_000

  /**
   * @param {MdnsTransport} transport
   * @param {object} options
   * @param {string} options.queryName - e.g. "_http._tcp.local"
   * @param {string} options.serviceType - e.g. "_http._tcp"
   * @param {string} options.domain - e.g. "local"
   * @param {string} options.protocol - e.g. "tcp"
   * @param {boolean} [options.isTypeEnumeration] - true for browseAll
   * @param {AbortSignal} [options.signal]
   * @param {() => void} [options.onDestroy] - Called when the browser is destroyed
   * @param {number} [options.reconfirmTimeoutMs] - Reconfirmation timeout (ms), default 10000
   * @param {number} [options.poofTimeoutMs=10000] - POOF window (RFC 6762 §10.5)
   * @param {number} [options.poofResponseWaitMs=2000] - Time to wait for response before counting as unanswered
   */
  constructor(transport, { queryName, serviceType, domain, protocol, isTypeEnumeration, signal, onDestroy, reconfirmTimeoutMs, poofTimeoutMs, poofResponseWaitMs }) {
    this.#transport = transport
    this.#queryName = queryName
    this.#serviceType = serviceType
    this.#domain = domain
    this.#protocol = protocol
    this.#isTypeEnumeration = isTypeEnumeration ?? false
    this.#signal = signal
    this.#onDestroy = onDestroy ?? null
    if (reconfirmTimeoutMs !== undefined) {
      this.#reconfirmTimeoutMs = reconfirmTimeoutMs
    }
    this.#poofTimeoutMs = poofTimeoutMs ?? 10_000
    this.#poofResponseWaitMs = poofResponseWaitMs ?? 2_000

    // Start listening and querying
    this.#transport.addHandler(this.#handlePacket)
    this.#transport.addQueryHandler(this.#handleIncomingQuery)
    this.#transport.addQueryHandler(this.#handleQuery)
    this.#scheduleInitialQuery()

    // Handle AbortSignal — the abort reason is forwarded to destroy() so the
    // iterator throws it (matching Node.js convention: events.on, Readable, setInterval).
    if (signal) {
      if (signal.aborted) {
        this.destroy(signal.reason)
      } else {
        this.#abortHandler = () => this.destroy(signal.reason)
        signal.addEventListener('abort', this.#abortHandler, { once: true })
      }
    }
  }

  /**
   * Manually remove a service by FQDN, emitting a `serviceDown` event.
   *
   * Use this when your application detects that a service is unreachable
   * (e.g. via a health check) before its TTL expires. The service is removed
   * from the `services` Map and its known-answer record is cleared, so it
   * will be re-discovered if the advertiser announces it again.
   *
   * @param {string} fqdn - Fully qualified service name (e.g. "My Service._http._tcp.local")
   * @returns {boolean} true if the service was found and removed, false otherwise
   */
  removeService(fqdn) {
    if (this.#destroyed) throw new Error('Browser has been destroyed')
    if (!this.services.has(fqdn)) return false
    this.#removeService(fqdn)
    return true
  }

  /**
   * Request reconfirmation of a service record (RFC 6762 §10.4).
   * Sends verification queries and removes the service if no response
   * is received within the timeout.
   * @param {string} fqdn - The service FQDN to reconfirm
   */
  reconfirm(fqdn) {
    if (this.#destroyed) throw new Error('Browser has been destroyed')
    if (!this.services.has(fqdn)) return
    // Already reconfirming this FQDN — don't double up
    if (this.#pendingReconfirms.has(fqdn)) return

    const timers = []

    // Send first PTR query immediately
    this.#sendReconfirmQuery()

    // Send second PTR query after ~2 seconds
    timers.push(setTimeout(() => {
      this.#sendReconfirmQuery()
    }, 2_000))

    // Set flush timeout — if no fresh response within the window, remove
    timers.push(setTimeout(() => {
      this.#pendingReconfirms.delete(fqdn)
      if (this.services.has(fqdn)) {
        this.#removeService(fqdn)
      }
    }, this.#reconfirmTimeoutMs))

    this.#pendingReconfirms.set(fqdn, { timers, startedAt: Date.now() })
  }

  /**
   * Cancel a pending reconfirmation for a service (called when a fresh
   * response is received, proving the service is still alive).
   * @param {string} fqdn
   */
  #cancelReconfirm(fqdn) {
    const pending = this.#pendingReconfirms.get(fqdn)
    if (!pending) return
    for (const timer of pending.timers) {
      clearTimeout(timer)
    }
    this.#pendingReconfirms.delete(fqdn)
  }

  /**
   * Flush all discovered services and restart querying from scratch.
   *
   * Call this after a network interface change (e.g. WiFi reconnect).
   * All current services are emitted as `serviceDown` events, caches are
   * cleared, and querying restarts with the initial rapid schedule.
   */
  resetNetwork() {
    if (this.#destroyed) return

    // Emit serviceDown for all known services
    for (const service of this.services.values()) {
      this.#emit({ type: 'serviceDown', service })
    }
    this.services.clear()
    this.#knownPtrRecords.clear()
    this.#pendingFqdns.clear()
    this.#addressTimestamps.clear()

    // Cancel pending goodbyes — those services are already flushed
    /* c8 ignore next 3 -- timer cleanup requires precise timing to have pending goodbyes during resetNetwork */
    for (const timer of this.#pendingGoodbyes.values()) {
      clearTimeout(timer)
    }
    this.#pendingGoodbyes.clear()

    // Cancel pending reconfirmations — those services are already flushed
    /* c8 ignore next 5 -- timer cleanup requires precise timing to have pending reconfirms during resetNetwork */
    for (const pending of this.#pendingReconfirms.values()) {
      for (const timer of pending.timers) {
        clearTimeout(timer)
      }
    }
    this.#pendingReconfirms.clear()

    // Clear POOF tracking
    /* c8 ignore next 3 -- timer cleanup requires precise timing to have POOF timers during resetNetwork */
    for (const timer of this.#poofTimers.values()) {
      clearTimeout(timer)
    }
    this.#poofTimers.clear()
    this.#poofTracking.clear()

    // Cancel existing timers
    if (this.#queryTimer) {
      clearTimeout(this.#queryTimer)
      this.#queryTimer = null
    }
    if (this.#ttlCheckTimer) {
      clearTimeout(this.#ttlCheckTimer)
      this.#ttlCheckTimer = null
    }

    // Restart queries from the beginning (fast initial schedule)
    this.#queryIndex = 0
    this.#scheduleInitialQuery()
  }

  /**
   * Stop browsing and end the async iterator.
   * @param {any} [reason] - If provided, the iterator throws this instead of
   *   returning done: true (matching Node.js convention for AbortSignal).
   */
  destroy(reason) {
    if (this.#destroyed) return
    this.#destroyed = true
    if (reason !== undefined) this.#destroyReason = reason

    if (this.#queryTimer) {
      clearTimeout(this.#queryTimer)
      this.#queryTimer = null
    }

    if (this.#ttlCheckTimer) {
      clearTimeout(this.#ttlCheckTimer)
      this.#ttlCheckTimer = null
    }

    /* c8 ignore next 3 -- timer cleanup requires pending goodbyes at destroy time */
    for (const timer of this.#pendingGoodbyes.values()) {
      clearTimeout(timer)
    }
    this.#pendingGoodbyes.clear()

    /* c8 ignore next 5 -- timer cleanup requires pending reconfirms at destroy time */
    for (const pending of this.#pendingReconfirms.values()) {
      for (const timer of pending.timers) {
        clearTimeout(timer)
      }
    }
    this.#pendingReconfirms.clear()

    this.#transport.removeHandler(this.#handlePacket)
    this.#transport.removeQueryHandler(this.#handleIncomingQuery)
    this.#transport.removeQueryHandler(this.#handleQuery)

    // Clean up POOF tracking
    for (const timer of this.#poofTimers.values()) {
      clearTimeout(timer)
    }
    this.#poofTimers.clear()
    this.#poofTracking.clear()

    if (this.#abortHandler && this.#signal) {
      this.#signal.removeEventListener('abort', this.#abortHandler)
      this.#abortHandler = null
    }

    // Notify parent (DnsSdBrowser) so it can remove us from its set.
    // Deferred via queueMicrotask so the callback always fires after the
    // constructor returns — avoids a TDZ reference error when destroy() is
    // called synchronously during construction (e.g. pre-aborted signal).
    if (this.#onDestroy) {
      const cb = this.#onDestroy
      this.#onDestroy = null
      queueMicrotask(cb)
    }

    // Wake the iterator so it can observe #destroyed and throw.
    if (this.#eventSignal) {
      this.#eventSignal.resolve()
    }
  }

  /** @returns {Promise<void>} */
  async [Symbol.asyncDispose]() {
    this.destroy()
  }

  /** @returns {AsyncIterableIterator<BrowseEvent>} */
  [Symbol.asyncIterator]() {
    if (this.#destroyed) throw new Error('Browser has been destroyed')
    if (this.#iterating) {
      throw new Error('ServiceBrowser only supports a single concurrent async iterator')
    }
    this.#iterating = true

    /** @type {AsyncIterableIterator<BrowseEvent>} */
    const iter = {
      next: async () => {
        while (true) {
          // Return buffered events first
          if (this.#eventBuffer.length > 0) {
            const value = /** @type {BrowseEvent} */ (this.#eventBuffer.shift())
            return { value, done: false }
          }

          // If destroyed and no more buffered events, end iteration.
          if (this.#destroyed) {
            this.#iterating = false
            throw this.#destroyReason ?? new Error('Browser has been destroyed')
          }

          // Wait for the next event.
          // If destroyed via abort while waiting, the deferred is rejected
          // and the throw propagates to the for-await consumer.
          this.#eventSignal = createDeferred()
          await this.#eventSignal.promise
          this.#eventSignal = null
        }
      },

      /* c8 ignore next 4 -- iterator return() is called by for-await-of break, timing-dependent */
      return: async () => {
        this.#iterating = false
        this.destroy()
        return { value: undefined, done: true }
      },

      [Symbol.asyncIterator]() { return iter },
    }
    return iter
  }

  // ─── Private methods ───────────────────────────────────────────────

  /**
   * Handle an incoming mDNS query packet (QR=0) for POOF.
   * Per RFC 6762 §10.5: if we see queries for which our cached records
   * would be expected to answer, but no answer is seen, the records
   * should be flushed after 2+ unanswered queries within the timeout window.
   * Arrow function to preserve `this` when used as a callback.
   * @type {(packet: DnsPacket) => void}
   */
  #handleQuery = (packet) => {
    if (this.#destroyed) return

    // Ignore our own queries that loop back via multicast (same guard
    // as #handleIncomingQuery uses for duplicate question suppression).
    if (Date.now() - this.#lastQuerySentAt < 100) return

    // Only interested in QM (multicast) queries for our service type.
    // QU queries may receive unicast responses we can't observe, so
    // counting them as unanswered would cause false POOF flushes.
    const questions = packet.questions || []
    const isRelevant = questions.some(
      (q) =>
        !q.qu &&
        q.name.toLowerCase() === this.#queryName.toLowerCase() &&
        q.type === RecordType.PTR
    )
    if (!isRelevant) return

    // For each cached service FQDN, track the query and start/extend a
    // response-wait timer. Multiple queries within the wait window are
    // all counted when the timer fires.
    const now = Date.now()
    for (const fqdn of this.#knownPtrRecords.keys()) {
      // Initialize or refresh tracking for this FQDN
      let tracking = this.#poofTracking.get(fqdn)
      if (!tracking || (now - tracking.firstSeenAt) > this.#poofTimeoutMs) {
        tracking = { queryCount: 0, firstSeenAt: now, pendingQueries: 0 }
        this.#poofTracking.set(fqdn, tracking)
      }
      tracking.pendingQueries = (tracking.pendingQueries || 0) + 1

      // If a response-wait timer is already running, it will handle
      // the accumulated pending queries when it fires
      if (this.#poofTimers.has(fqdn)) continue

      // Capture query observation time for window checks (not the timer
      // fire time, which includes the response-wait delay and could cause
      // the window to appear expired when it isn't).
      const queryObservedAt = now
      const timer = setTimeout(() => {
        this.#poofTimers.delete(fqdn)
        const current = this.#poofTracking.get(fqdn)
        if (!current || !current.pendingQueries) return

        // If tracking window expired, start fresh with pending queries
        /* c8 ignore next 4 -- requires POOF window expiry timing */
        if (queryObservedAt - current.firstSeenAt > this.#poofTimeoutMs) {
          current.queryCount = current.pendingQueries
          current.firstSeenAt = queryObservedAt
        } else {
          current.queryCount += current.pendingQueries
        }
        current.pendingQueries = 0

        // After 2+ unanswered queries within the window, flush the record
        if (current.queryCount >= 2 && (queryObservedAt - current.firstSeenAt) <= this.#poofTimeoutMs) {
          this.#removeService(fqdn)
        }
      }, this.#poofResponseWaitMs)

      this.#poofTimers.set(fqdn, timer)
    }
  }

  /**
   * Clear POOF tracking for a service FQDN when a valid response is observed.
   * @param {string} serviceFqdn
   */
  #clearPoofTracking(serviceFqdn) {
    this.#poofTracking.delete(serviceFqdn)
    const timer = this.#poofTimers.get(serviceFqdn)
    if (timer) {
      clearTimeout(timer)
      this.#poofTimers.delete(serviceFqdn)
    }
  }

  /** Send the initial query after a short random delay (RFC 6762 §5.2). */
  #scheduleInitialQuery() {
    // Random delay 20-120ms to avoid thundering herd (RFC 6762 §5.2)
    const jitter = 20 + Math.random() * 100
    this.#queryTimer = setTimeout(() => {
      this.#sendQuery()
      this.#queryIndex++
      this.#scheduleNextQuery()
    }, jitter)
  }

  /** Schedule the next query with exponential backoff. */
  #scheduleNextQuery() {
    if (this.#destroyed) return

    const intervalIndex = Math.min(this.#queryIndex, QUERY_INTERVALS_MS.length - 1)
    // Add 2% random jitter per RFC 6762 §5.2
    const baseInterval = QUERY_INTERVALS_MS[intervalIndex]
    const jitter = baseInterval * 0.02 * Math.random()
    const delay = baseInterval + jitter

    this.#queryTimer = setTimeout(() => {
      this.#sendQuery()
      this.#queryIndex++
      this.#scheduleNextQuery()
    }, delay)
  }

  /**
   * Cancel the current query timer and reschedule the next query.
   * Used by duplicate question suppression (RFC 6762 §7.3) to treat
   * another host's matching query as if we had sent our own.
   */
  #rescheduleQuery() {
    if (this.#destroyed) return
    if (this.#queryTimer) {
      clearTimeout(this.#queryTimer)
      this.#queryTimer = null
    }
    // Advance the query schedule as if we had just sent a query ourselves
    this.#queryIndex++
    this.#scheduleNextQuery()
  }

  /**
   * Handle an incoming mDNS query packet for duplicate question suppression.
   * Per RFC 6762 §7.3, if another host sends a QM query matching ours and
   * their Known-Answer section covers all the records we would include,
   * we suppress our next scheduled query.
   * Arrow function to preserve `this` when used as a callback.
   * @type {(packet: DnsPacket) => void}
   */
  #handleIncomingQuery = (packet) => {
    if (this.#destroyed) return

    // Only suppress during QM phase (after initial QU query has been sent)
    if (this.#queryIndex <= 0) return

    // Ignore our own queries that loop back via multicast.
    // If we sent a query very recently (<100ms), this is likely our own loopback.
    if (Date.now() - this.#lastQuerySentAt < 100) return

    // Check if any QM (multicast) question matches our query.
    // RFC 6762 §7.3 applies only to QM questions, not QU questions.
    const hasMatchingQuestion = packet.questions.some(
      (q) =>
        q.type === RecordType.PTR &&
        q.name.toLowerCase() === this.#queryName.toLowerCase() &&
        !q.qu
    )
    if (!hasMatchingQuestion) return

    // Check if their known answers cover ours. Use the same TTL>50% filter
    // as #sendQuery() so suppression decisions match what we'd actually send
    // (RFC 6762 §7.1).
    const theirAnswers = new Set(
      (packet.answers || [])
        .filter(
          (a) =>
            a.type === RecordType.PTR &&
            typeof a.name === 'string' &&
            a.name.toLowerCase() === this.#queryName.toLowerCase() &&
            typeof a.data === 'string'
        )
        .map((a) => /** @type {string} */ (a.data).toLowerCase())
    )

    const now = Date.now()
    const ourKnownAnswers = []
    for (const [fqdn, info] of this.#knownPtrRecords) {
      const elapsed = (now - info.receivedAt) / 1000
      const remaining = info.ttl - elapsed
      if (remaining > info.ttl / 2) {
        ourKnownAnswers.push(fqdn.toLowerCase())
      }
    }

    const allCovered = ourKnownAnswers.every((fqdn) => theirAnswers.has(fqdn))

    if (allCovered) {
      // Suppress our next query — treat as if we just sent it
      this.#rescheduleQuery()
    }
  }

  /** Send an mDNS PTR query, including known answers for suppression. */
  async #sendQuery() {
    if (this.#destroyed) return

    /** @type {import('./dns.js').DnsRecord[]} */
    const knownAnswers = []

    // Include known PTR records whose TTL is still >50% remaining
    const now = Date.now()
    for (const [fqdn, info] of this.#knownPtrRecords) {
      const elapsed = (now - info.receivedAt) / 1000
      const remaining = info.ttl - elapsed
      // Only include if remaining TTL > 50% of original (RFC 6762 §7.1)
      if (remaining > info.ttl / 2) {
        knownAnswers.push({
          name: this.#queryName,
          type: RecordType.PTR,
          class: 1,
          cacheFlush: false,
          ttl: Math.round(remaining),
          data: fqdn,
        })
      }
    }

    // Set QU (unicast-response) bit on the first query (RFC 6762 §5.4).
    // This allows responders to reply via unicast, reducing multicast traffic.
    const qu = this.#queryIndex === 0

    try {
      // Set timestamp before sending so the loopback guard in
      // #handleIncomingQuery filters out our own multicast query even if
      // it loops back before the await resolves.
      this.#lastQuerySentAt = Date.now()
      await this.#transport.sendQuery({
        questions: [{ name: this.#queryName, type: RecordType.PTR, qu }],
        answers: knownAnswers,
      })
    /* c8 ignore start -- non-fatal catch requires network send failure */
    } catch {
      // Query send failures are non-fatal — we'll retry on the next interval
    }
    /* c8 ignore stop */
  }

  /**
   * Send a PTR query for reconfirmation (RFC 6762 §10.4).
   * Does not include known answers — we want the responder to re-announce.
   */
  async #sendReconfirmQuery() {
    if (this.#destroyed) return
    try {
      this.#lastQuerySentAt = Date.now()
      await this.#transport.sendQuery({
        questions: [{ name: this.#queryName, type: RecordType.PTR, qu: false }],
      })
    /* c8 ignore start -- non-fatal catch requires network send failure */
    } catch {
      // Non-fatal — we'll retry
    }
    /* c8 ignore stop */
  }

  /**
   * Re-send the query with the QU bit set after receiving a truncated response.
   * This allows the responder to reply via unicast with the full record set
   * (RFC 6762 §18.5).
   */
  async #sendTruncatedRetry() {
    try {
      await this.#transport.sendQuery({
        questions: [{ name: this.#queryName, type: RecordType.PTR, qu: true }],
      })
    /* c8 ignore start -- non-fatal catch requires network send failure */
    } catch {
      // Non-fatal — the normal query schedule will retry
    }
    /* c8 ignore stop */
  }

  /**
   * Schedule a TTL expiration check at the time the soonest record expires.
   * Called whenever the set of known PTR records changes (new record added
   * or record removed). This is more efficient and responsive than a fixed
   * interval — it only wakes when a record actually needs to expire, and
   * services are removed within ~1 second of their TTL expiring.
   */
  #scheduleTtlCheck() {
    if (this.#destroyed) return

    // Cancel any existing scheduled check
    if (this.#ttlCheckTimer) {
      clearTimeout(this.#ttlCheckTimer)
      this.#ttlCheckTimer = null
    }

    if (this.#knownPtrRecords.size === 0) return

    // Find the soonest event: a refresh query at 80/85/90/95% TTL or expiry at 100%.
    // Per RFC 6762 §5.2, queries are sent at 80%, 85%, 90%, 95% of TTL with 2% jitter.
    const now = Date.now()
    let soonestDelay = Infinity

    for (const info of this.#knownPtrRecords.values()) {
      const ttlMs = info.ttl * 1000
      const expiresAt = info.receivedAt + ttlMs
      const expiryDelay = expiresAt - now

      // Find the next refresh threshold this record hasn't passed yet
      let nextEvent = expiryDelay
      for (const threshold of TTL_REFRESH_THRESHOLDS) {
        const refreshAt = info.receivedAt + ttlMs * threshold
        const refreshDelay = refreshAt - now
        if (refreshDelay > 0) {
          nextEvent = refreshDelay
          break
        }
      }

      if (nextEvent < soonestDelay) {
        soonestDelay = nextEvent
      }
    }

    // Clamp to at least MIN_TTL_CHECK_DELAY_MS to avoid busy-looping
    const delay = Math.max(soonestDelay, MIN_TTL_CHECK_DELAY_MS)

    this.#ttlCheckTimer = setTimeout(() => {
      this.#ttlCheckTimer = null
      this.#processRecordLifecycle()
    }, delay)
  }

  /**
   * Process record lifecycle: send refresh queries for records approaching
   * expiry (80/85/90/95% of TTL per RFC 6762 §5.2), and remove expired records.
   * Then reschedule for the next event.
   */
  #processRecordLifecycle() {
    if (this.#destroyed) return

    const now = Date.now()
    let needsRefresh = false

    for (const [fqdn, info] of this.#knownPtrRecords) {
      const elapsed = (now - info.receivedAt) / 1000
      const fraction = elapsed / info.ttl

      if (fraction >= 1) {
        // TTL fully expired — remove the service
        this.#removeService(fqdn)
      } else if (fraction >= TTL_REFRESH_THRESHOLDS[0]) {
        // Between 80-100% of TTL — need a refresh query (RFC 6762 §5.2)
        needsRefresh = true
      }
    }

    // Send a single refresh query for all records approaching expiry.
    // The normal PTR query will prompt the advertiser to re-announce.
    if (needsRefresh) {
      this.#sendQuery()
    }

    // Reschedule for the next soonest event (if any records remain)
    this.#scheduleTtlCheck()
  }

  /**
   * Handle an incoming mDNS response packet.
   * Arrow function to preserve `this` when used as a callback.
   * @type {(packet: DnsPacket) => void}
   */
  #handlePacket = (packet) => {
    if (this.#destroyed) return

    // If the response is truncated (TC bit), re-query with QU bit to get
    // the full response via unicast (RFC 6762 §18.5).
    if (packet.flags.tc) {
      this.#sendTruncatedRetry()
    }

    // Merge all record sections — answers and additionals always contain
    // relevant records, and some implementations also place records in the
    // authority section. Including all three is safe and maximizes
    // interoperability with non-standard advertisers.
    const allRecords = [...packet.answers, ...packet.authorities, ...packet.additionals]

    // First pass: find PTR records pointing to service instances
    for (const record of allRecords) {
      if (record.type !== RecordType.PTR) continue
      if (!this.#isRelevantPtrRecord(record)) continue

      const serviceFqdn = /** @type {string} */ (record.data)

      if (record.ttl === 0) {
        // Goodbye packet — schedule removal after 1 second (RFC 6762 §10.1)
        this.#scheduleGoodbye(serviceFqdn)
        continue
      }

      // A re-announcement cancels any pending goodbye for this service
      this.#cancelGoodbye(serviceFqdn)

      // Clear POOF tracking — we got a response for this record (RFC 6762 §10.5)
      this.#clearPoofTracking(serviceFqdn)

      // A fresh response cancels any pending reconfirmation (RFC 6762 §10.4)
      this.#cancelReconfirm(serviceFqdn)

      // Track for known-answer suppression (bounded by MAX_SERVICES)
      if (this.#knownPtrRecords.size < MAX_SERVICES || this.#knownPtrRecords.has(serviceFqdn)) {
        this.#knownPtrRecords.set(serviceFqdn, {
          ttl: record.ttl,
          receivedAt: Date.now(),
        })
        this.#scheduleTtlCheck()
      }

      // Look for SRV, TXT, A, AAAA records for this instance
      this.#resolveService(serviceFqdn, allRecords)
    }

    // Also handle standalone SRV/TXT/A/AAAA updates for already-known services.
    // Note: if #resolveService already processed a TXT/address update above (via PTR path),
    // the service in the map is already updated, so #handleRecordUpdates will see no diff
    // and will not double-emit a serviceUpdated event.
    this.#handleRecordUpdates(allRecords)

    // Populate subtypes from subtype PTR records (RFC 6763 §7.1).
    // These have the form _subtype._sub._type._proto.domain → instance FQDN.
    this.#handleSubtypeRecords(allRecords)
  }

  /**
   * Check if a PTR record is relevant to this browser.
   * @param {DnsRecord} record
   * @returns {boolean}
   */
  #isRelevantPtrRecord(record) {
    const name = record.name.toLowerCase()
    const queryName = this.#queryName.toLowerCase()
    return name === queryName
  }

  /**
   * Build or update a service from a set of records.
   * @param {string} serviceFqdn - e.g. "My Service._http._tcp.local"
   * @param {DnsRecord[]} records
   */
  #resolveService(serviceFqdn, records) {
    const existing = this.services.get(serviceFqdn)

    // Guard against resource exhaustion: cap the number of tracked services.
    // An attacker could flood the network with unique service names.
    if (!existing && this.services.size >= MAX_SERVICES) {
      return
    }

    // Find SRV record for this service (DNS names are case-insensitive per RFC 1035 §3.1)
    const fqdnLower = serviceFqdn.toLowerCase()
    const srvRecord = records.find(
      (r) => r.type === RecordType.SRV && r.name.toLowerCase() === fqdnLower
    )

    // Find TXT record for this service
    const txtRecord = records.find(
      (r) => r.type === RecordType.TXT && r.name.toLowerCase() === fqdnLower
    )

    if (!srvRecord && !existing) {
      if (this.#isTypeEnumeration) {
        // Service type enumeration: PTR data is a service type, not an instance.
        // No SRV/TXT/A records are expected — emit immediately.
        const service = /** @type {Service} */ ({
          name: serviceFqdn,
          type: serviceFqdn,
          protocol: '',
          domain: this.#domain,
          host: '',
          port: 0,
          addresses: [],
          txt: {},
          txtRaw: {},
          fqdn: serviceFqdn,
          subtypes: [],
          updatedAt: Date.now(),
        })
        this.services.set(serviceFqdn, service)
        this.#emit({ type: 'serviceUp', service })
        return
      }
      // Can't resolve without SRV — track as pending for when SRV arrives
      // in a separate packet (common with split responses from some advertisers)
      this.#pendingFqdns.add(serviceFqdn)
      return
    }

    const srvData = srvRecord
      ? /** @type {import('./dns.js').SrvData} */ (srvRecord.data)
      : existing
        ? { target: existing.host, port: existing.port, priority: 0, weight: 0 }
        : null

    if (!srvData) return

    // Parse TXT data
    const txtData = txtRecord
      ? /** @type {Uint8Array[]} */ (txtRecord.data)
      : []
    const { txt, txtRaw } = parseTxtData(txtData)

    // Find A/AAAA records for the target host.
    // If any address record has the cache-flush bit set (RFC 6762 §10.2),
    // the new addresses replace rather than merge with existing ones.
    const targetHost = srvData.target
    const { addresses, cacheFlush: addrFlush } = this.#collectAddresses(targetHost, records)

    // RFC 6762 §10.2: cache-flush bit means the sender is asserting this is the
    // complete set of records — old cached addresses received more than 1 second
    // ago should be flushed, but addresses received within the last 1 second are
    // kept to allow multi-packet announcement bursts.
    /* c8 ignore next 5 -- merging old addresses without flush requires multi-response scenario */
    if (existing && !addrFlush) {
      for (const addr of existing.addresses) {
        if (!addresses.includes(addr)) {
          addresses.push(addr)
        }
      }
    } else if (existing && addrFlush) {
      const now = Date.now()
      const addrTimestamps = this.#addressTimestamps.get(serviceFqdn)
      if (addrTimestamps) {
        for (const addr of existing.addresses) {
          if (addresses.includes(addr)) continue
          const receivedAt = addrTimestamps.get(addr)
          // Keep addresses received within the last 1 second (grace period)
          if (receivedAt !== undefined && (now - receivedAt) <= 1000) {
            addresses.push(addr)
          }
        }
      }
    }

    // Update per-address timestamps
    this.#updateAddressTimestamps(serviceFqdn, addresses)

    const instanceName = extractInstanceName(serviceFqdn, `${this.#serviceType}.${this.#domain}`)

    /** @type {Service} */
    const service = {
      name: instanceName,
      type: this.#serviceType,
      protocol: this.#protocol,
      domain: this.#domain,
      host: targetHost,
      port: srvData.port,
      addresses,
      txt: existing && !txtRecord ? existing.txt : txt,
      txtRaw: existing && !txtRecord ? existing.txtRaw : txtRaw,
      fqdn: serviceFqdn,
      subtypes: existing?.subtypes ?? [],
      updatedAt: Date.now(),
    }

    if (existing) {
      // Check if anything actually changed
      const txtChanged = txtRecord && !txtEqual(existing.txt, service.txt)
      const addrChanged = !arrayEqual(existing.addresses, service.addresses)
      const hostChanged = existing.host !== service.host
      const portChanged = existing.port !== service.port

      if (txtChanged || addrChanged || hostChanged || portChanged) {
        this.services.set(serviceFqdn, service)
        this.#emit({ type: 'serviceUpdated', service })
      }
      // If nothing changed, don't emit (duplicate suppression)
    } else {
      this.#pendingFqdns.delete(serviceFqdn)
      this.services.set(serviceFqdn, service)
      this.#emit({ type: 'serviceUp', service })
    }
  }

  /**
   * Handle updates to records for already-known services.
   * This catches TXT updates and address changes that arrive without PTR records.
   * @param {DnsRecord[]} records
   */
  #handleRecordUpdates(records) {
    for (const [fqdn, service] of this.services) {
      // Check for TXT updates (DNS names are case-insensitive per RFC 1035 §3.1)
      const fqdnLower = fqdn.toLowerCase()
      const txtRecord = records.find(
        (r) => r.type === RecordType.TXT && r.name.toLowerCase() === fqdnLower
      )
      if (txtRecord) {
        const txtData = /** @type {Uint8Array[]} */ (txtRecord.data)
        const { txt, txtRaw } = parseTxtData(txtData)

        if (txtRecord.ttl === 0) {
          // TXT goodbye — unusual but handle it
          continue
        }

        if (!txtEqual(service.txt, txt)) {
          const updatedService = { ...service, txt, txtRaw, updatedAt: Date.now() }
          this.services.set(fqdn, updatedService)
          this.#emit({ type: 'serviceUpdated', service: updatedService })
        }
      }

      // Check for address updates.
      // Cache-flush bit (RFC 6762 §10.2) means flush addresses received more than
      // 1 second ago, but keep those within the grace period.
      const { addresses: newAddresses, cacheFlush: addrFlush } = this.#collectAddresses(service.host, records)
      if (newAddresses.length > 0) {
        let finalAddresses
        if (addrFlush) {
          finalAddresses = [...newAddresses]
          const now = Date.now()
          const addrTimestamps = this.#addressTimestamps.get(fqdn)
          if (addrTimestamps) {
            for (const addr of service.addresses) {
              if (finalAddresses.includes(addr)) continue
              const receivedAt = addrTimestamps.get(addr)
              if (receivedAt !== undefined && (now - receivedAt) <= 1000) {
                finalAddresses.push(addr)
              }
            }
          }
        } else {
          finalAddresses = [...new Set([...service.addresses, ...newAddresses])]
        }
        if (!arrayEqual(service.addresses, finalAddresses)) {
          this.#updateAddressTimestamps(fqdn, finalAddresses)
          const updatedService = { ...service, addresses: finalAddresses, updatedAt: Date.now() }
          this.services.set(fqdn, updatedService)
          this.#emit({ type: 'serviceUpdated', service: updatedService })
        }
      }

      // Check for SRV goodbye
      const srvRecord = records.find(
        (r) => r.type === RecordType.SRV && r.name.toLowerCase() === fqdnLower && r.ttl === 0
      )
      if (srvRecord) {
        this.#scheduleGoodbye(fqdn)
      }
    }

    // Check for SRV records that resolve previously-pending FQDNs.
    // This handles split responses where PTR arrived in one packet and
    // SRV arrives later in a separate packet without a PTR re-announcement.
    if (this.#pendingFqdns.size > 0) {
      for (const record of records) {
        if (record.type !== RecordType.SRV) continue
        const srvNameLower = record.name.toLowerCase()
        for (const fqdn of this.#pendingFqdns) {
          if (fqdn.toLowerCase() === srvNameLower) {
            this.#resolveService(fqdn, records)
            break
          }
        }
      }
    }
  }

  /**
   * Extract subtypes from subtype PTR records and add them to known services.
   * Subtype PTR records have the form: _subtype._sub._type._proto.domain → instance FQDN.
   * @param {DnsRecord[]} records
   */
  #handleSubtypeRecords(records) {
    for (const record of records) {
      if (record.type !== RecordType.PTR) continue
      const nameLower = record.name.toLowerCase()

      // Check for _sub. pattern in the PTR name
      const subIdx = nameLower.indexOf('._sub.')
      if (subIdx === -1) continue

      const subtype = record.name.slice(0, subIdx)
      const serviceFqdn = /** @type {string} */ (record.data)
      const service = this.services.get(serviceFqdn)
      if (service && !service.subtypes.includes(subtype)) {
        const updatedService = {
          ...service,
          subtypes: [...service.subtypes, subtype],
          updatedAt: Date.now(),
        }
        this.services.set(serviceFqdn, updatedService)
        this.#emit({ type: 'serviceUpdated', service: updatedService })
      }
    }
  }

  /**
   * Collect A and AAAA addresses for a hostname from a set of records.
   * Also reports whether any address record had the cache-flush bit set
   * (RFC 6762 §10.2), which means the sender is asserting these are the
   * complete set and old cached addresses should be replaced, not merged.
   * @param {string} hostname
   * @param {DnsRecord[]} records
   * @returns {{ addresses: string[], cacheFlush: boolean }}
   */
  #collectAddresses(hostname, records) {
    /** @type {string[]} */
    const addresses = []
    const hostLower = hostname.toLowerCase()
    let cacheFlush = false
    for (const record of records) {
      if (record.name.toLowerCase() !== hostLower) continue
      if (record.type === RecordType.A || record.type === RecordType.AAAA) {
        const addr = /** @type {string} */ (record.data)
        if (!addresses.includes(addr)) {
          addresses.push(addr)
        }
        if (record.cacheFlush) cacheFlush = true
      }
    }
    return { addresses, cacheFlush }
  }

  /**
   * Schedule a service for removal after 1 second (RFC 6762 §10.1).
   * If a re-announcement arrives within that window, the goodbye is cancelled.
   * @param {string} serviceFqdn
   */
  #scheduleGoodbye(serviceFqdn) {
    // Don't schedule if already pending or service doesn't exist
    if (this.#pendingGoodbyes.has(serviceFqdn)) return
    if (!this.services.has(serviceFqdn)) return

    const timer = setTimeout(() => {
      this.#pendingGoodbyes.delete(serviceFqdn)
      this.#removeService(serviceFqdn)
    }, 1000)

    this.#pendingGoodbyes.set(serviceFqdn, timer)
  }

  /**
   * Cancel a pending goodbye for a service (e.g. when a re-announcement arrives).
   * @param {string} serviceFqdn
   */
  #cancelGoodbye(serviceFqdn) {
    const timer = this.#pendingGoodbyes.get(serviceFqdn)
    if (timer) {
      clearTimeout(timer)
      this.#pendingGoodbyes.delete(serviceFqdn)
    }
  }

  /**
   * Update per-address receive timestamps for a service.
   * New addresses get the current time; existing timestamps are preserved.
   * @param {string} serviceFqdn
   * @param {string[]} addresses
   */
  #updateAddressTimestamps(serviceFqdn, addresses) {
    const now = Date.now()
    let addrTimestamps = this.#addressTimestamps.get(serviceFqdn)
    if (!addrTimestamps) {
      addrTimestamps = new Map()
      this.#addressTimestamps.set(serviceFqdn, addrTimestamps)
    }
    for (const addr of addresses) {
      if (!addrTimestamps.has(addr)) {
        addrTimestamps.set(addr, now)
      }
    }
    // Remove timestamps for addresses no longer present
    for (const addr of addrTimestamps.keys()) {
      if (!addresses.includes(addr)) {
        addrTimestamps.delete(addr)
      }
    }
  }

  /**
   * Remove a service and emit serviceDown.
   * @param {string} serviceFqdn
   */
  #removeService(serviceFqdn) {
    this.#cancelGoodbye(serviceFqdn)
    this.#cancelReconfirm(serviceFqdn)
    this.#clearPoofTracking(serviceFqdn)
    // Always clean up tracking state, even for unresolved (pending) services.
    // Without this, expired PTR records for services that never received an SRV
    // would stay in #knownPtrRecords/#pendingFqdns and cause repeated failed
    // removal attempts from #processRecordLifecycle.
    this.#knownPtrRecords.delete(serviceFqdn)
    this.#pendingFqdns.delete(serviceFqdn)
    const service = this.services.get(serviceFqdn)
    if (service) {
      this.services.delete(serviceFqdn)
      this.#addressTimestamps.delete(serviceFqdn)
      this.#emit({ type: 'serviceDown', service })
    }
  }

  /**
   * Push an event to the buffer and wake any waiting consumer.
   * @param {BrowseEvent} event
   */
  #emit(event) {
    // Cap event buffer to prevent memory exhaustion when events aren't consumed
    /* c8 ignore next 3 -- overflow guard requires 1000+ unconsumed events */
    if (this.#eventBuffer.length >= MAX_EVENT_BUFFER) {
      this.#eventBuffer.shift()
    }
    this.#eventBuffer.push(event)
    if (this.#eventSignal) {
      this.#eventSignal.resolve()
    }
  }
}

/**
 * Shallow-compare two TXT objects.
 * @param {Record<string, string | true>} a
 * @param {Record<string, string | true>} b
 * @returns {boolean}
 */
function txtEqual(a, b) {
  const keysA = Object.keys(a)
  const keysB = Object.keys(b)
  if (keysA.length !== keysB.length) return false
  return keysA.every((k) => a[k] === b[k])
}

/**
 * Compare two string arrays (order-sensitive).
 * @param {string[]} a
 * @param {string[]} b
 * @returns {boolean}
 */
function arrayEqual(a, b) {
  if (a.length !== b.length) return false
  return a.every((v, i) => v === b[i])
}

// ─── AllServiceBrowser ─────────────────────────────────────────────────

/**
 * Maximum number of buffered events for AllServiceBrowser.
 */
const MAX_ALL_EVENT_BUFFER = 4096

/**
 * AllServiceBrowser — discovers all service instances on the network by
 * first enumerating service types (RFC 6763 §9), then spawning a
 * ServiceBrowser for each discovered type.
 *
 * Presents the same async iterable interface as ServiceBrowser, yielding
 * fully resolved BrowseEvents with real host, port, and addresses.
 */
export class AllServiceBrowser {
  /** @type {MdnsTransport} */
  #transport
  #domain
  #destroyed = false

  /**
   * The internal type enumeration browser.
   * @type {ServiceBrowser | null}
   */
  #typeBrowser = null

  /**
   * Sub-browsers for each discovered service type, keyed by type string
   * (e.g. "_http._tcp.local").
   * @type {Map<string, ServiceBrowser>}
   */
  #typeBrowsers = new Map()

  /**
   * Merged live map of all discovered service instances across all types.
   * @type {Map<string, Service>}
   */
  services = new Map()

  /** @type {BrowseEvent[]} */
  #eventBuffer = []
  /** @type {Deferred<void> | null} */
  #eventSignal = null
  /** @type {boolean} */
  #iterating = false

  /** @type {AbortSignal | undefined} */
  #signal
  /** @type {(() => void) | null} */
  #abortHandler = null
  /**
   * If set, the iterator throws this instead of returning done: true,
   * matching the Node.js convention (events.on, Readable, setInterval).
   * @type {any}
   */
  #destroyReason = undefined
  /** @type {(() => void) | null} */
  #onDestroy = null

  /**
   * @param {MdnsTransport} transport
   * @param {object} options
   * @param {string} options.domain
   * @param {AbortSignal} [options.signal]
   * @param {() => void} [options.onDestroy]
   */
  constructor(transport, { domain, signal, onDestroy }) {
    this.#transport = transport
    this.#domain = domain
    this.#signal = signal
    this.#onDestroy = onDestroy ?? null

    // Start the type enumeration browser
    this.#typeBrowser = new ServiceBrowser(transport, {
      queryName: SERVICE_TYPE_ENUMERATION,
      serviceType: '_services._dns-sd._udp',
      domain,
      protocol: 'udp',
      isTypeEnumeration: true,
    })

    // Consume type events in the background
    this.#consumeTypes()

    // Handle AbortSignal — the abort reason is forwarded to destroy() so the
    // iterator throws it (matching Node.js convention: events.on, Readable, setInterval).
    if (signal) {
      if (signal.aborted) {
        this.destroy(signal.reason)
      } else {
        this.#abortHandler = () => this.destroy(signal.reason)
        signal.addEventListener('abort', this.#abortHandler, { once: true })
      }
    }
  }

  /**
   * Get the first discovered service. Resolves as soon as any service
   * instance emits a serviceUp event.
   * @returns {Promise<Service>}
   */
  async first() {
    for await (const event of this) {
      if (event.type === 'serviceUp') {
        return event.service
      }
    }
    /* c8 ignore next -- only reachable if destroyed before any serviceUp event */
    throw new Error('Browser destroyed before finding a service')
  }

  /**
   * Flush all discovered services and restart querying from scratch.
   *
   * Call this after a network interface change (e.g. WiFi reconnect).
   * Delegates to each internal ServiceBrowser and clears the merged
   * services map.
   */
  /* c8 ignore next 11 -- AllServiceBrowser.resetNetwork requires active type browsers */
  resetNetwork() {
    if (this.#destroyed) return

    if (this.#typeBrowser) {
      this.#typeBrowser.resetNetwork()
    }
    for (const browser of this.#typeBrowsers.values()) {
      browser.resetNetwork()
    }
    this.services.clear()
  }

  /**
   * Stop all sub-browsers and end the async iterator.
   * @param {any} [reason] - If provided, the iterator throws this instead of
   *   returning done: true (matching Node.js convention for AbortSignal).
   */
  destroy(reason) {
    if (this.#destroyed) return
    this.#destroyed = true
    if (reason !== undefined) this.#destroyReason = reason

    // Destroy the type enumeration browser
    if (this.#typeBrowser) {
      this.#typeBrowser.destroy()
      this.#typeBrowser = null
    }

    // Destroy all sub-browsers
    for (const browser of this.#typeBrowsers.values()) {
      browser.destroy()
    }
    this.#typeBrowsers.clear()

    /* c8 ignore next 4 -- abort handler cleanup mirrors ServiceBrowser */
    if (this.#abortHandler && this.#signal) {
      this.#signal.removeEventListener('abort', this.#abortHandler)
      this.#abortHandler = null
    }

    // Notify parent — deferred via queueMicrotask (see ServiceBrowser.destroy).
    if (this.#onDestroy) {
      const cb = this.#onDestroy
      this.#onDestroy = null
      queueMicrotask(cb)
    }

    // Wake the iterator so it can observe #destroyed and throw.
    /* c8 ignore start -- mirrors ServiceBrowser */
    if (this.#eventSignal) {
      this.#eventSignal.resolve()
    }
    /* c8 ignore stop */
  }

  /** @returns {Promise<void>} */
  /* c8 ignore start -- asyncDispose is a standard protocol method */
  async [Symbol.asyncDispose]() {
    this.destroy()
  }
  /* c8 ignore stop */

  /** @returns {AsyncIterableIterator<BrowseEvent>} */
  [Symbol.asyncIterator]() {
    if (this.#destroyed) throw new Error('Browser has been destroyed')
    if (this.#iterating) {
      throw new Error('AllServiceBrowser only supports a single concurrent async iterator')
    }
    this.#iterating = true

    /** @type {AsyncIterableIterator<BrowseEvent>} */
    const iter = {
      next: async () => {
        while (true) {
          if (this.#eventBuffer.length > 0) {
            const value = /** @type {BrowseEvent} */ (this.#eventBuffer.shift())
            return { value, done: false }
          }
          /* c8 ignore start -- destroyed-while-iterating path mirrors ServiceBrowser */
          if (this.#destroyed) {
            this.#iterating = false
            throw this.#destroyReason ?? new Error('Browser has been destroyed')
          }
          /* c8 ignore stop */
          this.#eventSignal = createDeferred()
          await this.#eventSignal.promise
          this.#eventSignal = null
        }
      },
      /* c8 ignore start -- iterator return() called by for-await-of break */
      return: async () => {
        this.#iterating = false
        this.destroy()
        return { value: undefined, done: true }
      },
      /* c8 ignore stop */
      [Symbol.asyncIterator]() { return iter },
    }
    return iter
  }

  // ─── Private methods ───────────────────────────────────────────────

  /**
   * Push an event to the buffer and wake any waiting consumer.
   * @param {BrowseEvent} event
   */
  #emit(event) {
    /* c8 ignore next 3 -- overflow guard requires 1000+ unconsumed events */
    if (this.#eventBuffer.length >= MAX_ALL_EVENT_BUFFER) {
      this.#eventBuffer.shift()
    }
    this.#eventBuffer.push(event)
    if (this.#eventSignal) {
      this.#eventSignal.resolve()
    }
  }

  /**
   * Consume type enumeration events in the background and spawn/destroy
   * sub-browsers as types appear and disappear.
   */
  async #consumeTypes() {
    if (!this.#typeBrowser) return

    /* c8 ignore start -- type enumeration consumption requires browseAll with real network traffic */
    try {
      for await (const event of this.#typeBrowser) {
        if (this.#destroyed) break

        if (event.type === 'serviceUp') {
          this.#addTypeBrowser(event.service.fqdn)
        } else if (event.type === 'serviceDown') {
          this.#removeTypeBrowser(event.service.fqdn)
        }
      }
    } catch {
      // Browser was destroyed or transport errored — stop consuming
    }
    /* c8 ignore stop */
  }

  /**
   * Start browsing for instances of a specific service type.
   * @param {string} typeFqdn - e.g. "_http._tcp.local"
   */
  #addTypeBrowser(typeFqdn) {
    if (this.#typeBrowsers.has(typeFqdn)) return

    // Parse the type FQDN into components.
    // typeFqdn is e.g. "_http._tcp.local" → type="_http._tcp", domain="local"
    // or "_http._tcp.example.com" → type="_http._tcp", domain="example.com"
    // Service type is always the first two labels (_service._proto).
    const parts = typeFqdn.split('.')
    if (parts.length < 3) return

    const type = parts.slice(0, 2).join('.')
    const domain = parts.slice(2).join('.')
    const protocol = parts[1].replace(/^_/, '')

    const browser = new ServiceBrowser(this.#transport, {
      queryName: typeFqdn,
      serviceType: type,
      domain,
      protocol,
    })

    this.#typeBrowsers.set(typeFqdn, browser)
    this.#consumeInstanceEvents(typeFqdn, browser)
  }

  /**
   * Stop browsing for instances of a service type and remove its services.
   * @param {string} typeFqdn
   */
  /* c8 ignore next 13 -- requires a service type to disappear from the network */
  #removeTypeBrowser(typeFqdn) {
    const browser = this.#typeBrowsers.get(typeFqdn)
    if (!browser) return

    // Emit serviceDown for all instances of this type
    for (const [fqdn, service] of browser.services) {
      this.services.delete(fqdn)
      this.#emit({ type: 'serviceDown', service })
    }

    browser.destroy()
    this.#typeBrowsers.delete(typeFqdn)
  }

  /**
   * Forward events from a sub-browser into the unified event stream.
   * @param {string} typeFqdn
   * @param {ServiceBrowser} browser
   */
  /* c8 ignore start -- instance event forwarding requires browseAll with real discovery */
  async #consumeInstanceEvents(typeFqdn, browser) {
    try {
      for await (const event of browser) {
        if (this.#destroyed) break

        // Mirror changes into the merged services map
        if (event.type === 'serviceUp' || event.type === 'serviceUpdated') {
          this.services.set(event.service.fqdn, event.service)
        } else if (event.type === 'serviceDown') {
          this.services.delete(event.service.fqdn)
        }

        this.#emit(event)
      }
    } catch {
      // Browser was destroyed or transport errored — stop consuming
    }
  }
  /* c8 ignore stop */
}
