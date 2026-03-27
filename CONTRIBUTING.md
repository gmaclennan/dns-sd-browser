# Contributing

Thanks for your interest in contributing to dns-sd-browser!

## Development Setup

```bash
git clone https://github.com/gmaclennan/dns-sd-browser.git
cd dns-sd-browser
npm install
```

## Running Tests

```bash
npm test
```

Tests use Node's built-in test runner and real UDP multicast on loopback — no mocks. The test suite uses `dns-packet` as a reference implementation to construct mDNS response packets, ensuring our codec is cross-validated against a known-good encoder.

## Architecture

```
lib/
├── index.js      — DnsSdBrowser class (main entry, socket lifecycle)
├── browser.js    — ServiceBrowser (async iterable, query scheduling, service resolution)
├── dns.js        — DNS packet codec (encode queries, decode responses, name compression)
├── transport.js  — mDNS UDP socket (multicast join/send/receive, packet dispatch)
├── service.js    — Service type parsing, TXT record parsing
└── constants.js  — mDNS/DNS-SD constants
```

Key design decisions:

- **Async iterator over EventEmitter** — avoids the common footgun of unhandled `'error'` events and provides natural backpressure and cancellation.
- **Event buffering** — events are buffered between browser creation and iterator consumption, so no events are lost if there's a delay before iterating.
- **Private `#` fields** — all internal state uses private class fields to keep the public API surface minimal and prevent accidental coupling.
- **Single transport** — multiple `ServiceBrowser` instances share one UDP socket through the `DnsSdBrowser` class.

## Type Checking

Types are defined via JSDoc and can be checked with TypeScript:

```bash
npm run typecheck
```

## RFC References

When making changes, refer to the relevant RFCs:

- [RFC 6762 — Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762) — protocol rules for queries, responses, caching, name compression
- [RFC 6763 — DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc6763) — service type format, PTR/SRV/TXT record semantics, TXT key-value encoding

## Known Gaps

These are areas where the implementation does not yet fully comply with the RFCs. Tests for some of these exist as skipped tests. Contributions welcome:

- **TTL-based cache expiration** — services should be removed when their record TTLs expire, not just on goodbye packets
- **IPv6 multicast** — transport only joins the IPv4 multicast group (224.0.0.251), not the IPv6 group (FF02::FB)
- **Truncated messages** — the TC bit is not handled; multi-packet responses are not reassembled
- **QU bit** — queries don't set the unicast-response bit for initial queries (RFC 6762 §5.4)
- **Subtype browsing** — no API for browsing service subtypes

## Writing Tests

- Prefer end-to-end tests using real UDP sockets over unit tests
- Use `TestAdvertiser` (in `test/helpers/advertiser.js`) to simulate mDNS services
- Use `nextEvent()` and `collectEvents()` helpers for async iterator consumption with timeouts
- Each test suite should use its own random port (`getRandomPort()`) to avoid interference
- Always call `await mdns.ready()` after creating a browser to ensure the socket is bound before sending test packets

## Code Style

- Use clearly named variables and functions
- Add comments for non-obvious protocol logic (cite RFC section numbers)
- Keep the public API surface small — use `#private` for internals
- Avoid external runtime dependencies
