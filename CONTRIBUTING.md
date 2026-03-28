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
npm test           # runs tests with coverage report
```

Tests use Node's built-in test runner and real UDP multicast on loopback — no mocks. The test suite uses `dns-packet` as a reference implementation to construct mDNS response packets, ensuring our codec is cross-validated against a known-good encoder.

Coverage is collected via [c8](https://github.com/bcoe/c8). The coverage report is printed after each test run. For CI, `npm run test:ci` also generates an `lcov` report in `coverage/`.

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

The core DNS-SD browsing features are implemented and tested. Remaining areas for improvement:

- **Cache-flush bit semantics** — the cache-flush bit (RFC 6762 §10.2) is parsed but not acted upon. When a record arrives with the cache-flush bit set, the receiver should flush all cached records with the same name and type (except those received in the last second). Currently, addresses are merged rather than flushed, which can lead to stale addresses persisting when a service changes its IP.
- **Subtype population on Service objects** — the `subtypes` array on Service is always empty. When subtype PTR records are received, or when browsing a subtype, the subtypes should be populated.
- **TTL refresh queries** — RFC 6762 §5.2 recommends re-querying at 80%, 85%, 90%, and 95% of a record's TTL to refresh it before expiry. Currently, records simply expire at 100% TTL, which can cause brief service-down/service-up cycles for long-lived services.
- **Multi-packet known-answer splitting** — when the known-answer list is too large for a single query packet, it should be split across multiple packets with the TC bit set. Currently, all known answers are packed into a single packet.

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

## Manual Bonjour Compliance Testing

The automated test suite uses loopback multicast with synthetic packets. For real-world compliance testing against the system mDNS stack (Bonjour on macOS, Avahi on Linux), use the helper scripts in `scripts/`.

### Prerequisites

**macOS:** No extra setup — `dns-sd` is built in.

**Linux:** Install Avahi utilities:
```bash
sudo apt install avahi-utils avahi-daemon
```

### Test 1: Discover services advertised by the system mDNS

Start a service using the system mDNS daemon, then verify our browser finds it:

```bash
# Terminal 1: Advertise a test service via the system daemon
node scripts/bonjour-advertise.js --name "Compliance Test" --type _http._tcp --port 8080 --txt "path=/test,version=1"

# Terminal 2: Browse with our library
node scripts/bonjour-browse.js _http._tcp
```

Expected: Terminal 2 should show `+ UP Compliance Test` with the correct host, port, and TXT records.

### Test 2: Verify goodbye (service removal)

With both terminals running from Test 1, press Ctrl+C in Terminal 1 to stop advertising. Terminal 2 should show `- DOWN Compliance Test`.

### Test 3: Cross-validate against system browser

Compare our output against the system's own mDNS browser:

```bash
# macOS: system browser
dns-sd -B _http._tcp

# Linux: system browser
avahi-browse -r _http._tcp

# Our browser (in another terminal)
node scripts/bonjour-browse.js _http._tcp
```

Both should discover the same set of services. Verify:
- Same service instance names
- Same host and port
- Same TXT records
- Service removal events appear in both

### Test 4: Browse all service types

```bash
# Our browser
node scripts/bonjour-browse.js --all

# macOS equivalent
dns-sd -B _services._dns-sd._udp

# Linux equivalent
avahi-browse --all
```

### Test 5: Apple Bonjour Conformance Test (macOS only)

Apple provides a formal Bonjour Conformance Test (BCT) tool:

1. Download BCT from [Apple Developer](https://developer.apple.com/bonjour/) (requires Apple ID)
2. The download is `BonjourConformanceTest-<version>.dmg`
3. Run the BCT while our browser is active:
   ```bash
   node scripts/bonjour-browse.js _http._tcp
   ```
4. The BCT tests various protocol edge cases including:
   - Record TTL handling
   - Name conflict resolution
   - Cache flush behavior
   - Goodbye packet handling

> **Note:** The BCT is primarily designed for testing advertisers/responders, not browsers. Not all BCT tests are applicable to a browser-only implementation. Focus on the "Querier" and "Passive Observation" test categories.

> **Note:** BCT cannot run in GitHub Actions CI because macOS runners [disable mDNSResponder](https://github.com/actions/runner-images/issues/9628) for security isolation. Always run BCT on a local macOS machine.
