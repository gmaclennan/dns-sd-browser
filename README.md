# dns-sd-browser

Spec-compliant [DNS-SD](https://www.rfc-editor.org/rfc/rfc6763) browser over [Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762) for Node.js.

- **Async iterator API** — modern, backpressure-aware, no forgotten error handlers
- **Zero dependencies** — pure JavaScript, no native bindings
- **RFC compliant** — continuous querying, known-answer suppression, TTL expiration, IPv4+IPv6 multicast
- **Interoperable** — lenient with real-world advertiser quirks, strict on security
- **JSDoc typed** — full type information via JSDoc, checkable with TypeScript

## Install

```
npm install dns-sd-browser
```

Requires Node.js >= 22.

## Usage

```js
import { DnsSdBrowser } from 'dns-sd-browser'

const mdns = new DnsSdBrowser()
const browser = mdns.browse('_http._tcp')

for await (const event of browser) {
  switch (event.type) {
    case 'serviceUp':
      console.log(`Found: ${event.service.name} at ${event.service.host}:${event.service.port}`)
      console.log(`  Addresses: ${event.service.addresses.join(', ')}`)
      console.log(`  TXT:`, event.service.txt)
      break
    case 'serviceDown':
      console.log(`Lost: ${event.service.name}`)
      break
    case 'serviceUpdated':
      console.log(`Updated: ${event.service.name}`, event.service.txt)
      break
  }
}
```

### Find the first service

```js
const browser = mdns.browse('_http._tcp', {
  signal: AbortSignal.timeout(10_000)
})
for await (const event of browser) {
  if (event.type === 'serviceUp') {
    console.log(event.service.name, event.service.host, event.service.port)
    break // stops the browser
  }
}
```

### Object-form service type

```js
// These are equivalent:
mdns.browse('_http._tcp')
mdns.browse({ name: 'http', protocol: 'tcp' })
mdns.browse({ name: 'http' }) // protocol defaults to 'tcp'
```

### Browse a service subtype

Discover services registered under a specific subtype (RFC 6763 §7.1):

```js
const browser = mdns.browse('_http._tcp', { subtype: '_printer' })

for await (const event of browser) {
  if (event.type === 'serviceUp') {
    console.log(`Printer: ${event.service.name}`)
  }
}
```

### Browse all services

Discover every service on the network, regardless of type. Automatically enumerates service types and browses each one for fully resolved instances:

```js
const browser = mdns.browseAll()

for await (const event of browser) {
  if (event.type === 'serviceUp') {
    console.log(`[${event.service.type}] ${event.service.name} at ${event.service.host}:${event.service.port}`)
  }
}
```

### Browse service types only

If you only need to know which service types exist (without resolving instances), use `browseTypes()`:

```js
const browser = mdns.browseTypes()

for await (const event of browser) {
  if (event.type === 'serviceUp') {
    console.log('Service type found:', event.service.fqdn)
    // event.service.host/port/addresses will be empty — these are types, not instances
  }
}
```

### Stopping a browser

Breaking out of a `for await` loop or aborting via `AbortSignal` automatically stop the browser — no manual cleanup needed:

```js
// break / return automatically stops the browser
for await (const event of browser) {
  if (event.type === 'serviceUp') {
    break // browser is stopped and cleaned up
  }
}

// AbortSignal throws AbortError when aborted
const browser = mdns.browse('_http._tcp', {
  signal: AbortSignal.timeout(10_000)
})
try {
  for await (const event of browser) {
    console.log(event)
  }
} catch (err) {
  if (err.name === 'TimeoutError') {
    console.log('Browsing timed out')
  }
}
```

Call `browser.destroy()` explicitly only if you are **not** consuming the async iterator (e.g. only polling `browser.services`):

```js
const browser = mdns.browse('_http._tcp')

// Poll the live services map without iterating
setTimeout(() => {
  console.log('Found:', [...browser.services.values()])
  browser.destroy() // must destroy manually since we never iterated
}, 5000)
```

### Current services snapshot

`browser.services` is a live `Map<string, Service>` that reflects all currently discovered services, updated regardless of whether you're actively iterating:

```js
const browser = mdns.browse('_http._tcp')

// Later, check what's been found:
for (const [fqdn, service] of browser.services) {
  console.log(fqdn, service.host, service.port)
}
```

### Removing unreachable services

If your application detects that a service is unreachable (e.g. via a health check), you can remove it from the browser without waiting for its TTL to expire:

```js
browser.removeService('My Printer._http._tcp.local')
// Emits serviceDown and clears the cached record.
// If the advertiser re-announces, it will appear as a fresh serviceUp.
```

This is useful on unreliable networks where devices disappear without sending goodbye packets. Most mDNS advertisers (including Android's NSD) use a 75-minute TTL, so without manual removal, stale services would linger for a long time.

### Cleanup

Always destroy the `DnsSdBrowser` instance when done to close the mDNS socket. Destroying the `DnsSdBrowser` also stops all its browsers:

```js
await mdns.destroy() // stops all browsers and closes the socket
```

Or use `await using` for automatic cleanup:

```js
{
  await using mdns = new DnsSdBrowser()
  const browser = mdns.browse('_http._tcp')
  // mdns and all browsers cleaned up at end of block
}
```

## API

### `new DnsSdBrowser(options?)`

Create a new DNS-SD browser instance. Manages a shared mDNS socket.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `port` | `number` | `5353` | mDNS UDP port |
| `interface` | `string` | `'0.0.0.0'` | Network interface IP to bind to |

### `mdns.browse(serviceType, options?)`

Start browsing for a service type. Returns a `ServiceBrowser`.

- **serviceType**: `string` like `'_http._tcp'` or object `{ name: 'http', protocol?: 'tcp' }`
- **options.signal**: `AbortSignal` to cancel browsing
- **options.subtype**: `string` — browse a service subtype (RFC 6763 §7.1), e.g. `browse('_http._tcp', { subtype: '_printer' })` queries `_printer._sub._http._tcp.local`

### `mdns.browseAll(options?)`

Browse for all service instances on the network, regardless of type. Automatically enumerates service types and browses each for instances. Returns an `AllServiceBrowser` (same async iterable interface as `ServiceBrowser`).

- **options.signal**: `AbortSignal` to cancel browsing

### `mdns.browseTypes(options?)`

Browse for service types on the network. Returns lightweight `Service` objects representing types — `host`, `port`, and `addresses` will be empty.

- **options.signal**: `AbortSignal` to cancel browsing

### `mdns.ready()`

Returns a `Promise<void>` that resolves when the mDNS socket is bound and ready.

### `mdns.rejoin()`

Re-join multicast groups and restart all browsers after a network interface change (e.g. WiFi reconnect, Ethernet re-plug).

The OS drops multicast group membership when an interface goes down. This method re-establishes it, emits `serviceDown` for all previously discovered services, and restarts querying with the initial rapid schedule so services on the new network are discovered quickly.

Without calling `rejoin()`, previously discovered services would still eventually expire via their TTL timers (typically ~75 minutes), but the socket would not receive any new multicast responses until the multicast group is re-joined.

All previously known services are flushed as `serviceDown` because the browser cannot know whether you reconnected to the same network or a different one. On a different network those services don't exist; on the same network they will be re-discovered within seconds via the restarted query schedule.

```js
// Call from your application's network change handler
mdns.rejoin()

// The async iterator will receive serviceDown for all previous services,
// followed by serviceUp as services are re-discovered on the new network
```

### `mdns.destroy()`

Stop all browsers and close the mDNS socket. Returns `Promise<void>`.

### `ServiceBrowser`

Returned by `browse()` and `browseTypes()`. Implements `AsyncIterable<BrowseEvent>`.

### `AllServiceBrowser`

Returned by `browseAll()`. Same interface as `ServiceBrowser` — the `services` Map contains instances from all discovered types.

Both `ServiceBrowser` and `AllServiceBrowser` share this interface:

| Property/Method | Type | Description |
|-----------------|------|-------------|
| `services` | `Map<string, Service>` | Live map of currently discovered services |
| `removeService(fqdn)` | `boolean` | Manually remove a service, emitting `serviceDown`. Returns `true` if found. |
| `destroy()` | `void` | Stop browsing and end iteration (called automatically by `break` and `AbortSignal`) |
| `resetNetwork()` | `void` | Flush services and restart queries (called by `mdns.rejoin()`) |
| `[Symbol.asyncIterator]()` | `AsyncIterableIterator<BrowseEvent>` | Iterate over discovery events |
| `[Symbol.asyncDispose]()` | `Promise<void>` | For `await using` support |

### `BrowseEvent`

```ts
type BrowseEvent =
  | { type: 'serviceUp', service: Service }
  | { type: 'serviceDown', service: Service }
  | { type: 'serviceUpdated', service: Service }
```

#### Service resolution lifecycle

Discovering a DNS-SD service requires multiple DNS record types, each carrying a different piece of information:

1. **PTR** record — maps a service type (`_http._tcp.local`) to a specific instance name (`My Printer._http._tcp.local`). This is what browsing queries for.
2. **SRV** record — provides the target hostname and port for that instance (`printer.local:631`).
3. **TXT** record — carries metadata as key-value pairs (`path=/api`, `version=2`).
4. **A / AAAA** records — resolve the hostname to IPv4/IPv6 addresses (`192.168.1.50`).

Advertisers typically send all of these in a single response packet with the SRV, TXT, and address records in the "additionals" section. However, records can arrive in separate packets under normal conditions — for example, when a host's address changes (DHCP renewal), the advertiser sends just the new A record without re-sending the PTR or SRV. Records can also be split when the response exceeds the 1472-byte mDNS packet limit, or when different records have independent TTLs and are refreshed at different times.

This library emits `serviceUp` as soon as the SRV record is resolved (providing `host` and `port`). Other records may arrive in later packets — the service is progressively filled in via `serviceUpdated` events:

| Event | When | What's guaranteed | What may be empty |
|-------|------|-------------------|-------------------|
| `serviceUp` | SRV record resolved | `name`, `host`, `port`, `fqdn` | `addresses`, `txt`, `subtypes` |
| `serviceUpdated` | Any field changed | All fields reflect current state | — |
| `serviceDown` | TTL expired or goodbye | Snapshot at time of removal | — |

Each service emits exactly one `serviceUp`, followed by zero or more `serviceUpdated`, and at most one `serviceDown`. You will never receive a second `serviceUp` for the same service.

This matters when A/AAAA records arrive in a separate packet from the SRV (a split response). The `serviceUp` will have `addresses: []`, and a `serviceUpdated` follows shortly after with the addresses populated:

```js
const resolved = new Map()

for await (const event of browser) {
  if (event.type === 'serviceDown') {
    resolved.delete(event.service.fqdn)
    continue
  }
  const svc = event.service
  if (svc.addresses.length > 0 && !resolved.has(svc.fqdn)) {
    resolved.set(svc.fqdn, svc)
    console.log(`Ready: ${svc.name} at ${svc.addresses[0]}:${svc.port}`)
  }
}
```

If you only need a service once it has addresses, you can also poll the `services` Map — it always reflects the latest state regardless of which events you've consumed.

### `Service`

```ts
interface Service {
  name: string        // Instance name ("My Printer")
  type: string        // Service type ("_http._tcp")
  protocol: string    // "tcp" or "udp"
  domain: string      // "local"
  host: string        // Target hostname ("printer.local")
  port: number        // Port number
  addresses: string[] // IPv4 and IPv6 addresses
  txt: Record<string, string | true>  // Parsed TXT key-value pairs
  txtRaw: Record<string, Uint8Array>  // Raw TXT values
  fqdn: string        // Fully qualified name
  subtypes: string[]  // Service subtypes
  updatedAt: number   // Timestamp (ms)
}
```

## Edge cases and caveats

### `break` stops the browser

`break` or `return` from a `for await` loop automatically stops the browser — it cannot be iterated again. If you need to find the first service and then keep browsing, consume events without breaking:

```js
const browser = mdns.browse('_http._tcp')
let firstService
for await (const event of browser) {
  if (event.type === 'serviceUp' && !firstService) {
    firstService = event.service
    // don't break — keep browsing for more services
  }
}
```

### AbortSignal throws, doesn't end cleanly

Aborting via `AbortSignal` throws the abort reason from the `for await` loop, matching the Node.js convention (`events.on`, `Readable`, `setInterval` all throw `AbortError`). Use try/catch to handle it:

```js
try {
  for await (const event of browser) { /* ... */ }
} catch (err) {
  if (err.name === 'AbortError') {
    // browsing was cancelled
  }
}
```

In contrast, `browser.destroy()` ends iteration cleanly (no throw).

### Single async iterator

Each `ServiceBrowser` supports only **one** active async iterator at a time. Attempting to create a second will throw:

```js
const browser = mdns.browse('_http._tcp')
for await (const event of browser) { /* ... */ } // ok
for await (const event of browser) { /* ... */ } // throws — iterator already active
```

If you need multiple consumers, read from `browser.services` (the live Map) instead.

### `browseAll()` returns partial Service objects

`browseAll()` queries for service _types_, not service _instances_. The returned `Service` objects represent service types and have incomplete fields:

```js
const browser = mdns.browseAll()
for await (const event of browser) {
  // event.service.fqdn → "_http._tcp.local" (the type, not an instance)
  // event.service.host → ""
  // event.service.port → 0
  // event.service.addresses → []
}
```

To discover actual service instances, use the type from `browseAll()` to start a targeted `browse()`.

### `ready()` requires a prior `browse()` call

The mDNS transport is started lazily on the first `browse()` or `browseAll()` call. Calling `ready()` before any browse will throw:

```js
const mdns = new DnsSdBrowser()
await mdns.ready() // throws — transport not started yet

const browser = mdns.browse('_http._tcp')
await mdns.ready() // ok — transport is starting
```

### Transport start errors are deferred

If the mDNS socket fails to bind (e.g. permission denied, port conflict), the error is **not** thrown from `browse()`. The browser will silently produce no events. To surface transport errors, call `ready()` after starting a browse:

```js
const browser = mdns.browse('_http._tcp')
await mdns.ready() // throws if socket binding failed
```

### Event buffer overflow

Events are buffered (up to 4,096) while waiting for the async iterator to consume them. If a consumer is too slow, the **oldest events are silently dropped**. This means a slow consumer could miss `serviceUp` events and later receive `serviceDown` for services it never saw appear. The `browser.services` Map always reflects the current state regardless of buffer overflow.

### `services` Map keys are FQDNs

The `browser.services` Map is keyed by the fully qualified service name (e.g. `"My Printer._http._tcp.local"`), not the short instance name. Use `service.name` for the human-readable name:

```js
browser.services.get('My Printer._http._tcp.local') // ✓
browser.services.get('My Printer') // ✗ undefined
```

## RFC Compliance

This library implements the browser/querier side of:

- **[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)** — Multicast DNS
  - IPv4 and IPv6 multicast (224.0.0.251 and FF02::FB)
  - Continuous querying with exponential backoff (1s, 2s, 4s... up to 1h)
  - QU (unicast-response) bit on initial queries (§5.4)
  - Known-answer suppression in queries (§7.1)
  - TTL-based cache expiration — services are removed when their TTL expires
  - Cache-flush bit handling
  - Goodbye packets (TTL=0)
  - Truncated response handling — re-queries with QU bit when TC is set (§18.5)
  - DNS name compression (encoding and decoding)
  - Malformed packet rejection with detailed errors

- **[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)** — DNS-Based Service Discovery
  - PTR record browsing for service instances
  - SRV record resolution (host, port)
  - TXT record parsing (key=value, boolean flags, case-insensitive dedup)
  - Service type enumeration (`_services._dns-sd._udp.local`)
  - Subtype browsing (`_subtype._sub._type._proto.local`)
  - Duplicate suppression

## Interoperability

DNS-SD advertisers in the wild vary in how closely they follow the RFCs. This library is intentionally lenient about accepting non-standard responses, while remaining strict about security-relevant parsing.

### Accepted (lenient)

These advertiser quirks are handled gracefully:

| Quirk | Behavior | Seen in |
|---|---|---|
| Split responses (PTR in one packet, SRV in another) | Tracks pending FQDNs, resolves when SRV arrives | Normal mDNS behavior (see [resolution lifecycle](#service-resolution-lifecycle)) |
| Non-zero rcode in responses | Ignored per RFC 6762 §18.11 | Embedded devices |
| Records in authority section | Processed alongside answers and additionals | Various |
| Missing TXT record | Service emitted with empty `txt: {}` | Minimal advertisers, Android NSD |
| Empty TXT record (single `\x00` byte) | Parsed as empty `txt: {}` per RFC 6763 §6.1 | Android NSD |
| TXT `key=` for null values | Parsed as empty string (Android writes `key=` instead of boolean `key`) | Android NSD (`setAttribute(key, null)`) |
| Missing A/AAAA records | Service emitted with empty `addresses: []`, updated when they arrive | Normal mDNS behavior (see [resolution lifecycle](#service-resolution-lifecycle)) |
| Non-zero packet ID | Accepted (RFC 6762 says ID should be 0, but receivers must not require it) | Legacy implementations |
| Missing AA (authoritative) bit | Accepted | Various |
| SRV with port 0 | Accepted as-is | Services indicating "not ready" |
| Non-standard TTL values | Accepted as-is (e.g. Android NSD uses 75-minute / 4500s TTL) | Various, Android NSD |
| Cache-flush bit missing | Not required for processing | Some minimal advertisers |
| Mixed-case DNS names | Case-insensitive matching per RFC 1035 §3.1 | Various, Android NSD |
| Shared hostname across devices | Address resolved from same-packet records | Android NSD 7–12 (hardcoded `Android.local`) |
| Service name conflict suffix | Parentheses and spaces accepted in instance names per RFC 6763 | Android NSD (`"MyService (2)"`) |
| Service flickering (goodbye + quick re-announce) | 1-second goodbye grace period absorbs flicker | Android NSD |
| Long hostnames (40+ bytes) | Accepted up to the 253-char DNS name limit | Android NSD 13+ (`Android_<UUID>.local`) |

### Rejected (strict)

These are security-relevant and remain strictly enforced:

| Check | Why |
|---|---|
| QR bit must be 1 (response) | Processing queries as responses would be a spoofing vector |
| Opcode must be 0 (standard query) | Non-zero opcode means a different DNS operation |
| Packet must be ≥ 12 bytes | Below DNS header size is always corrupt |
| Record counts capped at 256/packet | Prevents CPU exhaustion from crafted headers |
| RDATA must fit within packet | Prevents out-of-bounds reads |
| DNS names ≤ 253 characters | RFC 1035 §2.3.4 limit, prevents memory abuse |
| Compression pointer loops detected | Prevents infinite loops (CVE-2006-6870) |
| Label length ≤ 63 bytes | RFC 1035 limit |
| Services capped at 1024/browser | Prevents memory exhaustion from flooding |

## Security

The DNS packet parser and service resolution logic are hardened against attack patterns found in historical CVEs for [Avahi](https://avahi.org/) and Apple's [mDNSResponder](https://opensource.apple.com/projects/mDNSResponder/).

**Packet parsing** — All input from the network is validated before processing:

- Packets below the 12-byte DNS header minimum are rejected
- Record counts in the header are capped at 256 per packet to prevent CPU exhaustion from crafted headers claiming thousands of records
- Each record's RDATA length is validated against the remaining packet bytes before parsing — prevents out-of-bounds reads (CVE-2023-38472 pattern)
- SRV records require a minimum RDATA length of 7 bytes; TXT string lengths are checked against the RDATA boundary (CVE-2023-38469 pattern)
- DNS name decompression validates pointer targets are within the packet buffer (CVE-2015-7987 pattern), detects pointer loops with a jump counter (CVE-2006-6870 pattern), and enforces the RFC 1035 §2.3.4 maximum name length of 253 characters
- Label lengths are validated against both the 63-byte RFC limit and the remaining buffer

**Resource limits** — Bounded data structures prevent memory exhaustion from flooding:

- Each browser tracks at most 1,024 services. Additional services are silently dropped.
- The known-answer PTR cache is bounded to the same limit
- The event buffer caps at 4,096 entries, dropping the oldest on overflow

**Response filtering** — The transport layer drops packets that are not valid mDNS responses:

- Only response packets are processed (QR bit must be set)
- Packets with non-zero opcode are dropped (non-standard DNS operations)
- Query packets with answers in them (a potential spoofing vector) are ignored

These defenses are verified by a dedicated security test suite (`test/security.test.js`) that exercises each attack pattern directly.

## Comparison with other libraries

There are several mDNS/DNS-SD libraries available for Node.js, each with different trade-offs. Here's how they compare:

| | dns-sd-browser | [bonjour-service](https://github.com/onlxltd/bonjour-service) | [multicast-dns](https://github.com/mafintosh/multicast-dns) | [dnssd](https://github.com/DeMille/dnssd.js) | [mdns](https://github.com/agnat/node_mdns) |
|---|---|---|---|---|---|
| **Browse** | Yes | Yes | Manual | Yes | Yes |
| **Advertise** | No | Yes | Manual | Yes | Yes |
| **API style** | Async iterator | EventEmitter | EventEmitter | EventEmitter | EventEmitter |
| **Dependencies** | 0 | 2 (`multicast-dns`, `fast-deep-equal`) | 2 (`dns-packet`, `thunky`) | 0 | Native (C++) |
| **TypeScript** | JSDoc types | Written in TS | `@types` available | No | No |
| **Known-answer suppression** | Yes | No | N/A (low-level) | Yes | System-level |
| **TTL expiration** | Yes | No | N/A (low-level) | Yes | System-level |
| **Continuous querying** | Yes (exponential backoff) | Yes (fixed interval) | N/A (low-level) | Yes | System-level |
| **Node.js** | >= 22 | Any | Any | >= 6 | Any (with native toolchain) |
| **Last published** | New | Nov 2024 | May 2022 | May 2018 | Nov 2020 |

### Notes

**[bonjour-service](https://github.com/onlxltd/bonjour-service)** is the most widely used pure-JS option. It provides both browsing and advertising with a simple EventEmitter API. It's a solid, well-maintained choice — especially if you need an advertiser too. However, it doesn't implement known-answer suppression or TTL-based cache expiration, which can lead to duplicate responses and stale services on busy networks.

**[multicast-dns](https://github.com/mafintosh/multicast-dns)** is a low-level mDNS library (~14M weekly downloads, mostly as a transitive dependency). It handles DNS packet encoding/decoding and multicast transport, but doesn't implement DNS-SD service browsing — you'd need to build that yourself on top. Great if you need raw mDNS control.

**[dnssd](https://github.com/DeMille/dnssd.js)** has the most complete RFC implementation among the pure-JS alternatives, with both browsing and advertising, zero dependencies, and proper known-answer suppression. Unfortunately it hasn't been updated since 2018 and is effectively unmaintained.

**[mdns](https://github.com/agnat/node_mdns)** uses native bindings to your OS's mDNS stack (Bonjour/Avahi), giving it the best conformance and performance. The downside is that it requires C++ compilation on install, platform-specific system libraries, and it hasn't been updated since 2020. See the [system mDNS section](#with-a-system-mdns-stack-bonjour-avahi) below for when this trade-off makes sense.

**dns-sd-browser** focuses on doing one thing well: browsing. It has no dependencies and implements the querier side of the RFCs thoroughly (known-answer suppression, TTL expiration, cache-flush handling, continuous querying with exponential backoff). The async iterator API avoids common EventEmitter pitfalls like forgotten error handlers. The trade-offs are that it's new and less battle-tested than the alternatives, it requires Node.js 22+, and it only browses — you'll need a separate library if you also need to advertise services.

## When to use this library

### With a Node.js advertiser (e.g. ciao)

This library is designed to run alongside a DNS-SD advertiser like [ciao](https://github.com/homebridge/ciao). A browser and advertiser on the same machine coexist well — they both bind to port 5353 with `SO_REUSEADDR` and receive all multicast traffic. This browser only sends queries and processes responses, while ciao sends responses and processes queries (it also monitors responses for conflict detection, but a browse-only module never announces records, so there is nothing to conflict with). The two RFC 6762 §15 concerns that apply to multiple *queriers* — known-answer list corruption and duplicated queries — don't apply here since only one side is querying. The only minor effect is that a unicast response to the browser's initial QU query may be delivered to ciao's socket instead, but the browser automatically retries via multicast on the next query interval.

### With a system mDNS stack (Bonjour, Avahi)

**On macOS and Linux**, the operating system already includes a full mDNS implementation (Bonjour on macOS, Avahi on most Linux distributions) that handles both advertising and browsing. Running an additional querier alongside the system stack has some drawbacks, as [RFC 6762 §15](https://www.rfc-editor.org/rfc/rfc6762#section-15) explains:

- **Port 5353 conflicts** — when multiple implementations bind to it with `SO_REUSEADDR`, only one receives unicast responses. This forces all queries to use multicast, increasing network traffic.
- **Known-answer list corruption** — when multiple queriers send simultaneous queries, responders may incorrectly merge their known-answer lists (which are assembled by source IP address), leading to missed answers.
- **Resource efficiency** — two independent queriers consume extra memory and CPU.

If you need a DNS-SD browser that uses the system mDNS on macOS/Linux, consider native bindings like the [`mdns`](https://www.npmjs.com/package/mdns) package. However, `mdns` requires C++ compilation on install and can be difficult to set up on some platforms — particularly Windows.

### Best suited for

- **Windows** — no system mDNS available
- **Cross-platform apps** — needs to work everywhere without native compilation
- **Pairing with ciao** — browser complement to ciao's advertiser, no native dependencies
- **Environments where system mDNS is absent** — containers, embedded systems, CI runners
- **Testing and development** — quick setup, no system dependencies

## Recommended advertiser

This library only browses — it does not advertise services. If you need to publish services on the local network, [@homebridge/ciao](https://github.com/homebridge/ciao) is a well-tested, actively maintained DNS-SD advertiser written in TypeScript. It is RFC 6762/6763 compliant, passes Apple's Bonjour Conformance Test, and is proven in production as part of the Homebridge ecosystem. A browser and advertiser on the same machine coexist well — see [With a Node.js advertiser](#with-a-nodejs-advertiser-eg-ciao) for details.

## License

MIT
