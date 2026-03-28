# dns-sd-browser

Spec-compliant [DNS-SD](https://www.rfc-editor.org/rfc/rfc6763) browser over [Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762) for Node.js. Designed as a complementary browser to the [ciao](https://github.com/homebridge/ciao) DNS-SD advertiser.

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
const browser = mdns.browse('_http._tcp')
const service = await browser.first()
console.log(service.name, service.host, service.port)
browser.destroy()
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

### Browse all service types

Discovers which service types are advertised on the network via `_services._dns-sd._udp.local` (RFC 6763 &sect;9):

```js
const browser = mdns.browseAll()

for await (const event of browser) {
  if (event.type === 'serviceUp') {
    console.log('Service type found:', event.service.fqdn)
  }
}
```

### Cancellation

```js
// With AbortController
const ac = new AbortController()
const browser = mdns.browse('_http._tcp', { signal: ac.signal })

setTimeout(() => ac.abort(), 10_000)

for await (const event of browser) {
  console.log(event)
}
// Loop exits when aborted

// With explicit destroy
browser.destroy()

// With await using (Symbol.asyncDispose)
{
  await using mdns = new DnsSdBrowser()
  const browser = mdns.browse('_http._tcp')
  // automatically cleaned up at end of block
}
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

### Cleanup

Always destroy the `DnsSdBrowser` when done to close the mDNS socket:

```js
await mdns.destroy() // stops all browsers and closes the socket
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

Browse for all service types on the network.

### `mdns.ready()`

Returns a `Promise<void>` that resolves when the mDNS socket is bound and ready.

### `mdns.destroy()`

Stop all browsers and close the mDNS socket. Returns `Promise<void>`.

### `ServiceBrowser`

Returned by `browse()` and `browseAll()`. Implements `AsyncIterable<BrowseEvent>`.

| Property/Method | Type | Description |
|-----------------|------|-------------|
| `services` | `Map<string, Service>` | Live map of currently discovered services |
| `first()` | `Promise<Service>` | Resolves with the first `serviceUp` event |
| `destroy()` | `void` | Stop browsing and end iteration |
| `[Symbol.asyncIterator]()` | `AsyncIterableIterator<BrowseEvent>` | Iterate over discovery events |
| `[Symbol.asyncDispose]()` | `Promise<void>` | For `await using` support |

### `BrowseEvent`

```ts
type BrowseEvent =
  | { type: 'serviceUp', service: Service }
  | { type: 'serviceDown', service: Service }
  | { type: 'serviceUpdated', service: Service }
```

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

### `first()` destroys the browser

`first()` iterates internally using `for await...of`. When it returns the first service, the `for await` loop exits early, which triggers the async iterator's `return()` method and calls `destroy()`. After calling `first()`, the browser is stopped and cannot be iterated again:

```js
const browser = mdns.browse('_http._tcp')
const service = await browser.first()
// browser is now destroyed — no need to call browser.destroy()
// browser.services will contain only the one service found
```

If you need to keep browsing after finding the first service, use the async iterator directly:

```js
const browser = mdns.browse('_http._tcp')
let firstService
for await (const event of browser) {
  if (event.type === 'serviceUp') {
    firstService = event.service
    break // also destroys the browser
  }
}
```

### `first()` without a timeout hangs forever

If no matching service exists on the network, `first()` will wait indefinitely. Always provide an `AbortSignal` with a timeout:

```js
const browser = mdns.browse('_http._tcp', {
  signal: AbortSignal.timeout(10_000)
})
const service = await browser.first() // throws after 10s if nothing found
```

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
| Split responses (PTR in one packet, SRV in another) | Tracks pending FQDNs, resolves when SRV arrives | ciao, avahi |
| Non-zero rcode in responses | Ignored per RFC 6762 §18.11 | Embedded devices |
| Records in authority section | Processed alongside answers and additionals | Various |
| Missing TXT record | Service emitted with empty `txt: {}` | Minimal advertisers |
| Missing A/AAAA records | Service emitted with empty `addresses: []` | Split responses |
| Non-zero packet ID | Accepted (RFC 6762 says ID should be 0, but receivers must not require it) | Legacy implementations |
| Missing AA (authoritative) bit | Accepted | Various |
| SRV with port 0 | Accepted as-is | Services indicating "not ready" |
| Non-standard TTL values | Accepted as-is | Various |
| Cache-flush bit missing | Not required for processing | Some minimal advertisers |
| Mixed-case DNS names | Case-insensitive matching per RFC 1035 §3.1 | Various |

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

## When to use this library

**On Windows**, there is no built-in mDNS stack. This library provides a pure-JavaScript DNS-SD browser that works out of the box — no native dependencies, no compilation, no system services to configure. This is the primary use case.

**On macOS and Linux**, the operating system already includes an mDNS implementation (Bonjour on macOS, Avahi on most Linux distributions). Where possible, it is advisable to use these system mDNS stacks instead of running a second, independent mDNS implementation. As [RFC 6762 §15](https://www.rfc-editor.org/rfc/rfc6762#section-15) explains, running multiple mDNS stacks on the same machine has several drawbacks:

- **Port 5353 conflicts** — mDNS uses a well-known port. When multiple implementations bind to it with `SO_REUSEADDR`, only one receives unicast responses. This forces all queries to use multicast, increasing network traffic.
- **Known-answer list corruption** — when multiple queriers send simultaneous queries, responders may incorrectly merge their known-answer lists (which are assembled by source IP address), leading to missed answers.
- **Resource efficiency** — two independent mDNS stacks consume twice the memory and CPU, which is compounded by running in an interpreted language.

If you need a DNS-SD browser that integrates with the system mDNS on macOS/Linux, consider using native bindings like the [`mdns`](https://www.npmjs.com/package/mdns) package. However, `mdns` requires C++ compilation on install and can be difficult to set up on some platforms — particularly Windows.

This library is best suited for:

- **Windows** — no system mDNS available
- **Cross-platform apps** — needs to work everywhere without native compilation
- **Environments where system mDNS is absent** — containers, embedded systems, CI runners
- **Testing and development** — quick setup, no system dependencies

## License

MIT
