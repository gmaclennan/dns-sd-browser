# dns-sd-browser

Spec-compliant [DNS-SD](https://www.rfc-editor.org/rfc/rfc6763) browser over [Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762) for Node.js. Designed as a complementary browser to the [ciao](https://github.com/homebridge/ciao) DNS-SD advertiser.

- **Async iterator API** — modern, backpressure-aware, no forgotten error handlers
- **Zero dependencies** — pure JavaScript, no native bindings
- **RFC compliant** — continuous querying, known-answer suppression, cache-flush, goodbye packets
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

## RFC Compliance

This library implements the browser/querier side of:

- **[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)** — Multicast DNS
  - Multicast queries on 224.0.0.251:5353
  - Continuous querying with exponential backoff (1s, 2s, 4s... up to 1h)
  - Known-answer suppression in queries
  - Cache-flush bit handling
  - Goodbye packets (TTL=0)
  - DNS name compression (encoding and decoding)
  - Malformed packet tolerance

- **[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)** — DNS-Based Service Discovery
  - PTR record browsing for service instances
  - SRV record resolution (host, port)
  - TXT record parsing (key=value, boolean flags)
  - Service type enumeration (`_services._dns-sd._udp.local`)
  - Duplicate suppression

### Not yet implemented

- IPv6 multicast (FF02::FB)
- TTL-based cache expiration (services are only removed via goodbye packets)
- Truncated message handling (TC bit)
- QU (unicast-response) bit in queries
- Subtype browsing

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
