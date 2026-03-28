import { describe, test, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { DnsSdBrowser } from '../lib/index.js'
import { TestAdvertiser } from './helpers/advertiser.js'
import { nextEvent, collectEvents, getRandomPort, delay, TEST_INTERFACE } from './helpers/utils.js'

describe('Service browsing', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(async () => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    // Trigger transport start and wait for socket to be ready
    mdns.browse('_noop._tcp').destroy()
    await mdns.ready()
    advertiser.clearQueries()
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('discovers a service announced on the network', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Test Web Server',
      type: '_http._tcp',
      host: 'testhost.local',
      port: 8080,
      addresses: ['192.168.1.5'],
      txt: { path: '/api', version: '2' },
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'Test Web Server')
    assert.equal(event.service.type, '_http._tcp')
    assert.equal(event.service.host, 'testhost.local')
    assert.equal(event.service.port, 8080)
    assert.equal(event.service.domain, 'local')
    assert.deepEqual(event.service.txt, { path: '/api', version: '2' })
    assert.ok(event.service.addresses.includes('192.168.1.5'))

    browser.destroy()
  })

  test('discovers multiple services of the same type', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Server A',
      type: '_http._tcp',
      host: 'a.local',
      port: 8080,
      addresses: ['192.168.1.10'],
    })

    await advertiser.announce({
      name: 'Server B',
      type: '_http._tcp',
      host: 'b.local',
      port: 9090,
      addresses: ['192.168.1.11'],
    })

    const events = await collectEvents(iter, 2)
    const names = events.map((e) => e.service.name).sort()
    assert.deepEqual(names, ['Server A', 'Server B'])
    assert.ok(events.every((e) => e.type === 'serviceUp'))

    browser.destroy()
  })

  test('populates browser.services with discovered services', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Tracked Service',
      type: '_http._tcp',
      host: 'tracked.local',
      port: 3000,
      addresses: ['10.0.0.1'],
    })

    await nextEvent(iter)

    assert.equal(browser.services.size, 1)
    const service = browser.services.values().next().value
    assert.equal(service.name, 'Tracked Service')
    assert.equal(service.port, 3000)

    browser.destroy()
  })

  test('includes IPv4 addresses from A records', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Multi-Address',
      type: '_http._tcp',
      host: 'multi.local',
      port: 80,
      addresses: ['192.168.1.1', '10.0.0.1'],
    })

    const event = await nextEvent(iter)
    assert.ok(event.service.addresses.includes('192.168.1.1'))
    assert.ok(event.service.addresses.includes('10.0.0.1'))

    browser.destroy()
  })

  test('includes IPv6 addresses from AAAA records', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'IPv6 Service',
      type: '_http._tcp',
      host: 'v6.local',
      port: 443,
      addressesv6: ['fe80::1', '::1'],
    })

    const event = await nextEvent(iter)
    assert.ok(event.service.addresses.length >= 1, 'should have at least one IPv6 address')

    browser.destroy()
  })

  test('reports fqdn for discovered service', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'My Service',
      type: '_http._tcp',
      host: 'myhost.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.service.fqdn, 'My Service._http._tcp.local')

    browser.destroy()
  })

  test('accepts object-form service type { name, protocol }', async () => {
    const browser = mdns.browse({ name: 'http', protocol: 'tcp' })
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Object Form',
      type: '_http._tcp',
      host: 'obj.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'Object Form')

    browser.destroy()
  })

  test('defaults protocol to tcp in object form', async () => {
    const browser = mdns.browse({ name: 'http' })
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Default TCP',
      type: '_http._tcp',
      host: 'tcp.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    const event = await nextEvent(iter)
    assert.equal(event.service.name, 'Default TCP')

    browser.destroy()
  })
})

describe('Service removal', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(() => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('reports serviceDown when goodbye packet received (TTL=0)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'Goodbye Service',
      type: '_http._tcp',
      host: 'bye.local',
      port: 8080,
    }

    await advertiser.announce({
      ...serviceInfo,
      addresses: ['192.168.1.1'],
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')

    await advertiser.goodbye(serviceInfo)

    const downEvent = await nextEvent(iter)
    assert.equal(downEvent.type, 'serviceDown')
    assert.equal(downEvent.service.name, 'Goodbye Service')

    browser.destroy()
  })

  test('removes service from browser.services on goodbye', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'Removed Service',
      type: '_http._tcp',
      host: 'removed.local',
      port: 4000,
    }

    await advertiser.announce({
      ...serviceInfo,
      addresses: ['192.168.1.1'],
    })

    await nextEvent(iter)
    assert.equal(browser.services.size, 1)

    await advertiser.goodbye(serviceInfo)
    await nextEvent(iter) // serviceDown

    assert.equal(browser.services.size, 0)

    browser.destroy()
  })
})

describe('Service updates', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(() => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('reports serviceUpdated when TXT record changes', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'Updating Service',
      type: '_http._tcp',
      host: 'update.local',
      port: 5000,
    }

    await advertiser.announce({
      ...serviceInfo,
      addresses: ['192.168.1.1'],
      txt: { version: '1' },
    })

    const upEvent = await nextEvent(iter)
    assert.equal(upEvent.type, 'serviceUp')
    assert.deepEqual(upEvent.service.txt, { version: '1' })

    await advertiser.updateTxt(serviceInfo, { version: '2', newkey: 'newval' })

    const updateEvent = await nextEvent(iter)
    assert.equal(updateEvent.type, 'serviceUpdated')
    assert.deepEqual(updateEvent.service.txt, { version: '2', newkey: 'newval' })

    browser.destroy()
  })

  test('updates service in browser.services on TXT change', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'TXT Update Service',
      type: '_http._tcp',
      host: 'txtup.local',
      port: 6000,
    }

    await advertiser.announce({
      ...serviceInfo,
      addresses: ['192.168.1.1'],
      txt: { initial: 'true' },
    })

    await nextEvent(iter) // serviceUp

    await advertiser.updateTxt(serviceInfo, { updated: 'true' })
    await nextEvent(iter) // serviceUpdated

    const service = browser.services.values().next().value
    assert.deepEqual(service.txt, { updated: 'true' })

    browser.destroy()
  })
})

describe('TXT record edge cases', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(() => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('handles empty TXT record', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Empty TXT',
      type: '_http._tcp',
      host: 'empty.local',
      port: 80,
      addresses: ['192.168.1.1'],
      txt: {},
    })

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.deepEqual(event.service.txt, {})

    browser.destroy()
  })

  test('handles TXT keys with no value (boolean flags per RFC 6763)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    await advertiser.announce({
      name: 'Bool TXT',
      type: '_http._tcp',
      host: 'bool.local',
      port: 80,
      addresses: ['192.168.1.1'],
      txt: { flagA: true, flagB: true },
    })

    const event = await nextEvent(iter)
    // Boolean flags: keys present without '=' sign
    // Per RFC 6763 §6.4, keys with no '=' mean "attribute is present"
    assert.ok('flagA' in event.service.txt)
    assert.ok('flagB' in event.service.txt)

    browser.destroy()
  })
})

describe('Duplicate handling', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(() => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('does not emit duplicate serviceUp for same service', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    const serviceInfo = {
      name: 'Duplicate Service',
      type: '_http._tcp',
      host: 'dup.local',
      port: 80,
      addresses: ['192.168.1.1'],
    }

    // Announce same service twice
    await advertiser.announce(serviceInfo)
    await delay(100) // ensure first packet is processed
    await advertiser.announce(serviceInfo)
    await delay(100) // ensure second packet is processed

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')

    // Verify exactly one service exists and no more events are buffered.
    // The second announce had identical data, so no serviceUpdated should fire.
    assert.equal(browser.services.size, 1)

    // Confirm no further events arrive (the buffer should be empty)
    await assert.rejects(
      nextEvent(iter, 500),
      { message: /Timed out/ }
    )

    browser.destroy()
  })
})

describe('Service type enumeration', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(async () => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    mdns.browse('_noop._tcp').destroy()
    await mdns.ready()
    advertiser.clearQueries()
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('browseAll discovers service types via _services._dns-sd._udp.local', async () => {
    const browser = mdns.browseAll()
    const iter = browser[Symbol.asyncIterator]()

    // Send a service type enumeration PTR record (RFC 6763 §9)
    // _services._dns-sd._udp.local -> _http._tcp.local
    await advertiser.announceServiceType('_http._tcp')

    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')

    browser.destroy()
  })
})

describe('Query behavior', () => {
  /** @type {number} */
  let port
  /** @type {DnsSdBrowser} */
  let mdns
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  beforeEach(async () => {
    mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    // Trigger transport start and wait for socket to be ready
    mdns.browse('_noop._tcp').destroy()
    await mdns.ready()
    advertiser.clearQueries()
  })

  afterEach(async () => {
    await mdns.destroy()
  })

  test('sends initial PTR query for the service type', async () => {
    const browser = mdns.browse('_http._tcp')

    // Wait for the browser to send its initial query
    const query = await advertiser.waitForQuery((q) =>
      (q.questions || []).some(
        (question) =>
          question.type === 'PTR' && question.name === '_http._tcp.local'
      )
    )

    assert.ok(query, 'should have received a PTR query')
    const question = query.questions?.find((q) => q.type === 'PTR')
    assert.equal(question?.name, '_http._tcp.local')

    browser.destroy()
  })

  test('includes known answers in subsequent queries (known-answer suppression)', async () => {
    const browser = mdns.browse('_http._tcp')
    const iter = browser[Symbol.asyncIterator]()

    // First, let the browser discover a service
    await advertiser.announce({
      name: 'Known Service',
      type: '_http._tcp',
      host: 'known.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    await nextEvent(iter) // serviceUp
    advertiser.clearQueries()

    // Wait for a subsequent query that should include known answers.
    // The browser should include the PTR record it already knows about
    // in the answer section of its query (RFC 6762 §7.1).
    // The first re-query fires ~1s after initial, so 10s is generous.
    const query = await advertiser.waitForQuery(
      (q) =>
        (q.questions || []).some((question) => question.type === 'PTR') &&
        (q.answers || []).length > 0,
      10000
    )

    // The known answer should be the PTR for the discovered service
    const knownAnswer = query.answers?.find(
      (a) => a.type === 'PTR' && a.data === 'Known Service._http._tcp.local'
    )
    assert.ok(knownAnswer, 'query should include known answer PTR record')

    browser.destroy()
  })
})

describe('API surface', () => {
  /** @type {number} */
  let port
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  test('browser.first() resolves with the first discovered service', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')
    await mdns.ready()

    // Announce after a short delay so .first() is already waiting
    setTimeout(async () => {
      await advertiser.announce({
        name: 'First Service',
        type: '_http._tcp',
        host: 'first.local',
        port: 80,
        addresses: ['192.168.1.1'],
      })
    }, 100)

    const service = await browser.first()
    assert.equal(service.name, 'First Service')

    browser.destroy()
    await mdns.destroy()
  })

  test('browser.destroy() ends async iteration', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')
    await mdns.ready()

    const events = []
    const iterationDone = (async () => {
      for await (const event of browser) {
        events.push(event)
      }
    })()

    await advertiser.announce({
      name: 'Before Destroy',
      type: '_http._tcp',
      host: 'bd.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    // Wait for the event to be processed
    await delay(500)

    browser.destroy()
    await iterationDone // Should resolve because destroy ends the iterator

    assert.ok(events.length >= 1, 'should have received at least one event')
    await mdns.destroy()
  })

  test('AbortSignal cancels browsing', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const ac = new AbortController()
    const browser = mdns.browse('_http._tcp', { signal: ac.signal })
    await mdns.ready()

    const events = []
    const iterationDone = (async () => {
      for await (const event of browser) {
        events.push(event)
      }
    })()

    await advertiser.announce({
      name: 'Before Abort',
      type: '_http._tcp',
      host: 'ba.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    await delay(500)
    ac.abort()
    await iterationDone

    assert.ok(events.length >= 1)
    await mdns.destroy()
  })

  test('DnsSdBrowser.destroy() stops all browsers', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser1 = mdns.browse('_http._tcp')
    const browser2 = mdns.browse('_ipp._tcp')

    const done1 = (async () => {
      for await (const _ of browser1) { /* consume */ }
    })()

    const done2 = (async () => {
      for await (const _ of browser2) { /* consume */ }
    })()

    await delay(200)
    await mdns.destroy()

    // Both iterations should complete after destroy
    await done1
    await done2
  })

  test('Symbol.asyncDispose support', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    assert.equal(typeof mdns[Symbol.asyncDispose], 'function')

    const browser = mdns.browse('_http._tcp')
    assert.equal(typeof browser[Symbol.asyncDispose], 'function')

    await mdns.destroy()
  })

  test('browser.services is a Map', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')

    assert.ok(browser.services instanceof Map)
    assert.equal(browser.services.size, 0)

    browser.destroy()
    await mdns.destroy()
  })
})

describe('Error handling', () => {
  /** @type {number} */
  let port
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  test('ignores malformed packets gracefully', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')
    await mdns.ready()
    const iter = browser[Symbol.asyncIterator]()

    // Send garbage data
    await advertiser.sendRaw(Buffer.from([0xff, 0xfe, 0x00, 0x01]))

    // Then send a valid announcement
    await advertiser.announce({
      name: 'After Garbage',
      type: '_http._tcp',
      host: 'ok.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    // The browser should recover and process the valid packet
    const event = await nextEvent(iter)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'After Garbage')

    browser.destroy()
    await mdns.destroy()
  })
})

describe('Event timing', () => {
  /** @type {number} */
  let port
  /** @type {TestAdvertiser} */
  let advertiser

  before(async () => {
    port = await getRandomPort()
    advertiser = new TestAdvertiser({ port })
    await advertiser.start()
  })

  after(async () => {
    await advertiser.stop()
  })

  test('events between browser creation and iterator start are not lost', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')
    await mdns.ready()

    // Announce BEFORE creating the iterator — this is the critical test.
    // Events must be buffered and delivered when iteration starts.
    await advertiser.announce({
      name: 'Early Bird',
      type: '_http._tcp',
      host: 'early.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    // Give time for the event to be processed and buffered
    await delay(300)

    // NOW create the iterator — the event should already be in the buffer
    const iter = browser[Symbol.asyncIterator]()
    const event = await nextEvent(iter, 1000)
    assert.equal(event.type, 'serviceUp')
    assert.equal(event.service.name, 'Early Bird')

    browser.destroy()
    await mdns.destroy()
  })

  test('services map is populated even without active iterator', async () => {
    const mdns = new DnsSdBrowser({ port, interface: TEST_INTERFACE })
    const browser = mdns.browse('_http._tcp')
    await mdns.ready()

    await advertiser.announce({
      name: 'No Iterator',
      type: '_http._tcp',
      host: 'noiter.local',
      port: 80,
      addresses: ['192.168.1.1'],
    })

    await delay(300)

    // browser.services should be populated even though we never iterated
    assert.equal(browser.services.size, 1)
    const service = browser.services.values().next().value
    assert.equal(service.name, 'No Iterator')

    browser.destroy()
    await mdns.destroy()
  })
})
