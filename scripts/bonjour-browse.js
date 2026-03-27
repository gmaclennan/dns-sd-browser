#!/usr/bin/env node
/**
 * Test browser for manual Bonjour compliance testing.
 *
 * Uses dns-sd-browser to discover services on the local network,
 * logging all events. Compare the output against the system's own
 * mDNS tools (dns-sd -B on macOS, avahi-browse on Linux) to verify
 * compliance.
 *
 * Usage:
 *   node scripts/bonjour-browse.js [service-type]
 *
 * Examples:
 *   node scripts/bonjour-browse.js                # browse _http._tcp
 *   node scripts/bonjour-browse.js _ipp._tcp      # browse printers
 *   node scripts/bonjour-browse.js --all           # browse all service types
 *
 * Press Ctrl+C to stop browsing.
 */

import { DnsSdBrowser } from '../lib/index.js'

const arg = process.argv[2] || '_http._tcp'
const mdns = new DnsSdBrowser()

const browser = arg === '--all'
  ? mdns.browseAll()
  : mdns.browse(arg)

console.log(`Browsing for ${arg === '--all' ? 'all service types' : arg}...`)
console.log('Press Ctrl+C to stop.\n')

process.on('SIGINT', async () => {
  console.log('\nStopping...')
  browser.destroy()
  await mdns.destroy()
  process.exit(0)
})

for await (const event of browser) {
  const ts = new Date().toISOString().slice(11, 23)
  const svc = event.service

  switch (event.type) {
    case 'serviceUp':
      console.log(`[${ts}] + UP   ${svc.name}`)
      console.log(`         type: ${svc.type} domain: ${svc.domain}`)
      console.log(`         host: ${svc.host}:${svc.port}`)
      if (svc.addresses.length > 0) {
        console.log(`         addr: ${svc.addresses.join(', ')}`)
      }
      if (Object.keys(svc.txt).length > 0) {
        console.log(`         txt:  ${JSON.stringify(svc.txt)}`)
      }
      console.log()
      break
    case 'serviceDown':
      console.log(`[${ts}] - DOWN ${svc.name}`)
      console.log()
      break
    case 'serviceUpdated':
      console.log(`[${ts}] ~ UPD  ${svc.name}`)
      if (Object.keys(svc.txt).length > 0) {
        console.log(`         txt:  ${JSON.stringify(svc.txt)}`)
      }
      console.log()
      break
  }
}
