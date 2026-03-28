#!/usr/bin/env node
/**
 * Test advertiser for manual Bonjour compliance testing.
 *
 * Registers a service via the system mDNS daemon (Bonjour on macOS,
 * Avahi on Linux) so you can test dns-sd-browser against a real
 * mDNS stack.
 *
 * Usage:
 *   node scripts/bonjour-advertise.js [options]
 *
 * Options:
 *   --name <name>    Service instance name (default: "Test Service")
 *   --type <type>    Service type (default: "_http._tcp")
 *   --port <port>    Port number (default: 8080)
 *   --txt <k=v,...>  TXT record key=value pairs, comma-separated
 *
 * Examples:
 *   node scripts/bonjour-advertise.js
 *   node scripts/bonjour-advertise.js --name "My Printer" --type _ipp._tcp --port 631
 *   node scripts/bonjour-advertise.js --txt "path=/api,version=2"
 *
 * On macOS, this uses the dns-sd CLI tool.
 * On Linux, this uses avahi-publish-service.
 *
 * Press Ctrl+C to stop advertising.
 */

import { spawn } from 'node:child_process'
import { platform } from 'node:os'

const args = process.argv.slice(2)

function getArg(name, defaultValue) {
  const idx = args.indexOf(`--${name}`)
  if (idx === -1 || idx + 1 >= args.length) return defaultValue
  return args[idx + 1]
}

const name = getArg('name', 'Test Service')
const type = getArg('type', '_http._tcp')
const port = getArg('port', '8080')
const txtArg = getArg('txt', '')

const txtPairs = txtArg
  ? txtArg.split(',').map((kv) => kv.trim())
  : []

const os = platform()

if (os === 'darwin') {
  // macOS: use dns-sd command
  const cmdArgs = ['-R', name, type, '.', port, ...txtPairs]
  console.log(`[macOS] dns-sd ${cmdArgs.join(' ')}`)
  console.log(`Registering "${name}" as ${type} on port ${port}...`)

  const proc = spawn('dns-sd', cmdArgs, { stdio: 'inherit' })
  proc.on('error', (err) => {
    console.error('Failed to start dns-sd:', err.message)
    process.exit(1)
  })

  process.on('SIGINT', () => {
    proc.kill()
    process.exit(0)
  })
} else if (os === 'linux') {
  // Linux: use avahi-publish-service
  const cmdArgs = [name, type, port, ...txtPairs]
  console.log(`[Linux] avahi-publish-service ${cmdArgs.join(' ')}`)
  console.log(`Registering "${name}" as ${type} on port ${port}...`)
  console.log('(Requires avahi-utils: sudo apt install avahi-utils)')

  const proc = spawn('avahi-publish-service', cmdArgs, { stdio: 'inherit' })
  proc.on('error', (err) => {
    if (err.code === 'ENOENT') {
      console.error('avahi-publish-service not found. Install it with:')
      console.error('  sudo apt install avahi-utils')
    } else {
      console.error('Failed to start avahi-publish-service:', err.message)
    }
    process.exit(1)
  })

  process.on('SIGINT', () => {
    proc.kill()
    process.exit(0)
  })
} else {
  console.error(`Unsupported platform: ${os}`)
  console.error('Manual Bonjour testing requires macOS or Linux with Avahi.')
  process.exit(1)
}
