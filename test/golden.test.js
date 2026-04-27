/**
 * Golden-packet replay tests.
 *
 * Decodes every `.bin` fixture under `test/fixtures/packets/` with
 * `lib/dns.js` and compares the result to a sibling `.snap.json` file.
 * Also walks any `.pcap` fixture, extracts each unique mDNS UDP payload,
 * and snapshots it as `<pcap>.NNN.snap.json` indexed by capture order
 * (zero-padded so lexical sort matches numeric order).
 *
 * A new fixture (or one without a snapshot) writes its snapshot on the
 * first run when `UPDATE_SNAPSHOTS=1` is set; otherwise the missing
 * snapshot is treated as a test failure so unreviewed bytes don't
 * silently freeze.
 *
 * Run `UPDATE_SNAPSHOTS=1 node --test test/golden.test.js` to refresh
 * snapshots after a deliberate change to the decoder. Review the JSON
 * diff before committing.
 *
 * @module
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, writeFileSync, existsSync, realpathSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { decode } from '../lib/dns.js'
import { extractMdnsPayloads } from './helpers/pcap.js'

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/packets/', import.meta.url))
const REPO_ROOT = fileURLToPath(new URL('../', import.meta.url))
const UPDATE = process.env.UPDATE_SNAPSHOTS === '1'

/**
 * Recursively collect every fixture file (bin or pcap) under `dir`.
 * Resolves symlinks via realpath to break loops.
 * @param {string} dir
 * @param {Set<string>} [visited] - Real paths already entered
 * @returns {string[]}
 */
function findFixtures(dir, visited = new Set()) {
  const real = realpathSync(dir)
  if (visited.has(real)) return []
  visited.add(real)

  /** @type {string[]} */
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...findFixtures(full, visited))
    else if (entry.isFile() && (entry.name.endsWith('.bin') || entry.name.endsWith('.pcap'))) {
      out.push(full)
    }
  }
  return out.sort()
}

/**
 * Convert a Uint8Array to a readable JSON form: prefer UTF-8 if the bytes
 * round-trip cleanly, otherwise hex. Keeps snapshots reviewable in PRs
 * without losing fidelity for binary data.
 * @param {Uint8Array} bytes
 * @returns {object}
 */
function bytesToJson(bytes) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    // Reject control characters (except tab/newline/CR) — they'd render badly
    // in a snapshot and usually mean the bytes weren't intended as text.
    // eslint-disable-next-line no-control-regex
    if (!/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)) {
      return { utf8: text }
    }
  } catch {
    // not valid UTF-8 — fall through to hex
  }
  return { hex: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex') }
}

/**
 * Recursively normalise a decoded packet into a stable JSON-serialisable
 * shape: Uint8Array values become { utf8 } or { hex } objects.
 * @param {unknown} value
 * @returns {unknown}
 */
function normalise(value) {
  if (value === null || value === undefined) return value
  if (value instanceof Uint8Array) return bytesToJson(value)
  if (Array.isArray(value)) return value.map(normalise)
  if (typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {}
    for (const key of Object.keys(value).sort()) {
      out[key] = normalise(/** @type {Record<string, unknown>} */ (value)[key])
    }
    return out
  }
  return value
}

/** @param {unknown} obj */
function stableStringify(obj) {
  return JSON.stringify(obj, null, 2) + '\n'
}

/**
 * Compare a decoded packet against its on-disk snapshot, writing under
 * UPDATE and asserting otherwise.
 * @param {string} snapPath - Absolute path to the .snap.json file
 * @param {string} label - Human-readable label for failure messages (repo-relative)
 * @param {unknown} decoded - Output of dns.decode()
 */
function assertSnapshot(snapPath, label, decoded) {
  const actual = stableStringify(normalise(decoded))

  if (!existsSync(snapPath)) {
    if (UPDATE) {
      writeFileSync(snapPath, actual)
      return
    }
    assert.fail(
      `Missing snapshot for ${label}. Run with UPDATE_SNAPSHOTS=1 to create it, then review the diff before committing.`
    )
  }

  const expected = readFileSync(snapPath, 'utf8')
  if (UPDATE && expected !== actual) {
    writeFileSync(snapPath, actual)
    return
  }

  assert.equal(
    actual,
    expected,
    `Snapshot mismatch for ${label}. If the change is intentional, re-run with UPDATE_SNAPSHOTS=1 and review the diff.`
  )
}

/**
 * Dedupe payloads by content and return them in original capture order.
 * @param {Uint8Array[]} payloads
 * @returns {Uint8Array[]}
 */
function dedupeByContent(payloads) {
  const seen = new Set()
  const out = []
  for (const p of payloads) {
    const h = createHash('sha256').update(p).digest('hex')
    if (seen.has(h)) continue
    seen.add(h)
    out.push(p)
  }
  return out
}

describe('Golden packet replay', () => {
  const fixtures = findFixtures(FIXTURES_DIR)
  assert.ok(fixtures.length > 0, 'no fixtures found under test/fixtures/packets/')

  for (const fixturePath of fixtures) {
    const relPath = relative(REPO_ROOT, fixturePath)

    if (fixturePath.endsWith('.bin')) {
      const snapPath = fixturePath + '.snap.json'
      test(`decodes ${relPath}`, () => {
        const buf = readFileSync(fixturePath)
        assertSnapshot(snapPath, relPath, decode(buf))
      })
      continue
    }

    // .pcap: extract every unique mDNS payload, snapshot each by capture
    // index. Zero-padding to 3 digits keeps lexical sort matching numeric
    // order (so the diff lists snapshots in capture order). It does NOT
    // prevent renumbering — adding/removing a payload mid-capture shifts
    // every later index. Replacing the whole pcap is therefore a deliberate
    // act: re-run with UPDATE_SNAPSHOTS=1 and review the full diff.
    test(`extracts and decodes ${relPath}`, () => {
      const buf = readFileSync(fixturePath)
      const payloads = dedupeByContent(extractMdnsPayloads(buf))
      assert.ok(payloads.length > 0, `no mDNS payloads found in ${relPath}`)
      payloads.forEach((payload, i) => {
        const idx = String(i).padStart(3, '0')
        const snapPath = `${fixturePath}.${idx}.snap.json`
        const label = `${relPath} [${idx}]`
        assertSnapshot(snapPath, label, decode(payload))
      })
    })
  }
})
