/**
 * Golden-packet replay tests.
 *
 * Decodes every `.bin` fixture under `test/fixtures/packets/` with
 * `lib/dns.js` and compares the result to a sibling `.snap.json` file.
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
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { decode } from '../lib/dns.js'

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/packets/', import.meta.url))
const REPO_ROOT = fileURLToPath(new URL('../', import.meta.url))
const UPDATE = process.env.UPDATE_SNAPSHOTS === '1'

/**
 * Recursively collect every `.bin` file under `dir`.
 * @param {string} dir
 * @returns {string[]}
 */
function findBinFiles(dir) {
  /** @type {string[]} */
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...findBinFiles(full))
    else if (entry.isFile() && entry.name.endsWith('.bin')) out.push(full)
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

describe('Golden packet replay', () => {
  const fixtures = findBinFiles(FIXTURES_DIR)
  assert.ok(fixtures.length > 0, 'no .bin fixtures found under test/fixtures/packets/')

  for (const binPath of fixtures) {
    const relPath = relative(REPO_ROOT, binPath)
    const snapPath = binPath + '.snap.json'

    test(`decodes ${relPath}`, () => {
      const buf = readFileSync(binPath)
      const decoded = decode(buf)
      const normalised = normalise(decoded)
      const actual = stableStringify(normalised)

      if (!existsSync(snapPath)) {
        if (UPDATE) {
          writeFileSync(snapPath, actual)
          return
        }
        assert.fail(
          `Missing snapshot for ${relPath}. Run with UPDATE_SNAPSHOTS=1 to create it, then review the diff before committing.`
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
        `Snapshot mismatch for ${relPath}. If the change is intentional, re-run with UPDATE_SNAPSHOTS=1 and review the diff.`
      )
    })
  }
})
