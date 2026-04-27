/**
 * Golden-packet replay tests.
 *
 * For every `.bin` and `.pcap` fixture under `test/fixtures/packets/`,
 * each unique mDNS payload is decoded twice:
 *
 * 1. Cross-validated against `dns-packet`. This is the actual correctness
 *    check — it catches divergence in the structurally-decoded fields
 *    (names, types, classes, TTLs, A/AAAA addresses, SRV target/port,
 *    PTR data, TXT byte arrays). Opaque types (HINFO/OPT/NSEC) are
 *    envelope-only because the two libraries decode their RDATA
 *    differently.
 *
 * 2. Compared against a sibling `.snap.json` snapshot. The snapshot is
 *    the reviewable artifact in PRs and the regression catch — it pins
 *    the *exact* decoder output for a given fixture, so any change
 *    becomes a JSON diff.
 *
 * Pcap fixtures are walked: each unique mDNS UDP payload (deduped by
 * content, kept in capture order) is snapshotted as `<pcap>.NNN.snap.json`.
 * Zero-padding to 3 digits keeps lexical sort matching numeric order;
 * it does NOT prevent renumbering when payloads are added or removed.
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
import { stringify as safeStringify } from 'safe-stable-stringify'
import * as dnsPacket from 'dns-packet'
import { decode } from '../lib/dns.js'
import { extractMdnsPayloads } from './helpers/pcap.js'

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/packets/', import.meta.url))
const REPO_ROOT = fileURLToPath(new URL('../', import.meta.url))
const UPDATE = process.env.UPDATE_SNAPSHOTS === '1'

/** Map of integer record types to dns-packet's string names. */
const TYPE_NAMES = {
  1: 'A',
  12: 'PTR',
  13: 'HINFO',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  41: 'OPT',
  47: 'NSEC',
  255: 'ANY',
}

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
 * JSON replacer: render binary RDATA as { hex } so the snapshot is
 * deterministic and lossless. Two shapes show up because Node's
 * `Buffer.toJSON()` runs before our replacer and converts Buffers to
 * `{ type: 'Buffer', data: [...] }`, while plain Uint8Arrays reach
 * the replacer untouched.
 * @param {string} _key
 * @param {unknown} value
 */
function jsonReplacer(_key, value) {
  if (value instanceof Uint8Array) {
    return {
      hex: Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('hex'),
    }
  }
  if (
    value !== null &&
    typeof value === 'object' &&
    /** @type {{ type?: unknown }} */ (value).type === 'Buffer' &&
    Array.isArray(/** @type {{ data?: unknown }} */ (value).data)
  ) {
    return {
      hex: Buffer.from(/** @type {{ data: number[] }} */ (value).data).toString('hex'),
    }
  }
  return value
}

/**
 * Serialise a decoded packet to a stable, reviewable JSON string.
 * `safe-stable-stringify` handles deterministic key ordering.
 * @param {unknown} decoded
 * @returns {string}
 */
function serialise(decoded) {
  return safeStringify(decoded, jsonReplacer, 2) + '\n'
}

/**
 * Compare a decoded packet against its on-disk snapshot, writing under
 * UPDATE and asserting otherwise.
 * @param {string} snapPath - Absolute path to the .snap.json file
 * @param {string} label - Human-readable label for failure messages (repo-relative)
 * @param {unknown} decoded - Output of dns.decode()
 */
function assertSnapshot(snapPath, label, decoded) {
  const actual = serialise(decoded)

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
 * Cross-check our decoder's output against `dns-packet` for the same
 * wire bytes. This is the correctness check — snapshots only catch
 * regressions of our own output, not bugs that have always been there.
 * @param {Uint8Array} buf
 * @param {ReturnType<typeof decode>} ours
 * @param {string} label
 */
function crossValidate(buf, ours, label) {
  const ref = dnsPacket.decode(Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength))
  assert.equal(ours.id, ref.id, `${label}: id`)

  for (const section of /** @type {const} */ (['questions', 'answers', 'authorities', 'additionals'])) {
    const our = ours[section]
    const refSec = ref[section] ?? []
    assert.equal(our.length, refSec.length, `${label}: ${section}.length`)
    for (let i = 0; i < our.length; i++) {
      compareRecord(section, our[i], refSec[i], `${label}: ${section}[${i}]`)
    }
  }
}

/**
 * @param {'questions' | 'answers' | 'authorities' | 'additionals'} section
 * @param {any} ours
 * @param {any} ref
 * @param {string} label
 */
function compareRecord(section, ours, ref, label) {
  // DNS names are case-insensitive (RFC 1035 §2.3.3); both libraries
  // preserve on-the-wire case, but case differences shouldn't fail.
  assert.equal(ours.name.toLowerCase(), ref.name.toLowerCase(), `${label}.name`)

  const expectedType = TYPE_NAMES[ours.type] ?? ours.type
  assert.equal(expectedType, ref.type, `${label}.type`)

  if (section === 'questions') return

  // OPT records repurpose the class field as EDNS UDP payload size and
  // the TTL field as extended-RCODE / version / flags (RFC 6891 §6.1.3),
  // so neither cross-checks meaningfully against dns-packet's OPT shape.
  if (ours.type !== 41) {
    assert.equal(ours.ttl, ref.ttl, `${label}.ttl`)
    assert.equal(!!ours.cacheFlush, !!ref.flush, `${label}.cacheFlush↔flush`)
  }

  switch (ours.type) {
    case 1: // A
    case 28: // AAAA
      assert.equal(ours.data, ref.data, `${label}.data`)
      break
    case 12: // PTR
      assert.equal(ours.data.toLowerCase(), ref.data.toLowerCase(), `${label}.data`)
      break
    case 33: // SRV
      assert.equal(ours.data.priority, ref.data.priority, `${label}.data.priority`)
      assert.equal(ours.data.weight, ref.data.weight, `${label}.data.weight`)
      assert.equal(ours.data.port, ref.data.port, `${label}.data.port`)
      assert.equal(
        ours.data.target.toLowerCase(),
        ref.data.target.toLowerCase(),
        `${label}.data.target`
      )
      break
    case 16: { // TXT
      const refTxt = Array.isArray(ref.data) ? ref.data : [ref.data]
      assert.equal(ours.data.length, refTxt.length, `${label}.data.length`)
      for (let i = 0; i < ours.data.length; i++) {
        const ourBytes = Buffer.from(
          ours.data[i].buffer,
          ours.data[i].byteOffset,
          ours.data[i].byteLength
        )
        assert.deepEqual(ourBytes, Buffer.from(refTxt[i]), `${label}.data[${i}]`)
      }
      break
    }
    // Opaque types (HINFO/OPT/NSEC/etc.): the two libraries return
    // different shapes, so envelope-only is the best we can do here.
  }
}

/**
 * Dedupe payloads by content (ignoring the 16-bit DNS transaction ID at
 * offset 0–1) and return them in original capture order. Real captures
 * tend to repeat the same logical query with rolling IDs; without this,
 * one Wireshark dump produces dozens of snapshots that differ only in
 * two bytes, all decoding through the same paths.
 * @param {Uint8Array[]} payloads
 * @returns {Uint8Array[]}
 */
function dedupeByContent(payloads) {
  const seen = new Set()
  const out = []
  for (const p of payloads) {
    if (p.byteLength < 2) continue
    const hash = createHash('sha256')
    hash.update(new Uint8Array(2)) // zero the id
    hash.update(p.subarray(2))
    const h = hash.digest('hex')
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
        const decoded = decode(buf)
        crossValidate(buf, decoded, relPath)
        assertSnapshot(snapPath, relPath, decoded)
      })
      continue
    }

    test(`extracts and decodes ${relPath}`, () => {
      const buf = readFileSync(fixturePath)
      const payloads = dedupeByContent(extractMdnsPayloads(buf))
      assert.ok(payloads.length > 0, `no mDNS payloads found in ${relPath}`)
      payloads.forEach((payload, i) => {
        const idx = String(i).padStart(3, '0')
        const snapPath = `${fixturePath}.${idx}.snap.json`
        const label = `${relPath} [${idx}]`
        const decoded = decode(payload)
        crossValidate(payload, decoded, label)
        assertSnapshot(snapPath, label, decoded)
      })
    })
  }
})
