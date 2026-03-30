# Test Review: Correctness, Brittleness, and Implementation Details

## 1. Tests That Don't Test What They Claim

### `fixes.test.js:368` — "allows a new iterator after the previous one returns done"

This test claims to verify that a new iterator works after the previous one finishes, but it actually tests that a *destroyed browser* allows creating new (immediately-done) iterators. The test itself acknowledges this in a comment: `// A new browser is needed since return() destroys the browser.` It creates `browser2`, destroys it, and verifies that a destroyed browser's iterator returns `done: true`. The name is misleading — it doesn't test iterator reuse after completion.

### `browse.test.js:1096` — "destroy during pending goodbye cleans up timers"

The comment says: *"If timers leaked, this test would fail with unhandled timer warnings or the process would hang."* But Node's test runner does **not** automatically detect or fail on leaked timers. This test will pass even if timers leak, as long as the timer callback doesn't crash. The test name promises timer cleanup verification but doesn't actually verify it.

### `rfc-compliance.test.js:614` — "only includes PTR with >50% TTL remaining"

With a 2s TTL, after `delay(1200)` the record is at 40% TTL remaining. The test asserts no known answer is included. But under slow CI, the query might arrive *after* the 2s TTL expires entirely, at which point the service is gone and produces no known answers for a completely different reason (service expired, not TTL suppression). The test passes either way but for potentially wrong reasons.

### `features.test.js:111` — "service with refreshed TTL is not expired"

After announcing with 2s TTL, the test waits 1s, refreshes to 4500s, then waits 2s more. But the final assertion (`browser.services.size, 1`) could pass if the initial timer just ran late, not because the refresh was actually processed. There's no positive assertion that the refresh was received (e.g. checking that `updatedAt` changed, or that the internal TTL was actually updated).

## 2. Brittle / Timing-Sensitive Tests

### `browse.test.js:797` — "sends initial PTR query within 20-120ms (RFC 6762 §5.2)"

Asserts `elapsed >= 15` and `elapsed < 250`. CI environments regularly experience scheduling jitter well beyond 250ms under load. This is one of the most likely tests to flake.

### `rfc-compliance.test.js:585` — "sends at least two queries with increasing intervals"

Asserts the interval between first and second query is `>= 800ms` and `< 2500ms` (expecting ~1000ms). Timer delays under CI load could easily push this past 2500ms.

### `rfc-compliance.test.js:1310` — "suppresses next query when another host sends matching QM query with sufficient known answers"

Complex timing chain: wait for 2 queries, wait 200ms past loopback guard, inject a query, clear queries, measure time to next query, assert `elapsed >= 5000`. Multiple timing assumptions compound: any one delay running long shifts the entire measurement window. The 15s timeout is generous, but the `>= 5000` lower bound is fragile if the browser's schedule gets perturbed.

### `rfc-compliance.test.js:1387` and `rfc-compliance.test.js:1462` — suppression negative tests

Both assert `elapsed < 6000` for a ~4s expected interval. Under load, the 4s timer could fire late enough to exceed the 6s bound even when behavior is correct.

### `browse.test.js:306` — "re-announcement within 1s cancels pending goodbye"

Uses `delay(200)` before re-announcing and `delay(1200)` to wait past the goodbye window. If the 200ms delay + network processing + re-announcement takes >1s total, the goodbye fires before the cancel. On a loaded system, 200ms of actual wall-clock time could consume much more process time.

### General pattern: `delay()` guards throughout the test suite

Many tests use short fixed delays to "wait for processing" (e.g., `browse.test.js:541`, `leniency.test.js:64`, `rfc-compliance.test.js:923`). These are race conditions waiting to happen — they assume internal processing completes within the delay, which isn't guaranteed under load.

## 3. Tests That Test Implementation Details

### `features.test.js:203`, `features.test.js:221`, `features.test.js:644` — QU bit verification via `'UNKNOWN_32769'`

These tests check `question?.class === 'UNKNOWN_32769'` which is `dns-packet`'s string representation of the QU bit (class field value `0x8001`). This couples the tests to `dns-packet`'s specific encoding of non-standard class values. If `dns-packet` changes this representation (e.g., to `'QU'` or a numeric value), these tests break even though the actual QU behavior is correct.

### `rfc-compliance.test.js:1492` and `rfc-compliance.test.js:1796` — raw buffer byte patching for QU bit

```js
quQuery[quQuery.length - 2] = 0x80
```

```js
quBuf.writeUInt16BE(quBuf.readUInt16BE(classOffset) | 0x8000, classOffset)
```

These assume specific byte positions in `dns-packet`'s encoded output. If `dns-packet` changes its encoding (e.g., adds padding, changes compression), these tests break silently or test the wrong bytes.

### `features.test.js:434` — TC bit test patches raw bytes

```js
buf[2] = buf[2] | 0x02
```

Same pattern — directly patches the encoded packet buffer based on assumed DNS header layout. While the DNS header format is standardized, this still couples the test to `dns-packet`'s encoding producing a standard-layout buffer with no wrapper bytes.

### `browse.test.js:605` — `browseAll` with `delay(500)` for sub-browser spawning

Uses a hardcoded 500ms delay to "give the type browser time to discover and spawn a sub-browser." This exposes the internal architecture (type browser -> sub-browser spawning) and the timing of that internal process.

## 4. Minor Issues

### `fixes.test.js:393` — "ready() surfaces the underlying transport error"

Uses port 1 to trigger EACCES, but silently passes if running as root. The try/catch pattern means the test can never fail — it either asserts on the error or silently succeeds. Consider using `test.skip()` explicitly when running as root, so test results clearly show whether the test actually ran.

### `browse.test.js:527` — duplicate detection uses timeout as negative assertion

```js
await assert.rejects(nextEvent(iter, 500), { message: /Timed out/ })
```

Using a 500ms timeout to prove no event was emitted is inherently racy — on a very slow system the event could arrive after 500ms, or on a very fast system, processing might not complete before the check.

## Summary

| Category | Count | Severity |
|---|---|---|
| Tests that don't test what they claim | 4 | Medium — misleading coverage |
| Timing-sensitive / brittle | 7+ | High — likely CI flakes |
| Coupled to implementation details | 6 | Medium — fragile under refactoring |
| Minor issues | 2 | Low |

## Recommendations

1. **Replace fixed delays with event-driven waits** — Instead of `delay(200)` then checking state, wait for the specific condition (e.g., poll `browser.services.size` or use the iterator).
2. **Widen timing bounds for CI** — The query timing tests (initial query, intervals, suppression) should use much more generous bounds or be marked with a `{ todo: 'timing-sensitive' }` annotation.
3. **Abstract away `dns-packet` encoding details** — Add a helper like `setQUBit(encodedPacket)` or `setTCBit(encodedPacket)` instead of patching raw byte offsets.
4. **Fix misleading test names** — Rename the iterator reuse test and the timer cleanup test to accurately describe what they verify.
5. **Make negative timing assertions more robust** — For "no event should arrive" tests, increase the timeout or use a mechanism that positively confirms processing completed before checking.
