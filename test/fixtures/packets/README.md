# Golden packet fixtures

Real-world mDNS / DNS-SD packets, used by `test/golden.test.js` to verify
that the decoder in `lib/dns.js` handles wire-format shapes that occur in
the wild — not just the ones we'd construct synthetically with `dns-packet`.

Each `.bin` file is the raw UDP payload of a single mDNS packet. Each has
a sibling `.snap.json` produced by `dns.decode()` and normalised
(`Uint8Array` values become `{ utf8 }` if the bytes round-trip cleanly,
`{ hex }` otherwise). On every test run the decoder is re-applied and the
result is compared to the snapshot — any decoder change shows up as a
reviewable JSON diff.

To refresh after a deliberate decoder change:

```sh
UPDATE_SNAPSHOTS=1 node --test test/golden.test.js
```

Review the snapshot diff before committing.

## Provenance

### `dnssd-js/`

24 fixtures imported verbatim from
[DeMille/dnssd.js — `test/data/packets/`](https://github.com/DeMille/dnssd.js/tree/master/test/data/packets),
licensed MIT (see `THIRD_PARTY_LICENSES` at the repo root). Notable cases
this corpus covers that our synthetic tests do not:

- NSEC records (type 47) in the additionals section, as Avahi /
  mDNSResponder commonly ship them.
- Real Chromecast service-probe packet (with TXT keys redacted in the
  upstream — IDs are padded with `1`s).
- AirPlay / RAOP-style instance names (`MAC@Name._raop._tcp.local`).
- A query with a long known-answer list (suppression edge cases).
- Multiple announcements with OPT pseudo-records.
- TXT records up to several hundred bytes.

For each case the corpus provides both a compressed packet (`*.bin`) and
a hand-uncompressed reference (`*.uncompressed.bin`), so name-compression
handling can be exercised in both directions.

### `wireshark/dns-mdns.pcap`

Single mDNS pcap from
[Wireshark sample captures](https://gitlab.com/wireshark/wireshark/-/blob/master/test/captures/dns-mdns.pcap),
public-domain per the
[SampleCaptures policy](https://wiki.wireshark.org/SampleCaptures). Not
yet replayed by the golden test — this is raw provenance for a follow-up
that adds a small pcap extractor.
