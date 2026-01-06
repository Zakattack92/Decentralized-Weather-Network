# Decentralized Weather Network — Protocol v1 (CBOR)

This document defines the on-wire **packet envelope** and **sample** schema for device → server
(and device → relay → server). The protocol is designed for:
- truth-first data (no interpolation)
- late/out-of-order acceptance
- low-power / low-bandwidth transport
- forward-compatible evolution

---

## 0) Encoding + Signature

- **Encoding:** CBOR (RFC 8949)
- **Signing:** HMAC-SHA256 over a deterministic CBOR encoding of `sig_v`.
- **Replay resistance:** `(did, seq)` uniqueness + server-side windowing.
- **Idempotency:** server dedupes by `(did, seq)` and per-sample `sid`.

---

## 1) Canonical Terms

- **DID (`did`)**: immutable device id (string)
- **Tier (`tier`)**: `"cabin" | "house" | "mansion" | "relay"`
- **Sensor bitmask (`s_bm`)**: uint64 capability declaration (provisioned; immutable)
- **Event bitmask (`e_bm`)**: uint32 event declaration (runtime; explicit)
- **Sample ID (`sid`)**: unique per sample (uint64) to support dedupe and referencing
- **Time (`t`)**: unix epoch milliseconds (int64). Device local time is acceptable; server tolerates drift.

---

## 2) Packet Envelope (v1)

Top-level CBOR **map** with the following keys.

### Required fields

| Key | Type | Notes |
|---|---:|---|
| `v` | uint | Protocol version. **Must be `1`**. |
| `did` | tstr | Device ID. |
| `tier` | tstr | `"cabin"|"house"|"mansion"|"relay"` |
| `fw` | tstr | Firmware version string (e.g. `"1.0.3"`). |
| `seq` | uint | Monotonic packet sequence (per device). |
| `sent_t` | int | Device time (ms) when packet was created/sent. |
| `s_bm` | uint | Sensor capability bitmask (uint64). |
| `samples` | array | Array of sample maps (see §3). |
| `sig_v` | bstr | Bytes of canonical CBOR used for signing (see below). |
| `sig` | bstr | HMAC-SHA256(signature over `sig_v`). |

### Optional fields (allowed in v1)

| Key | Type | Notes |
|---|---:|---|
| `rt` | tstr | Relay ID (if forwarded by relay). Relay must not modify `samples`. |
| `rssi` | int | Last-link RSSI (LoRa) at receiver, if known. |
| `snr` | int | Last-link SNR (LoRa) at receiver, if known. |
| `flags` | uint | Envelope flags (reserved). |

### `sig_v` canonicalization

`sig_v` is the CBOR encoding of this map:

```text
{
  "v":1,
  "did":...,
  "tier":...,
  "fw":...,
  "seq":...,
  "sent_t":...,
  "s_bm":...,
  "samples":[...]
  // plus any v1 optional fields that affect meaning:
  // "rt","rssi","snr","flags"
}
