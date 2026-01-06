import base64
import hmac
import hashlib
import json
from flask import Blueprint, request, jsonify, current_app

import cbor2
from .db import get_db

bp = Blueprint("ingest", __name__)

REQUIRED_ENVELOPE_KEYS = {
  "device_id",
  "firmware_version",
  "device_tier",
  "sensor_bitmask",
  "packet_sequence",
  "sent_timestamp",
  "samples",
  "hmac",
}

def _canonical_cbor(obj) -> bytes:
  # Canonical encoding is critical so HMAC verification is deterministic.
  return cbor2.dumps(obj, canonical=True)

def _load_device_secret(device_id: str) -> bytes | None:
  db = get_db()
  row = db.execute("SELECT secret_b64 FROM devices WHERE device_id = ?", (device_id,)).fetchone()
  if not row:
    return None
  return base64.b64decode(row["secret_b64"])

def _quarantine(device_id, packet_sequence, raw, reason):
  db = get_db()
  db.execute(
    "INSERT OR IGNORE INTO packets (device_id, packet_sequence, status, reason, raw_cbor) "
    "VALUES (?, ?, 'quarantined', ?, ?)",
    (device_id or "UNKNOWN", int(packet_sequence or -1), reason, raw),
  )
  db.commit()


@bp.post("/ingest/v1")
def ingest_v1():
  raw = request.get_data(cache=False, as_text=False)
  if not raw:
    return jsonify({"ok": False, "error": "empty_body"}), 400
  if len(raw) > 256_000:
    return jsonify({"ok": False, "error": "payload_too_large"}), 413

  # Decode CBOR
  try:
    env = cbor2.loads(raw)
  except Exception:
    _quarantine(None, None, raw, "cbor_decode_failed")
    return jsonify({"ok": False, "error": "bad_cbor"}), 400

  if not isinstance(env, dict):
    _quarantine(None, None, raw, "envelope_not_map")
    return jsonify({"ok": False, "error": "bad_envelope"}), 400

  missing = REQUIRED_ENVELOPE_KEYS - set(env.keys())
  if missing:
    _quarantine(env.get("device_id"), env.get("packet_sequence"), raw, f"missing_keys:{sorted(missing)}")
    return jsonify({"ok": False, "error": "missing_keys", "detail": sorted(missing)}), 400

  device_id = env.get("device_id")
  pkt_seq = env.get("packet_sequence")

  # Extract forcing types
  try:
    pkt_seq = int(pkt_seq)
    sent_ts = int(env.get("sent_timestamp"))
  except Exception:
    _quarantine(device_id, pkt_seq, raw, "bad_numeric_fields")
    return jsonify({"ok": False, "error": "bad_fields"}), 400

  # Verify HMAC
  provided_hmac = env.get("hmac")
  if not isinstance(provided_hmac, (bytes, bytearray)):
    _quarantine(device_id, pkt_seq, raw, "hmac_not_bytes")
    return jsonify({"ok": False, "error": "bad_hmac"}), 400

  secret = _load_device_secret(device_id)
  if not secret:
    _quarantine(device_id, pkt_seq, raw, "unknown_device")
    return jsonify({"ok": False, "error": "unknown_device"}), 401

  env_no_hmac = dict(env)
  env_no_hmac.pop("hmac", None)

  msg = _canonical_cbor(env_no_hmac)
  expected = hmac.new(secret, msg, hashlib.sha256).digest()

  if not hmac.compare_digest(expected, provided_hmac):
    _quarantine(device_id, pkt_seq, raw, "hmac_mismatch")
    return jsonify({"ok": False, "error": "unauthorized"}), 401

  # Minimal sample validation + write
  samples = env.get("samples")
  if not isinstance(samples, list) or len(samples) == 0:
    _quarantine(device_id, pkt_seq, raw, "samples_empty_or_not_list")
    return jsonify({"ok": False, "error": "bad_samples"}), 400

  sensor_bitmask = env.get("sensor_bitmask")

  db = get_db()
  cur = db.execute(
    "INSERT OR IGNORE INTO packets (device_id, packet_sequence, status, reason, raw_cbor) "
    "VALUES (?, ?, 'accepted', NULL, ?)",
    (device_id, pkt_seq, raw),
  )

  if cur.rowcount == 0:
    # A row already exists for this (device_id, packet_sequence)
    row = db.execute(
      "SELECT id, status FROM packets WHERE device_id=? AND packet_sequence=?",
      (device_id, pkt_seq),
    ).fetchone()

    if row and row["status"] == "quarantined":
      # upgrade quarantine -> accepted, and keep going
      db.execute(
        "UPDATE packets SET status='accepted', reason=NULL, raw_cbor=? WHERE id=?",
        (raw, row["id"]),
      )
      packet_id = row["id"]
    else:
      # already accepted => true duplicate
      return jsonify({"ok": True, "accepted_samples": 0, "note": "duplicate_packet"}), 200
  else:
    packet_id = cur.lastrowid


  accepted = 0
  for s in samples:
    if not isinstance(s, dict):
      continue
    try:
      sample_ts = int(s.get("sample_timestamp"))
      event_flags = int(s.get("event_flags") or 0)
      sensor_values = s.get("sensor_values")
      if not isinstance(sensor_values, dict):
        continue
    except Exception:
      continue

    db.execute(
      "INSERT INTO samples (device_id, packet_id, sample_ts, event_flags, sensor_bitmask, sensor_values_json) VALUES (?, ?, ?, ?, ?, ?)",
      (device_id, packet_id, sample_ts, event_flags, str(sensor_bitmask), json.dumps(sensor_values, separators=(",", ":"))),
    )
    accepted += 1

  db.commit()

  if accepted == 0:
    # Keep the packet accepted (it was authentic), but mark it suspicious later if you want.
    return jsonify({"ok": True, "accepted_samples": 0, "note": "no_valid_samples"}), 200

  return jsonify({"ok": True, "accepted_samples": accepted}), 200
