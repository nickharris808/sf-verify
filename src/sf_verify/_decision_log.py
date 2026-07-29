"""
_decision_log.py — an append-only, hash-CHAINED, SIGNED admission decision log.

Each admission decision appends one entry binding its `canonical_hash` (from a PCC bundle) into a
tamper-evident chain: entry N carries `prev_hash` = the hash of entry N-1, its own `entry_hash`, and
(when a key is configured) an HMAC/Ed25519 signature over that entry_hash. `verify_log` re-derives the
whole chain and detects any TAMPER (an altered field), DELETION or REORDER (a broken prev_hash link or a
seq gap), and forged signatures. This is the "signed audit record" a CISO wants: not just one receipt,
but an ordered, gap-proof ledger of every decision.

stdlib only (hashlib/hmac/json via `sign`). No key configured → the chain is still tamper-evident
(hash-linked), just unsigned — backward compatible.
"""
from __future__ import annotations

import hashlib
import json

from . import _sign as _sign

LOG_VERSION = "1"
_ZERO = "0" * 64


def _entry_hash(seq: int, prev_hash: str, canonical_hash: str, verdict, ts) -> str:
    blob = json.dumps({"seq": seq, "prev_hash": prev_hash, "canonical_hash": canonical_hash,
                       "verdict": verdict, "ts": ts}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


class DecisionLog:
    """An in-memory append-only chain. Persist `to_dict()` as JSON; re-hydrate with `DecisionLog(entries)`."""

    def __init__(self, entries=None):
        self.entries = list(entries or [])

    def append(self, canonical_hash: str, verdict, ts, key: bytes | None = None) -> dict:
        seq = len(self.entries)
        prev = self.entries[-1]["entry_hash"] if self.entries else _ZERO
        eh = _entry_hash(seq, prev, canonical_hash, verdict, ts)
        entry = {"seq": seq, "prev_hash": prev, "canonical_hash": canonical_hash,
                 "verdict": verdict, "ts": ts, "entry_hash": eh}
        sig = _sign.sign(eh, key=key)
        if sig is not None:
            entry["signature"] = sig
        self.entries.append(entry)
        return entry

    def to_dict(self) -> dict:
        return {"log_version": LOG_VERSION, "entries": self.entries}


def verify_log(log, key: bytes | None = None, *, require_signatures: bool = False,
               pinned_ed25519_public_key: str | None = None) -> tuple[bool, str]:
    """Re-derive the whole chain. Detects tamper (hash mismatch), deletion/reorder (broken prev link or
    seq gap), and invalid signatures. Returns (ok, reason)."""
    if isinstance(log, dict):
        if log.get("log_version") != LOG_VERSION:
            return False, f"unsupported log_version (want {LOG_VERSION})"
        entries = log.get("entries", [])
    else:
        entries = log
    # Supplying an out-of-band key is an authority-bearing operation.  It must not silently accept a stripped
    # unsigned chain; callers cannot accidentally request pinning without mandatory signatures.
    require_signatures = require_signatures or pinned_ed25519_public_key is not None or key is not None
    prev = _ZERO
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            return False, f"seq gap/reorder at index {i} (entry seq={e.get('seq')})"
        if e.get("prev_hash") != prev:
            return False, f"chain break at seq {i} (deletion or reorder)"
        eh = _entry_hash(e["seq"], e["prev_hash"], e["canonical_hash"], e["verdict"], e["ts"])
        if eh != e.get("entry_hash"):
            return False, f"entry {i} tampered (entry_hash mismatch)"
        if require_signatures and "signature" not in e:
            return False, f"entry {i} missing mandatory signature"
        if "signature" in e:
            if pinned_ed25519_public_key is not None:
                ok, why = _sign.verify_pinned_ed25519(eh, e["signature"], pinned_ed25519_public_key)
            else:
                ok, why = _sign.verify(eh, e["signature"], key=key)
            if not ok:
                return False, f"entry {i} signature invalid: {why}"
        prev = eh
    return True, f"{len(entries)} entries chain-verified"
