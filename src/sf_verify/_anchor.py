"""
_anchor.py — externally-anchorable Signed Tree Heads (STHs) over the decision-log chain.

WHY. `decision_log_refinement.py` DISCLOSES the one open hole in the shipped audit chain: `verify_log` accepts a
tail-truncated log as a valid prefix (dropping the LAST entry yields a shorter valid chain). Detecting that
"requires the head-hash length commitment (`chain_binds_history` fixes `l1.length = l2.length`) or an externally
anchored head, a higher layer." This module IS that higher layer.

A `SignedTreeHead` (STH) commits, for a log id, the chain LENGTH and the head entry_hash, signed with the existing
`pcc.sign` (HMAC default, Ed25519 optional). Published STHs form an append-only HEAD-CHAIN (`STH_n.prev_sth_hash =
STH_{n-1}.sth_hash`). An offline verifier that checks a served log AGAINST an STH rejects any log shorter than the
committed length — closing tail-truncation — which is exactly the operational binding to
`AuditChain.chain_binds_history` / `audit_trail_binds` (equal length + equal head ⇒ identical history, given the
cited `hcomb`).

Because the decision log is ALREADY a linear hash-chain (each entry binds `prev_hash`), the inclusion proof for
entry k is just the chain prefix `[0..k]`, and the consistency proof between lengths m ≤ n is the prefix `[0..n]`
whose first m entries reproduce `STH_m`'s head — the chain IS the Merkle path, so we expose those slices rather
than build a redundant tree.

HONESTY / SCOPE (do NOT upgrade): an STH is cryptographic tamper-evidence + authenticity, NOT a legal
non-repudiation instrument, NOT a notary (the same `pcc.sign` boundary). The consuming monitor (`pcc.witness`) is a
REFERENCE, SAME-HOST non-equivocation detector; a genuinely external, cross-host, gossiped transparency-log witness
needs a second host and is the disclosed frontier. Not new cryptography — SHA-256 collision-resistance is the cited
assumption. `ts` is a deterministic caller-supplied integer (never wall-clock) so STHs are byte-reproducible.
"""
from __future__ import annotations

import hashlib
import json

from . import _sign as _sign
from ._decision_log import verify_log, LOG_VERSION

STH_VERSION = "sf-sth/1"
_ZERO = "0" * 64
_STH_BODY_FIELDS = ("sth_version", "log_id", "length", "head_entry_hash", "prev_sth_hash", "ts")


def head_of(entries) -> str:
    """The head entry_hash of a chain (genesis `_ZERO` for the empty log)."""
    return entries[-1]["entry_hash"] if entries else _ZERO


def _sth_hash(body: dict) -> str:
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def make_sth(log_id: str, entries, prev_sth: dict | None = None, ts: int = 0,
             key: bytes | None = None, alg: str | None = None) -> dict:
    """Build (and sign, if a key/alg is available) a Signed Tree Head over the current chain state, linked to the
    previous STH via its `sth_hash`. Deterministic given (log_id, entries, prev_sth, ts, key)."""
    body = {
        "sth_version": STH_VERSION,
        "log_id": log_id,
        "length": len(entries),
        "head_entry_hash": head_of(entries),
        "prev_sth_hash": prev_sth["sth_hash"] if prev_sth else _ZERO,
        "ts": ts,
    }
    h = _sth_hash(body)
    sth = {**body, "sth_hash": h}
    sig = _sign.sign(h, key=key, alg=alg)
    if sig is not None:
        sth["signature"] = sig
    return sth


def verify_sth(sth, key: bytes | None = None) -> tuple[bool, str]:
    """A single STH is valid iff its recomputed hash matches and (when signed) its signature verifies."""
    if not isinstance(sth, dict) or "sth_hash" not in sth:
        return False, "malformed STH"
    if any(f not in sth for f in _STH_BODY_FIELDS):
        return False, "STH missing committed fields"
    body = {f: sth[f] for f in _STH_BODY_FIELDS}
    if _sth_hash(body) != sth["sth_hash"]:
        return False, "STH hash mismatch (tampered)"
    if "signature" in sth:
        ok, why = _sign.verify(sth["sth_hash"], sth["signature"], key=key)
        if not ok:
            return False, f"STH signature invalid: {why}"
    return True, "STH valid"


def verify_sth_strict(sth, *, pinned_operator_public_key: str,
                      expected_key_id: str | None = None) -> tuple[bool, str]:
    """Authority-bearing STH check: a signature is mandatory and its Ed25519 key is pinned out of band."""
    ok, why = verify_sth(sth)
    if not ok:
        return False, why
    if "signature" not in sth:
        return False, "unsigned STH refused by strict verifier"
    ok, why = _sign.verify_pinned_ed25519(
        sth["sth_hash"], sth["signature"], pinned_operator_public_key, expected_key_id)
    return (True, "STH valid under pinned operator key") if ok else (False, why)


def verify_sth_chain(sths, key: bytes | None = None) -> tuple[bool, str]:
    """The published head-chain: each STH links to the previous by `prev_sth_hash` and length is monotone
    non-decreasing (a length rollback is a truncation/fork attempt)."""
    prev_hash = _ZERO
    prev_len = -1
    for i, s in enumerate(sths):
        ok, why = verify_sth(s, key=key)
        if not ok:
            return False, f"STH {i}: {why}"
        if s["prev_sth_hash"] != prev_hash:
            return False, f"STH {i}: broken head-chain link"
        if s["length"] < prev_len:
            return False, f"STH {i}: non-monotone length (rollback/truncation)"
        prev_hash = s["sth_hash"]
        prev_len = s["length"]
    return True, f"{len(sths)} STHs chain-verified"


def verify_log_against_sth(entries, sth, key: bytes | None = None) -> tuple[bool, str]:
    """THE ANCHORED CHECK (closes tail-truncation). A served log is accepted under an STH iff (1) the chain
    itself re-verifies (`verify_log` — the shipped walk), (2) the STH is valid, (3) the served length EQUALS the
    committed length, and (4) the served head EQUALS the committed head. A truncated tail is shorter than the
    committed length ⇒ rejected at (3). This is the running binding to `AuditChain.chain_binds_history`."""
    ok, why = verify_log({"log_version": LOG_VERSION, "entries": entries}, key=key)
    if not ok:
        return False, f"chain invalid: {why}"
    sok, swhy = verify_sth(sth, key=key)
    if not sok:
        return False, f"anchor invalid: {swhy}"
    if len(entries) != sth["length"]:
        return False, (f"length mismatch vs anchor (served {len(entries)}, committed {sth['length']}) "
                       f"-- tail-truncation or extension caught")
    if head_of(entries) != sth["head_entry_hash"]:
        return False, "head mismatch vs anchor (fork/equivocation)"
    return True, f"log matches anchor at length {sth['length']}"


def publish_head(wal, entries, log_id: str = "default", prev_sth: dict | None = None, ts: int = 0,
                 key: bytes | None = None, alg: str | None = None) -> dict:
    """Build an STH over the current chain and RECORD it in a StepWAL as a `HEAD_PUBLISHED` frame — the reserved,
    previously-never-emitted frame kind. Additive: uses only `StepWAL.append`, never changes its semantics."""
    sth = make_sth(log_id, entries, prev_sth=prev_sth, ts=ts, key=key, alg=alg)
    if wal is not None:
        wal.append("HEAD_PUBLISHED", f"sth-{log_id}-{sth['length']}",
                   {"sth_hash": sth["sth_hash"], "length": sth["length"],
                    "head_entry_hash": sth["head_entry_hash"]})
    return sth


# --- inclusion / consistency proofs: the linear hash-chain IS the Merkle path ---------------------------------
def inclusion_proof(entries, seq: int) -> dict:
    """The inclusion proof for entry `seq`: the chain prefix `[0..seq]` (a verifier re-walks it)."""
    return {"seq": seq, "prefix": [dict(e) for e in entries[:seq + 1]]}


def verify_inclusion(proof, entry_hash: str, key: bytes | None = None) -> tuple[bool, str]:
    prefix = proof.get("prefix", [])
    ok, why = verify_log({"log_version": LOG_VERSION, "entries": prefix}, key=key)
    if not ok:
        return False, f"inclusion prefix invalid: {why}"
    if not prefix or prefix[-1].get("entry_hash") != entry_hash:
        return False, "entry not at the committed position"
    return True, f"inclusion verified at seq {proof.get('seq')}"


def consistency_proof(entries, m: int, n: int) -> dict:
    """The consistency proof between lengths m ≤ n: the chain prefix `[0..n]`, whose first m entries must
    reproduce the earlier head."""
    return {"m": m, "n": n, "prefix": [dict(e) for e in entries[:n]]}


def verify_consistency(proof, head_m: str, key: bytes | None = None) -> tuple[bool, str]:
    m, n = proof.get("m"), proof.get("n")
    prefix = proof.get("prefix", [])
    if m is None or n is None or m > n or len(prefix) != n:
        return False, "malformed consistency proof"
    ok, why = verify_log({"log_version": LOG_VERSION, "entries": prefix}, key=key)
    if not ok:
        return False, f"consistency prefix invalid: {why}"
    if head_of(prefix[:m]) != head_m:
        return False, "prefix does not reproduce the earlier head (inconsistent/forked)"
    return True, f"consistency verified {m}->{n}"
