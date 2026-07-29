"""
_sign.py — receipt signatures over a decision entry's canonical hash.

Before this, a receipt was sha256 tamper-EVIDENT (a recomputable canonical_hash) but UNSIGNED — anyone
could mint one; the only keyed thing in the repo was a demo HMAC with a hardcoded key. This adds an
authenticity layer over the receipt's `canonical_hash`:

  * DEFAULT — HMAC-SHA256 (stdlib `hmac`, ZERO new deps): a shared-secret signature keyed from
    `SF_RECEIPT_KEY` (env / K8s secret). Verifiable by any holder of the key. Signing the canonical_hash
    (not the whole bundle) preserves the extracted-vs-mirror reproducibility: the same decision yields
    the same canonical_hash → the same signature.
  * OPTIONAL — Ed25519 (public-verifiable, third-party non-repudiation) behind the `[crypto]` extra
    (`cryptography`). Selected with `SF_RECEIPT_ALG=Ed25519` + a private key in `SF_RECEIPT_ED25519_SK`
    (hex). If the extra/key is absent it degrades to unsigned (honest NA), exactly like the ortools rungs.

HONESTY / SCOPE: an HMAC signature is verifiable by a SHARED-SECRET holder; an Ed25519 signature is
PUBLIC-verifiable with the embedded public key. NEITHER is a legal non-repudiation instrument — they are
cryptographic tamper-evidence + authenticity, not a notarization. No real key is ever committed; tests
pass an explicit key.
"""
from __future__ import annotations

import hashlib
import hmac
import os

HMAC_ALG = "HMAC-SHA256"
ED25519_ALG = "Ed25519"
_LEGAL_NOTE = "cryptographic tamper-evidence + authenticity; NOT a legal non-repudiation instrument"


def key_from_env() -> bytes | None:
    """The HMAC key from SF_RECEIPT_KEY (env / mounted secret), or None (receipt stays unsigned)."""
    k = os.environ.get("SF_RECEIPT_KEY")
    return k.encode() if k else None


def key_id(key: bytes) -> str:
    """A NON-secret identifier for a key (sha256 of a domain-separated key), so a verifier can tell
    WHICH key signed without learning the key."""
    return "hmac-" + hashlib.sha256(b"sf-receipt-kid|" + key).hexdigest()[:16]


def sign(canonical_hash: str, key: bytes | None = None, alg: str | None = None) -> dict | None:
    """Sign a receipt's canonical_hash. Returns a signature dict, or None when no key/alg is available
    (the receipt stays UNSIGNED but tamper-evident — backward compatible)."""
    alg = alg or os.environ.get("SF_RECEIPT_ALG", HMAC_ALG)
    if alg == ED25519_ALG:
        return _sign_ed25519(canonical_hash)
    key = key if key is not None else key_from_env()
    if not key:
        return None
    sig = hmac.new(key, canonical_hash.encode(), hashlib.sha256).hexdigest()
    return {"alg": HMAC_ALG, "key_id": key_id(key), "sig": sig, "note": "shared-secret HMAC — " + _LEGAL_NOTE}


def verify(canonical_hash: str, signature: dict, key: bytes | None = None) -> tuple[bool, str]:
    """Verify a signature over canonical_hash. HMAC needs the shared key (arg or SF_RECEIPT_KEY);
    Ed25519 verifies with the signature's embedded public key (no secret needed)."""
    if not isinstance(signature, dict) or "alg" not in signature or "sig" not in signature:
        return False, "malformed signature"
    if signature["alg"] == ED25519_ALG:
        return _verify_ed25519(canonical_hash, signature)
    if signature["alg"] != HMAC_ALG:
        return False, f"unsupported signature alg {signature['alg']!r}"
    key = key if key is not None else key_from_env()
    if not key:
        return False, "no HMAC key configured (SF_RECEIPT_KEY) to verify the signature"
    expected = hmac.new(key, canonical_hash.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, signature.get("sig", "")):
        return True, "HMAC-SHA256 signature valid"
    return False, "HMAC-SHA256 signature INVALID (wrong key or tampered canonical_hash)"


# --- optional Ed25519 (public-verifiable) behind the [crypto] extra --------------------------------
def _ed25519_backend():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                                        Ed25519PublicKey)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return Ed25519PrivateKey, Ed25519PublicKey, Encoding, PublicFormat
    except Exception:
        return None, None, None, None


def ed25519_available() -> bool:
    """True iff the [crypto] extra is installed (else the Ed25519 path degrades to unsigned/NA)."""
    return _ed25519_backend()[0] is not None


def _sign_ed25519(canonical_hash: str) -> dict | None:
    Priv, _Pub, Encoding, PublicFormat = _ed25519_backend()
    sk_hex = os.environ.get("SF_RECEIPT_ED25519_SK")
    if Priv is None or not sk_hex:
        return None  # extra or key absent -> honest degrade to unsigned (like ortools NA)
    sk = Priv.from_private_bytes(bytes.fromhex(sk_hex))
    pk_raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    sig = sk.sign(canonical_hash.encode()).hex()
    return {"alg": ED25519_ALG, "key_id": "ed25519-" + hashlib.sha256(bytes.fromhex(pk_raw)).hexdigest()[:16],
            "sig": sig, "pubkey": pk_raw, "note": "ed25519 public-verifiable (embedded pubkey) — " + _LEGAL_NOTE}


def _verify_ed25519(canonical_hash: str, signature: dict) -> tuple[bool, str]:
    _Priv, Pub, _E, _P = _ed25519_backend()
    if Pub is None:
        return False, "ed25519 backend not installed ([crypto] extra) — cannot verify"
    if "pubkey" not in signature:
        return False, "ed25519 signature missing embedded pubkey"
    try:
        Pub.from_public_bytes(bytes.fromhex(signature["pubkey"])).verify(
            bytes.fromhex(signature["sig"]), canonical_hash.encode())
        return True, "ed25519 signature valid"
    except Exception as e:  # noqa: BLE001
        return False, f"ed25519 signature INVALID ({type(e).__name__})"


def verify_pinned_ed25519(canonical_hash: str, signature: dict, pinned_public_key: str,
                          expected_key_id: str | None = None) -> tuple[bool, str]:
    """Strict Ed25519 verification under an out-of-band pinned key.

    The legacy verifier intentionally accepts the public key embedded by the signer.  That proves internal
    self-consistency, not operator identity.  Authority-bearing paths must call this function and pin the key.
    """
    if not isinstance(signature, dict) or signature.get("alg") != ED25519_ALG:
        return False, "strict verifier requires Ed25519"
    if expected_key_id is not None and signature.get("key_id") != expected_key_id:
        return False, "signing key id mismatch"
    embedded = signature.get("pubkey")
    if embedded is not None and embedded != pinned_public_key:
        return False, "embedded public key differs from pinned operator key"
    _Priv, Pub, _E, _P = _ed25519_backend()
    if Pub is None:
        return False, "ed25519 backend unavailable"
    try:
        Pub.from_public_bytes(bytes.fromhex(pinned_public_key)).verify(
            bytes.fromhex(signature.get("sig", "")), canonical_hash.encode())
        return True, "ed25519 signature valid under pinned key"
    except Exception as exc:
        return False, f"ed25519 signature invalid under pinned key ({type(exc).__name__})"
