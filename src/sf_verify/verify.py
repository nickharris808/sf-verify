"""verify.py — the offline verification entry point."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ._anchor import verify_log_against_sth, verify_sth
from ._decision_log import verify_log


@dataclass
class VerifyResult:
    """The outcome of an offline verification.

    THREE VALUES, NOT TWO. `verdict` is the field a human or a CI job should read, and it is
    deliberately not a boolean, because there are three genuinely different outcomes:

        VERIFIED    the chain is intact AND an anchor proved the tail is complete
        UNVERIFIED  the chain is intact but NO anchor was supplied, so tail truncation
                    could not be checked -- an attacker who deleted the last N entries
                    leaves a prefix that verifies perfectly
        FAILED      the chain itself is broken

    An earlier version of this tool printed "VERIFIED" and exited 0 for the middle case, with
    the missing anchor mentioned only in a trailing note. That is exactly backwards: the note
    is the part people skim past, and the exit code is the part CI reads. A verifier that says
    PASS on a precondition it never checked is worse than no verifier, so the missing
    precondition now moves the VERDICT.
    """

    ok: bool
    reason: str
    n_entries: int = 0
    anchor_checked: bool = False
    anchor_ok: bool | None = None
    first_bad_seq: int | None = None
    proves: list[str] = field(default_factory=list)
    does_not_prove: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if not self.ok:
            return "FAILED"
        return "VERIFIED" if self.anchor_checked and self.anchor_ok else "UNVERIFIED"

    @property
    def exit_code(self) -> int:
        """0 only for a fully-verified log. 1 = broken chain. 2 = ABSTAIN (no anchor)."""
        return {"VERIFIED": 0, "FAILED": 1, "UNVERIFIED": 2}[self.verdict]

    def to_dict(self) -> dict:
        return {**self.__dict__, "verdict": self.verdict, "exit_code": self.exit_code}


# Stated on every result so a reader cannot mistake the scope of the guarantee.
_PROVES = [
    "every recorded entry is internally consistent and unmodified since it was written",
    "the chain is unbroken — no entry was inserted, reordered or removed",
    "if an anchor (STH) is supplied: the log has not been truncated at the tail",
]
_DOES_NOT_PROVE = [
    "that the deployment RECORDED everything it should have — absence of a leak is a claim about "
    "events that were never logged, and no log verifier can establish it",
    "that the recorded verdicts were correct policy decisions — only that they are faithfully recorded",
    "non-repudiation in a legal sense; signatures here are tamper-evidence",
]


class LogFormatError(Exception):
    """The log could not be read. Carries a message that says how to fix it.

    A stack trace tells the user where OUR code gave up. It does not tell them what to do.
    Every raise here names the file, the line, and the expected shape.
    """


def _load(path: str) -> list[dict]:
    """Read a JSONL decision log: one JSON object per line.

    Refuses rather than guesses. An empty log is an error, not an empty success -- verifying
    nothing and reporting a clean chain is the degenerate case this whole tool exists to avoid.
    """
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        raise LogFormatError(
            f"no such log file: {path}\n"
            f"  This command expects a JSONL decision log -- one JSON object per line.\n"
            f"  If you have a single JSON document with an 'entries' array, extract it first:\n"
            f"    python -c \"import json,sys;[print(json.dumps(e)) for e in "
            f"json.load(open('{path}'))['entries']]\" > log.jsonl") from None
    except OSError as e:
        raise LogFormatError(f"could not read {path}: {e}") from None

    entries = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            hint = ""
            if line.startswith("{") and lineno == 1 and '"entries"' in raw[:400]:
                hint = ("\n  This looks like a single JSON document, not JSONL. Each ENTRY must be "
                        "on its own line.")
            raise LogFormatError(
                f"{path}:{lineno}: not valid JSON ({e.msg}).{hint}\n"
                f"  Expected one JSON object per line.") from None
        if not isinstance(obj, dict):
            raise LogFormatError(
                f"{path}:{lineno}: expected a JSON object, got {type(obj).__name__}.\n"
                f"  Each line must be one decision entry, e.g. "
                f'{{"seq": 0, "prev_hash": "...", "entry_hash": "..."}}')

        # A log WRAPPER is not a log ENTRY. Without this check a compact one-line document
        # parses as a single malformed entry and gets reported as a BROKEN CHAIN -- telling
        # the user their log was tampered with when in fact they passed the wrong file. A
        # confidently wrong diagnosis is the same defect as a confidently wrong pass.
        if "entries" in obj and isinstance(obj["entries"], list) and "entry_hash" not in obj:
            raise LogFormatError(
                f"{path}:{lineno}: this is a log DOCUMENT (it has an 'entries' array), not a "
                f"log ENTRY.\n"
                f"  This command reads JSONL — one entry per line. Extract them first:\n"
                f"    python -c \"import json;[print(json.dumps(e)) for e in "
                f"json.load(open('{path}'))['entries']]\" > log.jsonl\n"
                f"  (Refusing rather than verifying the wrapper: that would report a broken "
                f"chain and send you hunting for tampering that never happened.)")
        entries.append(obj)

    if not entries:
        raise LogFormatError(
            f"{path} contains no entries.\n"
            f"  REFUSING to report a verdict on an empty log: an intact chain over zero entries "
            f"is vacuously true and says nothing about your deployment.")
    return entries


def verify_chain_file(log_path: str, anchor_path: str | None = None,
                      key: bytes | None = None) -> VerifyResult:
    entries = _load(log_path)
    ok, reason = verify_log(entries, key=key)
    bad = None
    if not ok:
        for e in entries:
            if isinstance(e, dict) and "seq" in e:
                bad = e["seq"]
                break
    res = VerifyResult(ok=bool(ok), reason=str(reason), n_entries=len(entries),
                       first_bad_seq=bad, proves=_PROVES, does_not_prove=_DOES_NOT_PROVE)
    if anchor_path:
        sth = json.load(open(anchor_path))
        sok, sreason = verify_sth(sth, key=key)
        aok, areason = verify_log_against_sth(entries, sth, key=key)
        res.anchor_checked = True
        res.anchor_ok = bool(sok and aok)
        if not res.anchor_ok:
            res.ok = False
            res.reason = f"{res.reason}; anchor: {sreason if not sok else areason}"
    return res
