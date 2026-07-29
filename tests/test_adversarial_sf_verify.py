"""Adversarial regression tests — the oracle is:

    NO INPUT MAY PRODUCE A CONFIDENT-LOOKING ANSWER THAT IS WRONG.

Each test here corresponds to an input that once produced, or could produce, a verdict the
analysis had not earned. They are permanent: the class they cover is the one that would destroy
the credibility of every other number in this portfolio.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sf_verify._decision_log import DecisionLog          # noqa: E402
from sf_verify.cli import main                            # noqa: E402
from sf_verify.verify import LogFormatError, verify_chain_file   # noqa: E402


def _write(entries, path):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return path


def _log(n=4):
    log = DecisionLog()
    for i in range(n):
        log.append(f"canon{i}", i % 2 == 0, 1700000000 + i)
    return log.to_dict()["entries"]


# --------------------------------------------------------------- the truncation oracle

def test_truncated_log_without_anchor_is_not_VERIFIED(tmp_path):
    """THE ONE THAT MATTERS.

    Deleting the tail of a hash chain leaves a prefix that verifies perfectly. Without an
    anchor the tool cannot tell that from a complete log, so it must not say VERIFIED.
    """
    entries = _log(4)
    p = _write(entries[:2], str(tmp_path / "truncated.jsonl"))
    res = verify_chain_file(p, None)

    assert res.ok is True, "the surviving prefix really is a valid chain"
    assert res.verdict == "UNVERIFIED", "but completeness was never checked"
    assert res.exit_code == 2, "and CI must not read that as a pass"


def test_intact_log_without_anchor_is_also_not_VERIFIED(tmp_path):
    """An intact log is indistinguishable from a truncated one without an anchor.

    So the honest verdict is the same in both cases. If this test ever fails because
    'the log was fine really', that is the hallucination coming back.
    """
    p = _write(_log(4), str(tmp_path / "full.jsonl"))
    res = verify_chain_file(p, None)
    assert res.verdict == "UNVERIFIED"
    assert res.exit_code == 2


def test_tampered_log_fails_regardless_of_anchor(tmp_path):
    entries = _log(4)
    entries[1]["verdict"] = not entries[1]["verdict"]      # flip an admission
    p = _write(entries, str(tmp_path / "tampered.jsonl"))
    res = verify_chain_file(p, None)
    assert res.verdict == "FAILED"
    assert res.exit_code == 1


# --------------------------------------------------------------- degenerate input

def test_empty_log_refuses_rather_than_reporting_a_clean_chain(tmp_path):
    """An intact chain over zero entries is vacuously true and means nothing."""
    p = str(tmp_path / "empty.jsonl")
    open(p, "w").close()
    with pytest.raises(LogFormatError) as ei:
        verify_chain_file(p, None)
    assert "no entries" in str(ei.value).lower()


def test_whitespace_only_log_also_refuses(tmp_path):
    p = str(tmp_path / "ws.jsonl")
    open(p, "w").write("\n\n   \n\n")
    with pytest.raises(LogFormatError):
        verify_chain_file(p, None)


# --------------------------------------------------------------- malformed input

def test_missing_file_explains_the_fix_instead_of_a_traceback(capsys, tmp_path):
    rc = main(["chain", str(tmp_path / "nope.jsonl")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no such log file" in err
    assert "JSONL" in err, "the message must say what shape it wanted"


def test_json_document_instead_of_jsonl_is_diagnosed(capsys, tmp_path):
    """The most likely real mistake: handing it the DecisionLog dict, not its entries."""
    p = str(tmp_path / "doc.json")
    json.dump({"entries": _log(2), "version": 1}, open(p, "w"), indent=2)
    rc = main(["chain", p])
    assert rc == 2
    err = capsys.readouterr().err
    assert "JSONL" in err


def test_non_object_line_is_refused(tmp_path):
    p = str(tmp_path / "bad.jsonl")
    open(p, "w").write('["not", "an", "object"]\n')
    with pytest.raises(LogFormatError) as ei:
        verify_chain_file(p, None)
    assert "expected a JSON object" in str(ei.value)


def test_enormous_log_does_not_change_the_verdict_rule(tmp_path):
    """Out-of-distribution size must not accidentally flip the anchor rule."""
    p = _write(_log(5000), str(tmp_path / "big.jsonl"))
    res = verify_chain_file(p, None)
    assert res.n_entries == 5000
    assert res.verdict == "UNVERIFIED", "size is irrelevant; the anchor is what is missing"


# --------------------------------------------------------------- the CLI contract

def test_cli_never_prints_VERIFIED_without_an_anchor(capsys, tmp_path):
    p = _write(_log(3), str(tmp_path / "x.jsonl"))
    rc = main(["chain", p])
    out = capsys.readouterr().out
    assert rc == 2
    headline = out.splitlines()[0]
    assert headline.startswith("UNVERIFIED")
    # Check the WORD, not a substring: "UNVERIFIED" of course contains "VERIFIED".
    assert headline.split()[0] != "VERIFIED", "the headline word must not read as success"
    assert "--anchor" in out, "and it must say how to get to VERIFIED"
