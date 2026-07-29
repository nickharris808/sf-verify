import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from sf_verify._decision_log import DecisionLog
from sf_verify.verify import verify_chain_file
from sf_verify.report import render

def _write_log(tmp, n=5, tamper_at=None):
    log = DecisionLog()
    for i in range(n):
        log.append(canonical_hash=f"h{i:03d}", verdict={"admit": i % 2 == 0}, ts=1000 + i)
    entries = [dict(e) for e in log.entries]
    if tamper_at is not None:
        entries[tamper_at]["verdict"] = {"admit": "TAMPERED"}
    p = os.path.join(tmp, "log.jsonl")
    with open(p, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return p

def test_intact_chain_verifies():
    with tempfile.TemporaryDirectory() as t:
        assert verify_chain_file(_write_log(t, 5)).ok is True

def test_tampered_entry_is_detected():
    """The load-bearing test: if this passes silently, the tool is worthless."""
    with tempfile.TemporaryDirectory() as t:
        r = verify_chain_file(_write_log(t, 5, tamper_at=2))
        assert r.ok is False and r.reason

def test_truncation_without_anchor_is_NOT_detected_and_we_say_so():
    """Honesty test: truncation is invisible without an anchor, and the result must admit it."""
    with tempfile.TemporaryDirectory() as t:
        p = _write_log(t, 5)
        lines = open(p).read().splitlines()[:3]
        open(p, "w").write("\n".join(lines) + "\n")
        r = verify_chain_file(p)
        assert r.ok is True                     # a truncated-but-consistent prefix still verifies
        assert r.anchor_checked is False
        assert any("recorded everything" in s.lower() for s in r.does_not_prove)

def test_result_always_states_what_it_cannot_prove():
    with tempfile.TemporaryDirectory() as t:
        r = verify_chain_file(_write_log(t, 3))
        assert r.does_not_prove and any("never logged" in s.lower() for s in r.does_not_prove)

def test_html_report_renders_and_carries_the_limits():
    with tempfile.TemporaryDirectory() as t:
        r = verify_chain_file(_write_log(t, 3))
        h = render(r, log_path="log.jsonl")
        assert "does NOT establish" in h and "<!doctype html>" in h
