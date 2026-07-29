"""report.py — a self-contained HTML report an auditor can open, print, or archive.

Deliberately states BOTH what the verification proves and what it cannot. A compliance report that
only lists green ticks invites a conclusion the evidence does not support.
"""
from __future__ import annotations

import html
import json

_CSS = """
:root{color-scheme:light dark}
body{font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
 margin:0;padding:2.5rem 1.5rem;background:#fbfbfc;color:#16181d}
main{max-width:52rem;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .25rem} .sub{color:#6b7280;margin:0 0 1.75rem}
.verdict{border-radius:10px;padding:1rem 1.25rem;font-weight:600;margin:0 0 1.5rem;border:1px solid}
.pass{background:#ecfdf5;border-color:#a7f3d0;color:#065f46}
.fail{background:#fef2f2;border-color:#fecaca;color:#991b1b}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1.75rem}
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid #e5e7eb;vertical-align:top}
th{color:#6b7280;font-weight:600;width:15rem}
h2{font-size:1rem;margin:1.75rem 0 .5rem}
ul{margin:.25rem 0 0;padding-left:1.15rem} li{margin:.3rem 0}
.limits{background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:.9rem 1.15rem}
.limits h2{margin-top:0;color:#92400e}
code{background:#f3f4f6;padding:.1rem .35rem;border-radius:4px;font-size:.9em}
footer{color:#6b7280;font-size:.85em;margin-top:2rem;border-top:1px solid #e5e7eb;padding-top:1rem}
@media(prefers-color-scheme:dark){body{background:#0d0f13;color:#e6e8ec}
 th,td{border-color:#252932} th{color:#9aa3b2} code{background:#1a1e26}
 .pass{background:#052e21;border-color:#0f5132;color:#6ee7b7}
 .fail{background:#2d0f14;border-color:#7f1d1d;color:#fca5a5}
 .limits{background:#2a2205;border-color:#78350f} .limits h2{color:#fcd34d}
 footer{border-color:#252932}}
"""


def render(result, *, log_path: str, anchor_path: str | None = None) -> str:
    r = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    ok = bool(r.get("ok"))
    e = html.escape
    rows = [("Log file", f"<code>{e(log_path)}</code>"),
            ("Entries verified", str(r.get("n_entries", 0))),
            ("Anchor (STH)", f"<code>{e(anchor_path)}</code>" if anchor_path else
             "<em>not supplied — tail truncation is therefore NOT checked</em>"),
            ("Anchor result", {True: "consistent", False: "INCONSISTENT", None: "n/a"}[r.get("anchor_ok")]),
            ("Detail", e(str(r.get("reason", ""))))]
    if r.get("first_bad_seq") is not None:
        rows.append(("First failing entry", f"seq {r['first_bad_seq']}"))
    tbl = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
    proves = "".join(f"<li>{e(x)}</li>" for x in r.get("proves", []))
    nots = "".join(f"<li>{e(x)}</li>" for x in r.get("does_not_prove", []))
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sf-verify report</title><style>{_CSS}</style></head><body><main>
<h1>Admission-decision log verification</h1>
<p class="sub">Re-derived offline by <code>sf-verify</code>. Nothing but the supplied files was trusted.</p>
<div class="verdict {'pass' if ok else 'fail'}">{'VERIFIED — the chain is intact' if ok else 'FAILED — the chain does not verify'}</div>
<table>{tbl}</table>
<h2>What this verification establishes</h2><ul>{proves}</ul>
<div class="limits"><h2>What it does NOT establish</h2><ul>{nots}</ul></div>
<footer>Signatures are tamper-evidence, not a legal non-repudiation instrument. Re-run this report
yourself: <code>sf-verify chain &lt;log&gt; --anchor &lt;sth&gt; --report out.html</code></footer>
</main></body></html>"""
