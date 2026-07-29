"""sf-verify CLI."""
from __future__ import annotations

import argparse
import json
import sys

from .report import render
from .verify import LogFormatError, verify_chain_file


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sf-verify",
        description="Re-derive a deployment's recorded admission decisions offline.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("chain", help="verify a hash-chained decision log")
    c.add_argument("log")
    c.add_argument("--anchor", help="Signed Tree Head. WITHOUT it the verdict is UNVERIFIED, "
                                    "because tail truncation cannot be detected")
    c.add_argument("--report", help="write a self-contained HTML report here")
    c.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    try:
        res = verify_chain_file(a.log, a.anchor)
    except LogFormatError as e:
        print(f"sf-verify: {e}", file=sys.stderr)
        return 2

    if a.report:
        open(a.report, "w", encoding="utf-8").write(render(res, log_path=a.log, anchor_path=a.anchor))
    if a.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(f"{res.verdict} — {res.n_entries} entries; {res.reason}")
        if res.verdict == "UNVERIFIED":
            # The verdict itself carries the caveat. This explains what to do about it.
            print("  WHY NOT VERIFIED: no anchor (Signed Tree Head) was supplied, so the tail was")
            print("  not checked. Deleting the last N entries leaves a prefix whose chain is")
            print("  perfectly intact — this tool cannot tell that from a complete log.")
            print("  Supply one with:  sf-verify chain <log> --anchor <sth.json>")
        print("  does NOT prove: " + res.does_not_prove[0])
    return res.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
