# sf-verify

**Re-derive an AI deployment's recorded admission decisions offline — and say UNVERIFIED when it cannot.**

[![tests](https://github.com/nickharris808/sf-verify/actions/workflows/tests.yml/badge.svg)](https://github.com/nickharris808/sf-verify/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

An auditor should not have to trust the system under audit, or run it. `sf-verify` reads a
hash-chained decision log and its Signed Tree Head, re-computes the chain from scratch, and trusts
nothing but the two files you were handed.

---

## Why this exists — a verdict with two values fails open

"We log every decision" is unfalsifiable on its own: the log is produced by the system under audit,
so an auditor reading it is trusting the thing being audited to describe itself honestly.

A hash chain fixes half of that. Each entry commits to its predecessor, so editing any entry after
the fact breaks every hash that follows, and that break is detectable by anyone — no credentials,
no network, no re-execution.

**It fixes only half, and the design decision here is what happens to the other half.**

Chain integrity is not completeness. An operator who deletes the last N entries leaves behind a
prefix that verifies flawlessly. Hashing alone cannot tell that prefix from a log nobody touched.
Detecting it needs an *anchor* — a Signed Tree Head committing to the chain's length and head.

So there are three genuinely different outcomes, and `VerifyResult.verdict` is deliberately not a
boolean ([`src/sf_verify/verify.py`](src/sf_verify/verify.py)):

| verdict | exit | what actually happened |
|---|---:|---|
| **VERIFIED** | `0` | the chain is intact **and** an anchor proved the tail is complete |
| **FAILED** | `1` | the chain itself is broken — something was edited, inserted or reordered |
| **UNVERIFIED** | `2` | the chain is intact but **no anchor was supplied**, so truncation was never checked |

> An earlier version of this tool printed `VERIFIED` and exited `0` for the middle case, with the
> missing anchor mentioned only in a trailing `note:`. That is exactly backwards. The note is the
> part people skim; the exit code is the part CI reads. **A verifier that says PASS on a
> precondition it never checked is worse than no verifier** — it converts "I did not look" into
> "I looked and it was fine", which is the one translation a verifier must never make.
>
> The missing precondition now moves the **verdict**. That is the whole design, and everything
> below is a consequence of it.

## Install

**Not yet on PyPI.** The command below is the one that works today. It installs from this repository, pinned to a tag.

```bash
pip install "git+https://github.com/nickharris808/sf-verify@v0.1.0"
```

`pip install sf-verify` is the intended command once the name is published. **It 404s today**, which is why it is not the first step above. The tag is pinned rather than `@main` so a reader installs the exact code this README documents.

Zero runtime dependencies; stdlib `hashlib`/`hmac`/`json` only. Python 3.10+, as declared in
[`pyproject.toml`](pyproject.toml).

## 30-second quickstart

Everything below was run to produce the output that follows it, exit codes included.

**Make a log to try it on.** (In production your gate writes these; this is the shipped library
doing the same thing, so the quickstart needs no deployment.)

```bash
python3 - <<'PY'
import json
from sf_verify._decision_log import DecisionLog
from sf_verify._anchor import make_sth

log = DecisionLog()
for i, (h, v) in enumerate([("a1b2c3d4", "ADMIT"), ("e5f6a7b8", "ADMIT"),
                            ("c9d0e1f2", "REFUSE"), ("3a4b5c6d", "ADMIT")]):
    log.append(canonical_hash=h * 8, verdict=v, ts=1000 + i)

with open("decisions.jsonl", "w") as f:
    for e in log.entries:
        f.write(json.dumps(e) + "\n")
json.dump(make_sth("prod-admission", log.entries, ts=1003), open("sth.json", "w"), indent=2)

# ... and the two adversarial variants used further down.
ents = json.loads(json.dumps(log.entries))
ents[2]["verdict"] = "ADMIT"                       # flip a recorded REFUSE
with open("tampered.jsonl", "w") as f:
    for e in ents:
        f.write(json.dumps(e) + "\n")
with open("truncated.jsonl", "w") as f:            # drop the last entry
    for e in log.entries[:-1]:
        f.write(json.dumps(e) + "\n")
PY
```

**Verify it.**

```console
$ sf-verify chain decisions.jsonl --anchor sth.json
VERIFIED — 4 entries; 4 entries chain-verified
  does NOT prove: that the deployment RECORDED everything it should have — absence of a leak is a claim about events that were never logged, and no log verifier can establish it
$ echo $?
0
```

That is the only input shape that earns exit `0`. Note that even the pass prints its own limit.

## Worked example — the three refusals

### 1. An intact log with no anchor: `UNVERIFIED`, exit 2

```console
$ sf-verify chain decisions.jsonl
UNVERIFIED — 4 entries; 4 entries chain-verified
  WHY NOT VERIFIED: no anchor (Signed Tree Head) was supplied, so the tail was
  not checked. Deleting the last N entries leaves a prefix whose chain is
  perfectly intact — this tool cannot tell that from a complete log.
  Supply one with:  sf-verify chain <log> --anchor <sth.json>
  does NOT prove: that the deployment RECORDED everything it should have — absence of a leak is a claim about events that were never logged, and no log verifier can establish it
$ echo $?
2
```

Read that carefully: **nothing is wrong with this log.** Every entry verifies. The tool still
refuses to say VERIFIED, because it was never given the thing that would let it check the tail.

### 2. The refusal is not paranoia — here is the attack it catches

Delete the last entry and hand over the prefix. Without an anchor the tool cannot tell:

```console
$ sf-verify chain truncated.jsonl
UNVERIFIED — 3 entries; 3 entries chain-verified
  WHY NOT VERIFIED: no anchor (Signed Tree Head) was supplied, so the tail was
  not checked. Deleting the last N entries leaves a prefix whose chain is
  perfectly intact — this tool cannot tell that from a complete log.
  Supply one with:  sf-verify chain <log> --anchor <sth.json>
  does NOT prove: that the deployment RECORDED everything it should have — absence of a leak is a claim about events that were never logged, and no log verifier can establish it
$ echo $?
2
```

Note it says `3 entries` where the intact log said `4`, and is otherwise **character-for-character
identical**. A two-valued verifier would have printed PASS here. With the anchor, the same file:

```console
$ sf-verify chain truncated.jsonl --anchor sth.json
FAILED — 3 entries; 3 entries chain-verified; anchor: length mismatch vs anchor (served 3, committed 4) -- tail-truncation or extension caught
  does NOT prove: that the deployment RECORDED everything it should have — absence of a leak is a claim about events that were never logged, and no log verifier can establish it
$ echo $?
1
```

**The `UNVERIFIED` and the `FAILED` are the same log.** The difference between them is entirely
whether you supplied the anchor — which is precisely why "no anchor" must not be a pass.

### 3. A flipped verdict: `FAILED`, exit 1

The single edit an operator would most want to get away with — turning a recorded `REFUSE` into an
`ADMIT`:

```console
$ sf-verify chain tampered.jsonl
FAILED — 4 entries; entry 2 tampered (entry_hash mismatch)
  does NOT prove: that the deployment RECORDED everything it should have — absence of a leak is a claim about events that were never logged, and no log verifier can establish it
$ echo $?
1
```

The entry is named. Every subsequent hash is invalidated too, so the *earliest* break localises the
edit.

### 4. Nothing to verify at all: exit 2, and no verdict

```console
$ : > empty.jsonl && sf-verify chain empty.jsonl
sf-verify: empty.jsonl contains no entries.
  REFUSING to report a verdict on an empty log: an intact chain over zero entries is vacuously true and says nothing about your deployment.
$ echo $?
2
```

An intact chain over zero entries is vacuously true. Reporting it as a pass is the degenerate case
this whole tool exists to avoid — the same vacuity that
[`gridlock`](https://github.com/nickharris808/gridlock) hit with an empty graph.

## CLI reference

One subcommand.

```
usage: sf-verify [-h] {chain} ...

Re-derive a deployment's recorded admission decisions offline.

positional arguments:
  {chain}
    chain     verify a hash-chained decision log

options:
  -h, --help  show this help message and exit
```

### `sf-verify chain <log>`

| flag | type | what it does |
|---|---|---|
| `log` | positional, required | path to a **JSONL** decision log — one JSON object per line |
| `--anchor ANCHOR` | path | Signed Tree Head. **Without it the verdict is UNVERIFIED**, because tail truncation cannot be detected |
| `--report REPORT` | path | write a self-contained HTML report there (no CSS/JS fetched at view time) |
| `--json` | flag | print the full `VerifyResult` as JSON, including `proves` / `does_not_prove` / `exit_code` |
| `-h, --help` | flag | usage |

`--json` prints everything the human output summarises, so a CI job never has to parse prose:

```console
$ sf-verify chain decisions.jsonl --anchor sth.json --json
{
  "ok": true,
  "reason": "4 entries chain-verified",
  "n_entries": 4,
  "anchor_checked": true,
  "anchor_ok": true,
  "first_bad_seq": null,
  "proves": [
    "every recorded entry is internally consistent and unmodified since it was written",
    "the chain is unbroken — no entry was inserted, reordered or removed",
    "if an anchor (STH) is supplied: the log has not been truncated at the tail"
  ],
  "does_not_prove": [
    "that the deployment RECORDED everything it should have — absence of a leak is a claim about events that were never logged, and no log verifier can establish it",
    "that the recorded verdicts were correct policy decisions — only that they are faithfully recorded",
    "non-repudiation in a legal sense; signatures here are tamper-evidence"
  ],
  "verdict": "VERIFIED",
  "exit_code": 0
}
$ echo $?
0
```

### Exit codes

The same three values across every tool in this portfolio, so "not checked" can never be misread as
"passed":

| code | verdict | meaning |
|---:|---|---|
| `0` | **VERIFIED** | chain intact **and** an anchor proved the tail is complete |
| `1` | **FAILED** | the chain is broken — an entry was edited, inserted or reordered; or the anchor disagrees |
| `2` | **UNVERIFIED** / no verdict | it could not be checked: no anchor, an empty log, an unreadable file, or the wrong file shape |

Exit `2` covers both "intact but incomplete evidence" and "I could not read this". Both are
non-answers, and neither is a pass.

### Library API

```python
from sf_verify import verify_chain_file

res = verify_chain_file("decisions.jsonl", "sth.json")
res.verdict        # 'VERIFIED' | 'UNVERIFIED' | 'FAILED'
res.exit_code      # 0 | 2 | 1
res.anchor_checked # False when no anchor was given — the reason for UNVERIFIED
res.first_bad_seq  # the seq of the earliest broken entry, or None
res.to_dict()      # the same dict `--json` prints
```

Also exported: `verify_log` (chain only), `verify_sth`, `verify_sth_chain` and
`verify_log_against_sth` (the anchor half), for callers that already hold parsed entries.

<!-- HONEST-SCOPE -->
## Honest scope — what a passing run proves, and what it does not

The two halves are inseparable. A tool that states only the first half is marketing.

**It proves:**

- that every recorded entry is internally consistent and unmodified since written
- that the chain is unbroken — nothing inserted, reordered or removed mid-log
- with an anchor: that the log has not been truncated at the tail

**It does NOT prove:**

- that the deployment RECORDED everything it should have. Absence of a leak is a claim about events that were never logged, and no log verifier can establish it
- that the recorded verdicts were correct decisions — only that they are faithfully recorded
- WITHOUT an anchor: anything about completeness. That case is UNVERIFIED, not VERIFIED

## Troubleshooting

| you see | what it means and how to fix it |
|---|---|
| `sf-verify says UNVERIFIED, not VERIFIED` | No anchor was supplied, so tail truncation could not be checked. Pass `--anchor <sth.json>`. This is the intended behaviour, not a failure. |
| `no such log file` | The path is wrong, or you passed a JSON document instead of JSONL. This command reads one JSON object per line. |

These strings are checked against the live code by `python oss/tools/gen_docs.py --verify`, so a changed message cannot leave stale advice behind.

Full CLI reference, generated from `--help`: [`docs/CLI.md`](docs/CLI.md)
<!-- /HONEST-SCOPE -->

### More errors you will actually hit

| you see | what it means and how to fix it |
|---|---|
| `UNVERIFIED` and exit `2` in CI | **Not a failure of the log.** Your pipeline treated a non-answer as a failure, or supplied no anchor. Publish an STH alongside the log and pass `--anchor`; or, if you knowingly accept an unanchored check, treat `2` as its own state — never fold it into `0`. |
| `contains no entries` | The log is empty or whitespace-only. Refused deliberately: an intact chain over zero entries is vacuously true. |
| `this is a log DOCUMENT (it has an 'entries' array), not a log ENTRY` | You passed a single JSON document, not JSONL. The message prints the one-liner that converts it. Refusing here is deliberate — verifying the wrapper would report a **broken chain** and send you hunting for tampering that never happened. |
| `not valid JSON ... Expected one JSON object per line` | A line is malformed or the file is pretty-printed JSON. Re-export as JSONL. |
| `length mismatch vs anchor (served N, committed M)` | Exactly what the anchor exists to catch: the log you were handed is shorter (or longer) than the one that was committed to. |
| `--report` written but empty-looking | The report is a single self-contained HTML file with inline CSS. It fetches nothing at view time, on purpose: an auditor's report that phones out is not offline evidence. |

**Offline behaviour.** Everything here runs air-gapped. There is no network path in this package at
all — no key servers, no timestamping service, no telemetry. `verify_chain_file` opens two files and
computes SHA-256. If you need a *cross-host* witness, that is out of scope and named as such in
[`src/sf_verify/_anchor.py`](src/sf_verify/_anchor.py).

## FAQ

**"You verify a log the system under audit wrote. Isn't that circular?"**
Partly, and the tool says so on every run. The chain rules out *retroactive* edits: the operator
must decide to lie at write time, in front of whatever else was watching, rather than tidying up
afterwards. That is a real narrowing and it is not the same as trusting the log. What it can never
establish is that the deployment recorded everything it should have — absence of a leak is a claim
about events that were never logged, and **no log verifier can establish it.** That sentence is
printed by every single run, including the passes.

**"If the anchor comes from the same operator, what does it buy?"**
Length and head, signed and published. An anchor is only as good as its publication: an STH nobody
else ever saw can be re-issued to match a shortened log. The value comes from a third party having
seen it, which is why `_anchor.py` supports an append-only head-chain (`STH_n.prev_sth_hash =
STH_{n-1}.sth_hash`). Anchoring *infrastructure* — a hosted transparency log with external
witnesses — is not in this package, and the monitor referenced in `_anchor.py` is explicitly a
**same-host reference** non-equivocation detector, not a gossiped witness network.

**"An Ed25519 signature — so this is legal non-repudiation?"**
No, and `_anchor.py` says "do NOT upgrade" about exactly this. Signatures here are
**tamper-evidence and authenticity**, not a notary. A signature checked against a key embedded in
the same artifact proves nothing about origin; you must hold the key out of band.

**"Exit 2 breaks my pipeline."**
That is the intended pressure. If exit 2 is inconvenient, the fix is to publish an anchor, not to
map 2 onto 0. Sibling tooling that measures how often this goes wrong across a fleet of verifiers is
[`abstain-bench`](https://github.com/nickharris808/abstain-bench) — "how often does a verifier pass
input it could not check?"

**"Where are the benchmark numbers?"**
There are none, deliberately. `sf-verify` is a decision procedure, not a measurement: the only
numbers in this README are the ones the commands above printed on this machine. When this portfolio
publishes a *measured* figure it ships the certificate it was computed from — see
[`kvleak`](https://github.com/nickharris808/kvleak) and
[`isolation-tax`](https://github.com/nickharris808/isolation-tax) for that pattern.

**"How do I know the refusals actually fire?"**
`tests/test_adversarial_sf_verify.py` exists for that. Run `python -m pytest -q` in this directory.

## Related tools

| | |
|---|---|
| [`signoff-cert`](https://github.com/nickharris808/signoff-cert) | the certificate format this pairs with — certificates that carry their own false-pass bound |
| [`gridlock`](https://github.com/nickharris808/gridlock) | the same three-valued design, applied to wait-for graphs: an empty graph ABSTAINS rather than certifying SAFE |
| [`abstain-bench`](https://github.com/nickharris808/abstain-bench) | measures how often a verifier passes input it could not check |
| [`proof-carrying-ci`](https://github.com/nickharris808/proof-carrying-ci) | runs this and its siblings as one CI check, with SARIF |

## The commercial edition

`sf-verify` **reads**. It re-derives a log someone else produced.

**Issuing** into this format at scale — the hosted transparency log, the anchoring service, and the
gate that emits entries as it makes decisions — is the licensed offering, and it is what makes the
`--anchor` half meaningful in production.

**Reading is free. Issuing at scale is the product.**

## Licence

Apache-2.0. **CLEAN** — verifies and reports; implements no filed apparatus. See
[`LICENSE`](LICENSE), [`LICENSE-TAG`](LICENSE-TAG) and [`CLAIMS-MAP.md`](CLAIMS-MAP.md).

## Contributing

Bug reports and pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

**A false accusation is a defect of equal severity to a missed detection.** If this tool flags something correct, open an issue with the input and the verdict you expected: over-refusal trains people to bypass refusals, which destroys the tool.

Citation metadata is in [CITATION.cff](CITATION.cff).

<!-- PORTFOLIO -->
---

## The rest of the portfolio

24 artifacts, one idea: **a measurement you cannot check is a press release.** Every tool
here reports; none of them gates.

**Tools**

| | |
|---|---|
| [`abstain-bench`](https://github.com/nickharris808/abstain-bench) | how often does a verifier pass input it could not check? |
| [`evidence`](https://github.com/nickharris808/evidence) | run the whole portfolio over your repo — the weakest leg, never the mean |
| [`floorgen`](https://github.com/nickharris808/floorgen) | what must your system remember? an exact lower bound |
| [`formal-proof-mcp`](https://github.com/nickharris808/formal-proof-mcp) | a proof kernel for your coding agent |
| [`gatecount`](https://github.com/nickharris808/gatecount) | exactly how many states does removing this check admit? |
| [`gridlock`](https://github.com/nickharris808/gridlock) | certify a wait-for relation cannot wedge |
| [`honestbench`](https://github.com/nickharris808/honestbench) | measure your CI's escape rate |
| [`kvleak`](https://github.com/nickharris808/kvleak) | cross-tenant leak scanner |
| [`kvprobe`](https://github.com/nickharris808/kvprobe) | model-substitution detector with a measured FPR |
| [`preregister`](https://github.com/nickharris808/preregister) | refuses to seal a plan whose conclusion is already fixed |
| [`proof-carrying-ci`](https://github.com/nickharris808/proof-carrying-ci) | the whole portfolio as one CI check, with SARIF |
| [`proof-to-code-drift`](https://github.com/nickharris808/proof-to-code-drift) | fail the build when the proof stops matching |
| [`sf-verify`](https://github.com/nickharris808/sf-verify) | re-derive admission decisions offline ← you are here |
| [`signoff-cert`](https://github.com/nickharris808/signoff-cert) | certificates that carry their own false-pass bound |
| [`tokencount`](https://github.com/nickharris808/tokencount) | a token count both parties can recompute |

**Benchmarks** — each recomputes one of our own published numbers from its certificate

| | |
|---|---|
| [`illusion-bench`](https://github.com/nickharris808/illusion-bench) | how many broken kernels does your oracle admit? |
| [`kv-reuse-econ-bench`](https://github.com/nickharris808/kv-reuse-econ-bench) | recompute our economics headline |
| [`llm-tenant-isolation-bench`](https://github.com/nickharris808/llm-tenant-isolation-bench) | recompute our isolation figures |

**Datasets**

| | |
|---|---|
| [`abstain-corpus`](https://huggingface.co/datasets/nickh007/abstain-corpus) | 32 inputs a verifier must NOT pass |
| [`kv-reuse-econ-traces`](https://huggingface.co/datasets/nickh007/kv-reuse-econ-traces) | per-workload reuse accounting + the closed form |
| [`kv-tenant-isolation-bench`](https://huggingface.co/datasets/nickh007/kv-tenant-isolation-bench) | isolation observations, uninterpretable rows included |
| [`llm-precision-fingerprints`](https://huggingface.co/datasets/nickh007/llm-precision-fingerprints) | precision-labelled logprobs with a negative control |

**Try it in a browser** — no install, no GPU

| | |
|---|---|
| [`tenant-leak-demo`](https://huggingface.co/spaces/nickh007/tenant-leak-demo) | the residency calculator |
| [`wait-for-visualiser`](https://huggingface.co/spaces/nickh007/wait-for-visualiser) | paste a wait-for graph, see the cycle |

### Documentation

Everything above, explained in one place: **<https://nickharris808.github.io/evidence-docs/>** —
the [tutorial](https://nickharris808.github.io/evidence-docs/start/tutorial/),
[what this proves and what it does not](https://nickharris808.github.io/evidence-docs/concepts/what-this-proves/),
and a [CLI reference](https://nickharris808.github.io/evidence-docs/reference/cli/) generated by
running `--help` on every published command.

### The commercial edition

Everything above is **measure-only** and Apache-2.0: it tells you what is true and never acts on
it. The **enforcement** side — binding a partition key at the admission decision, the compiled gate
corpus, and the certificate-*issuing* faucet — is covered by filed patents and licensed separately.

**Reading is free. Enforcing is licensed.**
<!-- /PORTFOLIO -->

<!-- BEGIN VERIFY-IN-TEN-MINUTES (generated by oss/tools/gen_readme_standard.py) -->

## Verify this in ten minutes

### 1. Install the version that exists today

```bash
pip install "git+https://github.com/nickharris808/sf-verify@v0.1.0"
```

*not on PyPI; the git tag is pinned so a reader installs the exact code this README documents.*

### 2. Run one command

```bash
sf-verify --help
```

Prints the subcommands; `sf-verify chain` needs a log and its signed tree head.

### 3. Where the numbers come from

Numbers in this README carry paths like `results/data/...`. **Those receipts live in a private research monorepo and you cannot open them** — they are cited so you can see exactly what was measured and where, not because the link resolves. What is public, and what you can check yourself, is: this package's own tests and `--selftest`; the benchmarks, which recompute the headline numbers from published inputs; and the Hugging Face datasets, whose every row names the certificate it came from. If a number here matters to you and none of those covers it, treat it as unverified.

---

Version 0.1.0 in the source tree · Apache-2.0 · cite via `CITATION.cff` in this repository · this block is generated by `oss/tools/gen_readme_standard.py` from a measurement of PyPI, the git tags and this tree, and `--check` fails if anyone edits it by hand.

<!-- END VERIFY-IN-TEN-MINUTES -->
