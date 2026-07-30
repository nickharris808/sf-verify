# sf-verify

**An auditor should not have to trust the system under audit — or run it.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

Re-derive an AI deployment's recorded admission decisions **offline**, from a hash-chained
decision log and its Signed Tree Head, trusting nothing but the inputs you were handed.

**Not yet on PyPI.** The command below is the one that works today. It installs from this repository, pinned to a tag.

```bash
pip install "git+https://github.com/nickharris808/sf-verify@v0.1.0"
```

`pip install sf-verify` is the intended command once the name is published. **It 404s today**, which is why it is not the first step above. The tag is pinned rather than `@main` so a reader installs the exact code this README documents.

## Why this exists

"We log every decision" is unfalsifiable on its own. The log is produced by the system under
audit, so an auditor reading it is trusting the thing being audited to describe itself honestly.

A hash chain fixes half of that. Each entry commits to its predecessor, so **editing any entry
after the fact breaks every hash that follows** — and that break is detectable by anyone, without
access to the running system, without credentials, and without re-executing anything.

`sf-verify` does that derivation and is scrupulous about the half it does **not** fix.

## Install

**Not yet on PyPI.** The command below is the one that works today. It installs from this repository, pinned to a tag.

```bash
pip install "git+https://github.com/nickharris808/sf-verify@v0.1.0"
```

`pip install sf-verify` is the intended command once the name is published. **It 404s today**, which is why it is not the first step above. The tag is pinned rather than `@main` so a reader installs the exact code this README documents.

## 30-second quickstart

```bash
sf-verify chain decisions.jsonl                       # re-derive the chain
sf-verify chain decisions.jsonl --anchor sth.json     # also check for tail truncation
sf-verify chain decisions.jsonl --report report.html  # a standalone HTML report
```

## Worked example

An intact log — **without an anchor**:

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

**Read that verdict carefully — it is the whole design.** The chain is intact and every entry
verifies. The tool still refuses to say VERIFIED, because *chain integrity is not completeness*.
An operator who deletes the last N entries leaves behind a prefix that verifies flawlessly, and
without an anchor no amount of hashing can distinguish that from a log nobody touched.

An earlier version printed `VERIFIED` here and exited `0`, with the missing anchor mentioned in a
trailing `note:`. That is backwards. The note is the part people skim; the verdict and the exit
code are what CI and a hurried human actually read. **A missing precondition now moves the
verdict**, which is the rule the whole portfolio is built on.

Now flip one recorded refusal into an admission — the single edit an operator would most want to
get away with:

```console
$ sf-verify chain tampered.jsonl
FAILED — 4 entries; entry 1 tampered (entry_hash mismatch)
  does NOT prove: that the deployment RECORDED everything it should have — absence of a leak is a claim about events that were never logged, and no log verifier can establish it
$ echo $?
1
```

The entry is named. Every subsequent hash is invalidated, so the earliest break localises the edit.

## Exit codes

The same three values across every tool in this portfolio, so "not checked" can never be misread
as "passed":

| code | verdict | meaning |
|---:|---|---|
| `0` | **VERIFIED** | chain intact **and** an anchor proved the tail is complete |
| `1` | **FAILED** | the chain is broken — an entry was edited, inserted or reordered |
| `2` | **UNVERIFIED** | it could not be checked: no anchor, empty log, or unreadable input |

## What it proves, and what it does not

This is printed in **every run**, not buried in documentation:

| | |
|---|---|
| ✅ **proves** | no entry was edited after it was written |
| ✅ **proves** | with an anchor, that the tail was not truncated |
| ⛔ **does NOT prove** | that the deployment **recorded everything it should have** |

That last row is the honest limit and it is not a small one. Absence of a leak is a claim about
events that were never logged, and **no log verifier can establish it**. A perfectly intact chain
is entirely compatible with a system that silently declined to log the decisions that mattered.

Without `--anchor`, truncation is unchecked and the tool says so on every run rather than letting
a green result imply more than it checked.

## The commercial edition

`sf-verify` **reads**. It re-derives a log someone else produced.

**Issuing** into this format at scale — the hosted transparency log, the anchoring service, and the
gate that emits entries as it makes decisions — is the licensed offering, and it is what makes the
`--anchor` half meaningful in production. See [`signoff-cert`](https://github.com/nickharris808/signoff-cert) for the certificate
format this pairs with.

**Reading is free. Issuing at scale is the product.**

## Licence

Apache-2.0 · **CLEAN** — verifies and reports; implements no filed apparatus.

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

## Contributing

Bug reports and pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

**A false accusation is a defect of equal severity to a missed detection.** If this tool flags something correct, open an issue with the input and the verdict you expected: over-refusal trains people to bypass refusals, which destroys the tool.

Citation metadata is in [CITATION.cff](CITATION.cff).

<!-- PORTFOLIO -->
---

## The rest of the portfolio

25 artifacts, one idea: **a measurement you cannot check is a press release.** Every tool
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
| [`negative-results-atlas`](https://huggingface.co/spaces/nickh007/negative-results-atlas) | ten claims we took back |
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
