# CLAIMS-MAP — sf-verify

**Tag: CLEAN. Licence: Apache-2.0.**

This file exists so the CLEAN tag is *auditable* rather than asserted.

## The line

Every method independent in the filed set terminates in a **physical actuation** step. The family
nearest this tool recites:

> *"…recording the recomputed root value over the evidence set … and **refusing to admit a gate
> decision** in reliance on the evidence set"*

and, for the transparency family:

> *"…emitting a certificate … and **writing bytes of a unit of computed state into a memory region
> of the relying party's environment, or refusing to write them**."*

`sf-verify` **re-derives a log someone else produced**. It reads entries, recomputes hashes,
compares against an anchor, and prints a verdict. It admits nothing, refuses nothing, writes
nothing into any relying party's environment, and issues no entries.

## Claims approached, and the step not performed

| Filed claim family | What it recites | What sf-verify does instead |
|---|---|---|
| Evidence-backed admission gating | maintaining an evidence set backing an admission gate; recomputing a root over it; **refusing to admit a gate decision** in reliance on it | Recomputes the chain and reports. The exit code is a reporting convention; nothing is gated. |
| Length-committing anchoring | binding a log to a committed length and head so tail truncation is closed, and **admitting or refusing** on the result | Verifies an anchor **supplied to it**. It does not produce anchors, does not operate a log, and does not act on the outcome. |
| Certificate issuance into a transparency log | computing over an evidence set, binding it into a durable record, and **writing the attested unit into the relying party's environment** | Performs the verification duals — recompute, compare — and writes only to stdout. |

## The honest limit is printed, not buried

Every run states what it does **not** prove: that the deployment **recorded everything it should
have**. Absence of a leak is a claim about events that were never logged, and no log verifier can
establish it. A perfectly intact chain is fully compatible with a system that silently declined to
log what mattered.

That limit is in the tool's output rather than only in this file, because a limitation a user never
sees is a limitation that does not exist in practice.

## Non-claims

- An intact chain attests that no entry was **edited** after it was written. It attests nothing
  about whether the entries are true, or complete.
- Without `--anchor`, tail truncation is unchecked, and the tool says so on every run.
