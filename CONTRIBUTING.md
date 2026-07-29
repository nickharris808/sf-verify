# Contributing to `sf-verify`

## The one rule

**No change may make this tool produce a confident-looking answer it has not earned.**

A patch that turns an abstention into a pass must say what is now being checked that was not
before. A patch that removes a refusal must say why the refused input is now checkable. Both are
welcome; the burden is on the change.

## A good pull request

1. A **failing test first** — preferably one that produces a wrong-looking-right answer rather
   than a crash. Crashes are easy; confident wrong answers are the risk.
2. The fix.
3. The README's scope section updated, if the change alters what the tool proves.

## What gets sent back

- **Weakening a test to make CI green.** Fix the cause. If the test itself was wrong, invert it
  with a comment rather than deleting it.
- **A hand-written list or count** of anything derivable. This has gone stale repeatedly here,
  silently, while still rendering.
- **A number in the README the published code does not produce.**
- **A verdict about a named third-party product.** Ship the checker, not a league table.

## Reporting a false accusation

If this tool flags something correct, that is a defect of **equal severity** to a missed
detection: over-refusal trains people to bypass refusals. Open an issue with the input and the
verdict you expected.

## Tests

```bash
pip install -e ".[dev]"
python -m pytest -q
```

Do not add another `-q` — the package already sets `addopts`, and `-qq` hides the summary so it
looks like nothing ran.

## Security

This tool takes untrusted input by design. If you find a way to make it execute code from a data
file, or to report a confident pass on input it cannot check, please open a private security
advisory rather than a public issue.

Full portfolio guide: <https://nickharris808.github.io/evidence-docs/guides/contributing/>
