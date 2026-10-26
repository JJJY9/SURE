# intent-mismatch

## What is in this directory

A very small web project: two files under `src/`, one route declared in one of
them, and nothing else.

| File | What is in it |
| --- | --- |
| `src/server.js` | the app, declaring one route: `/invoices` |
| `src/invoices.js` | the code behind that route |

Nobody asked for invoices. The request SURE was given was:

> add CSV export of the monthly totals

There is no CSV export in this project. There is no file about it, no route for
it, and no command that would produce it.

## What SURE should say

SURE should say that it compared the request against the project, found nothing
in the project that answers it, and report that as **one candidate** — not as a
verdict that the project is broken, and not as a verdict that the request was
met. The sentence is:

```
requirement `add CSV export of the monthly totals` has no implementation evidence
```

and it reaches the reader at the weight `note`, in the report's noise bucket
rather than its material list, with no blocker attached and nothing held back
from hand-off because of it.

Since `P7-T012` the run does raise one `Finding`, and it is not this sentence:
the proposal is surfaced as a planned check, no planned check runs in this
build, and `sure_core::findings_from_checks` raises a `cannot_confirm` finding
for it — at `note`, the proposal's own weight, saying that SURE planned a check
and did not run it rather than that the requirement is unmet. What the two are
never allowed to become is a claim about the project: the finding's status is
`cannot_confirm` and the candidate stays where it was.

That is deliberately modest, and it is the point of the fixture. SURE matched the
words of the request against the project's routes, its file paths, its declared
commands and the first non-blank line of each source file. Matching nothing there
means *SURE could not find it*, which is a statement about SURE's reading, not
about whether the export works. Dressing that up as a defect would turn every
word SURE fails to find into an accusation.

## Why a fixture with an answer this weak is worth having

Because the weak answer is the one that can drift. Three things are pinned, and
they are pinned by equality rather than by description:

1. exactly one requirement was checked, exactly one came back unmatched, and the
   comparison's own limitation field is empty — SURE had a request, and compared
   against it;
2. the one candidate is `note`, non-critical, inference-backed, and the
   aggregator files it under *style noise* while the material list stays empty;
3. a request the user stated and nothing implements is **never** silently
   dropped. Silence is the false green here: a report that says "No open
   findings." and nothing else about the CSV export leaves the reader to assume
   it was done.

There is a fourth thing, and it is the ceiling rather than the level: the same
candidate **cannot** be raised to `must_fix`. Its evidence is an inference, and
an inference cannot support the one severity that blocks a hand-off. A fixture
that recorded only "it is a note today" would leave the next person free to
raise it; this one records why it cannot be raised.

## The control, and why the fixture is worthless without it

A reporter that said *"requirement not met"* to everything the user asked for
would satisfy every sentence above. So the same request is put to the same
project with one thing moved: the implementing file is added.

| | The fixture | The control |
| --- | --- | --- |
| `src/server.js` | the same bytes | the same bytes |
| `src/invoices.js` | the same bytes | the same bytes |
| `src/csv-export.js` | absent | present |

The control's file starts with the line

```
// csv export of the monthly totals for the billing screen
```

and the test copies the fixture's own two files rather than writing them out
again, and asserts that the control differs from the fixture by exactly that one
path before it reads either answer. With the file present the answer must flip:
one requirement matched, nothing unmatched, no candidate at all, and the summary
one line shorter — the line counting the check that could not run is gone, and
the findings line above it is back to `No unresolved findings.`, because nothing is
planned and so nothing is left unrun. That second half is the flip the finding
producer is measured by, and the test asserts it by name rather than by line
count.

If SURE reported the mismatch anyway, it would be a checker that calls every
stated requirement unimplemented.

## How to see it for yourself

```
cargo test -p sure-core --test adversarial_fixture_detection -- intent_mismatch
```

That test reads `scenario.json`, supplies the goal through the same door the
`--goal` flag uses, drives SURE's real pipeline over this directory, asserts the
comparison, the identifier, the title, the severity, the evidence class, the
aggregate bucket and the whole rendered summary, then builds the control under
`target/tmp` and asserts the opposite.

## Watch out

The control's added file is **not** an implementation of a CSV export. It is a
comment that names the feature and a function that returns an empty list, and it
is there because SURE matches keywords against the first non-blank line of a
source file. The fixture is honest about that: what the control proves is that
the mismatch came from the request not being anchored anywhere, not that SURE can
tell whether a file works. A person reading the control as "the export is
implemented" would be reading a keyword match as a feature.

There is no case for this fixture in `evaluation/acceptance-manifest.json`. Its
`scenario.json` says why, and `FIXTURES_WITHOUT_A_MANIFEST_CASE` in
`crates/sure-testkit/tests/fixture_apps.rs` records the nearest row and the
reason this is a different defect.
