# dynamic-not-authorized

## What is in this directory

A very small Node project with one declared script, and one authorisation it
does not have.

| File | What is in it |
| --- | --- |
| `package.json` | the project, with one script: `"test": "node src/totals.test.js"` |
| `src/totals.js` | the code the script checks |
| `src/totals.test.js` | a hand-rolled check, using only Node's own `assert` |
| `sure.yaml` | the project **asking** for its own checks to be run |

Nothing here is broken, nothing is a placeholder, and nothing needs installing:
the check is four lines and a builtin module.

## What SURE does with it

The declared `test` script becomes one planned check — `run the tests`, severity
`must_fix`, critical — and SURE is not allowed to run it, because the person at
the keyboard has not said it may. So the check comes back as a check that did
not happen:

```
status                            skipped
reason (the frozen sentence)      Checking this would have meant running your project's code,
                                  and you have not allowed that.
```

That sentence is fixed in `crates/sure-domain/src/status.rs` for exactly this
reason. The test compares the whole of it, and the whole of the rendered report,
so a build that changed the words or stopped printing them would fail.

## It must stay visible

This is the whole fixture. The tempting failure is not a wrong word — it is a
check that disappears:

```
Not enough could be checked to say whether this is ready.
This project is not ready to hand off.
...
Unresolved findings: 1 Must fix.
4 check(s) could not run or were skipped. 2 of them are critical. (run the tests, build the project)
```

The last two lines are the check staying visible, and since `P7-T012` they are
two rather than one: the sentence that counts checks that could not run, and the
open `cannot_confirm` finding raised for that same check. Drop both and the
report reads as a project with nothing outstanding. It is not. Nothing was
checked at all: `coverage_checked` is zero, and the one thing SURE would have
had to run to say anything is the thing it was not allowed to run.

**The count is four and not one since `P18-T011`**, and the closing line is
where that is visible rather than only in `scenario.json`. The run holds a row
for every role the acceptance names: `package.json` declares `test` and nothing
else, so `build the project`, `check the code for style and likely mistakes` and
`check the types without building` are rows too — `Skipped` with
`NotApplicable`, `blocks_green` false, and the critical one of them in
`critical_out_of_scope` rather than in `critical_not_checked`. Before that task
the declarations a manifest cannot make were handed to the aggregate and dropped
into a field no renderer reads, so the report counted one of the four rows the
run was made of. The three extra rows are why the line says *2 of them are
critical*: the refused check and the critical undeclared role. They change no
verdict — `blocking` still holds the refused check alone, the aggregate is still
`not_enough_checked`, and the finding is still the one `cannot_confirm` anchored
to the check nobody authorised, because a scope limit is not a finding.

So the check is asserted in five separate places, because a field on a struct is
not a report a person reads: in the verdict's list of checks that did not run, in
the aggregate's list of critical checks that were not checked, in the coverage
summary, in the verdict's own finding list, and in the last two lines of the
summary above.

It must **not** be reported as a defect of the project either. The script is
declared, the file it names exists, and the reason it did not run is a permission
the user has not given — so the finding the run raises for it says exactly that
and nothing more: its status is `cannot_confirm`, its statement is that SURE
planned this check and did not run it, its impact is that nothing here is known
to be broken, and its next step is to run the check or to allow SURE to run it.
What would blame a project for something a person decided is a finding that calls
the code wrong or holds the project out of hand-off because of a defect, and the
false-positive outcome in `scenario.json` forbids that rather than the finding as
such.

## Why the project's own `sure.yaml` is here

`sure.yaml` says:

```yaml
execution:
  mode: host_confirmed
```

It gets nothing. A project file may ask, and only the user's own configuration
file — outside the project — may grant: that is the rule in
`docs/architecture/CONFIG_AUTHORITY.md`, and the fixture ships an asking project
so that a build which read execution authority out of the repository would be a
red test rather than an undetected escalation. The test asserts the request was
recorded, that it was refused, and that the run still planned under
`inspect_only`.

## The control, and why the fixture is worthless without it

A reporter that answered *"you have not allowed that"* to **everything** would
satisfy every sentence above and would be measuring nothing at all. So the same
project is run again with one thing moved, and it is not in the project:

> the user's own configuration file appears, saying `execution: mode:
> host_confirmed`

The file is written under a configuration root this test owns — `Paths::from_roots`
puts SURE's configuration root under `target/tmp` for the length of the test, and
`Authority::load` reads it the way `sure check` does. The machine's real
configuration directory is never read and never written. The same directory is
read by the same call, so nothing else can have moved.

With the grant, the answer must change:

- the check is no longer refused: **no result carries the not-authorized reason
  at all**;
- the plan's decision for it is `allowed` instead of `denied`;
- what it becomes is `unknown` with *Nothing was reported for this check, so SURE
  has no basis for a verdict on it.* — **not** a pass.

That last point is the point. Nothing in this build carries a planned check out,
so consent changes what SURE is *allowed* to do and not what it has *done*: the
coverage still shows nothing checked, the aggregate is still
`not_enough_checked`, and the rendered summary is the same six lines, word for
word, on both sides. If a later build learns to run the check, this declaration
is what has to be re-made — and it should be re-made deliberately rather than
discovered.

## How to see it for yourself

```
cargo test -p sure-core --test adversarial_fixture_detection -- an_unauthorised_dynamic_check
```

That test reads `scenario.json`, drives SURE's real pipeline over this directory
with execution unauthorised, asserts the status, the reason, the frozen sentence,
the five places the check stays visible and the whole rendered summary, then
writes the user's grant into a configuration root it owns and drives the same
pipeline again and asserts the opposite. Nothing is run inside the project and
nothing is written outside `target/tmp`.

The fixture has a case in `evaluation/acceptance-manifest.json` —
`dynamic-not-authorized`, not release-blocking, expected severity `note`,
expectation *unexecuted dynamic checks stay visible as not checked/skipped* — and
the two fields at the top of `scenario.json` are copied from that row rather than
chosen here. What SURE says about the *project* here is under that ceiling rather
than at it: nothing is claimed to be wrong, and the one finding the run raises is
`cannot_confirm` and carries the check's own `must_fix` — the weight of a check
nobody authorised, which `scenario.json` says in as many words beside the row.
This paragraph used to end "SURE produces no finding for this case at all", and
`P7-T012` made that false: a refused check is now reported as the uncertainty it
is rather than only as a field a reader has to go looking for.

## Watch out

The `must_fix` on the check is the weight of the check, not a verdict about the
project: the report's material and style-noise buckets are both empty, and the
test asserts that rather than leaving it to be assumed. A reader who takes
*1 of them are critical* for a failing test has misread a check that never ran
for one that ran and failed.

The `must_fix` finding is where that misreading is easiest to make, so it is
where the test is strictest: its status is `cannot_confirm` and never `open`, its
severity is the check's own rather than one chosen for the project, and it is
anchored to the check that did not run rather than to a file — so nothing in it
names the code as the thing to fix, and the `forbidden_outcomes` entry in
`scenario.json` forbids exactly the build that would make it do so.
