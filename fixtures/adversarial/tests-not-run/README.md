# tests-not-run

## What the AI claimed

> All 12 pytest unit tests pass.

That is the whole of the evidence for it. There is no project in this fixture to
run, and no test command in it to fail: the fixture is a **recording**, and the
question is what SURE does when it compares a sentence like that against one.

## What is actually in the recording

Two things happened, and the recording says so:

| When | What |
| --- | --- |
| 09:10:56 | a file was written: `src/orders.js` |
| 09:10:57 | an event named `mytest.finished`, summarised as `pytest unit tests, 12 passed, 0 failed` |

The second line is the one a person reads as "the tests ran". SURE does not read
it that way. To check a claim that the tests ran, SURE looks for an event whose
name belongs to the family it recognises for test runs, and that family is the
names beginning with `test.`. `mytest.finished` begins with `mytest.`

So SURE finds nothing it is willing to use, and it says so. It does not say the
tests failed — nothing here establishes that. It does not say the event is
malformed — the event is perfectly well formed. It says it has no recorded event
that supports the claim, and it attaches no evidence, because there is none to
attach.

The trap is one layer down, and it is worth knowing about: the part of SURE that
summarises events reads `mytest.finished` as a **test run** with a passing
summary, because it looks for the word `test` anywhere in the name. Everything
that reads events recognises this as a test run. The one thing that does not is
the check that decides whether to believe the claim — and that is the point of
the fixture. A name that looks like a result is not a result SURE can rest on.

## How to see it for yourself

There is nothing to run in this directory: the recording is declared in
`scenario.json`, not performed. To watch SURE read it:

```
cargo test -p sure-core --test adversarial_fixture_detection -- tests_not_run
```

That test reads the recording out of `scenario.json`, ingests the events the way
a real harness's events are ingested, writes them to a store under `target/tmp`,
and then asserts what SURE says — the outcome, the sentence a reader is shown,
the evidence, and the whole of the report section.

## Watch out

The recording holds an event that **says** twelve tests passed. That number is
the harness's own account of itself, and SURE records it as an observed event
rather than as a verified result. Nothing in this fixture ran anything.

There is also a file write one second before it. That matters: the write does
not invalidate the event (it came first), it is there so that the control below
has something to be compared against.

## The control

The same recording with **one field of one event moved**: `mytest.finished`
renamed to `test.finished`.

SURE must then answer the opposite way — `Confirmed`, one piece of evidence,
pointed at that event. If it still said "cannot confirm", it would be a checker
answering that to every claim it is shown, and the fixture would prove nothing
about this recording. The test checks that the control's events differ from the
fixture's in that one field and no other, before it reads the outcome.

## What SURE should say about it

SURE should tell the person reading the report that the claim about the tests is
**not confirmed**, in the words:

```
Cannot confirm: SURE has no recorded event that supports this claim.
```

with no evidence attached and no pointer invented. It must **not** report the
tests as passing, and it must not report them as failing either: the honest
answer is that nothing in the recording establishes either.

This case is release-blocking in `evaluation/acceptance-manifest.json`, which
also asks for it to be graded `must_fix`. SURE's claim checking carries the
weight `note` on what it finds and produces no finding at all here, so the
release contract is stricter than the product is today. That gap is recorded in
`scenario.json` rather than hidden, and closing it is a change to the layer that
decides what a release-blocking outcome is — not to this fixture.
