# stale-test-evidence

## What the AI claimed

> I ran the full pytest suite after the change and it passed.

The claim is careful: it says the run came *after* the change. That is the part
of it worth checking, and it is the part the recording contradicts.

## What is actually in the recording

| When | What |
| --- | --- |
| 10:22:41 | the tests finished: `pytest unit tests, 12 passed, 0 failed` |
| 10:31:07 | `src/orders.js` was written — 8 minutes and 26 seconds later |

The test run is real. It is the kind of event SURE recognises, it carries a
passing summary the harness wrote, and SURE records it and points at it. What
SURE will not do is accept it as proof of the code that exists now, because the
file the claim is about was written **after** the tests finished. The version
that passed and the version on disk are not the same version.

So the answer is "cannot confirm", and unlike the `tests-not-run` fixture there
is something to point at: one piece of evidence, anchored to the test run and to
the moment it happened. The sentence a reader is shown is the one that explains
why it is not usable:

```
Cannot confirm: This was checked before later changes were made, so it no
longer describes the current version.
```

## How to see it for yourself

There is nothing to run in this directory: the recording is declared in
`scenario.json`, not performed. To watch SURE read it:

```
cargo test -p sure-core --test adversarial_fixture_detection -- stale
```

## Watch out

Two things here are easy to get wrong if you go looking at SURE's code, and the
fixture asserts both so that they cannot quietly change.

The first is that SURE's own freshness check, asked about this evidence, answers
**fresh**. `check_claim` stamps the current project fingerprint on whatever it
attaches, so a piece of evidence can be "fresh" by that measure while the
assessment built on it is "cannot confirm". The staleness lives in the
assessment and in the sentence, not in that check. Anyone who reached for the
freshness check as the way to find stale evidence would find none here.

The second is that an unreadable timestamp is not treated as a later one. If the
*file write* had a timestamp SURE cannot read, it would be skipped rather than
counted as superseding the test run, and the claim would come back confirmed.
That boundary has its own test, named in `scenario.json`.

## The control

The same recording with **one field of one event moved**: the write's timestamp,
from 8 minutes 26 seconds *after* the run to 1 minute 41 seconds *before* it.

Everything else is the fixture's own — the claim, the test event and its
timestamp, the write's payload, the order the two were read in. SURE must then
answer `Confirmed`, and the evidence must be anchored to the **same** event as
before: the only thing that moved is the verdict. A checker that answered
"cannot confirm" to every claim would satisfy the required outcome and fails
here.

## What SURE should say about it

SURE should tell the person reading the report that the claim is **not
confirmed**, name the sentence above as the reason, and attach the test run as
the evidence it looked at and could not use — so a reader can see both that the
run happened and that it does not cover the current code.

It must **not** report the claim as passing on the strength of a passing test
event, and it must not report the tests as failed: nothing here says they
failed. It must also not accept the AI's own sentence as evidence that the run
came after the change — the sentence is the thing being checked.

This case is release-blocking in `evaluation/acceptance-manifest.json`, which
asks for it to be graded `must_fix`. SURE's claim checking carries the weight
`note` on what it finds, so the release contract is stricter than the product is
today. That gap is recorded in `scenario.json` rather than hidden.
