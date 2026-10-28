# unknown-evidence

## What the AI claimed

> I ran the pytest suite and it passed.

## What is actually in the recording

| When | What |
| --- | --- |
| 23:58:30 | a file was written: `src/orders.js` |
| `23:59:60` | the tests finished: `pytest unit tests, 12 passed, 0 failed` |

Read the second timestamp again. The time is `23:59:60` — a leap second. A
minute has 59 seconds, and this one has 60.

That is not a typo in the fixture, and it is not an accident of the format. The
rules that describe timestamps on the wire allow a second of 60, for the days
when a minute really does have one. SURE checks the shape of a timestamp when it
accepts an event, and `23:59:60Z` passes that check. Later, when SURE has to
decide whether that event can prove anything, it reads the timestamp with
different code — code that refuses a second of 60 — and gets nothing back.

So the event is there, it matches the claim, SURE found it, and SURE cannot say
when it happened. Without that, it cannot say whether the code changed
afterwards. It will not use evidence it cannot date, so the answer is "cannot
confirm":

```
Cannot confirm: I do not know which version of the code this applies to, so I
cannot use it as proof.
```

And it still points at what it found. One piece of evidence, anchored to the
test run and to the very timestamp it could not read — which is the difference
between "SURE found nothing" and "SURE found this and cannot place it".

## How to see it for yourself

There is nothing to run in this directory: the recording is declared in
`scenario.json`, not performed. To watch SURE read it:

```
cargo test -p sure-core --test adversarial_fixture_detection -- unknown_evidence
```

The event is ingested the way a real harness's event is ingested, so the check
that accepts `23:59:60Z` on the way in is exercised and not assumed.

## Watch out

This is the only state in SURE that produces the "I cannot place this" answer,
and it is the only fixture in this corpus that reaches it. Three sentences can
end a claim check with "cannot confirm", and each of the three fixtures here
owns exactly one of them: no event at all (`tests-not-run`), an event that came
before a later change (`stale-test-evidence`), and this one — an event with no
usable time.

The date is not a real leap second: none is scheduled. That is part of the
point. `23:59:60` is what a harness bug produces, or a leap-second table with a
date SURE has not been told about. The fixture is built on the disagreement
between the two parsers, not on a claim that a particular day had 61 seconds.

Nothing here says the event is malformed, and nothing here says the tests
failed. SURE accepted the event, stored it whole, and read it back. It simply
will not treat it as proof.

## The control

The same recording with **one field of one event moved**: the leap second
becomes `23:59:59`, the second before it, which SURE can read.

Everything else is the fixture's own. SURE must then answer `Confirmed`, with the
evidence anchored to the event at its new timestamp — so the only thing that
changed the answer is whether SURE could read the time. A checker that answered
"cannot confirm" to every claim, or to every event with a strange-looking
timestamp, fails here.

## What SURE should say about it

SURE should say it cannot confirm the claim, give the reason above, and attach
the event it found with the timestamp it could not read. A reader should be able
to tell that SURE is not saying the tests failed, not saying the event was
malformed, and not saying it found nothing.

This case is **not** release-blocking in `evaluation/acceptance-manifest.json`,
which asks for it to be graded `note` — the one of the three where the product
and the contract agree on the weight.
