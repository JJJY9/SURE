# missing-user-intent

## What is in this directory

A very small web project: two files under `src/`, one route declared in one of
them, and nothing else. Nothing in it is broken, and nothing in it is a
placeholder. It is the shape of an honest little service.

| File | What is in it |
| --- | --- |
| `src/server.js` | the app, declaring one route: `/bookings` |
| `src/bookings.js` | the code behind that route |

## What is missing

The request. Nobody ever told SURE what this project was supposed to do.

That is the whole fixture. The project is not the case; the case is what a
report is allowed to say about a project whose purpose was never provided.

## What SURE should say

SURE should look at the project, find nothing wrong with it, and then say — in
its own words, not in a footnote — that it cannot tell whether this is what the
user asked for, because it was never told what the user asked for:

```
I can check whether the current project runs and whether anything obviously looks
incomplete. I cannot confirm that it matches your original request because that
request was not provided to SURE.
```

That sentence is fixed. It is the one SURE must use, and the test compares the
whole rendered summary against the fixture's declaration, so a report that
quietly stopped carrying it would fail.

It must **not** say the project is complete, done, or matching the goal. There is
no goal to match. And it must not turn the missing request into a defect of the
project either: there is nothing here to fix.

## Why this matters more than it looks

The tempting failure is quiet. A report that shows a capability line, a headline
and "No unresolved findings." reads as a clean bill of health. On a project nobody
described, it is not a clean bill of health — it is silence, and a reader takes
it for a verdict on work SURE never saw the description of.

`evaluation/acceptance-manifest.json` has a case for this fixture, and the two
agree: not release-blocking, expected severity `note`, with the expectation
*no claim of full requirement fulfillment without trusted intent*. SURE produces
no finding here at all, which is under that ceiling rather than at it.

## The control, and why the fixture is worthless without it

A reporter that answered *"I cannot confirm that it matches your original
request"* to **everything** would satisfy every sentence above and would be
measuring nothing at all. So the same project is read again with one thing
moved: a goal is supplied.

> serve the bookings route

The project is the same directory, read by the same call, and the test asserts
the two readings of the project are identical before it looks at either answer —
so the goal is the only difference there is.

With a goal, the answer must flip in both directions:

- the label becomes **Comparable** instead of *after the fact*;
- the caveat disappears from the summary — the summary loses exactly that one
  line and gains nothing;
- one requirement is checked and it **matches**, against the `/bookings` route
  the project declares.

If SURE still said "I cannot confirm", the fixture would be recording a
pessimistic reporter rather than a missing request.

## How to see it for yourself

```
cargo test -p sure-core --test adversarial_fixture_detection -- missing_user_intent
```

That test reads `scenario.json`, drives SURE's real pipeline over this directory
with no goal, asserts the claim, the caveat, the sweep and the whole rendered
summary, then drives the same pipeline again with the goal above and asserts the
opposite. Nothing is run inside the project and nothing is written outside
`target/tmp`.

## Watch out

SURE's answer here is **not** a statement about the code. The project it reads
declares `/bookings` and implements it; a reader who takes "no open findings" as
"the work is done" has made a mistake SURE's caveat exists to prevent.

There is a second, smaller trap worth knowing about. With a goal supplied, SURE
matches that goal to the project by keyword, against the project's routes, its
component paths, its declared commands and the first non-blank line of each
source file. The control's goal matches because the word *bookings* appears in
the route the project declares. That is anchoring, not understanding, and the
fixture says so rather than leaving it to be discovered.
