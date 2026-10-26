# benign-test-mocks

A corpus case that is about *not* finding something.

The question this fixture answers is one sentence from
`evaluation/acceptance-manifest.json`:

> benign test mocks do not become must-fix production findings

## What the project is

A small checkout service, runnable with nothing installed but Node:

```
npm start        # node src/server.js
npm test         # node scripts/check.js
```

`src/` holds the service. `tests/`, `examples/`, `docs/` and `stubs/` hold the
things a real repository keeps beside it: a hand-written test double, a worked
example, a documentation snippet, and a stand-in for a service this project does
not own.

## Where the benign content is

Five files carry the vocabulary SURE's candidate scanners look for. Every one of
them is content a reviewer would be happy to see, and none of them is shipped
code:

| file | why it is benign | what reads it |
| --- | --- | --- |
| `tests/checkout.js` | a test double for the payment client | `candidate_scanner` — the word `mock`, in a `tests/` directory |
| `docs/snippets/usage.js` | the snippet a documentation page embeds | `candidate_scanner` — a `TODO`, in a `docs/` directory |
| `examples/quickstart.js` | a worked example with a placeholder address | `candidate_scanner` — the word `placeholder`, in an `examples/` directory |
| `stubs/pricing-api.js` | a stand-in for a service the project does not own | `candidate_scanner` — the word `stub`, in a `stubs/` directory |
| `src/gateway.mock.js` | the double a developer runs the screen against offline | `noop_heuristics` — `test@example.com`, in a file whose *name* marks it as a double |

Four of those five are classified by a directory and one by a file name, and
that is the point rather than an accident: `classify_path` answers both ways, and
a corpus that only ever exercised one of them would be measuring half a rule.
The one answered by a file name is `src/gateway.mock.js`, because `src/` is not a
conventional directory and the `.mock.` segment is the whole of what tells it
apart from the client it stands in for.

## What the answer has to be

Every one of the five is a `note`, and nothing any of the five detectors says
about this project is material. The fixture would be worth nothing if the five
were simply not read — a report that says `No unresolved findings.` because nothing
looked is not the same as one that says it because what it looked at cannot reach
a user — so the grading drives three controls over copies of this project, each
changing exactly one thing:

- lift `tests/checkout.js` out of its conventional directory, and the same bytes
  are still detected and reach `can_fix_later`;
- put the project's whole vocabulary in a markdown file inside `docs/`, and no
  detector reads it at all — which is why the documentation half of this corpus
  is a `.js` file;
- take the marker out of `src/gateway.mock.js`'s file name, and the same bytes
  reach `must_fix`, because a placeholder address in production is a
  substituted action rather than an unfinished marker.

The last one is the control that matters most, and it is the one worth reading
twice: `UnfinishedMarker` can never be `must_fix` even in production, so a corpus
of TODOs and mock words cannot show that the gate is doing anything. Only a
`SubstitutedAction` can, and this fixture has exactly one of those, in a file
whose file name is the whole reason it is a note.

That third control is also the only one that displaces a file rather than moving
one: two files cannot both be called `src/gateway.js`, so the double is copied
onto the real client's path and then removed. What keeps that from being a second
variable is measured, not asserted — the client it displaces produced no proposal
at all in the shipped project, and the grading test says so before it compares
the two readings.

## What this fixture does not claim

- It is not a claim that nothing benign anywhere escalates. The third control
  above is the measurement of that boundary: outside a test, example,
  documentation or mock-fixture path, the same bytes are a `must_fix`.
- It is not a severity calibration. It records what the product produced on the
  day it was written, and `P7-T011` owns the argument about which level is right.
