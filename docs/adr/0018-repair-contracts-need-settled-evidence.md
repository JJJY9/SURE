# ADR 0018 — A repair contract needs evidence a check can settle

Status: **Accepted** (2026-10-23)

Date: 2026-10-23

Implementation: `crates/sure-core/src/pipeline.rs` (`contracts_for`), and the
status/next-step rule in `crates/sure-core/src/findings_from_checks.rs`.

## Context

A check result becomes a finding whenever it did not pass. The finding's severity
is the check's own; its evidence class is the result's. Candidate checks are
allowed to carry `must_fix` while their evidence is still `Inference`:
`finding_gravity.rs` decides severity from what the gap would mean if true, not
from whether SURE established it, and the adversarial corpus requires that
combination (a fake payment path is `must_fix` + `inference`).

On 2026-10-23 a real MiQi repair job (`d1819474-802`, Medix project) showed what
that means one layer later. SURE produced three `UI action: click/submit handler`
findings, each `must_fix`, each with `Inference` evidence and the sentence
"Nothing has settled it: it was read from the source, and no command has been run
for it." The repair stage wrote a contract for each one, because each named a
check the run had planned. The repair agent read `web/app.js`, verified that all
three handlers call real functions and hit real backend routes, and — correctly —
changed nothing. The re-check still reported all three findings Open and `must
fix`. The agent did not fail; the contract asked it to fix a candidate SURE had
never established.

The evidence model already has the predicate this stage needed:
`Finding::is_grounded()` says whether the finding's own evidence can carry its
severity. For a `must_fix` it requires at least one anchor whose evidence class
is `ObservedFact` or `DeterministicCheck`. A `must_fix` + `Inference` candidate
is not grounded. The repair stage was not asking.

## Decision

**Only a grounded finding is repair-eligible.** `contracts_for` skips a finding
where `Finding::is_grounded()` is false and records the refusal in the stage
detail. It does not silently drop the finding: the finding remains in the report,
with a status and next step that say what SURE actually knows.

The status rule in `findings_from_checks` follows the same line:

- a check that did not run stays `CannotConfirm` (unchanged);
- a check that ran and whose evidence cannot carry its severity — a blocking
  `Inference`/`ModelAssessment`/`Unknown` result — becomes **`CannotConfirm`**,
  with a next step that says to check it by hand, not to change code to make the
  candidate disappear;
- a check that ran and whose evidence can carry its severity stays `Open` with
  the existing repair next step;
- a non-blocking candidate (a TODO marker, `can_fix_later`/`inference`) stays
  `Open` and remains repair-eligible, because removing the marker is an action a
  check can observe. The full-repair E2E depends on that contract existing.

No finding is hidden, no severity is lowered, and no false-green guard moves. A
`must_fix` candidate is still reported as `must_fix` — *if true, this blocks
hand-off* — while its status says SURE could not settle it. The user gets a
manual-verification task, not an impossible repair contract.

## Consequences

- A run whose findings are all candidates has no repair contracts; stage 11 is
  `not_run` with a sentence naming the findings and the reason. The panel's
  "hand this to an AI" action has nothing to hand over, which is the honest
  state.
- A mixed run still writes contracts for its grounded findings; the stage detail
  lists the refused ones and why.
- The fake-payment / no-op class of `must_fix` + `inference` findings no longer
  produces contracts. That is a deliberate trade-off: a candidate is something
  to look at, and a human can still act on it; SURE no longer asks an agent to
  "fix" it without a check that can observe the fix.
- `Finding::is_grounded` becomes load-bearing for the repair stage as well as for
  the release gate; a change to it now changes what SURE will repair.
- Candidate findings that could be settled by a different kind of check (a
  browser clicking the handler, a runtime probe) remain candidates until such a
  check exists. ADR 0017's support-ceiling reasoning is unaffected.

## Alternatives rejected

**Keep the contract for every finding and let the agent decide.** This is what
failed: the agent correctly decided nothing was wrong, and the panel still showed
`must fix`. The contract is SURE's statement that a fix is needed; it must not be
weaker than the evidence.

**Drop candidate findings from the report.** Hides a concern the user may want to
inspect, and makes the report less honest in the other direction.

**Downgrade every `must_fix` candidate to a lower severity.** Changes the
detector calibration and the adversarial corpus, and loses the "if true, this
blocks hand-off" reading.

**Make every inference finding `CannotConfirm`.** Would break the TODO repair
flow, where an inference identifies a marker that a small code change can remove
and a check can observe.

## Revisit when

A check can settle a UI action by actually exercising it (a browser click with a
state/network assertion, or a runtime probe). At that point the finding's
evidence class can become `DeterministicCheck`/`ObservedFact`, and the candidate
becomes repair-eligible through the ordinary rule rather than through an
exception.
