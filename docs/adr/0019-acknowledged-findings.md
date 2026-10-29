# ADR 0019 — A person can accept a finding SURE could not settle

Status: **Accepted** (2026-10-29)

Date: 2026-10-29

Implementation: `crates/sure-core/src/acknowledgement.rs` (the record and its
reader), `sure_domain::status::aggregate_with_accepted` (the aggregate rule),
`crates/sure-cli/src/acknowledge.rs` (the command), and the application step in
`crates/sure-core/src/pipeline.rs`.

## Context

Some findings can never be settled by a check. A `status: 200,` in an
OpenAI-compatible bridge, the word `mock` in a doc comment: the candidate
scanners match text, no command can decide the question, and ADR 0018 correctly
keeps these findings out of repair contracts — there is nothing an agent could
change that a check would observe.

What ADR 0018 did not provide is somewhere for the person's verification to go.
The finding's own next step says "check this by hand and decide whether a change
is needed", and then the run stays `needs_attention` forever, because the check
result it came from is a warning and nothing can make it pass. Measured on
open-dream-rsi (2026-10-29): all four dynamic checks passed (build, tests, mypy,
ruff) and the verdict still read `needs_attention`, with MiQi's acceptance panel
showing "cannot confirm" on a project a human had already reviewed.

The vocabulary has had the word for this all along: `FindingStatus::AcceptedRisk`,
"The user decided to live with it" — carried by the domain, the wire contract and
the renderers, and never produced by anything.

## Decision

**A person can record that they reviewed a finding, and the run reports it as an
accepted risk instead of an unresolved one.** Five rules keep that from becoming
a false green:

1. **Only findings SURE could not settle can be accepted.**
   `Finding::can_be_acknowledged` is true only when no piece of the finding's
   evidence could alone carry a `must_fix` (`ObservedFact` / `DeterministicCheck`).
   A candidate warning qualifies; a failing test, a checker error, a check that
   did not run and a claim that was contradicted do not. Accepting is an answer
   to SURE's honest uncertainty, never to a settled failure.

2. **The acknowledgement lives in the user-level store, outside the project.** It
   is the new `RecordKind::Acknowledgement`: a versioned, redacted row holding the
   project root, the finding's cross-run identity (title, anchor location,
   locator), the finding id it was made from, a mandatory reason, and when it was
   made. The checked project's files cannot add, remove or edit one — the agent
   whose work is being judged cannot silence a candidate by editing the thing
   being judged (ADR 0011's boundary, applied to acceptance).

3. **The identity is `FindingKey`'s** — the same key `reconcile` already uses to
   follow a finding across runs. If the evidence changes (the matched line moves
   or changes, the title changes), the key no longer matches and the finding comes
   back as unresolved. An acknowledgement is a statement about evidence SURE saw,
   not a blanket permission for a file.

4. **The finding keeps its evidence, severity and place in the report.** The
   matching finding's status becomes `AcceptedRisk`; its check result still says
   `warning`. The accepted finding leaves `open_findings()`, the re-check's
   still-open list and the repair-contract list, but it stays in the report, in
   the counts and in the history, labelled as accepted.

5. **Aggregation discounts only acknowledged warnings.**
   `aggregate_with_accepted` nullifies exactly one rule — the `needs_attention`
   contribution of `warning` results whose finding was acknowledged — and nothing
   else: `fail`, `error`, `unknown`, skipped checks, critical out-of-scope checks
   and the "nothing ran" rule are untouched. When a run is green *because of*
   acknowledgements, the headline gains a clause naming how many findings the
   person accepted, so it can never read as "everything passed" when something
   was reviewed and accepted instead.

The command is `sure acknowledge`: `--finding <id> --reason <text>` records,
`--list` shows what this project has accepted and why, `--undo <record-id>`
removes one. The id resolves in one of two ways, because a plain `sure check`
records nothing by design:

- from this project's recorded findings — the rows `sure repair` and
  `sure recheck` write — when no report is named;
- from the machine-form report a check printed (`--from FILE`, with the id in
  it), where the run itself wrote down the finding's identity, its
  `acknowledgeable` answer and the project state it was found against. The
  report is SURE's own output, not a project file, and the record is written
  from it rather than from anything typed.

The pipeline re-checks `can_be_acknowledged` against the live finding when an
acceptance is applied, so the record-time answer — the store row's or the
report's — is a courtesy, not the guarantee: an acceptance that names a settled
finding's identity never matches one.

## Consequences

- A project whose only non-green results are reviewed candidates can be `green`,
  and the headline says how many findings were accepted to get there. MiQi can
  show "accepted by you" instead of an unresolved problem.
- An unrelated edit above the matched line changes the finding's locator, so the
  acknowledgement stops matching and the finding comes back for one more review.
  That direction is deliberate: the alternative — keying on the file or the
  title alone — would hold an acknowledgement across a change the person never
  saw.
- The store is local (ADR 0002). An acknowledgement does not travel with the
  project; a second machine reports the candidate again until a person there
  reviews it.
- `DOMAIN_SEMANTICS_VERSION` moves to 2: the stored meaning of `accepted_risk`
  and of a green aggregate that counts acknowledged warnings is new.
- The acknowledgement records a *decision*, not evidence about the project. It is
  never rendered as proof that the code is correct, and `render_summary` still
  reports what SURE could not settle.

## Alternatives rejected

**Let the project declare its accepted findings (in `sure.yaml` or a baseline
file).** The project is editable by the agent under judgement; a self-issued
silence is exactly the bypass the authority rules exist to prevent (ADR 0011).

**Rewrite the acknowledged check result to `pass`.** The check did not pass, and
a stored pass that no command produced is the false green the status model
exists to prevent.

**Hide acknowledged findings from the report.** A hidden acceptance is
indistinguishable from a fix, and the person needs to see what they accepted.

**Allow acknowledging anything, including failures.** The run's verdict would
become the user's opinion of the project rather than SURE's evidence about it.

**A new `accepted` check status.** The six statuses are a reported *finding about
the check*; acceptance is a decision about a finding, and mixing the two would
make `warning` and `accepted` two spellings of one fact.

## Revisit when

A check can settle one of these candidates — a runtime probe, a browser click.
At that point the finding is grounded, ADR 0018's ordinary rule applies, and the
right action is a repair rather than an acceptance.
