# ADR 0017 — Lifting the support ceiling to `generic`

Status: **Accepted** (2026-10-23)

Date: 2026-10-23

Implementation: 2026-10-23 — `CEILING = SupportLevel::Generic`, the reason and
plain-description sentences, the tripwire, `support_levels.rs`, and
`docs/product/SUPPORTED_STACKS.md`. The residual gaps are follow-ups, not
conditions of this decision.

## Context

`SupportLevel::InspectOnly` (C) is the ceiling every project is reported at today
(`crates/sure-core/src/support.rs`). Level B is defined in
`docs/product/SUPPORTED_STACKS.md` as:

> SURE can discover common manifests/commands and run approved generic checks,
> but does not claim framework-specific completeness.

`docs/adr/0015-support-ceiling-evidence.md` set the ceiling at C because, at the
time, one of its three measured cases was false: a Node project on Windows was
stopped at the plan, and no product-path test had run a project's declared check
to completion on any platform. Its *Revisit when* section named the missing
reading: *a project's own declared check running to completion under the product's
real runner and passing, on a machine whose platform the claim would cover.*

That reading now exists, and the Windows obstacle that produced the first false
row has a product answer. The question this record decides is whether the whole
level-B sentence is earned, not merely whether one more check passes.

## Evidence

### The reading ADR 0015 asked for

- `crates/sure-cli/tests/finished_declared_check.rs`
  (`a_declared_check_finishes_and_its_result_reaches_both_cli_reports`) drives
  the real CLI over a Rust fixture: under `execution.mode: host_confirmed` the
  project's declared `cargo test` writes its marker, the report row is `pass`,
  the row is critical, and both the human and JSON reports carry it. Under
  `inspect_only` the same fixture's test does not run and the row is `skipped`.
- The test is part of `cargo test --workspace`, which the `ci` matrix runs on
  Windows, macOS and Linux. The `ci` run at `d618d23` is green on all three
  `rust` legs; the test's first commit (`4ec2e2d`) is red, and the follow-ups
  that carry the record are the commits after it.

### Honesty of the result, not only the pass

- `crates/sure-core/src/planned_work.rs`'s `CommandRun::status` maps a finished
  run: exit 0 with complete output is `Pass`; any other exit code is `Fail`;
  timeout or cancellation is `Unknown`; a run that never started is `Error`.
  `a_run_that_was_cut_short_never_leaves_a_critical_check_green` sweeps every
  termination and every process error and asserts none becomes `Pass` or
  `Warning`.
- A completed check that is reported as unrun, or a critical check that produced
  no result, is held out of green by `aggregation.rs` and its tests; the
  false-green rule is unchanged by this decision.

### The Windows obstacle and its product answer

- `crates/sure-core/src/package_launcher.rs` (bound at `sure-cli/src/check.rs`)
  translates a bare `npm`/`npx`/`pnpm`/`pnpx`/`yarn`/`yarnpkg` whose resolved
  file is a `.cmd`/`.bat` shim, when `node` and the manager's own shipped
  JavaScript entry (or the corepack dispatcher) are present, into
  `node <entry> <the plan's arguments>`. It does not read the batch file, build
  a command line or start an interpreter. `bun.cmd` is not translated.
- Real Windows runs of `npm run test`, `pnpm run test` and `yarn run test`
  produced `pass` for succeeding tests and `fail` (exit 1) for failing ones; the
  MiQi zero-mock E2E also ran `npm run test` and `python -m pytest` through SURE
  on Windows. These are local/MiQi readings, not a SURE CI test — see the gaps.

### The rest of the product path

- `inspect_only` still reaches no process: `pipeline.rs`'s
  `a_run_a_user_did_not_grant_starts_nothing` runs the real pipeline with a
  runner that records being called and asserts the record is empty.
- Service and page checks have real-process evidence with pass and fail results:
  `crates/sure-cli/tests/declared_service_check.rs`,
  `crates/sure-core/tests/runtime_start.rs`,
  `crates/sure-core/tests/browser_driver.rs`.
- Discovery grades Node, Python and Rust manifests `generic` (B) or
  `inspect_only` (C); no discovery path grades `first_class` (A) today.

## Assessment against level B

The core of the sentence is earned:

- common manifests/commands are discovered and graded by `discover`;
- a project's approved generic check runs to completion and passes under the
  product's real runner, on all three platforms SURE ships on;
- a non-zero exit is a `fail`, not a pass, and the mapping is swept by tests;
- the default mode still starts nothing without the user's grant.

What is **not** earned is level A: there are no framework-aware deterministic
checks claimed on every platform, and no discovery path grades A. This record
does not propose moving to A.

## Residual gaps (named, not hidden)

1. **No tracked end-to-end failing declared command in SURE's own CI.** The
   fail mapping is unit-tested, but the only tracked CLI run of a declared
   command is the passing Rust fixture. A failing fixture (`exit 1` → `fail`)
   should be added.
2. **Windows Node command evidence is not in SURE's CI.** The launcher's real
   runs and the MiQi E2E are local/cross-repository; a tracked Windows CI test
   that runs `npm run test` over a dependency-free fixture would make the level-B
   claim reproducible from this repository alone.
3. **Unknown shims remain stopped.** `bun.cmd` and any manager whose JavaScript
   entry the launcher cannot prove are still refused with the honest
   not-startable result. Level B does not promise every ecosystem, but the
   report's plain description must not read as if it did.
4. **Services are narrower than commands.** On Windows a declared service still
   accepts only `node_entry` (ADR 0016); a package-manager service launcher is
   rejected. Level B's "generic checks" covers what the plan can run; a service
   check that cannot start remains a visible not-checked row.
5. **The reason text assumes the old ceiling.** `what_sure_can_do`'s
   `understood != level` branch says "SURE has not run this project's checks …
   only been shown to work on one platform"; that sentence is now false and
   would also be wrong for a future A→B cap. It must be rewritten, not carried.
6. **The plain description promises more than "approved".** `SupportLevel::Generic`
   currently renders "SURE can find how this project is built and run, but does
   not understand everything about it." A reader may hear "runs by default".
   The sentence should say *when you allow it* and that a check that cannot start
   is reported as not checked.

## Decision

**Raise `CEILING` to `SupportLevel::Generic`, with the reason sentence rewritten
and the gaps above recorded as follow-ups.** Level B is the honest single
sentence for what the product can now do; keeping C would understate the
measured capability and contradict ADR 0015's own rule that a ceiling moves when
measurements earn it.

The change is not the constant alone. Accepting this record means:

1. `CEILING = SupportLevel::Generic`; `classify` reports B for projects discovery
   graded B, C where discovery itself is C. **No project reaches A.**
2. The capped-reason branch is rewritten so it never repeats the old "one
   platform" sentence; an A→B cap (unreachable today) gets its own truthful
   sentence before A grading exists.
3. `SupportLevel::Generic`'s plain description and the level-B reason state that
   checks run **when the user allows it**, and that a check whose command cannot
   be started is reported as not checked rather than passed.
4. The tripwire `the_ceiling_todays_build_claims_is_never_above_inspect_only`
   and `crates/sure-core/tests/support_levels.rs` are rewritten deliberately:
   levels become B for B-graded fixtures, exact reasons updated, C fixtures
   unchanged. `docs/product/SUPPORTED_STACKS.md` stops saying "the level any
   project can reach in this build is C" and "SURE cannot run it".
5. Follow-up tests (not conditions for the decision, because the core reading
   exists): a failing declared command end to end; a Windows tracked
   `npm run test` over a dependency-free fixture. Until they exist, the ADR says
   so rather than implying the coverage is complete.
6. The default `ExecutionMode::InspectOnly` and the consent gate are unchanged.

## What changes in reports

- A project discovery grades `generic` is reported at level B with the reason
  above. A project whose discovery is C stays C.
- The human, JSON and portable reports all read `ProjectSupport`; the JSON
  `support.level` becomes `generic` for those projects. No schema field changes.
- The aggregate/verdict severity and hand-off readiness do not derive from the
  support level; a B label does not turn a not-enough-checked run green. The
  level is rendered in the report's support section, not used as a verdict
  input.

## Alternatives rejected

**Keep C until every gap closes.** The core reading ADR 0015 named exists, and
the gaps are coverage of the claim rather than counter-evidence to it. Waiting
would keep the product's own report saying "cannot safely run it" after a
tracked, three-platform run of a project's check. It is the safer-looking answer
and the less honest one.

**Raise to A as well.** No discovery path grades A and no framework-aware checks
run on every platform; the record would have no evidence under it.

**Change `SupportLevel::plain_description` alone and leave the ceiling at C.**
That makes the report say "generic" without the level, which is the vocabulary
lying in a different field; the level and the sentence have to move together.

**Make the ceiling a function of the platform or the discovered stack.** It
would be the most precise answer, and it is a redesign of what a support level is
(ADR 0015 rejected it at this size). `CEILING` stays a constant until a record
takes that design.

## Consequences

- The constant and its tripwire test change deliberately, not silently; the
  test's failure message is the instruction to rewrite it.
- `MiQi` pins the fork's behavior SHA (`SURE_FORK_SHA = c0d28b4`). If this
  change is merged and accepted, that pin must move to the new behavior commit
  and `sure-e2e` must be re-run; a documentation-only commit does not.
- The reason text is user-facing and is asserted verbatim in
  `support_levels.rs`; the new sentences must be reviewed as prose, not only as
  test strings.
- No false-green property changes: `inspect_only` still starts nothing, a
  non-zero exit is still `fail`, and a not-checked critical check still blocks
  green.

## Revisit when

- A discovery path starts grading A, so the A→B cap becomes reachable and needs
  its own sentence.
- The two follow-up measurements exist (failing command end to end; Windows
  tracked `npm run test`), at which point the residual-gap section shrinks.
- A second platform-specific shim family appears (bun, a new manager) and the
  launcher does not cover it; the level-B description must say which starts are
  proven rather than implying all.
