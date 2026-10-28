# ADR 0014 — The planned-check execution contract

Status: Accepted

Date: 2026-09-22

Implementation: **wired on 2026-09-22 by `P18-T007`** — `crates/sure-core/src/pipeline.rs`
now builds the `PermissionPlan` from the mode and the permissions the run was handed,
asks `Enforcement::of` about every scheduled check, and hands the admitted commands to
`planned_check_runner`. Read the **Context** section below as the state at `47e13c0`
rather than as today: the sentence it quotes from stages 5 and 6 (*"This build has no
runner for a planned check, so none of them ran"*) is gone from the tree, and the two
sentences written in the present tense about an unwired pipeline — decision 5 and the
last consequence — are corrected in place below.

## Context

SURE plans checks and runs none of them. Measured at `47e13c0`:

- stage 4 of the pipeline builds a `CheckSchedule` (`crates/sure-core/src/pipeline.rs:689`);
- stage 5 and stage 6 report what *would* run as a sentence — "This build has no runner for a planned check, so none of them ran" (`pipeline.rs:739`, `pipeline.rs:1563`);
- `aggregation.rs:281` turns a check that came back with nothing into `CheckStatus::Unknown`;
- `Enforcement::of`, `PermissionPlan::new` and `Supervisor::start` exist, are wired to each other, and have no product caller.

Two facts make the gap harder than "wire up the runner".

**The executable work does not survive discovery.** `checks::node::NodeChecks::of` calls `command_for(...) -> Result<String, MissingKind>` and files the returned *rendered line* — `npm run build` — into `CheckReason::DeclaredCommand { command }` (`node.rs:285`). Python (`python.rs:460`), Rust (`rust.rs:277`), `core_flow.rs:571` and `runtime_probes.rs:709` do the same. From that moment the only form of the work is display text, and the safest-looking way to execute it — split the string, run the pieces — is exactly the act that turns a display string back into a program. `docs/architecture/EXECUTION_SAFETY.md` says the plan and the enforcement exist so that "no check drives on that road yet"; this ADR is about the road.

**Windows does not have the programs the plan names.** `process/mod.rs` records the measurement: a name with no extension is completed with `.exe` and nothing else, so a bare `npm` is not found on a machine where `npm.cmd` is on `PATH`; and naming `npm.cmd` makes Windows start `cmd.exe` to run it. A builder that produced `npm` would plan a command that cannot start; one that produced a shell string would be the thing the invariants forbid.

## Decision

**Executable work is a typed value from the point of discovery onward, and only an admitted one reaches a process.**

1. A new core-internal vocabulary — `PlannedWork`, `CheckOperation`, and one spec per kind of work (`CommandSpec`, `ServiceCheckSpec`, `BrowserCheckSpec`, `PrecomputedEvidence`) — carries the program, the argument vector, the working directory, the environment policy, the deadline and the output bound as **named fields**. There is no variant that takes a string to be split, and no function that splits one: `ProcessRequest` has the same rule one layer down, and this is that rule carried back to where the work is first known.

2. **A check and its operation are bound by construction.** `PlanBuilder::propose` takes `PlannedWork`, and `CheckSchedule` carries the operation beside the proposal it belongs to. A check whose operation could not be produced is not proposed at all and is reported as a check SURE could not plan — the same treatment a role with no declared script already gets. There is no side table keyed by `CheckId` that a walker could forget to fill.

3. **The schedule is metadata; the operation is the executable half.** `CheckProposal` keeps its shape and stays what a report reads. Nothing in a report, a protocol schema or a wire form changes.

4. **`Enforcement::admitted()` remains the only door.** `AdmittedCommand::new` stays private, no convenience constructor is added beside it, and the runner takes its work from `Enforcement::admitted()`. A command constant or a `CommandSpec` is not a launch: the runner cannot start one without the admitted wrapper, and that is a fact about a type rather than a rule for a reader.

5. **`inspect_only` is a value, not an absence.** Under `inspect_only` every project-running operation is `Denied` by `consent::decide_for` before any runner sees it, and **a run under it reaches no process** — which, since `P18-T007` wired the runner, is a measurement rather than a reading: `pipeline.rs`'s `a_run_a_user_did_not_grant_starts_nothing` drives the real path with a runner that records being called and asserts the record is empty. The property is checked in two places: the census in `tests/spawn_sites.rs`, which since that task holds *which files may name the types on the route* rather than the absence of a route, and an end-to-end fixture that runs `sure check` over a project whose declared tests would write a file, and asserts the file is not there.

6. **Every scheduled check produces exactly one explicit result.** A check the mode stopped keeps the plan's own stopped result. A check the mode admitted and the runner produced nothing for becomes `Error` — never a silence, never a pass. Two results for one `CheckId` is an internal error and stops the run. `aggregate`'s existing rule that an unreported critical check is `NotEnoughChecked` is unchanged and is now reached rarely rather than always.

7. **A missing observation is an error, and severity never decides status.** Exit 0 with a complete capture is `Pass`; a non-zero exit from the project's own check is `Fail`; a spawn failure, a deadline, a cancellation, a stop that could not be confirmed, or output that was materially truncated is `Error` or `Unknown` and never `Pass`. Static detectors report from what they already observed, without a process: a deterministic contradiction is `Fail`, an inference that cannot establish the property is `Warning` or `Unknown`, and a detector that could not run is `Error`.

8. **Runtime evidence is bound to the fingerprint that produced it.** The pre-run fingerprint is already computed in stage 3; the relevant project state is recomputed after execution and an earlier pass does not stand as current evidence if it changed. Builds and tests legitimately write caches and artifacts, so the comparison is the repository's existing fingerprint semantics and ignore rules — not a byte-for-byte diff of the tree. `FingerprintOptions` decides what counts.

9. **`host_confirmed` is consent, not containment.** It means the user allowed these commands to run on this machine. It does not confine them, it does not make the project's test script safe, and no report, document or message may describe it as a sandbox. Tier-2 containment is `container.rs`, which this ADR does not touch and which remains plan-only.

10. **Services and browsers run one at a time and each gets its own lifetime.** A service check starts its own service, waits a bounded window, optionally asks one loopback question, stops it, and produces its result — in that order, on every path including failure, timeout and an observation that errored. No shared service instances, no parallel runtime checks, no multi-service topologies. **The stop always happens; how much of the service it reaches is a platform fact and is reported rather than assumed.** `Stop::WholeTree` is what `taskkill /T /F` reporting success means, and it is what a Windows build gets; every other platform runs `Child::kill` on the one process SURE holds and reports `Stop::ProcessOnly`, because putting a child in its own process group needs `unsafe`, which this workspace forbids. On those platforms anything the service started may still be running, and `crate::process::outcome`'s `Stop` is where a caller reads which of the two happened.

11. **A service is not given SURE's environment.** `service::Supervisor` currently hands a service `ProcessRequest`'s default, `Environment::inherited`, and its own module comment records that as a gap rather than a decision. A service started from the product path gets an explicit environment instead, and the policy is settled and tested **before** any service check is wired in.

## What this excludes, deliberately

- Container execution or a container fallback for host work.
- Automatic dependency installation. `PythonChecks::install` stays a step that is not a check and stays unreached from the pipeline.
- Arbitrary custom shell commands, and any command read out of a README, a manifest's prose or model output.
- Live external payment, email, OAuth, database or cloud-provider validation.
- Parallel runtime checks and shared multi-service topologies.
- Any claim of OS-level containment for `host_confirmed`.
- An interactive consent UI.
- Promoting `model_assessment` evidence to `deterministic_check`.

If one of these turns out to be necessary, it stops here and becomes its own record rather than being folded into the runner.

## Alternatives rejected

**Parse `CheckReason::DeclaredCommand.command` back into a program and arguments.** The smallest diff by far, and it is the defect: a display string that a person reads would become the source of a program that runs, so the set of things SURE executes would be decided by the same text a report prints. It also cannot represent a workspace member's directory or a Windows `.cmd` name, so the parse would have to invent both.

**A side table from `CheckId` to operation, filled by the same walk that proposes checks.** Keeps `CheckProposal` untouched. Rejected because the two lists can disagree, and the disagreement is invisible: a proposal whose operation the walker forgot becomes an `Error` at run time when it could have been a type error at build time.

**Give `CheckProposal` the operation directly and skip `PlannedWork`.** Fewer types, but it puts an `OsString` program inside the value every renderer, coverage summary and repair contract already holds, and it makes `CheckProposal` the thing that decides what runs. The split is the point: one half is what a person reads, the other is what a machine starts.

**Let the runner accept a `PlannedCommand` instead of an `AdmittedCommand`.** One less lifetime to thread. Rejected because it deletes the property `enforce.rs` was built to have — that the first check to run project code cannot start something the enforcement did not admit.

**Run `.cmd` names on Windows by wrapping them in `cmd.exe /c`.** This is what the operating system does anyway, so it looks like explicitness rather than a widening. Rejected because `safety::classify` answers `UnreadText` for a batch-file name on purpose (`safety.rs:78`), and building the wrapper would be SURE constructing the interpreter it just said it could not read — the "no raw shell execution" invariant with a loop in it. The consequence is accepted and visible rather than worked around: on Windows a package-manager script is a batch file, so those checks are stopped with a reason, and the product does not pretend otherwise. **This consequence was superseded for command checks on 2026-10-22 by a route that does not construct an interpreter — see the amendment at the end of this record. The `cmd.exe /c` rejection itself stands.**

## Consequences

- `PlanBuilder::propose` and the ecosystem builders change shape, so the diff reaches every module that proposes a check. The completeness scanners — which are all precomputed evidence — move to the same door rather than keeping a second one.
- `CheckSchedule` carries work that is not report metadata. It stays core-internal; `sure-cli` reads `proposal()` and never the operation.
- On Windows, Node checks whose only runner is `npm.cmd`, `yarn.cmd`, `pnpm.cmd` or `bun.cmd` are stopped by the classifier rather than run. This is a real loss of coverage on the primary development platform and it is the honest reading of "a name is not evidence of behaviour". A project that declares a `node.exe`-based runner is unaffected. **Superseded for command checks on 2026-10-22 — see the amendment at the end of this record.**
- The support ceiling in `support::CEILING` moves only if the measurements in `P18-T012` earn it. The default outcome of this ADR is that it does not move: level B says SURE can run approved generic checks, and a build that runs them on one platform and not on another has not earned a single sentence for both.
- `tests/spawn_sites.rs` was written to fail the day the first check reaches the runner. **It did not fail, and the reason is worth keeping**: `P18-T007`'s wiring named no type that census is about (`pipeline.rs` names `CommandRunner`, not `ProcessRequest`), so what went false was a paragraph rather than a rule. The paragraph, the entry for `process/request.rs` and the ceiling's own reason were rewritten in that task; the constant did not move, for the reason two bullets above.

## Frozen semantics

The execution vocabulary — `ExecutionMode`, `ExecutionDecision`, `ActionKind`, `CommandClass`, `CommandEffects` — and the check vocabulary — `CheckStatus`, `NotCheckedReason`, `CheckResult`, `blocks_green` — are unchanged by this ADR. `docs/architecture/FROZEN_SEMANTICS.md` is where they are pinned. What this ADR adds is a representation, not a status.

## Revisit when

A second runner exists — a container executor, or a service topology SURE did not start. Both would need an admission decision of their own, and this contract's claim is about the work SURE launches, not about every process that ends up running.

## Amendment — 2026-10-22: a known package-manager shim may be started through its own JavaScript entry

The consequence above — *"On Windows, Node checks whose only runner is `npm.cmd`,
`yarn.cmd`, `pnpm.cmd` or `bun.cmd` are stopped by the classifier rather than run"* — was
true when this record was accepted and is no longer true of the product path.
`crates/sure-core/src/package_launcher.rs`, bound at the composition root
(`sure-cli/src/check.rs`) the same way the browser driver is, resolves a **bare**
`npm`/`npx`/`pnpm`/`pnpx`/`yarn`/`yarnpkg` whose `ProgramPath` answer is a `.cmd` or
`.bat` shim, when `node` and the manager's own shipped JavaScript entry (or the corepack
dispatcher) are present, into `node <entry> <the plan's arguments>`.

This is not the alternative this record rejected. The launcher does not read the batch
file, does not build a command line, and does not start a command interpreter; it starts
`node`, a program the safety classifier already knows, with a file the installed manager
ships. Every other shape — a `.ps1`, a name that resolves to nothing, a shim without its
JavaScript side, any program that is not one of those names — keeps the honest
`InterpreterRequired` / not-found result this record describes. **`bun.cmd` is one of
those other shapes**: the launcher translates only the names above, and bun's shim is not
one of them. The resolver's answer is unchanged: `ProgramPath` still says
`InterpreterRequired` for `npm.cmd`, because that is still what naming the batch file would
do.

**Services are not on this path.** `StartSmoke` starts what a service declaration names
and does not hold a `ProcessRunner`; the service declaration still accepts only
`node_entry` on Windows, and ADR 0016's rejection of a package-manager service launcher
stands.

