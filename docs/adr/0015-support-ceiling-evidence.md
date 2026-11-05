# ADR 0015 — The support ceiling, on the measurements that were taken

Status: Accepted — **superseded by ADR 0017 (2026-10-23)**, which raised the
ceiling to `Generic` once the `Revisit when` reading existed. The readings below
remain the evidence record; this record's decision is no longer the ship state.

Date: 2026-09-22

Implementation: **`P18-T012` took the readings and left `support::CEILING` where it was.**
Three files carry the consequence: `crates/sure-core/src/support.rs`'s module comment no
longer says the macOS and Linux legs have never run (they have), `crates/sure-core/tests/
browser_probe.rs`'s walk covers every crate rather than one, and this record is the
measurement ADR 0014's last consequence pointed forward to. The constant itself was
unchanged at the time; ADR 0017 is the later record that moves it.
(`crates/sure-core/src/support.rs:180` — it was `:152` before this task rewrote the
module comment above it).

## Context

`support::CEILING` is the highest support level any project can reach in this build.
`docs/product/SUPPORTED_STACKS.md` defines the levels by what SURE can **do**, and
level B — `Generic` — is *"discover common manifests/commands **and run approved generic
checks**"*. So the ceiling is a claim about running a project's own checks, and the
question this record settles is whether that claim is now true enough to report.

Three things had changed by the time this task ran:

- `P18-T007` wired the runner. A run handed the right permissions reaches a process and
  starts a project's command. The sentence *"this build runs no project code"* became
  false and was removed from `crates/` and `docs/`.
- `P18-T009` and `P18-T010` added two more ways to start something — a service check and a
  browser check — with the same admission rule.
- ADR 0014 left the ceiling where it was and said why: *"level B says SURE can run
  approved generic checks, and a build that runs them on one platform and not on another
  has not earned a single sentence for both."* It also named the task that would settle
  it: *"The support ceiling in `support::CEILING` moves only if the measurements in
  `P18-T012` earn it."*

That sentence is a **rule** — a ceiling moves when a measurement earns it, and not
because a path was wired. It is not evidence about whether the ceiling is correct, and
nothing below leans on it.

## The measurements

Taken on 2026-09-22, on this workstation (Windows 11 x64), against the tree at `f8db077`.

**One: what this machine answers for the names a Node check would use.** Through the
product's own resolver — `ProgramPath::of_this_machine().resolve(OsStr::new(name))`,
instrumented by a temporary test that was deleted after the reading:

```
      npm -> InterpreterRequired("C:\\Program Files\\nodejs\\npm.cmd")  startable=false
      npx -> InterpreterRequired("C:\\Program Files\\nodejs\\npx.cmd")  startable=false
     pnpm -> InterpreterRequired("C:\\Users\\lishi\\AppData\\Roaming\\npm\\pnpm.cmd")  startable=false
     yarn -> Absent  startable=false
     node -> Executable("C:\\Program Files\\nodejs\\node.exe")  startable=true
    cargo -> Executable("C:\\Users\\lishi\\.cargo\\bin\\cargo.exe")  startable=true
      git -> Executable("C:\\Program Files\\Git\\cmd\\git.exe")  startable=true
```

The same reading enumerated every file on `PATH` whose name begins `npm`. **The
extensionless `npm` file is there** — `C:\Program Files\nodejs\npm`, the shell script npm
ships — beside `npm.cmd` and `npm.ps1`, and `PATHEXT` on this machine is
`.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL`. The Windows completion
table probes `com`, `exe`, `bat`, `cmd`, `ps1` (`crates/sure-core/src/planned_work.rs:
1231-1240`) and never the bare name, so the file that would run on macOS is on this
machine and is not the answer. `npm.cmd` is, and this build does not start a batch file.

**Two: what the other platforms' table answers.** The non-Windows completion is
`WITHOUT_PATHEXT = &[("", Completion::Executable)]` (`planned_work.rs:1257`), and it is
compiled under `cfg(any(not(windows), test))` for exactly this reason. On this machine,
`planned_work::tests::a_platform_that_completes_a_bare_name_with_nothing_finds_the_name_
itself` (`planned_work.rs:2311`) hands that table a directory holding a file named `npm`
and asserts `Resolution::Executable`. **It passes.** So the product's own answer for the
same bare name differs by platform, and the difference is a table this repository wrote
and tests rather than a behaviour anybody observed.

**Three: the platform legs have run.** Reported by `gh run view 35720783926`, the `ci`
workflow run on `f8db077` — the tip of `claude/planned-check-runner` and the tree this
record is about:

```
shellcheck-secondary               completed  success
rust (windows-latest)              completed  success
rust (ubuntu-latest)               completed  success
bootstrap-validate-windows         completed  success
rust (macos-latest)                completed  success
```

Each `rust` leg ran `cargo test --workspace --all-features --no-fail-fast`. **This
corrects a sentence in `crates/sure-core/src/support.rs`, which said the macOS and Linux
legs *"have never run at all"*.** They had, and they are green on this commit. That
sentence has been rewritten; it was the one part of the ceiling's stated reason that the
measurements contradicted.

## What none of those measurements show

**No test in this repository runs a project's own declared check to completion under the
product's real runner, on any platform.** Every test that carries a check all the way to
`ProcessRunner` hands it a `Cancellation` that was cancelled **before the run began**, so
the product's own runner is reached and nothing starts:

- `crates/sure-core/tests/declared_commands.rs` — `a_critical_declaration_that_cannot_run
  _blocks_green_and_is_counted`;
- `crates/sure-core/tests/adversarial_fixture_detection.rs:2185` — `fn nothing_starts()`,
  with the comment saying so;
- `crates/sure-cli/tests/runtime_results_reach_the_reports.rs:127-131` — `fn
  a_runner_that_starts_nothing()`.

What *is* measured is the seam and its two sides: `pipeline.rs`'s
`a_run_a_user_granted_reaches_the_runner_and_is_never_reported_as_passed` shows a Rust
project, a user's own configuration file granting `run_project_code`, and a runner that
**is** asked — with the row that comes back an `Error` and never a pass;
`a_run_a_user_did_not_grant_starts_nothing` shows the other side with a recording runner
that is never called. **The distance between "the runner was reached" and "the project's
check ran and passed" is the distance this record does not close.** Closing it means
running a real `cargo test` or `npm test` inside the suite, which is a decision about the
gate rather than a measurement this task could take.

## Decision

**The ceiling does not move. `CEILING` stays `SupportLevel::InspectOnly`, and its stated
reason is replaced.**

The old reason had two halves: a run under the default mode reaches no process, and level
B is a claim about every platform while one platform has not earned it. The first half is
still true and measured. **The second half is replaced**, because its supporting sentence
was false and its shape does not fit what was measured.

What replaces it is this: **level B is one sentence, and the measurements split the space
it would cover into three parts that do not agree.**

| case | what was measured | level B's claim |
| --- | --- | --- |
| Windows, Node project | `npm` resolves to `npm.cmd`, `InterpreterRequired`, not startable; the check is stopped by the classifier (superseded for command checks on 2026-10-22 — see the amendment at the end) | **false** |
| Windows, Rust project | the plan admits `cargo.exe`, the runner is reached under a user's grant | **reachable, not demonstrated end to end** |
| macOS and Linux | the table answers `Executable` for a bare name, and `cargo test` is green on the leg | **the table says yes; no run of a project's check happened** |

`SupportLevel` is a constant on this module and a `ProjectSupport` value in the report, and
`classify` takes the weaker of what SURE read and this ceiling. A constant cannot carry a
claim whose three parts disagree, and the honest single sentence over all three is the
weaker one. Moving the ceiling to `Generic` would put one word over a set of cases the
evidence separates — which is the same defect, one level up, as reporting a check as
passed because nothing went wrong.

**The rule the decision follows is ADR 0014's and is not quoted as evidence for itself**:
a ceiling moves when measurements earn it. On these measurements it is not earned, and the
default outcome ADR 0014 predicted is the one that holds — for a reason this task
measured rather than for the reason that ADR wrote down.

## Alternatives rejected

**Move the ceiling to `Generic` because the runner is wired and CI is green on three
platforms.** The tempting reading of measurement three, and it is a correlation rather
than the claim. CI being green on macOS means the *tests* pass there; it does not mean
SURE ran a project's Node tests there, because no test does that anywhere. And the same
commit's Windows leg cannot run a Node project's own check at all. A green matrix leg is
evidence about this repository's suite, not about the sentence level B makes.

**Move it only for platforms where the resolver answers `Executable`.** This would be the
honest version of the change, and it is not available at this size: the ceiling is a
`const`, not a function of the machine, and making it one puts a platform question into a
value `classify` reads from a `Discovery` — a discovery that does not know what is on
`PATH`. The change is a redesign of what a support level is, and it is not earned by a
reading about `npm.cmd`.

**Write the ceiling's reason as "nothing runs project code".** Already false since
`P18-T007` and already removed. Recorded here because it is the sentence a reader arriving
from ADR 0014's context section would still expect to find.

**Leave the reason as it was and correct only the one false sentence.** Cheapest, and it
leaves a reason whose argument is *"the other platforms have not been tried"* while the
measurement says the interesting failure is on the platform that **has** been tried. A
reason that survives its own contradicted premise by keeping the premise's shape is the
thing this record exists to avoid.

## Consequences

- `crates/sure-core/src/support.rs`'s module comment and `CEILING`'s doc are rewritten to
  the measured asymmetry: not "the other platforms have never run" but "a Node project on
  Windows is stopped, a Rust project's runner is reached, and the end-to-end run is
  unmeasured everywhere". The tests in that module that pin today's answer are unchanged
  and still fail the day the constant is raised deliberately.
- `crates/sure-core/tests/browser_probe.rs`'s rule five no longer passes by not looking.
  Its walk covered `crates/sure-core` alone and could not see `sure-cli/src/check.rs:328`,
  where `P18-T010` put the product's one driver construction, so the rule forbade a name
  it never read. The walk now covers every shipped crate, matching `tests/spawn_sites.rs`,
  and the composition root is exempted **by name**. Its failure message no longer says a
  new name moves the ceiling — that was the coupling this record breaks.
- `crates/sure-core/tests/spawn_sites.rs`'s paragraphs that point a reader forward to this
  task now carry the answer instead of the question.
- **A Node project on Windows loses coverage in a way a user can see**, and ADR 0014
  already accepted it: the check is stopped by the classifier with a reason rather than
  run. This record makes that loss part of the ceiling's stated reason rather than a
  footnote to it.
- The `&[]` that `aggregate_run`'s `missing` argument receives from every caller but one
  (`pipeline.rs:983` passes `&planned.missing`) is left as a recorded risk rather than
  guarded: the declaration path is measured end to end from the pipeline in
  `crates/sure-core/tests/declared_commands.rs`, and a guard that fired only when a
  hypothetical second caller existed would be a test with no product behind it.

## What this record does not say

It does not say a Node check *cannot* run on Windows. It says the name `npm` on this
machine resolves to a file this build declines to start, which is a measurement about one
program and one machine. A project whose scripts run through `node.exe` — a `node
./scripts/test.mjs`, or a runner that is itself an `.exe` — is unaffected, and that case
is the one ADR 0014 left open.

It does not say the macOS and Linux readings are equivalent to Windows readings. The table
is the same and the tests are green, and neither of those is a run of a project's check.

It does not settle whether `docs/architecture/ECOSYSTEM_DISCOVERY.md`'s grade table and
`docs/product/SUPPORTED_STACKS.md`'s level table should be reconciled. That conflict is
recorded in `support.rs` and is the owner's to settle; this record leaves it where it was.

## Revisit when

A measurement shows a project's own declared check running to completion under the
product's real runner and passing, on a machine whose platform the claim would cover. That
is a reading this repository can take — it is a test that starts a real project command —
and it is the reading this record is missing rather than a reading it refused.

## Amendment — 2026-10-22: the first row's "stopped" is no longer the product path

The table row *"Windows, Node project — `npm` resolves to `npm.cmd`,
`InterpreterRequired`, not startable; the check is stopped by the classifier"* records the
reading taken when this record was written. On 2026-10-22 the product runner gained a
launcher for the package managers Windows installs as batch shims
(`crates/sure-core/src/package_launcher.rs`; ADR 0014's amendment). When `node` and the
manager's own shipped JavaScript entry (or the corepack dispatcher) are present, a bare
`npm`/`npx`/`pnpm`/`pnpx`/`yarn`/`yarnpkg` check is started as
`node <entry> <the plan's arguments>`; real runs on this workstation produced `pass` for a
succeeding `npm`/`pnpm`/`yarn` test and `fail` (exit 1) for a failing one. (`bun.cmd` is
not translated; the launcher's list is the managers above.) The resolver's answer is
unchanged — `ProgramPath` still says `InterpreterRequired` — so the row's first half
still describes the plan; its second half ("the check is stopped") no longer describes
the product path.

**`CEILING` does not move in this amendment, and moving it is now an open decision.**
The launcher changes the first row; it is not the only row that has moved since this
record was written. `sure-cli/tests/finished_declared_check.rs` (added by `4ec2e2d`,
P19-T005) drives the CLI under `host_confirmed`, runs a real Rust fixture's declared
`cargo test`, asserts the report row is `pass`, and is part of the `cargo test
--workspace` run on all three CI legs (the `ci` run at `d618d23` is green on all three).
That is the reading the *Revisit when* section
above asked for. Whether it earns level B for every project and every kind of check is a
decision that needs its own record and its own reasoning — the reading covers one
ecosystem's declared command, and this amendment is a launcher correction, not that
record. `CEILING` therefore stays `InspectOnly` until that decision is taken rather than
because the measurement is missing.

