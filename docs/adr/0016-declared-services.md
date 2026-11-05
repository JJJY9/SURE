# ADR 0016 — The local services a project declares

Status: Accepted

Date: 2026-09-23

Implementation: **wired on 2026-09-23 by `P18-T012`'s follow-up.**
`crates/sure-core/src/config/services.rs` is the shape a declaration may be
written in, `crates/sure-core/src/service_plan.rs` turns one into checks, and
`pipeline.rs` proposes them at stage 4 beside the Node, Python and Rust checks.
The route from a plan to a process is unchanged — nothing here adds a spawn site,
and `crates/sure-core/tests/spawn_sites.rs` did not move — so what this record
decided is a **way into the plan that already existed**. Read the **Context**
section below as the state before this change: no production planner constructed
a `CheckOperation::Service` or a `CheckOperation::Browser`, and the paragraphs in
`pipeline.rs` that said so are corrected in place rather than left standing.

## Context

SURE plans checks and enforces them, and since `P18-T007` one road carries a
check out: `PlannedWork` → `CheckSchedule` → `PermissionPlan` →
`Enforcement::admitted()` → `planned_check_runner` → a result. Two kinds of work
on that road were reachable from tests and from no product path:

- `ServiceCheckSpec` and `CheckOperation::Service`, with `StartSmoke::planned`
  behind them (`P18-T009`);
- `BrowserCheckSpec`, `CheckOperation::Browser` and `browser::Driver`
  (`P18-T010`).

**A discovered project cannot reach either, and the reason is ADR 0014's own.**
`runtime_probes.rs` plans an *observation* for a project whose manifest says it
serves, because a manifest's start script is a rendered line and turning a
rendered line back into a program and an argument vector is the parse that ADR
forbids. So the two checks that could start a project were planned for nobody,
and `checks.start_local_services` and `checks.browser_probe` decided the fate of
checks that a manifest might one day imply.

**What a project can write today is prose about itself, not a form SURE can hold
as data.** `sure.yaml` is the one file in the project addressed to SURE, and
before this change it had no way to say *start the server in `packages/api` and
look at `/`* in a shape anything downstream could execute. The three ways to give
it one are the alternatives rejected below.

**And the platform question is settled, not open.** A launcher kind is a promise
that SURE can start a project this way, which is a claim about the platforms SURE
runs on. `docs/adr/0015-support-ceiling-evidence.md` is the record of what
`P18-T012` measured; a promise is made where the evidence is.

## Decision

**A project may declare a local service in a restricted, typed shape, and SURE
plans checks from that declaration and nothing else.**

1. **The declaration is data, and the launcher is a tag.** `checks.services` is a
   list of `ServiceDeclaration`: `name`, an optional `directory`, a `launcher`, a
   `port`, a `readiness` path and an optional `page`. `launcher` is written as a
   mapping whose `kind` key selects the variant —
   `launcher: { kind: node_entry, entry: server.js }` — and `Launcher::NodeEntry
   { entry }` has exactly one variant in this build, with **no field in it that
   accepts a command line**. A project names a kind; SURE supplies the program.

   **The tag is a `kind` key rather than a YAML `!tag`, and that is a constraint
   rather than a preference.** `serde_yaml_ng` implements `deserialize_enum` by
   requiring a tag, so the externally tagged spelling a person writes first —
   `launcher: { node_entry: { entry: … } }` — **does not parse at all**:
   `invalid type: map, expected a YAML tag starting with '!'`. An internally
   tagged enum is read as an ordinary mapping instead, which makes it the only
   one of the two spellings a project can write in this format and the only one
   whose unknown keys `deny_unknown_fields` can reach, so a key beside `entry` is
   a load error and not a setting that quietly did nothing. The first draft of
   this shape was the other spelling, and it survived a round of unit tests
   because every one of them built the struct in Rust and none deserialized the
   format; `config/services.rs` now carries the test that reads the documented
   block through `Config::from_yaml`.

2. **What SURE supplies is its own constant, for every field a command line would
   have carried.** The program is `node` as a **name** and never a resolved path,
   so which `node` runs is this machine's answer through `PATH` and not a
   project's. The argument vector is `[entry]` — one element, built as a vector
   and never rendered and re-split. The working directory is the scan root joined
   with the declared `directory`, under the root when the declaration omits it and
   refused when it leaves it. The limits are `checks::CHECK_LIMITS`, unwidened.

   **Containment is decided twice, by text and then by resolution**, because the
   first answer is not the question. `..` and absolute paths are refused before the
   file system is consulted — that is the refusal with the better sentence — and
   whatever survives is canonicalised on both sides and required to be inside the
   project by `crate::paths::is_within`. A junction or a symbolic link leading out
   of the tree passes every textual test and is what the second lock is for, and
   `mklink /J` needs no privilege at all: a rule that read only the spelling would
   have been a rule about a project with rights a project does not need. **The
   first draft had only the first lock**, and gutting the second makes both of its
   tests fail with *no refusal at all* — a service planned, and started, outside
   the project SURE was handed.

3. **A service is not given SURE's own environment.** ADR 0014's decision 11,
   carried out where the plan is made: the command is `Environment::only` over
   the machine's own minimum, so nothing of the user's and nothing of SURE's
   settings reaches a service. This is the one field where a declared service
   differs from a declared check, which runs in the user's own environment, and
   the asymmetry is deliberate: a check is the project's own command for the
   project's own tooling, and a service is a program SURE starts **in order to
   watch it**. One consequence is stated with it in
   `docs/architecture/EXECUTION_SAFETY.md`: a service that starts another program
   by name may not find it — which is a reported failure rather than something
   SURE works around. **A second sentence stood here and is corrected rather than
   deleted**: it said the program `node` is still found because SURE resolves it
   in its own process, and the first CI run in which these cases compiled on
   macOS and Linux falsified it. Off Windows a bare name is resolved by the
   operating system out of the environment the child is handed, so a service
   handed an empty block cannot be started at all — measured at `dfbd94f` in runs
   `35834410398` and `35834415130`, `7 passed; 11 failed` on both platforms, each
   failure *SURE could not start "node" … No such file or directory (os error
   2)*, on machines where the same jobs had just run `node` by that name. What is
   resolved in SURE's own process is the *check*'s program; a service's is
   resolved by the child's own spawn, which is why the Unix minimum is now the
   search path and the Windows minimum is not.

   **The minimum is a measurement, and the first draft of this decision took
   none.** It passed an empty block, and the cost was found on the product path
   rather than reasoned about: the declared service was planned, admitted and
   started, and reported as having *ended by itself after 65 milliseconds* with
   exit code 134, because `node` aborts inside
   `node::InitializeOncePerProcessInternal` before it reads one line of the
   declared entry when `SystemRoot` is absent. That one variable is the whole
   difference. It is not a starting point somebody may extend on speculation:
   the measurement, and the variables that were tried alone and did not help,
   live beside the code in `service_plan.rs`, and a platform whose minimum nobody
   has measured passes nothing — the position
   `docs/adr/0015-support-ceiling-evidence.md` takes.

   **The platform that had no measurement got one, and it is a different
   variable.** macOS and Linux are not platforms whose minimum can be read off
   the Windows one: their minimum is `PATH`, because without it no declaration
   naming a program can start there at all — the `dfbd94f` reading above — and
   the search path is what makes a bare name resolvable rather than something
   that makes a service behave differently. So the two branches of
   `service_environment` now pass different variables, each with its own
   measurement beside it, and neither is a starting point for the other: the
   Windows measurement recorded that `PATH` alone changes nothing *there*, and a
   reader who carried that sentence across platforms would be making the
   substitution this ADR's own last sentence forbids.

4. **Readiness and page are validated through `probe::Endpoint::loopback`.** Not
   through a second copy of its rule: the endpoint constructor is what refuses a
   path that would not be a request line, and reusing it makes a non-loopback URL,
   a userinfo authority, an external redirect and a backslash path
   *unrepresentable* rather than unlikely — there is no host field to fill in.
   **Port zero is refused one layer up, at the declaration**, because the endpoint
   accepts zero as the valid `u16` it is and the fact that it is not an address to
   ask is a fact about the declaration.

5. **Every way a declaration can be wrong is a value with a sentence on it.**
   Empty name, duplicate name, directory outside the project, directory that is
   not there, entry outside its directory, entry that is not there, entry that is
   not `.js`/`.mjs`/`.cjs`, port zero, and a readiness or page path the endpoint
   refuses — one `ServiceRefusal` variant each, carried into the stage-4 report.
   *Outside* covers both answers a path can give: one that leads out of the
   project by what it says and one that leads out by where it resolves to, which
   is why the two refusals each carry both cases in their sentence rather than
   gaining a vocabulary entry nobody could tell apart.
   **Never a dropped row, and never a `debug_assert`**: a declaration SURE will not
   act on is something the project's author has to be told.

6. **Planning ends at `PlanBuilder::propose`.** This ADR adds a proposer, not a
   runner: no `AdmittedCommand` is constructed, `Enforcement::admitted()` is not
   called, and no spawn site moves. `ServicePlan::add_to` mirrors
   `ProbePlan::add_to`, refusals included.

7. **The two rows reuse the probe vocabulary rather than restating it.**
   `CheckOperation::Service` carries the same severity, criticality, evidence
   class and action as `ProbeKind::Serve`; the browser row does the same through
   `ProbeKind::Interface`, with the identifiers `check_id(name, "service")` and
   `check_id(name, "servicepage")`. The numbers are read out of `PROBES` through
   a `pub(crate)` accessor, so a project that declares a service and a project
   whose manifest implies one are graded by one table.

8. **The preferences decide, and what they leave unplanned is recorded.** `never`
   on `checks.start_local_services` plans neither row — the browser setting is not
   consulted, because a browser check on a service nobody starts would start it.
   `auto` plans the service row and no browser row. `always` plans both when a page
   was declared, and records a gap rather than inventing a target when none was.
   Each gap is a `ServiceGap` naming the declaration and the setting, and **no gap
   is a `ScopeReduction`**: that vocabulary belongs to the run's own settings and
   already states them; a second report of the same reduction in a second
   vocabulary would be wrong about which layer it described.

9. **A component a declaration covers is left to the declaration.**
   `runtime_probes.rs` plans no static `Serve` or `Interface` probe for it and
   records `NotPlannedBecause::DeclaredAsAService`, so a reader is never shown
   *nothing has settled this* beside the run that settles it. The matching uses
   the same directory spelling `directory_of(manifest)` produces, so the two
   layers cannot disagree about which component a declaration is about.

10. **A declaration grants nothing.** `run_project_code` for the service and
    `connect_service` for the page come from the user's own configuration, on the
    authority order every other request follows, and a project's file can neither
    grant them nor move the mode. The browser check is not covered by the service's
    authorisation: `browser::absence` asks about `ActionKind::BrowserProbe`
    separately, which is what a run that permitted a service and not a page needs
    in order to report a serve row and an absence rather than a look.

## What this excludes, deliberately

- A free-form `command:` string, in any spelling.
- A package-manager-script launcher (`npm run start` and its relatives).
- A Rust launcher and a Python launcher, this round.
- Multi-service topologies, service discovery, and any shared service instance.
- External services: everything here is loopback, on the declared port.
- Dependency installation before a service starts, and any fetch or build step
  that would make one possible.
- Container execution of a declared service. A declaration is host work, which is
  what the mode vocabulary already says about it.

## Alternatives rejected

**A free-form `command:` string in the declaration.** The smallest format by far,
and it is the defect ADR 0014 rejected one layer down: `sure.yaml` is
project-controlled, so a command string is a project asking SURE to run anything
it likes, passing through the classifier as text SURE cannot read. It would also
make the plan's identity depend on a string a renderer could round-trip
differently.

**Split `CheckReason::DeclaredCommand.command` — which is already rendered — back
into a program and arguments, and offer that as a launcher.** No new format, no
new planning, and it reuses the checks that exist. Rejected for the reason ADR
0014 gives: the display string would become the source of a program that runs, and
the set of things SURE executes would be decided by the same text a report prints.

**A launcher that names a package manager's script.** `npm run start` is how most
Node projects really start, so this looks like the launcher with the most coverage
in it. On Windows the program behind it is `npm.cmd`, a batch file, and
`planned_work.rs`'s `classify` answers `InterpreterRequired` for one rather than
building a `cmd.exe /c` wrapper — ADR 0014's own consequence, kept rather than
worked around. A launcher kind would therefore plan, on SURE's primary development
platform, checks that cannot start.

**A Rust launcher (`cargo run`).** The obvious second variant, and it makes SURE a
build-and-fetch driver: compiling a project SURE was handed means fetching that
project's dependencies, which the non-goals exclude and `checks.start_local_services`
never promised. What a Rust project can always declare SURE already declares for
it — `cargo build`, `cargo test` — as a check, which is where compiling belongs.

**A Python launcher.** Symmetrical with `node_entry` and cheap to write. Which
`python` a machine has is the question `P18-T012` measured and did not settle on
all three platforms, and a launcher kind is a promise rather than a wish
(`docs/adr/0015-support-ceiling-evidence.md`). Adding it in the same round as the
first launcher is exactly the "it compiles, therefore it is supported" substitution
the support ceiling exists to prevent.

**Leave declarations out and let a manifest keep implying a start.** No new
format, no new refusals, and it keeps the two checks unreachable for ever — which
is the state `checks.start_local_services` and `checks.browser_probe` were already
in: settings deciding the fate of checks nobody could plan.

## Consequences

- **The two unreachable doors are reachable, and what changes is the plan.**
  `CheckOperation::Service` and `CheckOperation::Browser` can now come out of stage
  4 for a project that declares one. Nothing on the execution route moved, and
  `tests/spawn_sites.rs` did not need an entry: this file plans and proposes, and
  names no type that census is about.
- **Paragraphs that said "no planner in this build emits one" became false and
  were corrected in place** — in `pipeline.rs`'s test doubles, whose service and
  browser arms still answer `Error` for a run configured with no declaration, and
  in the comment above the assertion that no service or page reached the runner.
  The assertions did not change; what they are a fact about did.
- **A declaration is at most two checks, and the schedule orders them.** The
  browser row runs no project code (`ActionKind::BrowserProbe`), so the schedule —
  which sorts by `runs_nothing()`, not by declaration order — puts the page row
  before the serve row. A reader sees them in that order and both carry the
  declaration's name.
- **The ceiling did not move.** `support::CEILING` stays `InspectOnly`: a service
  check that runs here and not on the other two platforms is the same asymmetry
  ADR 0015 recorded, and this change adds a way to plan a check, not evidence that
  it runs anywhere.
- **A project that declares a service now has to be right about it.** A refusal is
  visible in the stage-4 report, and a declaration the run was not permitted to
  carry out leaves a checked-and-not-run result rather than a silence — which is
  the price of the door being a door.

## Frozen semantics

The execution vocabulary — `ExecutionMode`, `ExecutionDecision`, `ActionKind`,
`CommandClass`, `CommandEffects`, `Permission` — and the check vocabulary —
`CheckStatus`, `NotCheckedReason`, `CheckResult`, `blocks_green` — are unchanged by
this ADR, and so are `ScopeReduction` and the run's own scope reporting.
`checks.start_local_services` and `checks.browser_probe` keep the meanings they
already had; what is new is a list they can be about.

## Revisit when

A second launcher kind is needed. **The enum is the extension point**: a variant,
a refusal vocabulary entry beside it, and the same three questions answered for the
platform it claims — the program SURE would run, the files the declaration has to
name, and the evidence that it works on every platform SURE claims. Or when a project
needs a service topology SURE did not start, which is a question about admission
rather than about this format, and belongs in its own record.

## Amendment — 2026-10-22

The package-manager launcher added for **command checks** on 2026-10-22
(`crates/sure-core/src/package_launcher.rs`; ADR 0014's amendment) is not on the service
path. `StartSmoke` starts what the service declaration names and does not hold a
`ProcessRunner`, so a package-manager service launcher remains rejected for the reason
above: on Windows the program behind `npm run start` is still a batch file the service
supervisor would name. A service launched by a package-manager script is a different
capability with its own admission question, not a consequence of the command-check
launcher.

