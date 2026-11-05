//! `P4-T001`'s acceptance, checked rather than asserted.
//!
//! The task's sentence is:
//!
//! > *Ordered plan includes reason, evidence class and execution requirements
//! > per check.*
//!
//! Three claims in one sentence, and they are not the same kind of claim. That
//! each entry *carries* a reason, an evidence class and its requirements is
//! behavioural — it is checked here from outside the crate, which is also what
//! proves the accessors are public and the seam is usable. That the plan is
//! *ordered* is a property rather than a value, so it is checked against the
//! rules the module states rather than against one expected list. And that the
//! ordering does not depend on how the checks arrived cannot be demonstrated by
//! running one case at all, so it is a sweep.
//!
//! # The five rules
//!
//! **One: the acceptance sentence, over a plan and not over one proposal.**
//! Every entry, with the reason, the evidence class and the requirements read
//! back through the public API.
//!
//! **Two: the order is the rules' order, whatever order the proposals arrived
//! in.** Every permutation of a four-check set, built from outside the crate,
//! lands on the same sequence — and that sequence is asserted to be the one the
//! three rules describe, so a stably wrong plan fails too.
//!
//! **Three: nothing in the product proposes a check except where it is allowed
//! to.** No shipped file outside [`MAY_PROPOSE`] names [`CheckProposal`],
//! [`CheckReason`], [`ExecutionRequirements`] or [`PlanBuilder`]. **This rule was
//! meant to fail, and it did**: it was written before any proposer existed, it
//! fired on `P4-T002`, and that commit named `src/checks/node.rs` in the
//! exemption with its reason — which is the moment this paragraph said somebody
//! would read it. The rule survives the failure rather than being deleted,
//! because what it now holds is the thing that is still true: a file that begins
//! proposing checks is a decision, and the list is where the decision is written
//! down. `every_exemption_from_the_proposer_rule_is_still_a_proposer` is the
//! other half — an exemption whose file has stopped naming any of the four words
//! is a hole in the rule rather than an exception to it, and it fails too.
//!
//! **Four: the schedule cannot spell a verdict.** The shipped part of
//! `schedule.rs` names `CheckStatus` zero times, and `CheckResult` four times in
//! four roles — a doc sentence, an import, one signature and one call. The
//! status a blocked check gets is the domain's `not_run` constructor's to choose,
//! so there is no place here where a schedule entry could be turned into a pass.
//!
//! **Five: the frozen plan does not grow a reason.** `CheckPlan` in
//! `sure-domain/src/vocabulary.rs` holds identifiers and nothing else, and the
//! reason and the evidence class this task adds live in `sure-core`. That
//! boundary is the reason `Enforcement` did not have to change for this task, and
//! a field appearing in the domain record is an ADR-level decision rather than a
//! refactor.
//!
//! # What is not claimed here
//!
//! **None of this says a check is a good one.** The schedule will faithfully
//! order and carry a check that is worthless, or one whose evidence class is a
//! lie, and rules one to five are silent about it — the same limit `browser.rs`
//! states about its drivers. What they hold is that the plan a report is built
//! from cannot be quietly incomplete in the two ways that matter: a check dropped
//! for being unrunnable, and an order that depends on somebody's loop.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sure_core::consent::PermissionPlan;
use sure_core::enforce::Enforcement;
use sure_core::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
use sure_core::scan::{ScanOptions, scan};
use sure_core::schedule::{
    CheckProposal, CheckReason, CheckSchedule, ExecutionRequirements, PlanBuilder, ScheduledCheck,
};
use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::{
    ActionKind, ExecutionDecision, ExecutionMode, ExecutionPermissions, Permission,
};
use sure_domain::ids::{CheckId, FingerprintId};
use sure_domain::severity::Severity;
use sure_domain::status::{CheckStatus, NotCheckedReason};

/// The one file allowed to build a check, as a path from the repository root.
const THE_BUILDER: &str = "crates/sure-core/src/schedule.rs";

/// The same file as the `crates/` walk reports it, relative to that root.
///
/// Two spellings of one path, because the two checks that name this file reach it
/// by different routes, and `the_two_spellings_of_the_builders_path_agree` is what
/// stops them drifting into two files — the mistake `browser_probe.rs` records
/// making once.
const THE_BUILDER_IN_THE_WALK: &str = "src/schedule.rs";

/// The file that owns the frozen plan record.
const THE_FROZEN_PLAN: &str = "crates/sure-domain/src/vocabulary.rs";

/// Words that mean something in the product has begun proposing checks.
///
/// Four type names rather than one, because a proposer can be written from any
/// end: a function that returns a `CheckProposal`, one that names a `CheckReason`,
/// one that hands `ExecutionRequirements` to something else, or one that reaches
/// for `PlanBuilder`. Naming any of them outside the builder is the thing rule
/// three is about, and a rule that waited for the whole set to appear would not
/// fire until the feature was finished.
const PROPOSER_WORDS: &[&str] = &[
    "CheckProposal",
    "CheckReason",
    "ExecutionRequirements",
    "PlanBuilder",
];

/// The shipped files allowed to name a proposal type, each with its reason.
///
/// **The reason is part of the entry rather than a comment beside it.** The
/// failure message rule three prints asks for exactly two things — the file and
/// why — and a `(path, reason)` pair makes those one act instead of two, so a
/// file cannot arrive on this list without a sentence explaining it.
///
/// Paths are as the `crates/` walk spells them, which is what
/// `the_two_spellings_of_the_builders_path_agree` exists to keep honest: a path
/// from the repository root used here would match nothing, and a rule that
/// exempts nothing while appearing to exempt something is a false green with a
/// comment on it.
const MAY_PROPOSE: &[(&str, &str)] = &[
    (
        THE_BUILDER_IN_THE_WALK,
        "the four types are defined here, so this file names all of them by \
         definition and always will",
    ),
    (
        "src/checks/node.rs",
        "`P4-T002`, the first proposer: it turns a JavaScript or TypeScript \
         project's declared scripts into checks. `schedule.rs`'s own \
         documentation named this task as the one that would arrive, and the \
         rule below is what made its arrival a deliberate edit rather than a \
         quiet one. `P4-T003` and `P4-T004` did belong here too when they \
         landed, and each of them was a diff to this list",
    ),
    (
        "src/checks/python.rs",
        "`P4-T003`, the second: it turns a Python project's declared tools into \
         checks. The entry above said this file would be a diff to this list when \
         it landed, and it is — which is the rule working rather than the rule \
         being inconvenient. It is also the first proposer whose module produces \
         something that is *not* a check (an `InstallStep`), and the reason it \
         may still name these four types is that keeping an install out of a \
         `CheckProposal` is the whole of what the acceptance asks: the type \
         discipline is what makes *without silent package installation* structural \
         instead of a convention",
    ),
    (
        "src/checks/rust.rs",
        "`P4-T004`, the third and the last one the other two entries named: it \
         turns a Rust project's `Cargo.toml` and toolchain declarations into \
         checks. It is here for the same reason as the two above — a file that \
         decides which checks exist is a decision, and this list is where the \
         decision is written down — and its own module documentation is where \
         the interesting part is argued: `cargo fmt` rewrites the source tree, so \
         this proposer runs `cargo fmt --check` instead and titles the check \
         accordingly, because evidence from a command that changed the tree \
         cannot be bound to the state the change was made to",
    ),
    (
        "src/checks/go.rs",
        "the Go proposer from the MiQi integration (`PR #15`): it turns a \
         `go.mod`, and each module a `go.work` names, into `go test`, \
         `go build` and `go vet` checks. The entry was missing when the \
         proposer landed and this list only noticed when the Java proposer \
         was added; the rule is unchanged — a file that decides which checks \
         exist is a decision, and the decision is written here",
    ),
    (
        "src/checks/dotnet.rs",
        "the .NET proposer from the MiQi integration (`PR #17`): it turns a \
         solution or project file into `dotnet test`, `dotnet build` and — \
         when the project configures formatting — `dotnet format \
         --verify-no-changes`. Same missing entry as the Go one above, added \
         in the same commit for the same reason",
    ),
    (
        "src/checks/java.rs",
        "the Java proposer from the MiQi integration: it turns a Maven \
         `pom.xml` into `mvn -B -ntp test` and `mvn -B -ntp package \
         -DskipTests`. A Gradle project gets no proposal at all because its \
         build script is code SURE does not read, so what this file decides \
         is which Maven projects have checks and which have missing commands",
    ),
    (
        "src/runtime_probes.rs",
        "`P5-T001`, and the first entry on this list that is not a submodule of \
         `checks/`: it is a level above the three proposers rather than beside \
         them, because it does not read a manifest format — it asks `checks`'s \
         own `node` proposer for a component's start command and turns it into a \
         check that starts the project and looks at it. It is here for the same \
         reason as the three above, and the reason is worth restating for a file \
         that could be mistaken for a consumer: **a check that starts a server is \
         a check**, so the plan entry, the reason and the execution requirements \
         are built here and nothing downstream decides them again",
    ),
    (
        "src/http_routes.rs",
        "`P5-T003`, and the entry `P5-T001` named in advance: that task's module \
         documentation recorded that a route check could not be proposed because \
         *nothing in the discovery holds a route*, and that routes were \
         `P5-T003`'s work arriving *with the reading that can point at them*. \
         This is that reading, so the file proposes for exactly the reason the \
         entry above does — it reads a project's source rather than a manifest \
         format, and what it finds is a check. **The reason it builds is \
         `CheckReason::RouteDeclared`, the variant added to `schedule.rs` with \
         it**, which is the part that could not be written before: a reason for a \
         route check has to name the file *and the line* SURE read the route on, \
         and a `FilePresent` naming a `package.json` would have been a claim \
         about a file that says no such thing",
    ),
    (
        "src/core_flow.rs",
        "`P5-T005`: it turns a fixture or project description of a safe local \
         acceptance flow into checks. The flow is typed YAML — start a service \
         by component and script role, probe a declared local route, or run a \
         browser probe — and each step maps to the same [`ActionKind`] the \
         rest of the product uses, with the same evidence class, severity and \
         permission semantics. **There is no path from a flow step to \
         [`ActionKind::ArbitraryCommand`]**: the structs carry \
         `#[serde(deny_unknown_fields)]`, and a YAML document that tries to \
         slip a `command:` key in is refused at parse time rather than ignored",
    ),
    (
        "src/external_service.rs",
        "`P5-T006`: it detects project behaviors that require real external \
         systems — payment processors, email delivery services and cloud storage \
         providers — and produces checks that can only be confirmed against the \
         real outside service. Detection is entirely static, from \
         `package.json` dependencies, import/require statements in source files \
         and environment variable references. The checks it produces carry \
         [`ActionKind::ExternalService`] and resolve to \
         [`NotCheckedReason::ExternalServiceUnavailable`] because SURE cannot \
         confirm them locally",
    ),
    (
        "src/candidate_scanner.rs",
        "`P6-T001`: it scans source files for TODO, FIXME, mock, stub and \
         placeholder patterns, and produces candidate checks that include the \
         file, line and context where each pattern was found. Candidates are \
         not automatically product defects: they carry `critical: false` and \
         `EvidenceClass::Inference`, and their severity is `finding_gravity`'s \
         answer for the category and the place rather than this module's — a \
         marker in production code is above `note`, the same marker in a test \
         file is a `note`. The reason they \
         build is `CheckReason::CandidateFound`, the variant added to \
         `schedule.rs` with this module, because a candidate check has to name \
         *where SURE read the pattern* and a `FilePresent` naming a file would \
         not be specific enough",
    ),
    (
        "src/noop_heuristics.rs",
        "`P6-T003`: it scans source files for no-op / fake-success patterns — \
         fake email addresses or domains, fake payment or sandbox tokens, \
         no-op function bodies that return constant success values, and \
         hard-coded success responses for external integrations. It produces \
         candidate checks with `critical: false` and `EvidenceClass::Inference`, \
         with the severity `finding_gravity` returns for the gap and the place \
         — a substituted action in production code is `must_fix` — using \
         `CheckReason::CandidateFound` to \
         anchor each proposal to the file, line and context where the pattern \
         was found. The `CandidateContext` classifier distinguishes test, \
         example, mock-fixture and production code",
    ),
    (
        "src/demo_data_heuristics.rs",
        "`P6-T004`: it scans source files for hard-coded demo-data patterns — \
         demo analytics values, hard-coded demo or sample datasets, placeholder \
         user or content IDs, and hard-coded chart or dashboard demo values. It \
         produces candidate checks with `critical: false` and \
         `EvidenceClass::Inference`, at the severity `finding_gravity` returns \
         for unreal content that reaches a user — `should_fix_first`, the \
         weight `demo-analytics`'s `scenario.json` requires — using \
         `CheckReason::CandidateFound` to \
         anchor each proposal to the file, line and context where the pattern \
         was found. The `CandidateContext` classifier distinguishes test, \
         example, mock-fixture and production code, preferring Product context \
         when both exist",
    ),
    (
        "src/route_consistency.rs",
        "`P6-T005`: it reads frontend route expectations from source files \
         (`fetch`, `axios`, React Router `path=`, Vue Router `path:`) and \
         compares them against backend routes read by `http_routes.rs`. \
         Frontend paths with no corresponding backend route become candidate \
         checks carrying `critical: false` and `EvidenceClass::Inference`, at \
         the severity `finding_gravity` returns for a route a user walks into \
         that is not there, anchored with `CheckReason::CandidateFound` \
         to the frontend file and line where the unmatched path was read. \
         Dynamic routes, template literals and slotted paths are skipped rather \
         than guessed",
    ),
    (
        "src/ui_action_bridge.rs",
        "`P6-T006`: it scans frontend source files for declared UI action \
         bindings (`onClick`, `onSubmit`, action links) and produces candidate \
         checks. When runtime browser evidence confirms an action, the proposal \
         carries `EvidenceClass::ObservedFact` and `ActionKind::BrowserObservation`; \
         otherwise it remains `EvidenceClass::Inference` with `ActionKind::ReadFile`. \
         Checks use `critical: false` and `CheckReason::CandidateFound` anchored to \
         the source file, line and context, and take the severity `finding_gravity` \
         returns for the place the action was declared — the class carries the \
         difference between a declared handler and an observed one, not the weight",
    ),
    (
        "src/intent_implementation.rs",
        "`P6-T008`: it compares a project's stated intent against its discovered \
         implementation and produces candidate checks only where a concrete \
         comparison fails. User requirements (`ExplicitUserGoal` and \
         `ObservedUserRequest`) are matched deterministically against component \
         paths, declared commands, HTTP routes and source-file identifiers; \
         unmatched requirements, documented instructions (`ProjectSpec`) and agent \
         claims (`AgentClaim`) become candidate checks carrying `critical: false`, \
         `EvidenceClass::Inference`, `CheckReason::CandidateFound` and the \
         severity `finding_gravity` gives a statement about declared intent, which \
         is `note`: what a requirement says and what the code does are two \
         documents, and the comparison between them is an inference. Inferred \
         sources are ignored, and when no \
         trusted user requirement exists the module returns the frozen \
         after-the-fact limitation instead of fabricating a passing result",
    ),
    (
        "src/false_completion_aggregator.rs",
        "`P6-T009`: it aggregates the candidate checks produced by the P6 false-completion \
         scanners, deduplicating proposals that share an evidence anchor and keeping \
         only the most serious one. It names `CheckProposal` because it receives, \
         selects and returns concrete proposals, and it names `CheckReason` to read \
         each proposal's anchor and `names_something` predicate. The module does not \
         invent new checks; it only decides which of several proposals about the same \
         place should survive",
    ),
    (
        "src/finding_gravity.rs",
        "`P7-T011`, and it proposes nothing: it is the rule that says how serious a \
         finding a detector has already made is, and what a reader should be told \
         about it. It names `CheckReason` because the reason *is* the rule's input \
         — whether it names anything, and whether the anchor it carries is one a \
         reader can open — and it names no `CheckProposal` at all, because it \
         returns a severity and a rationale rather than a check. **The distinction \
         this entry exists to make checkable**: this file decides how heavily an \
         existing finding is weighed, never which checks exist. Every proposal \
         that reaches a builder still comes from the modules in the entries above, \
         and a `CheckProposal` constructed here would be the second proposer this \
         rule is written to prevent",
    ),
    (
        "src/pipeline.rs",
        "`P7-T010`, and the first entry on this list that is not a proposer in the \
         sense the eight above are: it decides nothing about which checks exist. It \
         is the orchestration `docs/architecture/CHECK_PIPELINE.md` describes, and \
         every proposal it hands the builder came from a module already listed \
         above — `checks`, `runtime_probes` and the six completeness scanners are \
         all called from its plan stage, and it adds no candidate of its own. It \
         names the four types because it *holds* the builder those proposers are \
         handed and reads back the plan they produced: `PlanBuilder::refused` is \
         what lets it report a candidate that could not become a check, and the \
         schedule it builds is what the aggregate, the coverage summary and the \
         verdict are all computed over — and, since `P18-T007`, what the runner is \
         handed, which is a fact about the check's *operation* rather than about \
         who proposed it. **If this file ever gains a line that \
         constructs a `CheckProposal`, that is a proposer and belongs in a \
         `checks/` module rather than here** — which is the distinction this entry \
         is written down to make checkable rather than assumed",
    ),
    (
        "src/report.rs",
        "`P7-T010`, and the second entry here that decides nothing: every line of \
         this file that names one of the four words is inside its `#[cfg(test)]` \
         module, where a fixture builds a one-check schedule so that a check's \
         frame, its exit status and its two streams can be tested against a run \
         that has a clean variant and an unclean one. A real project cannot \
         supply the clean variant in this build — every check that would run the \
         project's code is stopped by the mode a run starts in, and stage 8 has \
         no provider — so `sure check` is 1 for both projects it was measured \
         over: a scratch crate (`0 of 2` produced a result, both stopped by \
         `inspect_only`) and this repository (`14 of 18` produced a result, the \
         four dynamic ones stopped), which is why the pair is built rather than \
         observed. **The first half of that reason was written as *stage 5 reads \
         every static check as `unknown`*, and `P18-T007` made that false** by \
         wiring the runner: stage 5 now reports the 14 static checks' own \
         results, as the run above its second reading shows. The shipped half of \
         the file proposes nothing; **a line naming \
         a proposer word above `#[cfg(test)]` would be a proposer arriving in the \
         CLI, and this entry is not cover for it**",
    ),
    (
        "src/acceptance_report.rs",
        "`P14-T011`, and the third entry here that decides nothing: it proposes \
         for no project, and no product path reaches it — its only caller is \
         `crates/sure-core/tests/acceptance_report_runner.rs`, because the corpus \
         it reads (`evaluation/` and `fixtures/adversarial/`) is a repository \
         artefact that exists in a checkout and not in a user's installation. Two \
         things in it name these words, and neither is a check arriving in the \
         product. The first is reading the scanners in the entries above: \
         `CandidateScanner::proposed`, `NoOpHeuristics::proposed`, \
         `DemoDataHeuristics::proposed`, `RouteConsistency::proposed` and \
         `UiActionBridge::proposals` all return `Vec<CheckProposal>`, and this \
         file measures their severities, evidence classes and anchors rather than \
         adding a candidate of its own. The second is the `check-crash` case, \
         whose fixture declares its checks and its runs in `scenario.json`: the \
         file rebuilds **the fixture's own declaration** into the proposals the \
         product's `PlanBuilder` is handed, so that what runs, what the mode \
         refuses and what the aggregator makes of the results are the product's \
         computation and not this file's. **The corpus decides which checks exist \
         here, and the file reads no project's manifest to make one** — a \
         proposal built from anything but that fixture would be the proposer this \
         rule exists to prevent, in a module whose reason for existing is to \
         report what other modules did",
    ),
    (
        "src/findings_from_checks.rs",
        "`P7-T012`, and the fifth entry here that decides nothing: it reads the \
         `CheckResult`s a run already has and turns each one that is a gap into a \
         `Finding`. It names `PlanBuilder` in exactly one place — inside its \
         `#[cfg(test)]` module, where `empty_schedule()` builds a plan with \
         nothing in it, because `PlanBuilder::build` is the only door any code in \
         this tree has to a `CheckSchedule` and the unit tests need one that \
         proposes nothing. The file names none of the other three words anywhere, \
         and there is no `propose` call in it: every check a finding here is about \
         was proposed by a module in the entries above and reached this one as a \
         result. **A line above `#[cfg(test)]` naming any of the four would be a \
         proposer arriving in the module that reads results, and this entry is not \
         cover for it**",
    ),
    (
        "src/planned_work.rs",
        "`P18-T002`, and the sixth entry here that decides nothing: it is the value \
         that carries a check's proposal beside the operation that would carry the \
         check out, so a caller that has one of the two cannot have the other \
         missing. It names `CheckProposal` because it *holds* one — a field, a \
         constructor and an accessor, plus `PrecomputedEvidence::to_result`, which \
         is handed a proposal and **reads** its weight rather than building one, so \
         it is a consumer and not a proposer either. Every proposal that reaches \
         the file was built by a module in the entries above and is stored, handed \
         back unchanged, or read for the severity and identity it already carries. \
         **A line here that built a proposal of its own, rather than storing and \
         returning its caller's, would be a proposer**, and this entry is not cover \
         for it. The entry was missing until `P18-T003` ran this rule against the \
         file: the task that added it ran the module's own tests and not this one, \
         so the rule was red for a whole task and nothing read it — which is the \
         failure mode the list is written down to make visible",
    ),
    (
        "src/planned_check_runner.rs",
        "`P18-T006`, and the seventh entry here that decides nothing: it is the door \
         between a plan and a process, and it proposes for no project. Every line of \
         the file that names one of the four words is inside its `#[cfg(test)]` \
         module. `PlanBuilder::new` is the only door any code in this tree has to a \
         `CheckSchedule`, and the runner's own rules — one result per scheduled \
         check, an admitted check that reported nothing is an `Error` rather than a \
         missing row, and a command the enforcement did not admit never reaching the \
         runner — can only be exercised against a schedule that really has checks in \
         it, so the fixtures build one and the words appear there and nowhere else. \
         The shipped half reads `scheduled.proposal()` for the identity and the \
         weight it already carries, in the same way `findings_from_checks.rs` above \
         reads a result it was handed; it constructs no proposal and hands no \
         proposal to a builder. **A line above `#[cfg(test)]` naming any of the four \
         would be a proposer arriving in the runner, and this entry is not cover for \
         it**",
    ),
    (
        "src/service_plan.rs",
        "`P18-T012`'s follow-up, and the first entry here whose project writes its \
         declaration in `sure.yaml` rather than in a manifest: it turns a \
         `checks.services` entry into the two checks a declared service can be — \
         start it, and look at a page on it — so it is a proposer for the reason \
         `runtime_probes.rs` above is one, and not a consumer for the reason \
         `planned_work.rs` is one. **What it is not is another way to run \
         something**: the launcher a declaration names is a tagged enum \
         (`config/services.rs`) instead of a command line, the program it plans is \
         the constant `node`, and the argument vector is built as one element, so \
         there is no string anywhere in this file that is split back into \
         arguments. It proposes and stops: no admission, no admitted command, no \
         process — the same seam every entry above stands on",
    ),
];

/// Read a file the rules are stated against, refusing to check a file that could
/// not be read.
///
/// A rule that passes because its subject was not found is the false green this
/// repository is built against, so a missing file is a failure and not a skip.
fn read(relative: &str) -> String {
    let path = sure_testkit::repository_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// Whether a line is prose rather than code.
///
/// The paragraphs that *explain* a rule have to be able to name the thing the
/// rule is about, which is why rule three skips them.
fn is_prose(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// Every **shipped** `.rs` file under `crates/`, with its text.
///
/// Narrowed to `src/`, because the rule is about code that ships: a test file is
/// *supposed* to name these types — this one does — and a rule that counted them
/// would be a rule nobody could satisfy. The walk is the product's own scanner so
/// that "a file in this crate" means here what it means everywhere else, and it is
/// asserted complete, because a source rule over an unknown subset of the sources
/// is the false green this test exists to prevent.
fn shipped_sources() -> Vec<(String, String)> {
    let crates = sure_testkit::repository_root().join("crates");
    let walked = scan(&crates, ScanOptions::default()).expect("crates/ is a directory");
    assert!(
        walked.is_complete(),
        "the source tree could not be read completely, so these rules would be \
         checking an unknown subset of it"
    );

    let shipped: Vec<(String, String)> = walked
        .files()
        .filter(|entry| {
            entry
                .path
                .extension()
                .is_some_and(|extension| extension == "rs")
        })
        .map(|entry| {
            let path = crates.join(&entry.path);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            (entry.display_path(), text)
        })
        .filter(|(path, _)| path.contains("src"))
        .collect();

    assert!(
        shipped.len() > 10,
        "the source walk found {} shipped files, which is not this workspace — the \
         filter is matching the wrong thing",
        shipped.len()
    );
    shipped
}

/// The part of a file above its `#[cfg(test)]` module.
///
/// Rule four is about code that ships, and `schedule.rs`'s own tests build results
/// and name statuses because that is what testing a mapping looks like. Counting
/// them would make the rule unsatisfiable, and the rule that *is* satisfiable —
/// "no test may check a status" — is false and should be.
///
/// `None` when there is no test module, which the caller refuses rather than
/// treating as "the whole file ships": with no test module the counts would
/// silently include whatever the file grew later.
fn shipped_part(text: &str) -> Option<&str> {
    text.split_once("\n#[cfg(test)]")
        .map(|(shipped, _)| shipped)
}

/// The body of `pub struct CheckPlan { ... }`, to its closing brace.
///
/// Returns `None` rather than an empty string when the struct is not found. **An
/// empty body would satisfy every rule stated against it**, and a parse that fails
/// into a smaller, plausible answer is the defect this repository has hit more
/// than once; the test below refuses the `None` instead of treating it as a struct
/// with no fields.
fn check_plan_body(text: &str) -> Option<&str> {
    const OPENS: &str = "pub struct CheckPlan {";
    let start = text.find(OPENS)?;
    let body = &text[start + OPENS.len()..];
    let end = body.find("\n}")?;
    Some(&body[..end])
}

/// A proposal with everything a proposal needs and nothing that distinguishes it,
/// so a test that wants to vary one thing varies exactly that.
fn proposal(
    id: CheckId,
    title: &str,
    severity: Severity,
    evidence_class: EvidenceClass,
    actions: &[ActionKind],
) -> CheckProposal {
    CheckProposal::new(
        id,
        title,
        severity,
        false,
        evidence_class,
        CheckReason::ProjectWide,
        actions,
    )
}

/// The plan entry for a proposal, since `P18-T003` a proposal plus its operation.
///
/// **A candidate observation, because that is the whole of what these fixtures
/// establish.** Every check below is built by hand and nothing here starts a
/// process or reads a file: the value is *nothing has settled this check*, which
/// maps to a warning and never to a pass — the one answer that claims nothing.
/// These files are about ordering, decisions and enforcement rather than about
/// operations, so what they supply beside the proposal is the most conservative
/// thing they can honestly say, and `P18-T004` is the task that replaces the
/// placeholders on the product's own paths with real observations.
fn work(proposal: CheckProposal) -> PlannedWork {
    PlannedWork::new(
        proposal,
        CheckOperation::Precomputed(PrecomputedEvidence::candidate(
            "this fixture builds a plan and observes nothing",
        )),
    )
}

fn titles(schedule: &CheckSchedule) -> Vec<&str> {
    schedule
        .checks()
        .iter()
        .map(|scheduled| scheduled.proposal().title())
        .collect()
}

/// A builder for a run that may execute the project's code.
fn an_executing_builder() -> PlanBuilder {
    PlanBuilder::new(
        ExecutionMode::HostConfirmed,
        ExecutionPermissions {
            run_project_code: true,
            ..ExecutionPermissions::inspect_only()
        },
    )
}

#[test]
fn every_check_in_the_plan_carries_a_reason_an_evidence_class_and_its_requirements() {
    // The acceptance sentence. Read from an integration test rather than from the
    // module's own tests, which is what makes it a claim about the public seam
    // rather than about code that can reach private fields.
    let mut builder = an_executing_builder();
    builder
        .propose(work(CheckProposal::new(
            CheckId::generate(),
            "the lockfile matches the manifest",
            Severity::MustFix,
            true,
            EvidenceClass::ObservedFact,
            CheckReason::FilePresent {
                path: "package-lock.json".to_owned(),
            },
            &[ActionKind::ReadFile, ActionKind::ReadMetadata],
        )))
        .unwrap();
    builder
        .propose(work(CheckProposal::new(
            CheckId::generate(),
            "the declared tests pass",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            CheckReason::DeclaredCommand {
                declared_in: "package.json".to_owned(),
                command: "npm test".to_owned(),
            },
            &[ActionKind::RunTests],
        )))
        .unwrap();
    builder
        .propose(work(CheckProposal::new(
            CheckId::generate(),
            "nothing surprising in the layout",
            Severity::CanFixLater,
            false,
            EvidenceClass::ModelAssessment,
            CheckReason::StackPresent {
                component: "web".to_owned(),
                stack: "node".to_owned(),
            },
            &[ActionKind::ListDirectory],
        )))
        .unwrap();

    let schedule = builder.build();
    assert_eq!(schedule.len(), 3, "a proposal was lost building the plan");

    let mut classes = Vec::new();
    for (index, scheduled) in schedule.checks().iter().enumerate() {
        let entry = scheduled.proposal();
        // The three named in the acceptance, each read through its accessor.
        let reason = entry.reason();
        assert!(reason.names_something(), "{reason:?} names nothing");
        assert!(!reason.plain_description().trim().is_empty());

        let class = entry.evidence_class();
        assert!(!class.as_str().trim().is_empty());
        classes.push(class.as_str());

        let requirements = entry.requirements();
        assert!(!requirements.is_empty(), "the check would do nothing");
        assert!(!requirements.actions().is_empty());
        assert!(
            !requirements.permissions_needed().is_empty(),
            "a check that needs no permission is one nothing would be asked about"
        );

        // And the entry renders, which is what a report does with it.
        assert!(!scheduled.plain_description().trim().is_empty());
        assert_eq!(
            scheduled.position(),
            index,
            "an entry's position is not where the plan put it"
        );
    }

    // The evidence classes are not all one value, which is what makes carrying the
    // field worth anything: a plan that could only ever say `unknown` would satisfy
    // every assertion above while distinguishing nothing.
    classes.sort_unstable();
    classes.dedup();
    assert!(
        classes.len() >= 3,
        "three proposals with three evidence classes produced {classes:?}, so the \
         field is not travelling from the proposal to the plan"
    );

    // The requirements are computed from the actions and not copied from the
    // caller, which is the half of "execution requirements" that could be faked.
    let requirements_of = |title: &str| {
        schedule
            .checks()
            .iter()
            .find(|scheduled| scheduled.proposal().title() == title)
            .expect("the check is in the plan")
            .proposal()
            .requirements()
            .clone()
    };

    // Running the tests is one action and it needs one permission. `Inspect` is
    // *not* added on top: `ActionKind::required_permission` is a total mapping
    // from an action to what that action costs, and a check that also has to read
    // something says so by listing the read among its actions -- which is the
    // proposer's job and not something this module may infer.
    let tests = requirements_of("the declared tests pass");
    assert!(tests.runs_project_code());
    assert!(!tests.runs_nothing());
    assert_eq!(tests.permissions_needed(), [Permission::RunProjectCode]);

    // And the other direction, from a check that only reads: two actions, one
    // permission, deduplicated.
    let lockfile = requirements_of("the lockfile matches the manifest");
    assert!(!lockfile.runs_project_code());
    assert!(lockfile.runs_nothing());
    assert!(lockfile.is_inspection_only());
    assert_eq!(lockfile.actions().len(), 2);
    assert_eq!(lockfile.permissions_needed(), [Permission::Inspect]);
}

#[test]
fn the_order_is_the_one_the_rules_describe_whatever_order_the_checks_arrived_in() {
    // The module's own test sweeps all 120 permutations of five checks. This one
    // sweeps 24 of four and exists for a different reason: it builds the plan
    // through the public API only, so it holds the promise for a caller rather
    // than for the module's own tests.
    let kinds = [
        ("reads", Severity::Note, ActionKind::ReadFile),
        ("tests", Severity::MustFix, ActionKind::RunTests),
        ("lists", Severity::CanFixLater, ActionKind::ListDirectory),
        ("builds", Severity::ShouldFixFirst, ActionKind::Build),
    ];
    let proposals: Vec<CheckProposal> = kinds
        .iter()
        .map(|(title, severity, action)| {
            proposal(
                CheckId::generate(),
                title,
                *severity,
                EvidenceClass::DeterministicCheck,
                &[*action],
            )
        })
        .collect();

    // Rule one puts the checks that run nothing first -- reads, lists -- and rule
    // two puts the worse first inside each half. So: no-code half is lists
    // (CanFixLater) then reads (Note), and the code half is tests (MustFix) then
    // builds (ShouldFixFirst).
    let expected = ["lists", "reads", "tests", "builds"];

    // The arrival orders are collected rather than counted, so a generator that
    // visited the same permutation 24 times fails instead of passing: a sweep is
    // exactly the kind of loop whose failure is a smaller, plausible answer, and a
    // count cannot tell 24 permutations from one permutation 24 times.
    let mut visited: Vec<Vec<usize>> = Vec::new();
    for order in permutations(4) {
        let mut builder = an_executing_builder();
        for index in &order {
            builder.propose(work(proposals[*index].clone())).unwrap();
        }
        let built_schedule = builder.build();
        assert_eq!(
            titles(&built_schedule),
            expected,
            "the plan built from arrival order {order:?} is not the order the rules \
             describe, so either the order depends on how the checks arrived or the \
             rules are not the ones implemented"
        );
        assert!(
            !visited.contains(&order),
            "the sweep visited {order:?} twice, so it is not a sweep"
        );
        visited.push(order);
    }
    assert_eq!(visited.len(), 24, "4! permutations were not all visited");
    assert!(
        visited.iter().all(|order| order.len() == 4),
        "the permutation generator produced a shorter sequence than it was asked for"
    );
}

/// Every permutation of `0..n`.
fn permutations(n: usize) -> Vec<Vec<usize>> {
    fn walk(n: usize, current: &mut Vec<usize>, used: &mut Vec<bool>, out: &mut Vec<Vec<usize>>) {
        if current.len() == n {
            out.push(current.clone());
            return;
        }
        for candidate in 0..n {
            if used[candidate] {
                continue;
            }
            used[candidate] = true;
            current.push(candidate);
            walk(n, current, used, out);
            current.pop();
            used[candidate] = false;
        }
    }

    let mut out = Vec::new();
    walk(n, &mut Vec::new(), &mut vec![false; n], &mut out);
    out
}

#[test]
fn a_check_that_cannot_run_stays_in_the_plan_and_can_only_be_skipped() {
    // The failure this guards against is a plan that reads as complete: a check
    // dropped for being unrunnable leaves a report with nothing missing from it,
    // which is the shape of every false green this repository has recorded.
    let mut builder = PlanBuilder::new(
        ExecutionMode::InspectOnly,
        ExecutionPermissions::inspect_only(),
    );
    builder
        .propose(work(CheckProposal::new(
            CheckId::generate(),
            "the declared tests pass",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            CheckReason::DeclaredCommand {
                declared_in: "package.json".to_owned(),
                command: "npm test".to_owned(),
            },
            &[ActionKind::RunTests],
        )))
        .unwrap();
    builder
        .propose(work(proposal(
            CheckId::generate(),
            "the manifest is readable",
            Severity::CanFixLater,
            EvidenceClass::ObservedFact,
            &[ActionKind::ReadMetadata],
        )))
        .unwrap();

    let schedule = builder.build();
    assert_eq!(
        schedule.len(),
        2,
        "a check that cannot run was dropped from the plan"
    );
    assert_eq!(schedule.may_run().count(), 1);
    assert_eq!(schedule.blocked().count(), 1);
    assert_eq!(
        schedule.may_run().count() + schedule.blocked().count(),
        schedule.len(),
        "the two halves are not complements, so a caller counting one of them \
         would be counting a plan that is either short or long"
    );

    let blocked: &ScheduledCheck = schedule.blocked().next().expect("one blocked check");
    assert_eq!(blocked.decision(), ExecutionDecision::Denied);
    assert_eq!(
        blocked.blocked_by(),
        Some(Permission::RunProjectCode),
        "the entry names the one permission that would change the answer"
    );
    // It still carries the acceptance's three things, which is the point of
    // keeping it: a blocked check is not an entry with less in it.
    assert_eq!(blocked.proposal().title(), "the declared tests pass");
    assert!(blocked.proposal().reason().names_something());
    assert_eq!(
        blocked.proposal().evidence_class(),
        EvidenceClass::DeterministicCheck
    );
    assert!(blocked.proposal().requirements().runs_project_code());

    // The only status reachable from a schedule entry is `skipped`, and the
    // evidence class collapses to `unknown` on the way -- a check that did not run
    // established nothing, whatever its result would have been worth.
    let result = blocked
        .not_run(&FingerprintId::generate())
        .expect("a blocked check has a result saying it did not run");
    assert_eq!(result.status, CheckStatus::Skipped);
    assert!(!result.status.is_green());
    assert!(!result.status.produced_a_result());
    assert_eq!(result.evidence_class, EvidenceClass::Unknown);
    assert_eq!(
        result.not_checked_reason,
        Some(NotCheckedReason::ExecutionNotAuthorized)
    );
    assert!(
        result.blocks_green(),
        "a critical check that never ran must forbid a green verdict"
    );

    // And a check that would run has no such result at all, so a caller cannot
    // reach a skipped row for something that happened.
    assert!(
        schedule
            .may_run()
            .next()
            .expect("one runnable")
            .not_run(&FingerprintId::generate())
            .is_none()
    );
}

#[test]
fn the_schedule_hands_enforcement_its_checks_in_the_same_order() {
    // The bridge. `planned_checks` is what a caller hands to `Enforcement`, and if
    // it were built by a second pass over a differently sorted list the plan a
    // report shows and the plan that was executed could disagree.
    let mut builder = an_executing_builder();
    for (title, severity, action) in [
        ("runs", Severity::Note, ActionKind::RunTests),
        ("reads", Severity::MustFix, ActionKind::ReadFile),
        ("lists", Severity::MustFix, ActionKind::ListDirectory),
    ] {
        builder
            .propose(work(proposal(
                CheckId::generate(),
                title,
                severity,
                EvidenceClass::DeterministicCheck,
                &[action],
            )))
            .unwrap();
    }

    let schedule = builder.build();
    let planned = schedule.planned_checks();
    assert_eq!(planned.len(), schedule.len());
    for (index, (scheduled, planned)) in schedule.checks().iter().zip(&planned).enumerate() {
        assert_eq!(
            scheduled.position(),
            index,
            "positions are not the plan's own"
        );
        assert_eq!(scheduled.proposal().id(), planned.id());
        assert_eq!(scheduled.proposal().title(), planned.title());
        assert_eq!(scheduled.proposal().severity(), planned.severity());
        assert_eq!(scheduled.proposal().critical(), planned.critical());
    }

    // And the frozen record accepts them, which is the two types meeting.
    let permissions = PermissionPlan::new(
        ExecutionMode::HostConfirmed,
        FingerprintId::generate(),
        ExecutionPermissions {
            run_project_code: true,
            ..ExecutionPermissions::inspect_only()
        },
    );
    let enforcement = Enforcement::of("plan-1", permissions, &planned);
    assert_eq!(
        enforcement.check_plan().all_checks().len(),
        schedule.may_run().count(),
        "the frozen plan holds a different number of checks from the schedule's \
         runnable half"
    );
    assert!(
        enforcement.unscheduled().is_empty(),
        "a scheduled check was not in the frozen plan: {:?}",
        enforcement.unscheduled()
    );
}

#[test]
fn nothing_in_the_product_proposes_a_check_that_is_not_meant_to() {
    // Rule three, and it is an absence, so it is the source text that is checked.
    let mut found = Vec::new();
    for (path, text) in shipped_sources() {
        if MAY_PROPOSE
            .iter()
            .any(|&(exempt, _)| path.ends_with(exempt))
        {
            continue;
        }
        for (number, line) in text.lines().enumerate() {
            if is_prose(line) {
                continue;
            }
            if PROPOSER_WORDS.iter().any(|word| line.contains(word)) {
                found.push(format!("{path}:{}: {}", number + 1, line.trim()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "a shipped file has begun proposing checks. That is a real change and not a \
         test to update: it means something in the product decides which checks \
         exist, which is `P4-T002`/`P4-T003`/`P4-T004`'s work. Add the file to \
         `MAY_PROPOSE` and say why, in the same commit. Found:\n  {}",
        found.join("\n  ")
    );

    // The other half, and it is behavioural rather than textual: the builder itself
    // can be handed nothing and returns a plan with nothing in it, so there is no
    // path from "no proposer" to "a plan that looks checked".
    let empty = PlanBuilder::new(
        ExecutionMode::InspectOnly,
        ExecutionPermissions::inspect_only(),
    )
    .build();
    assert!(empty.is_empty());
    assert!(empty.planned_checks().is_empty());
    assert_eq!(empty.mode(), ExecutionMode::InspectOnly);
}

#[test]
fn every_exemption_from_the_proposer_rule_is_still_a_proposer() {
    // **An exemption has two ways to be wrong and the rule above can only see
    // one.** It fails when a file that should be on the list is not; it says
    // nothing at all about a file that is on the list and no longer names any of
    // the four words. That second one is the worse failure, because it is a hole
    // in the rule that reads exactly like a deliberate exception: the next file
    // to begin proposing checks could be moved into the same directory, or the
    // exemption widened by a character, and every test here would still pass.
    let sources = shipped_sources();

    for &(exempt, why) in MAY_PROPOSE {
        assert!(
            !why.trim().is_empty(),
            "{exempt} is exempted with no reason, and the reason is the whole of \
             what makes this list a decision rather than a loophole"
        );
        assert!(
            exempt.starts_with("src/"),
            "{exempt} is not spelled the way the `crates/` walk spells a path, so \
             it matches no file and exempts nothing"
        );

        let (path, text) = sources
            .iter()
            .find(|(path, _)| path.ends_with(exempt))
            .unwrap_or_else(|| {
                panic!(
                    "{exempt} is exempted from the proposer rule and is not a \
                     shipped source file, so the exemption names nothing"
                )
            });

        let named: Vec<&str> = PROPOSER_WORDS
            .iter()
            .copied()
            .filter(|word| {
                text.lines()
                    .any(|line| !is_prose(line) && line.contains(word))
            })
            .collect();
        assert!(
            !named.is_empty(),
            "{path} is exempted from the proposer rule and no longer names any of \
             {:?} in code, so the exemption has outlived what it was written for \
             and the rule is now weaker than it reads. Remove the entry.",
            PROPOSER_WORDS
        );
    }

    // And the list is not empty, which is the vacuity guard for the whole test:
    // an empty `MAY_PROPOSE` would satisfy every assertion above and would mean
    // rule three had quietly become "nothing in the product proposes a check".
    assert!(!MAY_PROPOSE.is_empty());
    assert!(
        MAY_PROPOSE
            .iter()
            .any(|&(exempt, _)| exempt == THE_BUILDER_IN_THE_WALK),
        "the builder is not on the list, so the rule above is checking a file \
         that defines the four words it looks for"
    );
}

#[test]
fn the_schedule_cannot_spell_a_verdict() {
    let text = read(THE_BUILDER);

    // The vacuity guard, before the counts: a file that could not be found or is
    // not the schedule module would give zero of both and pass.
    assert!(
        text.contains("pub struct CheckSchedule") && text.contains("pub struct CheckProposal"),
        "the file at {THE_BUILDER} is not the schedule module, so the counts below \
         would be counting nothing"
    );

    let shipped = shipped_part(&text).unwrap_or_else(|| {
        panic!(
            "{THE_BUILDER} has no `#[cfg(test)]` module, so this rule cannot tell \
             shipped code from test code and the counts below would include whatever \
             the file grows later"
        )
    });
    assert!(
        shipped.contains("pub struct CheckSchedule"),
        "the text above the test module is not the shipped module — the split found \
         the wrong boundary"
    );

    for (needle, expected, why) in [
        (
            "CheckStatus",
            0,
            "the status a blocked check gets is `CheckResult::not_run`'s to choose. \
             A status named here is a second place a verdict is spelled, and a \
             schedule entry that could be turned into a pass is the false green this \
             module is written against",
        ),
        (
            "CheckResult",
            4,
            "a doc sentence, an import, one signature and one call. A fifth is a \
             second way out of a schedule and into a result",
        ),
        (
            "CheckId::generate",
            0,
            "identity is the caller's, because a check SURE minted an id for could \
             not be joined back to the plan that proposed it across a re-check",
        ),
    ] {
        let found = shipped.matches(needle).count();
        assert_eq!(
            found, expected,
            "the shipped part of {THE_BUILDER} contains {found} of `{needle}` and \
             should contain {expected}: {why}"
        );
    }

    // And the one call out is the one that produces a skipped result, so the
    // counts above are about the function they claim to be about.
    assert_eq!(shipped.matches("pub fn not_run").count(), 1);
}

#[test]
fn the_frozen_plan_does_not_grow_a_reason() {
    // Rule five. The three things this task adds are the schedule's, and the
    // domain's record holds identifiers: `Enforcement::of` did not have to change
    // for `P4-T001`, and adding a field to `CheckPlan` is an ADR-level decision
    // rather than a convenience.
    let text = read(THE_FROZEN_PLAN);
    let body = check_plan_body(&text).expect(
        "`pub struct CheckPlan {` was not found in the vocabulary, so this rule \
         checked nothing",
    );

    // The vacuity guard: a body found but empty would pass a "names none of these"
    // rule while saying nothing.
    assert!(
        body.contains("pub mode: ExecutionMode"),
        "the struct body does not contain the field it is known by, so the parse \
         found the wrong region: {body:?}"
    );

    for forbidden in ["CheckReason", "EvidenceClass", "ExecutionRequirements"] {
        assert!(
            !body.contains(forbidden),
            "the frozen plan has grown a `{forbidden}`. That is the boundary this \
             task kept: a schedule entry may carry a reason and an evidence class, \
             and the record that says what execution allowed holds identifiers. \
             Moving it into the domain is an ADR, not a refactor. Body:\n{body}"
        );
    }
}

#[test]
fn the_two_spellings_of_the_builders_path_agree() {
    // Written because they disagreed once, in `browser_probe.rs`: `src/schedule.rs`
    // used as a path from the repository root reads nothing, and the rule built on
    // it would have checked an empty file rather than failing.
    assert!(
        THE_BUILDER.ends_with(THE_BUILDER_IN_THE_WALK),
        "{THE_BUILDER} does not end with {THE_BUILDER_IN_THE_WALK}, so the walk's \
         spelling of the schedule module names a different file — or none"
    );
    assert!(THE_BUILDER_IN_THE_WALK.starts_with("src/"));
}

#[test]
fn the_plan_is_usable_from_outside_the_crate() {
    // A last, cheap rule with a specific job: every type the acceptance names has
    // to be nameable and constructible by a caller in another crate, because the
    // proposer `P4-T002` writes will be. This test compiles only if that holds.
    let requirements = ExecutionRequirements::of(&[ActionKind::ReadFile]);
    assert_eq!(requirements.permissions_needed(), [Permission::Inspect]);
    assert!(requirements.is_inspection_only());
    assert!(requirements.runs_nothing());
    assert!(!requirements.can_touch_network());
    assert!(!requirements.can_modify_disk());
    assert_eq!(requirements.actions(), [ActionKind::ReadFile]);

    let reason = CheckReason::StackPresent {
        component: "web".to_owned(),
        stack: "node".to_owned(),
    };
    assert!(reason.plain_description().contains("web"));
    assert!(reason.names_something());

    let built: CheckSchedule = an_executing_builder().build();
    assert!(built.is_empty());
}
