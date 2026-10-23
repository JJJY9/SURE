//! The one support level for the thing a person pointed SURE at.
//!
//! Step 1 of `docs/architecture/CHECK_PIPELINE.md` ends *"…and support level."*
//! [`crate::discover`] answers that per ecosystem — what each manifest declared,
//! and how well SURE understands it. This module answers it for the **project**,
//! the directory the person named, and fills
//! [`Project::support`](sure_domain::vocabulary::Project::support).
//!
//! `docs/product/SUPPORTED_STACKS.md` is the authority for what the three levels
//! mean, and it defines them by what SURE can **do**:
//!
//! | Level | The product doc's definition |
//! | --- | --- |
//! | A — `first_class` | framework-aware discovery **and meaningful deterministic checks** |
//! | B — `generic` | discover common manifests/commands **and run approved generic checks** |
//! | C — `inspect_only` | inspect files and config, lacking safe or reliable run semantics |
//!
//! # The rule
//!
//! **The project's level is the weakest of two things: what SURE read, and what
//! SURE can do with it.**
//!
//! [`weakest`] takes both. Neither alone is the answer: a project whose manifest
//! SURE read perfectly would still be level A if reading were all a level
//! claimed, and a project with no manifest at all would still be level A if
//! capability were all it claimed. The level is a claim about what a person gets
//! from pointing SURE at this directory, and that is the smaller of the two.
//!
//! # Why the ceiling is [`SupportLevel::InspectOnly`] in this build
//!
//! Both level A and level B include *running* something — "meaningful
//! deterministic checks", "approved generic checks" — and **as of `P18-T007` this
//! build does run a project's checks**. [`crate::pipeline`] asks
//! [`crate::enforce`] about every check the schedule holds, keeps the ones the
//! mode and the permissions admit, and hands those to
//! [`crate::planned_check_runner`], the one file that turns a planned command
//! into a request for [`crate::process`]'s runner. The sentence this section used
//! to carry — *"this build runs no project code"* — is **false today and is
//! written nowhere in `crates/` or `docs/` any more**.
//!
//! What is still true, and what this section is now for, is why the ceiling did
//! not move with it. Two things, and neither one is "nothing can run":
//!
//! **A run under the default mode still reaches no process.** `inspect_only` is
//! the mode a run starts in, and the mode a *project* file cannot move in either
//! direction: [`crate::config::Authority::execution_mode`] answers it unless the
//! **user's own** file grants `run_project_code` and names a mode that runs
//! project code (`docs/architecture/CONFIG_AUTHORITY.md`). Under it
//! [`crate::enforce`] admits no command that starts a process, so the runner is
//! never asked — and that is measured rather than asserted: `pipeline.rs`'s
//! `a_run_a_user_did_not_grant_starts_nothing` runs the real pipeline over a Rust
//! project with a runner that records being called, and asserts the record is
//! empty.
//!
//! **And the readings have moved since the ceiling was set, without settling
//! it** (`docs/adr/0015-support-ceiling-evidence.md` holds them; this paragraph
//! is what they now produce).
//!
//! * **Windows, a Node project: the resolver still says not startable, and the
//!   product runner now starts a known shim anyway.** Measured on this
//!   workstation through this module's own resolver —
//!   `ProgramPath::of_this_machine().resolve(OsStr::new("npm"))` answers
//!   `Resolution::InterpreterRequired("C:\Program Files\nodejs\npm.cmd")` and
//!   `is_startable()` is false, and the same is true of `npx` and `pnpm`.
//!   **The extensionless `npm` file is on `PATH` and is not the answer**: the
//!   Windows completion table probes `com`/`exe`/`bat`/`cmd`/`ps1` and never the
//!   bare name, so the file that would run on macOS resolves to a batch file
//!   this build declines to start (the alternative
//!   `docs/adr/0014-planned-check-execution-contract.md` rejected). Since
//!   2026-10-22 the product runner translates the known package-manager shims
//!   into `node` and the JavaScript entry the manager ships
//!   (`crate::package_launcher`), so a Windows Node project's declared check can
//!   run; real `npm`/`pnpm`/`yarn` runs produced `pass` and `fail` results. The
//!   resolver's answer is unchanged. A tracked test now completes a Rust
//!   project's declared check through the CLI on all three CI legs
//!   (`sure-cli/tests/finished_declared_check.rs`); see the next two bullets.
//! * **A Rust project's declared check runs to completion in a tracked test.**
//!   `finished_declared_check.rs` (added by `4ec2e2d`) drives the CLI under
//!   `host_confirmed`, the fixture's `cargo test` writes its marker, and the
//!   report row is asserted `pass`. `cargo` and `git` resolve `Executable`, and
//!   the seam-only reading this module used to quote is no longer the whole
//!   story.
//! * **macOS and Linux: the same tracked CLI test runs there.** The non-Windows
//!   completion resolves a bare `npm` file to `Executable`
//!   (`planned_work.rs`'s `WITHOUT_PATHEXT`, tested on Windows by
//!   `a_platform_that_completes_a_bare_name_with_nothing_finds_the_name_itself`),
//!   and `cargo test --workspace` runs `finished_declared_check.rs` on both legs,
//!   so a project's declared check completes on those platforms too. **This
//!   paragraph said the opposite until `P18-T012`** — that those legs "have
//!   never run at all" — and that was a recollection rather than a reading; it
//!   is the one part of the ceiling's stated reason a measurement contradicted.
//!
//! Level B is one sentence about running approved generic checks. The readings
//! now cover a Rust project's declared check on all three platforms (the tracked
//! CLI test above) and a Node project on Windows (local probes), but whether that
//! set earns the single sentence for every project and every kind of check is an
//! open decision, recorded in ADR 0015's amendment. This module keeps the weaker
//! level until that decision is taken; moving a constant in a documentation pass
//! would be the substitution ADR 0014 warned about, one level up.
//!
//! **The census that used to be the evidence for the ceiling is now the evidence
//! for something narrower, and deliberately so.** `tests/spawn_sites.rs` holds
//! the list of files that may name a `Supervisor`, a `StartSmoke` or a
//! `ProcessRequest`, and the product now reaches that last one — through
//! `pipeline.rs` into `planned_check_runner.rs`. So the claim is no longer "no
//! product path reaches the runner" but **"the product path that reaches the
//! runner can only start what the mode admitted"**, which is the property
//! `enforce.rs` was built to have: a command arrives at a runner as an admitted
//! value or not at all. That file's paragraphs carry the argument; this one only
//! points at it. [`crate::doctor`] is the other side of the same discipline — it
//! looks for the programs a build on this machine uses and reports where each one
//! is, which is SURE talking about its own prerequisites without running any of
//! them. *Probes* would be a claim this build cannot make, and it does not make
//! it.
//!
//! So the honest answer for every project in this build is still level C, and
//! [`CEILING`] is what says so in one place. It is a constant rather than a
//! comment because a claim this load-bearing wants a name that code can point
//! at: the day the readings earn a level, this is the line that changes, and
//! `the_ceiling_todays_build_claims_is_never_above_inspect_only` fails until
//! somebody raises it deliberately.
//!
//! # A conflict in the vocabulary, recorded rather than resolved quietly
//!
//! `docs/architecture/ECOSYSTEM_DISCOVERY.md`'s grade tables award `Generic` to
//! any project with a readable manifest, with the reason *"SURE can find how the
//! project is built and run"* — that is, SURE can find **the commands**. The
//! product doc's level B is a higher bar: finding the commands **and running
//! approved generic checks**. One word, two bars.
//!
//! This module takes the product doc's bar, because it is the document titled
//! *Supported stacks and support levels* and because the difference is visible
//! to a user: [`SupportLevel::plain_description`] renders `Generic` as *"SURE
//! can find how this project is built and run"*, and SURE cannot run it. The
//! other reading — that the level states what SURE **understands**, discovery's
//! grade is the whole answer, and the ceiling should be `Generic` — is a real
//! one, it is the owner's to settle, and it is a two-line change here plus the
//! tests that pin today's answer.
//!
//! **Where the level and the grade disagree, the reason says both**, so the
//! report never reconciles them by silence. See [`what_sure_can_do`].
//!
//! # What it does not do
//!
//! **It does not read anything.** It is a view over a [`Discovery`], so it
//! cannot disagree with the discovery it came from about what was in the
//! project — and a caller may classify a discovery whose directory has since
//! been deleted. `a_classification_survives_the_project_being_deleted` holds
//! that.
//!
//! **It does not decide whether the project is good.** It says how far SURE's
//! support reaches; whether the project's own declarations are honest is what
//! the checks after it are for.
//!
//! **It does not consult the execution mode or the permissions — and since
//! `P18-T007` that is a decision rather than a consequence.** A grant says what
//! the user *allowed*; a level says what SURE can *do*. Those two came apart when
//! the runner was wired: a granted run **can** run approved generic checks, and
//! the ceiling stays at `InspectOnly` anyway, because level B is a claim about
//! every platform SURE runs on and one platform has not earned it for both. A
//! level that moved with a settings file would be a level that says what the
//! person had allowed rather than what the build can do, and it would make the
//! same project read as two different levels on two runs. What a permission
//! cannot do is make a check exist that was never written, which is the part of
//! the old sentence that was always about the level.

use sure_domain::vocabulary::{ProjectSupport, StackClassification, SupportLevel};

use crate::discover::Discovery;

/// The best level any project can reach in this build.
///
/// [`SupportLevel::InspectOnly`], and since `P18-T007` the reason is **not** that
/// this build runs no project code — it does. The reason is the measured
/// asymmetry `docs/adr/0015-support-ceiling-evidence.md` records (the first row
/// re-read on 2026-10-22): a Node project on Windows reaches the known-shim
/// launcher (local probes); a Rust project's declared check completes in the
/// tracked CLI test `finished_declared_check.rs` on all three CI legs; and
/// whether that set earns level B for every project and every kind of check is
/// an open decision in ADR 0015's amendment. **This doc used to say one platform
/// had never been tried; that was wrong, and the module comment says what
/// replaced it.** Raising this to [`SupportLevel::Generic`] is the whole of the
/// change the day that decision is recorded; the tests in this module are
/// written to fail at that moment rather than to accommodate it.
pub const CEILING: SupportLevel = SupportLevel::InspectOnly;

/// Classify the project a discovery was made of.
///
/// The level is the weaker of what SURE read and what [`CEILING`] allows, and
/// the reason names both: which stack set the level, why the build cannot go
/// above the ceiling, and what a person gets at the level it lands on.
#[must_use]
pub fn classify(discovery: &Discovery) -> ProjectSupport {
    let stacks = discovery.stacks();
    // No ecosystem found is a level and not a missing value: there is nothing
    // whose build SURE read, which is `InspectOnly`'s own definition.
    // `ProjectSupport::unrecorded` is the *other* kind of nothing — nobody
    // classified the project — and this function never returns it.
    let understood = match stacks.first() {
        Some(first) => weakest(first.level, stacks.iter().map(|stack| stack.level)),
        None => SupportLevel::InspectOnly,
    };
    let level = weakest(understood, [CEILING]);
    let reason = format!(
        "{} {} {}",
        what_was_read(discovery, &stacks, understood),
        what_sure_can_do(understood, level),
        level.plain_description(),
    );
    ProjectSupport::new(level, reason)
}

/// The weakest of a set of levels.
///
/// [`SupportLevel`] declares its variants best first, so the *weakest* is
/// [`Ord::max`]; that type's own comment is where the ordering is written down
/// and `the_order_of_the_levels_is_by_strength` is what holds it. `min` here
/// would be a rule that promotes a project to the strongest thing found in it,
/// which is the opposite of what a support claim is for.
///
/// The first level is a parameter rather than part of the iterator so that this
/// is total: a caller always has one, and there is no empty case to answer for.
fn weakest(first: SupportLevel, rest: impl IntoIterator<Item = SupportLevel>) -> SupportLevel {
    rest.into_iter().fold(first, SupportLevel::max)
}

/// What SURE read here, and the level that reading earned.
///
/// Names the stacks **at the weakest level**, which are the ones that set it. A
/// reader can put each name against `Project::stacks` and see the same value
/// there, which is what makes the level auditable rather than asserted.
fn what_was_read(
    discovery: &Discovery,
    stacks: &[StackClassification],
    understood: SupportLevel,
) -> String {
    if stacks.is_empty() {
        return nothing_was_found(discovery);
    }
    let named: Vec<&str> = stacks
        .iter()
        .filter(|stack| stack.level == understood)
        .map(|stack| stack.stack.as_str())
        .collect();
    let listed = list(&named);
    let level = understood.as_str();
    let letter = understood.letter();
    match stacks.len() {
        1 => format!("SURE read one stack here, {listed}, and graded it {level} ({letter})."),
        total if named.len() == total => format!(
            "SURE read {total} stacks here — {listed} — and graded all of them {level} ({letter})."
        ),
        total => format!(
            "SURE read {total} stacks here and graded the weakest of them — {listed} — \
             {level} ({letter})."
        ),
    }
}

/// The sentence for a project discovery found no ecosystem in.
///
/// The scan's completeness is part of it: *"found nothing"* over a walk that did
/// not see the whole project is a stronger claim than the walk supports, and the
/// difference is one clause rather than a second level.
fn nothing_was_found(discovery: &Discovery) -> String {
    let looked_for: Vec<&str> = discovery
        .looked_for()
        .iter()
        .map(|ecosystem| ecosystem.plain_name())
        .collect();
    let listed = list(&looked_for);
    let mut out = format!("SURE looked for {listed} here and found nothing it reads");
    if !discovery.is_complete() {
        out.push_str(", and it did not see the whole project");
    }
    out.push('.');
    out
}

/// What SURE can do with the project, and why that is a different level from
/// the reading when it is.
///
/// **This is where the two vocabularies are reconciled in front of the user
/// rather than behind them.** A project with a readable `Cargo.toml` is graded
/// `generic` by discovery and reported at level C here, and a reason that just
/// said "level C" would leave the difference for the reader to notice or not.
fn what_sure_can_do(understood: SupportLevel, level: SupportLevel) -> String {
    if understood == level {
        return format!(
            "So the project is at level {} ({}).",
            level.letter(),
            level.as_str()
        );
    }
    format!(
        "That reading alone would be level {} ({}), but SURE has not run this project's checks: it \
         runs none unless you grant it, and it has only been shown to work on one platform. Level \
         A needs meaningful deterministic checks and level B needs approved generic checks, so the \
         project is at level {} ({}).",
        understood.letter(),
        understood.as_str(),
        level.letter(),
        level.as_str(),
    )
}

/// A list a person reads: `a`, `a and b`, `a, b and c`.
///
/// Written out rather than joined with commas because these sentences are the
/// plain-language surface, and `node, python, rust` inside a sentence that
/// already has commas in it reads as one thing with two qualifiers.
fn list(names: &[&str]) -> String {
    match names {
        [] => "none".to_owned(),
        [only] => (*only).to_owned(),
        [first, middle @ .., last] => {
            let mut out = String::from(*first);
            for name in middle {
                out.push_str(", ");
                out.push_str(name);
            }
            out.push_str(" and ");
            out.push_str(last);
            out
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The test `SupportLevel`'s own comment names as the thing holding its
    /// variant order. It lives here because the order is not a fact about the
    /// type's shape — nothing in the enum's declaration says which end is
    /// strong — but about the rule that consumes it.
    #[test]
    fn the_order_of_the_levels_is_by_strength() {
        assert!(
            SupportLevel::FirstClass < SupportLevel::Generic,
            "variants are declared best first, so a stronger level must compare lower"
        );
        assert!(
            SupportLevel::Generic < SupportLevel::InspectOnly,
            "the weakest level must compare highest, because `weakest` is `Ord::max`"
        );
    }

    #[test]
    fn weakest_picks_the_weakest_whatever_order_it_arrives_in() {
        assert_eq!(
            weakest(SupportLevel::FirstClass, [SupportLevel::InspectOnly]),
            SupportLevel::InspectOnly
        );
        assert_eq!(
            weakest(SupportLevel::InspectOnly, [SupportLevel::FirstClass]),
            SupportLevel::InspectOnly,
            "the fold must not depend on where the weak level sits"
        );
        assert_eq!(
            weakest(
                SupportLevel::Generic,
                [SupportLevel::FirstClass, SupportLevel::InspectOnly]
            ),
            SupportLevel::InspectOnly
        );
        assert_eq!(
            weakest(SupportLevel::FirstClass, [SupportLevel::Generic]),
            SupportLevel::Generic
        );
        assert_eq!(
            weakest(SupportLevel::InspectOnly, []),
            SupportLevel::InspectOnly,
            "one level on its own is the weakest of one"
        );
    }

    /// **A tripwire, not an invariant.** The ceiling is a claim about what this
    /// build can do, and the day the readings earn a level this test is meant to
    /// fail: raising [`CEILING`] to `Generic` or `FirstClass` and then reading why
    /// is the point, not an obstacle. It is written as a property over every
    /// variant so that adding a stronger variant to `SupportLevel` fails here too,
    /// rather than quietly leaving a level no project can be reported at.
    #[test]
    fn the_ceiling_todays_build_claims_is_never_above_inspect_only() {
        for level in SupportLevel::ALL {
            assert_ne!(
                weakest(*level, [CEILING]),
                SupportLevel::FirstClass,
                "level A needs meaningful deterministic checks on every platform SURE ships on, \
                 and this build has not been measured running them; if those readings exist now, \
                 raise `CEILING` and rewrite this test deliberately"
            );
            assert_ne!(
                weakest(*level, [CEILING]),
                SupportLevel::Generic,
                "level B needs approved generic checks wherever SURE runs, and this build runs \
                 them on one platform and not on another — the module comment and ADR 0014 say \
                 why, and `P18-T012` owns the measurement that would change the answer"
            );
        }
    }

    #[test]
    fn a_list_reads_as_a_person_would_say_it() {
        assert_eq!(list(&[]), "none");
        assert_eq!(list(&["rust"]), "rust");
        assert_eq!(list(&["node", "python"]), "node and python");
        assert_eq!(list(&["node", "python", "rust"]), "node, python and rust");
    }
}
