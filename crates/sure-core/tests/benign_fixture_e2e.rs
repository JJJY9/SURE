//! The benign false-positive corpus, graded by measurement rather than by shape.
//!
//! `P14-T010`'s acceptance is one sentence:
//!
//! > *Test mocks/examples/docs TODOs do not become indiscriminate must-fix
//! > findings.*
//!
//! Two weaker readings of that sentence pass without measuring anything, and
//! this file is built to refuse both.
//!
//! The first is **silence**. A report that says `No unresolved findings.` about a
//! project because nothing read it is the false green this whole product exists
//! to catch, and a corpus of benign files satisfies *do not become must-fix* by
//! being invisible just as well as it does by being graded. So every assertion
//! here is a positive one: a named file in `fixtures/adversarial/benign-test-mocks/`
//! is read by a named detector, and what comes out is the level the corpus
//! declares. The five files were chosen so that each of the five candidate
//! detectors has exactly one home, and `CandidateScanner`, `NoOpHeuristics` and
//! `DemoDataHeuristics` each report **at most one proposal per category per
//! project** — anchored at the first matching file in sort order — which is why
//! exactly one file in the corpus carries the word `mock` and exactly one
//! carries `TODO`. A second benign file carrying the same word would not be
//! measured here, and the corpus's `notes` records that limit rather than
//! leaving it to be discovered.
//!
//! The second weak reading is **a harmless gap kind**. `UnfinishedMarker` is
//! capped one level below `must_fix` by `sure_core::finding_gravity` whatever
//! the path says, so a corpus of TODOs, mock words and placeholders would
//! satisfy the acceptance without the context gate ever being asked a question.
//! The corpus therefore carries one file whose gap kind is `SubstitutedAction`
//! — the only kind the gravity rule ever lifts to `must_fix` — and the third
//! control takes the file-name convention away from it and measures what
//! happens. That control is the boundary of the acceptance rather than a
//! contradiction of it: the case is about *test mocks, examples and docs
//! TODOs*, and the control is what the same bytes answer outside them.
//!
//! # What is read from where
//!
//! The shipped directory is read where it lives, for the reason
//! `adversarial_fixture_detection.rs` gives: the directory is the artefact, and
//! a copy would be a different project the day someone edits one and not the
//! other. The three controls are **copies** under the workspace's git-ignored
//! `target/tmp`, each with exactly the changes its own `scenario.json` declares
//! — and the filesystem is compared against that declaration afterwards, so a
//! control that altered more than it says is a failing test rather than a
//! silent extra variable.
//!
//! Nothing here opens a store and nothing here writes to one. Discovery and the
//! five detectors are pure functions of a directory, so grading this corpus
//! leaves the machine's SURE data exactly as it found it.
//!
//! # What is not claimed
//!
//! **A verdict.** These are candidates. `CheckProposal::severity` is what a
//! check would carry if it were not satisfied; none of the five detectors sets
//! `critical`, so nothing here decides whether the project passes. The
//! aggregate is asserted to hold nothing *material* — not to hold nothing.
//!
//! **A severity calibration.** This file records what the product produced on
//! the day it was written. `P7-T011` owns the argument about which level is
//! right for which gap, and `finding_severity_rule.rs` owns the sweep that holds
//! every fixture's measured severity against the release manifest.
//!
//! **That a `false_positive` declaration is enforced.** The corpus's
//! `forbidden_outcomes` use two kinds, and `false_positive` is prose: nothing in
//! the tree reads it as a rule. What holds the level is the `control` blocks
//! below, which assert the severity the product actually produces, and the
//! `status` outcome, which asserts the aggregate. `fixture_apps.rs` reads the
//! `false_green` entries and requires one of them, because that kind is the
//! release rule; the other is written down for a reader.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sure_core::candidate_context::{CandidateContext, classify_path};
use sure_core::candidate_scanner::CandidateScanner;
use sure_core::demo_data_heuristics::DemoDataHeuristics;
use sure_core::discover::{DiscoverOptions, Discovery, discover};
use sure_core::evidence::EvidenceClass;
use sure_core::false_completion_aggregator::aggregate;
use sure_core::noop_heuristics::NoOpHeuristics;
use sure_core::route_consistency::RouteConsistency;
use sure_core::schedule::CheckProposal;
use sure_core::severity::Severity;
use sure_core::ui_action_bridge::UiActionBridge;

/// The corpus case this file grades.
const FIXTURE: &str = "benign-test-mocks";

// --- the fixture and its declarations ------------------------------------

fn fixture() -> PathBuf {
    sure_testkit::repository_root()
        .join("fixtures")
        .join("adversarial")
        .join(FIXTURE)
}

/// The corpus's machine-readable half.
fn scenario() -> Value {
    let path = fixture().join("scenario.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

/// Every required outcome the corpus declares of one kind.
///
/// The kind is read rather than assumed: this file grades the `finding` entries
/// and the `control` entries, and a third kind appearing would not be silently
/// swept into either.
fn outcomes_of_kind(kind: &str) -> Vec<Value> {
    scenario()["required_outcomes"]
        .as_array()
        .cloned()
        .expect("required_outcomes is an array")
        .into_iter()
        .filter(|outcome| outcome["kind"].as_str() == Some(kind))
        .collect()
}

fn string(entry: &Value, key: &str) -> String {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("an outcome declares no `{key}`: {entry}"))
        .to_owned()
}

/// The context the corpus declares for one outcome, as the classifier's own
/// vocabulary.
///
/// A name outside this list panics rather than falling back to `Product`: an
/// outcome whose `path_context` was mistyped would otherwise be graded against
/// the one answer that makes the assertion below pass for the wrong reason.
fn declared_context(entry: &Value) -> CandidateContext {
    let name = string(entry, "path_context");
    match name.as_str() {
        "test" => CandidateContext::Test,
        "example" => CandidateContext::Example,
        "doc" => CandidateContext::Doc,
        "mock_fixture" => CandidateContext::MockFixture,
        "product" => CandidateContext::Product,
        other => panic!("`{other}` is not a context `sure_core::candidate_context` classifies"),
    }
}

/// The words a detector's own title carries for one context.
///
/// Written out here rather than read from the detector, deliberately. The
/// assertion this serves is *the title's context and the classifier agree*, and
/// reading the phrase from the same table the title was built from would make
/// that assertion true by construction. A change to either table fails here, in
/// one place, with both strings named.
fn phrase(context: CandidateContext) -> &'static str {
    match context {
        CandidateContext::Test => " in tests",
        CandidateContext::Example => " in examples",
        CandidateContext::Doc => " in documentation",
        CandidateContext::MockFixture => " in mock fixtures",
        CandidateContext::Product => " in production code",
    }
}

fn severity_of(name: &str) -> Severity {
    Severity::ALL
        .iter()
        .copied()
        .find(|severity| severity.as_str() == name)
        .unwrap_or_else(|| panic!("`{name}` is not one of the levels SURE has"))
}

fn evidence_class_of(entry: &Value) -> EvidenceClass {
    serde_json::from_value(entry["evidence_class"].clone()).unwrap_or_else(|error| {
        panic!(
            "`{}` is not an evidence class: {error}",
            entry["evidence_class"]
        )
    })
}

// --- what the five detectors say about a project --------------------------

/// One proposal, reduced to the facts the corpus declares about it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reading {
    /// The module that proposed it, as the corpus names it.
    surface: &'static str,
    title: String,
    severity: Severity,
    /// The file the proposal points at, relative to the project root.
    anchor: String,
    critical: bool,
    evidence_class: EvidenceClass,
}

fn discovery_at(root: &Path) -> Discovery {
    discover(root, &DiscoverOptions::default())
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", root.display()))
}

/// Every proposal the five candidate detectors make about one project.
///
/// The five are driven here in the order `finding_severity_rule.rs` drives them,
/// and each proposal is tagged with the module it came from, because the corpus
/// declares which detector reads which file and that declaration is part of what
/// this file grades.
fn readings(root: &Path) -> Vec<Reading> {
    let discovery = discovery_at(root);
    let mut found = Vec::new();
    collect(
        "candidate_scanner",
        CandidateScanner::of(&discovery).proposed(),
        &mut found,
    );
    collect(
        "noop_heuristics",
        NoOpHeuristics::of(&discovery).proposed(),
        &mut found,
    );
    collect(
        "demo_data_heuristics",
        DemoDataHeuristics::of(&discovery).proposed(),
        &mut found,
    );
    collect(
        "route_consistency",
        RouteConsistency::of(&discovery).proposed(),
        &mut found,
    );
    let ui = UiActionBridge::of(&discovery).proposals();
    collect("ui_action_bridge", &ui, &mut found);
    found.sort_by(|left, right| {
        (left.anchor.as_str(), left.title.as_str())
            .cmp(&(right.anchor.as_str(), right.title.as_str()))
    });
    found
}

fn collect(surface: &'static str, proposals: &[CheckProposal], into: &mut Vec<Reading>) {
    for proposal in proposals {
        let anchor = proposal.reason().anchor().unwrap_or_else(|| {
            panic!(
                "{surface}: `{}` names no place for a reader to go and look",
                proposal.title()
            )
        });
        assert!(
            anchor.is_checkable(),
            "{surface}: `{}` points at an anchor with nothing in it: {anchor:?}",
            proposal.title()
        );
        into.push(Reading {
            surface,
            title: proposal.title().to_owned(),
            severity: proposal.severity(),
            anchor: anchor.location.clone(),
            critical: proposal.critical(),
            evidence_class: proposal.evidence_class(),
        });
    }
}

/// The part of a reading a control declares: which detector said it, what it
/// said, how heavy it was and where it was found.
///
/// The anchor's `locator` is left out on purpose — it carries the matched line
/// number and the source text around it, and a control that pinned those would
/// be declaring the fixture's own contents twice.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Signature {
    surface: String,
    title: String,
    severity: String,
    anchor: String,
}

fn signature(reading: &Reading) -> Signature {
    Signature {
        surface: reading.surface.to_owned(),
        title: reading.title.clone(),
        severity: reading.severity.as_str().to_owned(),
        anchor: reading.anchor.clone(),
    }
}

fn signatures(readings: &[Reading]) -> Vec<Signature> {
    let mut found: Vec<Signature> = readings.iter().map(signature).collect();
    found.sort();
    found
}

// --- the controls, applied to copies --------------------------------------

/// A project under the workspace's git-ignored `target/tmp`.
///
/// The claiming rules live in `sure_testkit::scratch`, and the history behind
/// them is this repository's: clearing a fixed path and treating it as fresh
/// fails on Windows, and the test then describes a directory that was never
/// emptied. Nothing is adopted — a directory is taken with `create_dir`, which
/// fails when the name is taken, and one that is already there is skipped rather
/// than entered — and the helper clears only directories carrying *its own*
/// process's id, which no live process can own.
struct Scratch {
    project: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        Self {
            project: sure_testkit::scratch::directory("benign-test-mocks controls", name),
        }
    }
}

/// The control the corpus declares under one name.
fn control(name: &str) -> Value {
    outcomes_of_kind("control")
        .into_iter()
        .find(|outcome| outcome["control"]["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("the corpus declares no control named `{name}`"))
}

/// Every file under a directory, by path relative to it, with `/` separators.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .expect("a file under the directory being walked")
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            files.insert(relative, bytes);
        }
    }
    files
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", to.display()));
    for entry in std::fs::read_dir(from)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", from.display()))
    {
        let entry = entry.expect("a directory entry");
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap_or_else(|error| {
                panic!(
                    "cannot copy {} to {}: {error}",
                    path.display(),
                    target.display()
                )
            });
        }
    }
}

/// How two directory trees differ, in the same words a change is declared with.
fn differences(
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
) -> Vec<String> {
    let mut found = Vec::new();
    for (path, bytes) in before {
        match after.get(path) {
            None => found.push(format!("removed {path}")),
            Some(changed) if changed != bytes => found.push(format!("changed {path}")),
            Some(_) => {}
        }
    }
    for path in after.keys() {
        if !before.contains_key(path) {
            found.push(format!("added {path}"));
        }
    }
    found.sort();
    found
}

/// Apply one control's declared changes, and answer with the difference they
/// were supposed to make.
fn apply(project: &Path, changes: &[Value]) -> Vec<String> {
    let read = |path: &str| {
        std::fs::read(project.join(path))
            .unwrap_or_else(|error| panic!("a control reads {path}, which does not read: {error}"))
    };
    let write = |path: &str, bytes: &[u8]| {
        let full = project.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::write(&full, bytes)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
    };

    let mut intended = Vec::new();
    for change in changes {
        let verb = change["change"]
            .as_str()
            .unwrap_or_else(|| panic!("a change declares no verb: {change}"));
        match verb {
            "move" => {
                let (from, to) = (string(change, "from"), string(change, "to"));
                let bytes = read(&from);
                write(&to, &bytes);
                std::fs::remove_file(project.join(&from)).unwrap_or_else(|error| {
                    panic!("a control moves {from}, which does not remove: {error}")
                });
                intended.push(format!("added {to}"));
                intended.push(format!("removed {from}"));
            }
            "copy" => {
                let (from, to) = (string(change, "from"), string(change, "to"));
                let bytes = read(&from);
                write(&to, &bytes);
                intended.push(format!("changed {to}"));
            }
            "add" => {
                let path = string(change, "path");
                let contents = string(change, "contents");
                write(&path, contents.as_bytes());
                intended.push(format!("added {path}"));
            }
            "remove" => {
                let path = string(change, "path");
                std::fs::remove_file(project.join(&path)).unwrap_or_else(|error| {
                    panic!("a control removes {path}, which does not remove: {error}")
                });
                intended.push(format!("removed {path}"));
            }
            other => panic!("the change verb `{other}` is one this grader cannot perform"),
        }
    }
    intended.sort();
    intended
}

/// A copy of the shipped fixture with one declared control applied to it.
///
/// The declaration is checked against the disk rather than trusted: what the
/// changes were *supposed* to do and what the two trees differ by have to be the
/// same list, or the control has a second variable in it and measures nothing.
fn controlled(name: &str) -> PathBuf {
    let block = control(name);
    let scratch = Scratch::new(name);
    copy_tree(&fixture(), &scratch.project);
    let changes = block["control"]["changes"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("the `{name}` control declares no changes"));
    assert!(
        !changes.is_empty(),
        "the `{name}` control declares an empty change list, so it is the shipped fixture under \
         another name"
    );
    let intended = apply(&scratch.project, &changes);
    let measured = differences(&tree(&fixture()), &tree(&scratch.project));
    assert_eq!(
        measured, intended,
        "the `{name}` control altered the project by more or less than it declares"
    );
    scratch.project
}

/// The reading set a control must produce: the shipped set with the reading the
/// control says it replaces taken out, and the ones it declares put in.
///
/// The `unchanged` list is checked here rather than taken on trust, so a control
/// whose `replaces` named the wrong file fails instead of quietly excusing an
/// extra difference.
fn expected_after_control(name: &str) -> Vec<Signature> {
    let block = control(name);
    let shipped = signatures(&readings(&fixture()));
    let mut expected = shipped.clone();
    match block["control"]["replaces"].as_str() {
        Some(replaced) => {
            expected.retain(|signature| signature.anchor != replaced);
            assert_eq!(
                expected.len() + 1,
                shipped.len(),
                "the `{name}` control says it replaces the reading anchored at {replaced}, and the \
                 shipped fixture has {} readings there",
                shipped.len() - expected.len()
            );
        }
        None => assert!(
            block["control"]["expected_outcomes"]
                .as_array()
                .is_none_or(Vec::is_empty),
            "the `{name}` control adds a reading without saying which one it replaces"
        ),
    }

    let unchanged = block["control"]["unchanged"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("the `{name}` control declares no `unchanged` list"));
    let mut declared: Vec<String> = unchanged
        .iter()
        .map(|path| {
            path.as_str()
                .unwrap_or_else(|| panic!("the `{name}` control's `unchanged` list holds {path}"))
                .to_owned()
        })
        .collect();
    declared.sort();
    let mut derived: Vec<String> = shipped
        .iter()
        .map(|signature| signature.anchor.clone())
        .collect();
    derived.retain(|anchor| Some(anchor.as_str()) != block["control"]["replaces"].as_str());
    derived.sort();
    assert_eq!(
        declared, derived,
        "the `{name}` control's `unchanged` list is not the shipped readings minus the one it \
         replaces"
    );

    for outcome in block["control"]["expected_outcomes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        expected.push(Signature {
            surface: string(&outcome, "surface"),
            title: string(&outcome, "title"),
            // Parsed rather than copied, so a control that asked for a level
            // SURE does not have fails here instead of comparing two strings
            // that were never going to be equal anyway.
            severity: severity_of(&string(&outcome, "required_severity"))
                .as_str()
                .to_owned(),
            anchor: string(&outcome, "anchor"),
        });
    }
    expected.sort();
    expected
}

// --- the corpus, measured -------------------------------------------------

#[test]
fn every_benign_file_the_corpus_names_is_read_and_answers_note() {
    let shipped = fixture();
    let found = readings(&shipped);
    let declared = outcomes_of_kind("finding");

    assert!(
        !declared.is_empty(),
        "the corpus declares no finding at all, so this test grades nothing"
    );
    // The direction that catches an unmeasured file: the two sets have the same
    // size, so a detector that fired on something the corpus does not declare is
    // a failing test rather than an extra line nobody reads.
    assert_eq!(
        found.len(),
        declared.len(),
        "the corpus declares {} findings and the five detectors produced {}:\n  {found:#?}",
        declared.len(),
        found.len()
    );

    for outcome in &declared {
        let surface = string(outcome, "surface");
        let title = string(outcome, "title");
        let context = declared_context(outcome);
        let matching: Vec<&Reading> = found
            .iter()
            .filter(|reading| reading.surface == surface.as_str() && reading.title == title)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "the corpus declares one `{surface}` finding titled `{title}` and the detectors produced \
             {} of them:\n  {found:#?}",
            matching.len()
        );
        let reading = matching[0];

        // Where the file stands, and the detector's own title saying the same
        // thing. The two are separate assertions because the corpus's `title`
        // was copied from the measurement: without the second, a title whose
        // context word contradicted the classifier would pass.
        assert_eq!(
            classify_path(Path::new(&reading.anchor), &shipped, None),
            context,
            "{} is classified as {:?} and the corpus declares {context:?}",
            reading.anchor,
            classify_path(Path::new(&reading.anchor), &shipped, None)
        );
        assert!(
            reading.title.ends_with(phrase(context)),
            "the corpus calls {} a {context:?} file and the detector's title does not say so: `{}`",
            reading.anchor,
            reading.title
        );

        // The acceptance's own sentence, per file: read, and not a must-fix.
        assert_eq!(
            reading.severity.as_str(),
            string(outcome, "required_severity"),
            "{}: the corpus requires `{}` and SURE reaches `{}`",
            reading.anchor,
            string(outcome, "required_severity"),
            reading.severity.as_str()
        );
        assert_eq!(
            reading.severity,
            Severity::Note,
            "{} is a benign part of this project and SURE reached `{}` about it",
            reading.anchor,
            reading.severity.as_str()
        );
        // The other two things a heavier finding would carry with it. Neither is
        // set by any of the five detectors today, and both are asserted rather
        // than assumed because either one alone would make the finding reach a
        // reader as a stop.
        assert!(
            !reading.critical,
            "{}: a candidate decided a verdict",
            reading.anchor
        );
        assert_eq!(
            reading.evidence_class,
            evidence_class_of(outcome),
            "{}: the evidence class moved",
            reading.anchor
        );
        assert_eq!(
            reading.evidence_class,
            EvidenceClass::Inference,
            "{}: a candidate backed by an inference is claiming more than that",
            reading.anchor
        );
    }
}

#[test]
fn every_file_the_corpus_calls_benign_is_one_of_its_declared_findings() {
    // The corpus keeps two lists of the same five files — the `benign_files`
    // table a reader is shown and the `anchor` of each finding — and this is what
    // holds them together. A sixth benign file added to the table without a
    // detector reading it would satisfy every assertion above and would be a file
    // the corpus describes as measured when it is not.
    let block = scenario()["project"]["benign_files"]
        .as_object()
        .cloned()
        .unwrap_or_else(|| panic!("{FIXTURE}/scenario.json declares no benign_files table"));

    let mut named: Vec<String> = block.keys().cloned().collect();
    named.sort();
    let mut declared: Vec<String> = outcomes_of_kind("finding")
        .iter()
        .map(|outcome| string(outcome, "anchor"))
        .collect();
    declared.sort();
    assert_eq!(
        named, declared,
        "the files the corpus calls benign and the files its findings are anchored at are not the \
         same five"
    );

    for path in &named {
        assert!(
            fixture().join(path).is_file(),
            "the corpus calls {path} a benign file of this project, and the fixture does not ship it"
        );
        assert!(
            !block[path].as_str().unwrap_or_default().trim().is_empty(),
            "{path} is called benign with no reason given"
        );
    }
}

#[test]
fn the_aggregate_over_the_project_has_nothing_material_in_it() {
    // The manifest's row for this case is `expected_severity: "note"` and
    // `release_blocking: false`, and until this fixture existed that row was
    // answered by an assertion about a directory that was not there. What is
    // asserted here is the level the product reached; that the corpus's own
    // `expected_severity` is that level, and that it agrees with the manifest's
    // row, is `crates/sure-testkit/tests/fixture_apps.rs`'s to check.
    let discovery = discovery_at(&fixture());
    let mut proposals: Vec<CheckProposal> = Vec::new();
    proposals.extend(CandidateScanner::of(&discovery).proposed().iter().cloned());
    proposals.extend(NoOpHeuristics::of(&discovery).proposed().iter().cloned());
    proposals.extend(
        DemoDataHeuristics::of(&discovery)
            .proposed()
            .iter()
            .cloned(),
    );
    proposals.extend(RouteConsistency::of(&discovery).proposed().iter().cloned());
    proposals.extend(UiActionBridge::of(&discovery).proposals());
    assert!(
        !proposals.is_empty(),
        "the project produced nothing to aggregate"
    );

    let aggregated = aggregate(proposals);
    assert!(
        aggregated.material().is_empty(),
        "a candidate from this project is material:\n  {:#?}",
        aggregated.material()
    );
    assert_eq!(
        aggregated.style_noise().len(),
        outcomes_of_kind("finding").len(),
        "the aggregate filed {} candidates as noise and the corpus declares {} findings",
        aggregated.style_noise().len(),
        outcomes_of_kind("finding").len()
    );
    assert_eq!(aggregated.duplicates_dropped(), 0);

    let heaviest = aggregated
        .all_candidates()
        .iter()
        .map(|proposal| proposal.severity())
        .max_by_key(|severity| severity.rank());
    let declared = scenario()["expected_severity"]
        .as_str()
        .expect("the corpus declares no expected_severity")
        .to_owned();
    assert_eq!(
        heaviest.map(Severity::as_str),
        Some(declared.as_str()),
        "the corpus asks for `{declared}` and the heaviest level SURE reaches about this project \
         is `{:?}`",
        heaviest.map(Severity::as_str)
    );
}

// --- the controls ---------------------------------------------------------

#[test]
fn the_control_that_lifts_the_test_double_out_of_its_directory_still_reads_it() {
    // The control that stops the corpus's `note` from being silence. The same
    // bytes, with the conventional directory taken away and nothing else
    // changed, are still read — the proposal exists at all — and the level rises
    // to `can_fix_later`, because an unfinished marker in production code is one
    // level above a note and one below `must_fix`.
    let name = "convention_removed_from_the_directory";
    let root = controlled(name);
    let found = readings(&root);

    assert_eq!(
        signatures(&found),
        expected_after_control(name),
        "the `{name}` control did not read the project the way the corpus declares"
    );
    let moved = found
        .iter()
        .find(|reading| reading.anchor == "checkout.js")
        .unwrap_or_else(|| panic!("the lifted double was not read at all: {found:#?}"));
    assert_ne!(
        moved.severity,
        Severity::Note,
        "the same bytes outside a `tests/` directory are still a note, so the note the shipped \
         fixture reports does not come from where the file stands"
    );
    assert_eq!(moved.severity, Severity::CanFixLater);
    assert!(!moved.critical);
}

#[test]
fn the_control_that_writes_the_vocabulary_in_markdown_reaches_no_detector() {
    // The measurement behind `is_source_candidate`, and the reason the
    // documentation half of this corpus is a `.js` file inside `docs/` rather
    // than the obvious `.md` one. The control adds the corpus's own vocabulary —
    // TODO, mock, placeholder, stub — in markdown under `docs/`, and the reading
    // set does not move by one entry. A corpus that had answered `note` because
    // nothing looked would look exactly like this from the outside, which is why
    // the shipped fixture's own check is that the `.js` file *was* read.
    let name = "vocabulary_in_markdown";
    let root = controlled(name);
    assert!(
        root.join("docs/setup.md").is_file(),
        "the control did not write the markdown file it declares"
    );

    assert_eq!(
        signatures(&readings(&root)),
        expected_after_control(name),
        "markdown under `docs/` reached a detector, or something else about the project changed \
         with it"
    );
}

#[test]
fn the_control_that_takes_the_file_name_convention_away_reaches_must_fix() {
    // The control the other two cannot replace, and the reason this corpus
    // contains a `substituted action` at all: `UnfinishedMarker` is capped one
    // level below `must_fix` by the gravity rule whatever the path says, so a
    // corpus of TODOs and mock words satisfies `do not become must-fix` without
    // the context gate ever being asked. Here the same bytes keep the same
    // placeholder address and lose the file-name segment that marked them as a
    // hand-written double, and the answer is `must_fix`.
    let name = "convention_removed_from_the_file_name";
    let root = controlled(name);
    let found = readings(&root);

    // The copy displaces the project's real client, because two files cannot
    // both be called `src/gateway.js`. That is declared and checked above, and
    // what makes it not a second variable is measured here: the file it
    // displaces produced no reading at all in the shipped fixture, so replacing
    // it cannot have removed one.
    let shipped = readings(&fixture());
    assert!(
        !shipped
            .iter()
            .any(|reading| reading.anchor == "src/gateway.js"),
        "the shipped fixture now has a reading anchored at the real client, so this control \
         displaces one reading with another and measures two things: {shipped:#?}"
    );

    assert_eq!(
        signatures(&found),
        expected_after_control(name),
        "the `{name}` control did not read the project the way the corpus declares"
    );
    let double = found
        .iter()
        .find(|reading| reading.anchor == "src/gateway.js")
        .unwrap_or_else(|| panic!("the renamed double was not read at all: {found:#?}"));
    assert_eq!(
        double.title,
        "project contains fake email addresses or domains in production code"
    );
    assert_eq!(
        double.severity,
        Severity::MustFix,
        "the same address outside a `*.mock.js` file is no longer `must_fix`, so the note the \
         shipped fixture reports is not coming from the file-name convention"
    );
    assert!(
        double.severity.blocks_hand_off(),
        "`must_fix` is the level that stops a hand-off, and the corpus says so about this control"
    );
    assert!(!double.critical);
    assert_eq!(double.evidence_class, EvidenceClass::Inference);
}

#[test]
fn every_control_this_corpus_declares_is_one_this_file_drives() {
    // The guard every list in this tree has, for the reason the other lists
    // have it: a control declared in the corpus and driven by nothing is a
    // claim nobody measured, and the three tests above would go on passing
    // while the fourth control's `why` read as though it had been checked.
    let mut named: Vec<String> = outcomes_of_kind("control")
        .iter()
        .map(|outcome| {
            outcome["control"]["name"]
                .as_str()
                .unwrap_or_else(|| panic!("a control declares no name: {outcome}"))
                .to_owned()
        })
        .collect();
    named.sort();

    let mut driven = [
        "convention_removed_from_the_directory",
        "vocabulary_in_markdown",
        "convention_removed_from_the_file_name",
    ]
    .map(str::to_owned)
    .to_vec();
    driven.sort();
    assert_eq!(
        named, driven,
        "the corpus declares controls this file does not drive, or drives one it does not declare"
    );
}
