//! A person's recorded acceptance changes the verdict, and stops applying when
//! the evidence changes (ADR 0019).
//!
//! # What this file holds
//!
//! The pipeline over a real fixture, not the pieces: a Node project whose only
//! source file contains one `status: 200,` a scanner infers a candidate from.
//! Nothing can settle that candidate, so the run is `needs_attention` — the
//! state the feature exists for. Then the acceptance is recorded in the store,
//! and the same run reads `green` with a headline that says a finding was
//! accepted to get there. Then the evidence moves, and the finding comes back.
//!
//! # What is not claimed
//!
//! Not that the candidate is a good candidate — the detectors are tested in
//! `adversarial_fixture_detection.rs` and `benign_fixture_e2e.rs`. What is
//! measured here is what a recorded decision does to the same run.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use sure_core::acknowledgement::{AcknowledgementIndex, acknowledge};
use sure_core::config::{Config, ExecutionSettings};
use sure_core::pipeline::{Pipeline, Purpose, RunOutcome};
use sure_core::planned_check_runner::ProcessRunner;
use sure_core::process::Cancellation;
use sure_core::recheck_lifecycle::case_rule_for;
use sure_core::store::Store;
use sure_domain::finding::FindingStatus;
use sure_domain::status::AggregateSeverity;

/// A project SURE does not recognise as a stack, so the plan holds only what
/// the scanners propose — no build/test/lint/typecheck declarations that would
/// each be a skipped row in an inspecting run — and one source line the no-op
/// heuristics match.
fn fixture() -> PathBuf {
    let root = sure_testkit::scratch::directory("acknowledged-findings", "bridge");
    std::fs::create_dir_all(root.join("src")).expect("src exists");
    std::fs::write(root.join("src").join("bridge.js"), BRIDGE).expect("the source is written");
    root
}

/// The success path of an OpenAI-compatible bridge — the shape the adversarial
/// corpus requires the hard-coded-success detector to report, and the same shape
/// a real bridge legitimately contains.
const BRIDGE: &str = "function respond(body) {\n  return {\n    status: 200,\n    body,\n  };\n}\n";

/// The same file with one comment line above the match, so the finding's
/// locator — which names the line number — changes and the acceptance no
/// longer applies.
const BRIDGE_MOVED: &str = "// one example of the success path\nfunction respond(body) {\n  return {\n    status: 200,\n    body,\n  };\n}\n";

fn store_in(name: &str) -> Store {
    let dir = sure_testkit::scratch::directory("acknowledged-findings", name);
    Store::open_at(&dir.join("store.db")).expect("the store opens")
}

/// `sure check` over the fixture, under a store that may hold acceptances.
fn check(root: &Path, store: Option<&Store>) -> RunOutcome {
    let config = Config::default();
    let stop = Cancellation::new();
    stop.cancel();
    let runner = ProcessRunner::new(stop);
    Pipeline {
        project: root,
        purpose: Purpose::Check,
        config: &config,
        execution: ExecutionSettings::inspect_only(),
        store,
        goal: None,
        analysis: Default::default(),
        external_commands: &[],
        runner: &runner,
    }
    .run()
    .run
    .expect("the pipeline finished without a run outcome")
}

fn the_candidate(run: &RunOutcome) -> &sure_domain::finding::Finding {
    let candidates: Vec<_> = run
        .verdict
        .findings
        .iter()
        .filter(|finding| finding.title.contains("hard-coded success"))
        .collect();
    assert_eq!(
        candidates.len(),
        1,
        "the fixture did not produce exactly one candidate: {:?}",
        run.verdict
            .findings
            .iter()
            .map(|finding| (&finding.title, finding.status))
            .collect::<Vec<_>>()
    );
    candidates[0]
}

#[test]
fn an_accepted_candidate_turns_the_run_green_and_comes_back_when_the_evidence_moves() {
    let root = fixture();
    let store = store_in("verdict");

    // 1. The candidate run: present, unsettled, and not green.
    let before = check(&root, Some(&store));
    let candidate = the_candidate(&before);
    assert_eq!(candidate.status, FindingStatus::CannotConfirm);
    assert!(
        candidate.can_be_acknowledged(),
        "a candidate is the kind of finding an acceptance exists for"
    );
    assert_eq!(
        before.verdict.aggregate.severity,
        AggregateSeverity::NeedsAttention
    );

    // 2. The person reviews it and records the decision.
    let root_text = root.to_string_lossy().into_owned();
    acknowledge(
        &store,
        &root_text,
        &before.verdict.fingerprint,
        candidate,
        "a real HTTP 200 in an API handler",
        case_rule_for(&root_text),
    )
    .expect("the acceptance is recorded");

    // 3. The same run, now with the decision on record.
    let after = check(&root, Some(&store));
    let accepted = the_candidate(&after);
    assert_eq!(accepted.status, FindingStatus::AcceptedRisk);
    assert!(
        !accepted.status.needs_attention(),
        "an accepted finding is not unresolved"
    );
    assert_eq!(
        accepted.severity, candidate.severity,
        "severity is untouched"
    );
    assert_eq!(
        after.verdict.aggregate.severity,
        AggregateSeverity::Green,
        "the only non-green contribution was the accepted warning: {:?}",
        after
            .verdict
            .findings
            .iter()
            .map(|finding| (&finding.title, finding.status))
            .collect::<Vec<_>>()
    );
    assert!(
        after
            .verdict
            .aggregate
            .headline
            .contains("1 finding you reviewed and accepted"),
        "a green run because of an acceptance must say so: {}",
        after.verdict.aggregate.headline
    );
    assert!(
        after
            .verdict
            .findings
            .iter()
            .any(|finding| { finding.status == FindingStatus::AcceptedRisk })
    );

    // 4. The evidence moves — one line above the match — and the decision no
    //    longer applies: the same identity is what the record was made about.
    std::fs::write(root.join("src").join("bridge.js"), BRIDGE_MOVED)
        .expect("the source is rewritten");
    let moved = check(&root, Some(&store));
    let back = the_candidate(&moved);
    assert_eq!(
        back.status,
        FindingStatus::CannotConfirm,
        "an acceptance must not outlive the evidence it was made about"
    );
    assert_eq!(
        moved.verdict.aggregate.severity,
        AggregateSeverity::NeedsAttention
    );

    // 5. The stale record is still on the list, which is what lets a person see
    //    what they once accepted.
    let records = AcknowledgementIndex::load(&store, &root_text).expect("the store reads");
    assert!(!records.is_empty());
}
