//! Select the checks that should be re-run after a repair.
//!
//! The repair contract already carries a `recheck` list from the finding that
//! generated it. This module adds two things to that list:
//!
//! 1. **Affected checks** whose own anchor overlaps an evidence anchor from the
//!    contract, because a fix that touches a location should re-verify any check
//!    that is about that location.
//! 2. **Relevant regression checks** — deterministic checks that run project code
//!    and are serious enough that a side-effect of the fix would matter — because
//!    a repair that only re-runs the original check can hide breakage elsewhere.
//!
//! The result is de-duplicated and kept in schedule order, so the re-check plan
//! is stable and readable.
//!
//! # The circularity, and the seed that breaks it
//!
//! [`select_impacted_checks`] takes a [`RepairContract`], and
//! `RepairContract::from_finding` refuses an empty re-check list — so the
//! selector cannot be called before the constructor that needs its answer. The
//! way out is not to loosen either: it is [`seed_rechecks`], which reads a
//! [`Finding`] alone and returns the checks that finding already names.
//!
//! **The seed is a subset of what [`select_impacted_checks`] returns, and that is
//! why it is not a second rule.** The selector's first act is to copy the
//! contract's own `recheck` list into its answer; the contract's `recheck` list is
//! the seed. So every check the seed names is in the selection by construction,
//! and the seed can only ever be the smaller of the two. What the seed must not
//! do — and does not — is decide anything the selector decides: it adds no
//! anchored check, no regression check, and no check the finding did not name.

use sure_domain::evidence::{EvidenceAnchor, EvidenceClass};
use sure_domain::finding::Finding;
use sure_domain::ids::{AnyId, CheckId, IdKind};
use sure_domain::severity::Severity;
use sure_domain::vocabulary::RepairContract;

use crate::schedule::{CheckSchedule, ScheduledCheck};

/// The checks a finding names as able to observe whether it is fixed, without
/// asking any schedule.
///
/// This is [`seed_rechecks`] before its filter: every evidence anchor on the
/// finding whose `subject_id` is a check, in the order the anchors appear, with
/// no regard for whether the current run plans them.
///
/// # Why a caller would want this rather than [`seed_rechecks`]
///
/// A **re-check** reads this list to reconstruct the contract an earlier repair
/// run wrote for a finding this run no longer produces. The earlier contract's
/// checks may have left the schedule — for a candidate-driven check that is
/// exactly what the subject's disappearance means, and it is the one absence
/// that resolves a finding rather than keeping it open. [`seed_rechecks`]'s
/// filter exists for the *other* direction: a seed is about to be handed to
/// `RepairContract::from_finding` for a contract written from this very run, and
/// naming a check this run did not plan would make an acceptance test nobody can
/// run. The reconstruction is not writing a new acceptance test; it is re-asking
/// an earlier one, and the selector widens it against the current plan the same
/// way it widens every contract's.
#[must_use]
pub fn named_checks(finding: &Finding) -> Vec<CheckId> {
    let mut named: Vec<CheckId> = Vec::new();
    for evidence in &finding.evidence {
        let Some(id) = check_id_in(&evidence.anchor) else {
            continue;
        };
        if !named.contains(&id) {
            named.push(id);
        }
    }
    named
}

/// The checks a finding names as able to observe whether it is fixed.
///
/// # What it reads
///
/// Every evidence anchor on the finding whose `subject_id` is a check, in the
/// order the anchors appear. A finding built by
/// [`crate::findings_from_checks`] carries exactly one, and it is the check whose
/// result produced the finding — the check that was failing, or the check that
/// was planned and did not run.
///
/// This is the seed `crates/sure-core/tests/repair_fixture_e2e.rs` used to name
/// by hand before the rule had a home; that file now calls this function like
/// every other caller, so there is one answer to *which check can observe whether
/// this is fixed* rather than a product answer and a test answer that agree today.
///
/// # What it refuses
///
/// An anchor whose text names no check is not a seed, and neither is one whose
/// identifier is not a [`CheckId`] — a finding that names no check gets an empty
/// list, and an empty list is what `RepairContract::from_finding` refuses. That
/// refusal is the point: a one-check contract naming a check nobody can run
/// (`RepairContract::from_finding_with_one_check` with a generated identifier) is
/// a contract that satisfies the letter of the rule and is unactionable, and this
/// function cannot produce one.
///
/// # `schedule`
///
/// The identifiers are filtered to checks the run's own schedule holds, so a seed
/// is always something a re-check could actually re-run. An identifier that is
/// absent from the schedule is dropped rather than returned: the selector keeps
/// contract identifiers the schedule has lost, because a contract outlives the
/// schedule it was built from, but a *seed* built here is being built for a
/// contract that is about to be made from this very run, and a check this run did
/// not plan is a check this run cannot re-check.
#[must_use]
pub fn seed_rechecks(finding: &Finding, schedule: &CheckSchedule) -> Vec<CheckId> {
    named_checks(finding)
        .into_iter()
        .filter(|id| schedule.get(id).is_some())
        .collect()
}

/// The check an anchor points at, when it points at one.
fn check_id_in(anchor: &EvidenceAnchor) -> Option<CheckId> {
    let subject: &AnyId = anchor.subject_id.as_ref()?;
    if subject.kind() != IdKind::Check {
        return None;
    }
    CheckId::parse(subject.as_str()).ok()
}

/// Select the checks to re-run for `contract` from `schedule`.
///
/// The returned identifiers are in the order they appear in the schedule, with
/// no duplicates. The contract's own `recheck` list is always included first,
/// followed by affected and regression checks discovered from the schedule.
/// Identifiers that are present in the contract but missing from the schedule
/// are still returned, because the contract may outlive the schedule it was
/// built from.
#[must_use]
pub fn select_impacted_checks(contract: &RepairContract, schedule: &CheckSchedule) -> Vec<CheckId> {
    let mut selected: Vec<CheckId> = Vec::new();

    // The finding that generated the contract already named the checks that can
    // observe whether the fix worked.
    for id in &contract.recheck {
        selected.push(id.clone());
    }

    let contract_locations = contract_anchor_locations(contract);

    for scheduled in schedule.checks() {
        let id = scheduled.proposal().id().clone();
        if selected.contains(&id) {
            continue;
        }
        if is_affected(scheduled, &contract_locations) {
            selected.push(id);
            continue;
        }
        if is_relevant_regression(scheduled) {
            selected.push(id);
        }
    }

    selected
}

/// Every non-empty text fragment in the contract's evidence anchors that can be
/// matched against a check reason.
fn contract_anchor_locations(contract: &RepairContract) -> Vec<String> {
    let mut locations: Vec<String> = Vec::new();
    for evidence in &contract.evidence {
        push_location(&mut locations, &evidence.anchor);
    }
    locations
}

fn push_location(locations: &mut Vec<String>, anchor: &EvidenceAnchor) {
    if !anchor.location.trim().is_empty() {
        locations.push(anchor.location.clone());
    }
    if !anchor.locator.trim().is_empty() {
        locations.push(anchor.locator.clone());
    }
}

/// Whether the scheduled check's reason points at a location the contract's
/// evidence also points at.
fn is_affected(scheduled: &ScheduledCheck, contract_locations: &[String]) -> bool {
    let Some(check_anchor) = scheduled.proposal().reason().anchor() else {
        return false;
    };
    let check_locations = [&check_anchor.location, &check_anchor.locator];
    for contract_location in contract_locations {
        for check_location in check_locations {
            if overlaps(contract_location, check_location) {
                return true;
            }
        }
    }
    false
}

/// Two strings overlap when one contains the other, case-insensitively on
/// Windows where file paths are case-insensitive and case-sensitively
/// elsewhere. The goal is to catch `src/email/send.rs` matching
/// `src/email/send.rs:42` without requiring exact equality.
fn overlaps(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    if left.is_empty() || right.is_empty() {
        return false;
    }
    #[cfg(windows)]
    {
        let left = left.to_lowercase();
        let right = right.to_lowercase();
        left.contains(&right) || right.contains(&left)
    }
    #[cfg(not(windows))]
    {
        left.contains(right) || right.contains(left)
    }
}

/// Whether a check is a serious enough deterministic regression test that it
/// should run after a code change even when its anchor does not overlap the
/// repair location.
fn is_relevant_regression(scheduled: &ScheduledCheck) -> bool {
    let proposal = scheduled.proposal();
    // Only checks that actually exercise project code can catch side effects of
    // a code change. Static inspection checks are already cheap to run, but they
    // are not the regression suite this rule is about.
    if !proposal.requirements().runs_project_code() {
        return false;
    }
    if proposal.evidence_class() != EvidenceClass::DeterministicCheck {
        return false;
    }
    // "Relevant" means serious enough that a regression would matter: must-fix
    // or should-fix-first. Note checks are deliberately excluded because they
    // are not release-blocking.
    matches!(
        proposal.severity(),
        Severity::MustFix | Severity::ShouldFixFirst
    )
}
