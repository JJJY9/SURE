#![forbid(unsafe_code)]
//! SURE check engine.
//!
//! This crate will hold the discovery, planning, checking and reporting engine.
//! It currently re-exports the frozen domain vocabulary so that callers have a
//! single import path, and so that the crate boundary is exercised from the
//! first commit rather than introduced later.

pub mod acceptance_report;
pub mod aggregation;
pub mod allowance;
pub mod analysis_provider;
pub mod approval;
pub mod browser;
pub mod browser_driver;
pub mod candidate_context;
pub mod candidate_scanner;
pub mod capability_report;
pub mod checks;
pub mod claim_capture;
pub mod claim_checker;
pub mod claim_report;
pub mod components;
pub mod config;
pub mod consent;
pub mod container;
pub mod core_flow;
pub mod coverage_summary;
pub mod db_migrations;
pub mod demo_data_heuristics;
pub mod dependency_state;
pub mod diagnostics;
pub mod discover;
pub mod doctor;
pub mod documents;
pub mod enforce;
pub mod env_completeness;
pub mod external_service;
pub mod false_completion_aggregator;
pub mod finding_gravity;
pub mod findings_from_checks;
pub mod fingerprint;
pub mod full_recording;
pub mod harness_event;
pub mod hook_protection;
pub mod http_routes;
pub mod intent_capture;
pub mod intent_implementation;
pub mod intent_model;
pub mod noop_heuristics;
pub mod normalizer;
pub mod package_launcher;
pub mod paths;
pub mod pipeline;
pub mod plain_language_finding;
pub mod planned_check_runner;
pub mod planned_work;
pub mod privacy;
pub mod probe;
pub mod process;
pub mod project_intent;
pub mod project_verdict;
pub mod protection_history;
pub mod recheck_lifecycle;
pub mod recording_projection;
pub mod redact;
pub mod references;
pub mod release_gate;
pub mod repair_impact;
pub mod route_consistency;
pub mod runtime_probes;
pub mod runtime_start;
pub mod safety;
pub mod scan;
pub mod schedule;
pub mod semantic_contract;
pub mod service;
pub mod service_plan;
pub mod session_event_store;
pub mod setup;
pub mod store;
pub mod support;
pub mod ui_action_bridge;

pub use sure_domain::{
    PRODUCT_EXPANSION, PRODUCT_NAME, PRODUCT_PROMISE, capability, evidence, execution, finding,
    ids, intent, severity, status, vocabulary,
};

/// The integration protocol version this core build speaks.
///
/// Re-exported rather than restated, so a core that has not been taught a newer
/// protocol cannot claim to speak it. Declaring it here is what makes the
/// `sure-core -> sure-protocol` boundary a real edge rather than a manifest
/// line; [`negotiate`] is the rule that uses it.
pub const PROTOCOL_VERSION: u32 = sure_protocol::PROTOCOL_VERSION;

/// The product name.
pub const NAME: &str = PRODUCT_NAME;

/// The product promise shown to users.
pub const PROMISE: &str = PRODUCT_PROMISE;

/// The version rule, re-exported from the crate that owns the wire contract.
///
/// The CLI answers a caller that asks whether the two can talk, and the event
/// reader refuses a document in a version this build does not speak. They are
/// the same rule, so they are the same function rather than two comparisons that
/// happen to agree today. Re-exported rather than reached directly because
/// `sure-cli` has one edge into the engine, not two (ADR 0001, and the note in
/// its manifest).
pub use sure_protocol::handshake::{Handshake, negotiate};

/// The version number of this build, without the product name.
///
/// Re-exported so that a report naming the build and a `sure version` naming it
/// cannot disagree: `sure_core::VERSION` is the same constant
/// [`version_string`] is built from, not a second copy of it.
pub const VERSION: &str = sure_domain::VERSION;

/// The version string reported by the CLI.
#[must_use]
pub fn version_string() -> String {
    sure_domain::version_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_core_reexports_the_frozen_vocabulary() {
        assert_eq!(NAME, "SURE");
        assert_eq!(PROMISE, "AI says it's done. Be SURE.");
        assert_eq!(
            status::NO_TRUSTED_INTENT_LIMITATION,
            sure_domain::status::NO_TRUSTED_INTENT_LIMITATION,
            "the re-export must be the same constant, not a copy that can drift"
        );
        assert!(status::NO_TRUSTED_INTENT_LIMITATION.contains("cannot confirm"));
    }

    #[test]
    fn a_critical_skipped_check_cannot_aggregate_to_green_through_the_core_reexport() {
        let result = status::CheckResult::not_run(
            ids::CheckId::generate(),
            "run the test suite",
            severity::Severity::MustFix,
            true,
            status::NotCheckedReason::ExecutionNotAuthorized,
            ids::FingerprintId::generate(),
        );
        assert!(!status::aggregate(&[result]).is_green());
    }
}
