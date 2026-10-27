//! What SURE was told to check against, and which channel the words arrived on.
//!
//! # The one channel the checked project cannot write
//!
//! A project's README, its `sure.yaml`, its task list: every one of them is a
//! file inside the project, and the project is written by the same agent whose
//! work is being judged. A goal found in any of them is therefore
//! [`IntentSource::ProjectSpec`] — documentation — and
//! [`Config::goal_source`](crate::config::Config::goal_source) is the one place
//! that says so, in one line, for every caller.
//!
//! The command line is the other channel. `sure check --goal "…"` is words the
//! operator handed to SURE directly. They are
//! [`IntentSource::ExplicitUserGoal`], and that is one of only two sources
//! [`IntentSource::is_user_requirement`] accepts — which is the whole difference
//! between a project SURE may compare against what was asked for and a project
//! SURE may only describe. This module is where those words become a
//! [`Requirement`].
//!
//! # What "explicit" claims, and what it does not
//!
//! It claims **where the words entered SURE**: an argument to this program, not
//! a file inside the directory being checked. It does not claim that a person
//! typed them. SURE cannot authenticate the operator of its own command line,
//! and an agent that runs `sure check --goal "…"` supplies a goal exactly as a
//! person would. The label is a fact about the channel, and
//! `docs/architecture/PROJECT_INTENT.md` records the limit rather than letting
//! the word "explicit" imply a guarantee this module cannot make.
//!
//! # Why recording a goal is not full recording
//!
//! [`IntentSource::requires_full_recording`] is true of exactly one source,
//! [`IntentSource::ObservedUserRequest`], because that one is material captured
//! from a harness session — a transcript, kept only under the opt-in
//! `docs/security/PRIVACY.md` describes. A goal typed to SURE is not captured
//! material: there is no session and no transcript, and nothing is kept that the
//! user did not just hand over in the same breath. So the requirement is written
//! with [`raw_retained`](Requirement::raw_retained) set and no opt-in is
//! consulted, which is the second half of what this module exists for.
//!
//! # The wording is kept, and not tidied
//!
//! [`Requirement::text`] is documented as "normalized to one sentence where
//! possible", and a goal supplied on the command line is deliberately not
//! normalized at all: it is stored exactly as it arrived, minus nothing. SURE
//! rewording what the user asked for is the overclaim
//! `MASTER_PROMPT.md` §3 forbids, and a summary that dropped a clause would be
//! a requirement the user never stated. That is why
//! [`raw_retained`](Requirement::raw_retained) is set here rather than left
//! false: it is not a summary, and the flag says so.
//!
//! # Why one row per requirement
//!
//! `schemas/project-intent.schema.json` describes a single requirement, not the
//! container around it — `sure_protocol::documents` records why, and the short
//! version is that the container has no source of its own, being the union of
//! its requirements' sources. Storing an intent is therefore storing each of its
//! requirements, and a reader that wants the container back reassembles it.

use std::fmt;

use sure_domain::ids::FingerprintId;
use sure_domain::intent::{IntentSource, ProjectIntent, Requirement};
use sure_protocol::documents::DocumentKind;

use crate::store::{RecordKind, Store, StoreError};

/// The identifier SURE gives the goal supplied on the command line.
///
/// Fixed rather than generated, because within one project there is one goal the
/// user stated and a reader comparing today's goal with last week's has to be
/// able to find both. A fresh identifier per invocation would make every
/// statement a new requirement, and "did the user change what they asked for?"
/// would become an identity-matching problem instead of a comparison of two
/// strings.
///
/// A constant rather than a literal so that a test reading a stored goal back
/// knows what to look for without restating the string, and so that a change to
/// it is a change in one place.
pub const EXPLICIT_GOAL_ID: &str = "goal";

/// Why a statement SURE was given is not a requirement SURE will record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentError {
    /// The goal was empty, or nothing but whitespace.
    ///
    /// A requirement with no words in it is not a requirement. Storing one would
    /// put a blank row in the history that reads as something the user asked for
    /// and gives a later report nothing to compare against.
    EmptyGoal,
}

impl fmt::Display for IntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGoal => f.write_str(
                "SURE was given a goal with no words in it, so nothing was recorded. \
                 A goal is what the project is checked against, and an empty one would \
                 become a requirement no report could state.",
            ),
        }
    }
}

impl std::error::Error for IntentError {}

/// Why an intent could not be written to the store.
///
/// Two variants rather than one because the two failures have different
/// remedies: one is a bug in how a requirement becomes a document, and the other
/// is the store saying no — contention, a schema violation, a file that is not
/// there any more.
#[derive(Debug, Clone, PartialEq)]
pub enum RecordError {
    /// A requirement could not be turned into a JSON document.
    ///
    /// Unreachable for the fields [`Requirement`] has today, which are a string,
    /// an enum, a boolean and a list of identifiers. It is not written as an
    /// `expect` because `Requirement` is a wire type: a later version may add a
    /// field that does not serialize, and the answer then is to refuse to write
    /// rather than to store a requirement that silently lost part of itself.
    NotJson {
        /// What the serializer said.
        message: String,
    },
    /// The store refused the write.
    Store(StoreError),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson { message } => write!(
                f,
                "SURE could not write this goal down, so nothing was recorded. This is a \
                 fault in SURE rather than in the goal.\n\n{message}"
            ),
            Self::Store(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotJson { .. } => None,
            Self::Store(error) => Some(error),
        }
    }
}

impl From<StoreError> for RecordError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Turn a goal supplied on the command line into the requirement(s) it is.
///
/// A goal written on one line is one requirement and keeps the exact text it
/// arrived with. A goal written on several non-empty lines is several
/// requirements, one per line: otherwise a goal whose first clause is
/// implemented and whose second is not is matched as a whole, and the missing
/// half never reaches the report. The first line keeps [`EXPLICIT_GOAL_ID`];
/// the rest are `goal-2`, `goal-3`, ... so a report can name one line without
/// colliding with another.
///
/// The emptiness test trims, because `--goal "   "` is a goal with no words in
/// it however it was spelled; a single-line value is stored without trimming,
/// because trimming is already an edit. Multi-line values are stored per line,
/// trimmed of surrounding whitespace.
///
/// # Errors
///
/// [`IntentError::EmptyGoal`] if the goal has no words in it.
pub fn explicit_goal(goal: &str) -> Result<ProjectIntent, IntentError> {
    if goal.trim().is_empty() {
        return Err(IntentError::EmptyGoal);
    }
    let lines: Vec<&str> = goal
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() <= 1 {
        return Ok(ProjectIntent::from_requirements(vec![
            Requirement::new(EXPLICIT_GOAL_ID, goal, IntentSource::ExplicitUserGoal)
                .with_raw_retained(true),
        ]));
    }
    let requirements = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let id = if index == 0 {
                EXPLICIT_GOAL_ID.to_owned()
            } else {
                format!("{EXPLICIT_GOAL_ID}-{}", index + 1)
            };
            Requirement::new(id, *line, IntentSource::ExplicitUserGoal).with_raw_retained(true)
        })
        .collect();
    Ok(ProjectIntent::from_requirements(requirements))
}

/// Write every requirement in an intent to the store, against one project state.
///
/// The fingerprint is the project state the goal was stated against. It is not a
/// claim that the goal stops applying when the project changes — a goal is not a
/// statement about the code, and `docs/architecture/PROJECT_INTENT.md` says how a
/// reader is meant to use this. It is recorded because the store's only
/// project-aware write takes one, and because "you told SURE this when the
/// project looked like this" is a fact a report can use.
///
/// # What is not atomic
///
/// Each requirement is one row and one transaction, because the schema describes
/// one requirement. An intent with several requirements can therefore be written
/// in part if the store refuses somewhere in the middle, and the rows already
/// written stay. A multi-line explicit goal produces one requirement per line,
/// so a partial failure to write leaves the rows already written; the multi-source
/// work owned by a later task is where that has to be answered rather than here.
///
/// # Errors
///
/// [`RecordError::Store`] if the store refuses a row — including
/// [`StoreError::Rejected`] if a requirement does not match
/// `schemas/project-intent.schema.json`, which is the check that keeps a
/// requirement shaped like a requirement.
pub fn record(
    store: &Store,
    project_root: &str,
    fingerprint: &FingerprintId,
    intent: &ProjectIntent,
) -> Result<Vec<i64>, RecordError> {
    let kind = RecordKind::Document(DocumentKind::ProjectIntent);
    let mut rows = Vec::with_capacity(intent.requirements.len());
    for requirement in &intent.requirements {
        let document = serde_json::to_value(requirement).map_err(|error| RecordError::NotJson {
            message: error.to_string(),
        })?;
        rows.push(store.append_for(kind, &document, project_root, fingerprint)?);
    }
    Ok(rows)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_goal_becomes_one_requirement_the_user_owns() {
        let intent = explicit_goal("make the login form reject an empty password").unwrap();
        assert_eq!(intent.requirements.len(), 1);

        let requirement = &intent.requirements[0];
        assert_eq!(requirement.id, EXPLICIT_GOAL_ID);
        assert_eq!(
            requirement.text,
            "make the login form reject an empty password"
        );
        assert_eq!(requirement.source, IntentSource::ExplicitUserGoal);
        assert_eq!(
            requirement.authority(),
            sure_domain::intent::RequirementAuthority::UserRequirement
        );
    }

    #[test]
    fn a_multiline_goal_becomes_one_requirement_per_line() {
        let intent = explicit_goal(
            "项目提供 add 函数

让结算页支持优惠券
",
        )
        .unwrap();
        assert_eq!(intent.requirements.len(), 2);
        assert_eq!(intent.requirements[0].id, EXPLICIT_GOAL_ID);
        assert_eq!(intent.requirements[0].text, "项目提供 add 函数");
        assert_eq!(intent.requirements[1].id, "goal-2");
        assert_eq!(intent.requirements[1].text, "让结算页支持优惠券");
        assert!(
            intent
                .requirements
                .iter()
                .all(|requirement| requirement.source == IntentSource::ExplicitUserGoal)
        );
    }

    #[test]
    fn a_single_line_goal_keeps_its_exact_text() {
        let intent = explicit_goal("  keep the spaces  ").unwrap();
        assert_eq!(intent.requirements.len(), 1);
        assert_eq!(intent.requirements[0].text, "  keep the spaces  ");
    }

    #[test]
    fn the_same_goal_keeps_the_same_identifier_however_many_times_it_is_stated() {
        // The property the identifier is fixed for, and the one a per-invocation
        // identifier would break: two runs of `sure check --goal` in one project
        // are two statements of *the same* requirement, so a reader asking "did
        // the user change what they asked for?" compares two strings. Written as
        // a comparison between two independent calls rather than against the
        // constant, because a test that read the constant back would agree with
        // any identifier the constant happened to hold — including a generated
        // one, which is the mistake this is here to catch.
        let last_week = explicit_goal("stop the nightly job from double-charging").unwrap();
        let today = explicit_goal("stop the nightly job from double-charging twice").unwrap();
        assert_eq!(
            last_week.requirements[0].id, today.requirements[0].id,
            "a goal stated twice in one project became two requirements"
        );
        // And the value is the one the constant names, so that the two agree for
        // a reader that looks the requirement up by it.
        assert_eq!(today.requirements[0].id, EXPLICIT_GOAL_ID);
    }

    #[test]
    fn the_goal_is_stored_as_the_user_wrote_it() {
        // Not trimmed, not re-wrapped, not summarized. A goal that gained or lost
        // a word on the way in is a requirement the user did not state, and this
        // is the assertion that says so — including the case where the shaping is
        // as innocent as whitespace.
        //
        // The multi-sentence case is here because a mutation found the hole, not
        // because it was thought of first. `Requirement::text` is documented as
        // "normalized to one sentence where possible", so "keep the first
        // sentence" is the most plausible way to get this wrong — and every goal
        // in this test originally had no full stop in it, so cutting at the first
        // one changed nothing and the whole suite stayed green. A user writing a
        // goal writes several sentences when it takes several to say what they
        // want, which is exactly when losing the rest matters most.
        for goal in [
            "  keep the leading spaces  ",
            "quotes \"inside\" and a trailing tab\t",
            "stop the nightly job from double-charging. It runs twice when the clock \
             changes, and the second charge is not refunded.",
            "1.0 is the version. e.g. this. and that.",
        ] {
            let intent = explicit_goal(goal).unwrap();
            assert_eq!(
                intent.requirements[0].text, goal,
                "the goal was edited on the way in"
            );
        }

        // A multi-line goal is several requirements; each line is kept as the
        // user wrote it (surrounding whitespace trimmed).
        let lines = explicit_goal("line one\n  line two  ").unwrap();
        assert_eq!(lines.requirements.len(), 2);
        assert_eq!(lines.requirements[0].text, "line one");
        assert_eq!(lines.requirements[1].text, "line two");
    }

    #[test]
    fn the_goal_is_marked_as_kept_because_nothing_was_summarized() {
        // `raw_retained` false means "SURE kept a summary". For a goal supplied
        // on the command line that would be false in both senses: the words are
        // the user's own, and nothing about them was shortened.
        let intent = explicit_goal("ship it").unwrap();
        assert!(intent.requirements[0].raw_retained);
    }

    #[test]
    fn recording_a_goal_needs_no_full_recording_opt_in() {
        // The acceptance's second half, as a property of the value rather than of
        // the call site: the source this module produces is not the source that
        // requires a transcript to be kept.
        let intent = explicit_goal("make the tests pass").unwrap();
        for requirement in &intent.requirements {
            assert!(
                !requirement.source.requires_full_recording(),
                "{:?} would need the full-recording opt-in",
                requirement.source
            );
        }
    }

    #[test]
    fn a_goal_with_no_words_in_it_is_refused_rather_than_stored() {
        for goal in ["", " ", "\t", " \n ", "\r\n"] {
            assert_eq!(
                explicit_goal(goal),
                Err(IntentError::EmptyGoal),
                "{goal:?} was accepted as a goal"
            );
        }
    }

    #[test]
    fn a_goal_of_only_whitespace_is_refused_and_a_goal_with_any_word_is_not() {
        // The boundary, from both sides. The refusal above is only meaningful if
        // a word anywhere in the string is enough to get past it.
        assert!(explicit_goal("   fix   ").is_ok());
        assert!(explicit_goal("a").is_ok());
        // A non-breaking space is Unicode whitespace, so a goal made only of
        // them has no words in it either. SURE must not decide emptiness by ASCII.
        assert!(explicit_goal("  ").is_err());
        assert!(explicit_goal(" fix ").is_ok());
    }

    #[test]
    fn the_intent_this_produces_is_one_sure_may_compare_a_project_against() {
        // The consequence of the source label, read through the domain's own
        // predicate rather than restated here: this is the difference between
        // "SURE may say what you asked for" and the after-the-fact limitation.
        let intent = explicit_goal("stop the nightly job from double-charging").unwrap();
        assert!(intent.has_user_requirement());
        assert!(intent.has_explicit_user_goal());
        assert!(!intent.is_after_the_fact());
        assert_eq!(
            intent.requirement_claim(),
            sure_domain::status::RequirementClaim::Comparable
        );
    }

    /// Every variant of [`IntentError`], listed by hand.
    ///
    /// A list rather than a match, for the reason `crate::store::error::tests`
    /// gives for its own `every_error`: the claim is about *all* of them, and a
    /// test that reached the variants through the code under test would be
    /// asking the thing it is checking which cases to check.
    fn every_error() -> Vec<IntentError> {
        vec![IntentError::EmptyGoal]
    }

    #[test]
    fn every_error_says_what_sure_did_instead() {
        // The rule `crate::store::error` states for its own variants: a user who
        // reads a failure has to be able to tell what did not happen. Here that
        // is the more specific promise that a refused goal left their history
        // exactly as they left it.
        for error in every_error() {
            let text = error.to_string();
            assert!(
                text.contains("nothing was recorded") || text.contains("nothing was written"),
                "{error:?} does not say what SURE did instead: {text}"
            );
        }
    }
}
