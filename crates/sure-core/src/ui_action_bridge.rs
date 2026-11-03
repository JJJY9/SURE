//! UI-action completeness bridge.
//!
//! `P6-T006`'s acceptance:
//!
//! > *Runtime-backed UI evidence used where available; static-only result remains
//! > inference.*
//!
//! # What it does
//!
//! Scans frontend source files for declared UI action bindings (`onClick`,
//! `onSubmit`, etc.) and produces candidate checks. When runtime browser
//! observations are available, matching declared actions are upgraded from
//! [`EvidenceClass::Inference`] to [`EvidenceClass::ObservedFact`].
//!
//! # What it does not do
//!
//! It does not drive a browser — that is [`crate::browser_driver`]'s work. It
//! accepts observed elements as input and performs the matching.

use std::collections::HashSet;
use std::path::Path;

use sha2::{Digest as _, Sha256};
use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::ids::FingerprintId;
use sure_domain::status::{CheckResult, NotCheckedReason};

use crate::candidate_context::classify_path;
use crate::checks::check_id;
use crate::discover::Discovery;
use crate::finding_gravity::{GapKind, Reach, gravity_of};
use crate::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
use crate::redact::escape_control_characters;
use crate::scan::display_path;
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

/// What kind of interactive element was observed at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObservedElementKind {
    /// A clickable button.
    Button,
    /// A form with a submit action.
    Form,
    /// A link that triggers an action rather than plain navigation.
    Link,
}

/// One interactive element the browser observed on the page.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObservedElement {
    /// What kind of element was seen.
    pub kind: ObservedElementKind,
    /// Text, label, or other identifier that describes the element.
    pub label: String,
}

/// A UI action kind found in source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UiActionKind {
    Click,
    Submit,
}

impl UiActionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Click => "click",
            Self::Submit => "submit",
        }
    }
}

/// One UI action declared in frontend source.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UiAction {
    kind: UiActionKind,
    element: String,
    file: String,
    line: usize,
    context: String,
}

/// Runtime evidence of interactive UI elements, produced by a browser check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UiRuntimeEvidence {
    /// Elements the browser observed on the page.
    pub elements: Vec<ObservedElement>,
}

/// The UI-action completeness checks SURE proposes.
///
/// Built by [`Self::of`], which is the only constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiActionBridge {
    actions: Vec<UiAction>,
    evidence: UiRuntimeEvidence,
}

impl UiActionBridge {
    /// What SURE would check about UI-action completeness.
    ///
    /// One proposal per (file, kind) group of frontend UI action bindings. A
    /// project with no detectable action bindings produces nothing.
    #[must_use]
    pub fn of(discovery: &Discovery) -> Self {
        let mut actions = Vec::new();
        scan_frontend_files(discovery, &mut actions);
        Self {
            actions,
            evidence: UiRuntimeEvidence::default(),
        }
    }

    /// Incorporate runtime browser evidence.
    ///
    /// After calling this, [`Self::proposals`] will use
    /// [`EvidenceClass::ObservedFact`] for a group only when **every**
    /// declaration in it has a matching observed element; one unmatched
    /// declaration keeps the group an inference.
    #[must_use]
    pub fn with_evidence(mut self, evidence: UiRuntimeEvidence) -> Self {
        self.evidence = evidence;
        self
    }

    /// The checks SURE would run, in no particular order.
    ///
    /// **One proposal per (file, kind), not per declaration.** A single-page
    /// app binds dozens of click handlers in one component file; one proposal
    /// per binding turned one question into hundreds of rows and hundreds of
    /// separate acceptances, which is a list nobody can answer. The group keeps
    /// every declaration's context in the reason and the set's digest in the
    /// anchor, so the claim is still about exactly the declarations that were
    /// read — see [`CheckReason::UiActionsFound`](crate::schedule::CheckReason).
    #[must_use]
    pub fn proposals(&self) -> Vec<CheckProposal> {
        // Deduplicate before grouping: the same binding can be matched twice on
        // one line. The key is the one the single-proposal version used.
        let mut seen: HashSet<String> = HashSet::new();
        let mut bindings: Vec<(&UiAction, bool)> = Vec::new();
        for action in &self.actions {
            let key = format!("{}:{}:{}", action.file, action.line, action.context);
            if !seen.insert(key) {
                continue;
            }
            let observed = self
                .evidence
                .elements
                .iter()
                .any(|candidate| matches_action(action, candidate));
            bindings.push((action, observed));
        }
        // Deterministic order: group by (file, kind), then by declaration.
        bindings.sort_by(|a, b| {
            a.0.file
                .cmp(&b.0.file)
                .then_with(|| a.0.kind.as_str().cmp(b.0.kind.as_str()))
                .then_with(|| a.0.line.cmp(&b.0.line))
                .then_with(|| a.0.context.cmp(&b.0.context))
        });

        let mut proposals = Vec::new();
        let mut start = 0;
        while start < bindings.len() {
            let file = bindings[start].0.file.clone();
            let kind = bindings[start].0.kind;
            let mut end = start + 1;
            while end < bindings.len()
                && bindings[end].0.file == file
                && bindings[end].0.kind == kind
            {
                end += 1;
            }
            let group = &bindings[start..end];
            start = end;

            let first = group[0].0;
            let all_observed = group.iter().all(|(_, observed)| *observed);
            let (evidence_class, actions): (EvidenceClass, &[ActionKind]) = if all_observed {
                (
                    EvidenceClass::ObservedFact,
                    &[ActionKind::BrowserObservation],
                )
            } else {
                (EvidenceClass::Inference, &[ActionKind::ReadFile])
            };

            let title = if group.len() == 1 {
                format!(
                    "UI action: {} handler on {} in `{}`",
                    kind.as_str(),
                    escape_control_characters(&first.element),
                    escape_control_characters(&file)
                )
            } else {
                format!(
                    "UI action: {} {} handlers in `{}` that SURE has not watched",
                    group.len(),
                    kind.as_str(),
                    escape_control_characters(&file)
                )
            };

            let reason = CheckReason::UiActionsFound {
                path: file.clone(),
                kind: kind.as_str().to_owned(),
                count: group.len(),
                first_line: first.line,
                first_context: first.context.clone(),
                set_digest: set_digest(group),
            };
            // **A declared UI action SURE has no evidence about is rated
            // `must_fix`, and that is the corpus's decision rather than a
            // convenience.** `fixtures/adversarial/dead-button/scenario.json`
            // requires `must_fix` for this very proposal and says why in its own
            // words: *an inference about a primary action must stay visible
            // rather than be assumed fine*. Until `P7-T011` this module said
            // `Note` here, and the aggregator filed it as style noise, so the
            // only evidence about the fixture's dead button was invisible.
            //
            // What is claimed is narrow: a user-facing action is declared, and
            // SURE has not established what it does. That is not a statement that
            // the handler is broken — no detector here reads a handler body — and
            // it is the reason the severity does not travel with a raised
            // evidence class: the class stays `Inference` unless the browser
            // observed the element, exactly as `P6-T006`'s acceptance requires.
            //
            // **The warning does move the verdict, and the corpus's own rule is
            // why.** `status::aggregate` keeps a run out of green while any
            // warning is unaccepted, whatever `critical` says, so a healthy
            // single-page app stays `needs_attention` until a person answers the
            // question. Grouping is what makes that answer survivable: one file's
            // bindings are one decision, not hundreds. The severity is the group's
            // strongest declaration, so a primary action in the file keeps the
            // whole group `must_fix` and cannot disappear into style noise.
            // `classify_path` reads the path itself and ignores both the root and
            // the component graph, so the empty root here is the honest argument
            // rather than a placeholder that changes the answer.
            let reach = Reach::from(classify_path(Path::new(&file), Path::new(""), None));
            let gravity = gravity_of(&reason, evidence_class, reach, GapKind::SubstitutedAction);

            proposals.push(CheckProposal::new(
                check_id(&file, &format!("ui_actions_{}", kind.as_str())),
                title,
                gravity.severity(),
                false,
                evidence_class,
                reason,
                actions,
            ));
        }

        proposals.sort_by(|a, b| a.id().as_str().cmp(b.id().as_str()));
        proposals
    }

    /// Whether there is nothing to check.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Hands every proposal to a plan builder.
    ///
    /// **Each proposal is paired with the observation this bridge actually
    /// made, which is a [`StaticObservation::Candidate`] in both of its two
    /// shapes.** The static shape
    /// read a binding in a frontend file and never watched the handler; the
    /// runtime shape had a browser observe an element that matches the declared
    /// action, and still never watched what the action does — no click is
    /// performed here, and the module comment above says this bridge does not
    /// read a handler body. So neither is a `Holds`: a pass would say the action
    /// works, and the element being on the page is not that. The difference
    /// between the two shapes is the *class* on the proposal, which is
    /// `ObservedFact` when a browser saw the element and `Inference` when it did
    /// not, and that is where P6-T006's acceptance lives — not in the status.
    ///
    /// [`StaticObservation::Candidate`]: crate::planned_work::StaticObservation::Candidate
    pub fn add_to(&self, builder: &mut PlanBuilder) {
        for proposal in self.proposals() {
            let work = PlannedWork::new(proposal.clone(), observation_of(&proposal));
            if let Err(refusal) = builder.propose(work) {
                debug_assert!(
                    builder.refused().contains(&refusal),
                    "the builder returned a refusal it did not record"
                );
            }
        }
    }

    /// One skipped result per proposed check that has no runtime evidence.
    ///
    /// A UI-action check without runtime evidence cannot be confirmed as a
    /// defect from static inspection alone, so every inference proposal becomes
    /// a skipped result with [`NotCheckedReason::UnknownReason`].
    #[must_use]
    pub fn not_checked(&self, project_fingerprint: &FingerprintId) -> Vec<CheckResult> {
        self.proposals()
            .iter()
            .filter(|p| p.evidence_class() == EvidenceClass::Inference)
            .map(|proposal| {
                CheckResult::not_run(
                    proposal.id().clone(),
                    proposal.title().to_owned(),
                    proposal.severity(),
                    proposal.critical(),
                    NotCheckedReason::UnknownReason,
                    project_fingerprint.clone(),
                )
            })
            .collect()
    }
}

/// The work beside one proposal: the reading that produced it, and no more.
///
/// **The class decides which of the two sentences is true, and nothing else
/// changes.** Both are the reason's own rendering — the same sentences a report
/// prints — with what was *not* seen after it, because that is the half a
/// candidate claims.
fn observation_of(proposal: &CheckProposal) -> CheckOperation {
    let unsettled = if proposal.evidence_class() == EvidenceClass::ObservedFact {
        "a browser saw a matching element on the page; what the action does when \
         somebody uses it was not watched"
    } else {
        "the binding was read in the source; the handler was never watched, and \
         nothing here says what it does"
    };
    CheckOperation::Precomputed(PrecomputedEvidence::candidate(format!(
        "{} Nothing has settled it: {unsettled}.",
        proposal.reason().plain_description()
    )))
}

/// A digest of one group's declarations, line numbers excluded.
///
/// The group's anchor names this digest, and the anchor is the acceptance
/// identity (ADR 0019): adding, removing or replacing a declaration changes the
/// digest and brings the question back, while moving the same declarations
/// around the file does not. Sorted so the order the scan met the lines in
/// cannot change the digest.
fn set_digest(group: &[(&UiAction, bool)]) -> String {
    let mut lines: Vec<String> = group
        .iter()
        .map(|(action, _)| {
            format!(
                "{}\t{}\t{}",
                action.kind.as_str(),
                action.element,
                action.context
            )
        })
        .collect();
    lines.sort_unstable();
    let mut hasher = Sha256::new();
    for line in &lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether an observed element matches a declared UI action.
fn matches_action(action: &UiAction, observed: &ObservedElement) -> bool {
    let kind_matches = matches!(
        (action.kind, observed.kind.clone()),
        (UiActionKind::Click, ObservedElementKind::Button)
            | (UiActionKind::Click, ObservedElementKind::Link)
            | (UiActionKind::Submit, ObservedElementKind::Form)
    );

    if !kind_matches {
        return false;
    }

    // Fuzzy match: the observed label appears in the source context.
    let context_lower = action.context.to_lowercase();
    let label_lower = observed.label.to_lowercase();
    context_lower.contains(&label_lower)
}

/// Scan source files for UI action bindings.
fn scan_frontend_files(discovery: &Discovery, actions: &mut Vec<UiAction>) {
    let mut candidates: Vec<&Path> = discovery
        .scan
        .files()
        .map(|entry| entry.path.as_path())
        .filter(|path| is_frontend_source(path))
        .collect();
    candidates.sort_unstable();

    let mut files_read = 0_usize;
    let mut bytes_read = 0_u64;

    for path in candidates {
        if files_read >= 512 || bytes_read > 16 * 1024 * 1024 {
            break;
        }

        let full = discovery.root.join(path);
        if !is_within_project(&discovery.root, &full) {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(&full) else {
            continue;
        };
        if metadata.len() > 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&full) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };

        files_read += 1;
        bytes_read = bytes_read.saturating_add(metadata.len());

        let file = display_path(path);
        let open_tags = open_tag_by_line(&text);
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            let open_tag = open_tags.get(index).and_then(|tag| tag.clone());
            for (kind, element) in actions_on_line(line) {
                let element = element
                    .or_else(|| open_tag.clone())
                    .unwrap_or_else(|| default_element(kind).to_owned());
                let context = escape_control_characters(line.trim());
                actions.push(UiAction {
                    kind,
                    element,
                    file: file.clone(),
                    line: line_number,
                    context,
                });
            }
        }
    }
}

/// Whether a file is a frontend source file this module reads.
fn is_frontend_source(path: &Path) -> bool {
    let extension = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    matches!(
        extension.as_deref(),
        Some("js" | "jsx" | "ts" | "tsx" | "vue" | "svelte" | "mjs" | "cjs" | "mts" | "cts")
    )
}

/// Every UI action binding on one line.
fn actions_on_line(line: &str) -> Vec<(UiActionKind, Option<String>)> {
    let mut found = Vec::new();

    // onClick= or onClick: (React/JSX/Vue bindings)
    for pattern in ["onClick=", "onClick:"] {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find(pattern) {
            let before = &line[..search_from + start];
            let element = tag_name_before(before);
            found.push((UiActionKind::Click, element));
            search_from += start + pattern.len();
        }
    }
    // Vue @click with optional modifiers (@click.prevent, @click.stop, etc.)
    {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find("@click") {
            let end = search_from + start + "@click".len();
            let next = line[end..].chars().next();
            if next == Some('=') || next == Some('.') || next == Some(' ') || next == Some('\t') {
                let before = &line[..search_from + start];
                let element = tag_name_before(before);
                found.push((UiActionKind::Click, element));
            }
            search_from = end + 1;
        }
    }

    // onSubmit= or onSubmit: (React/JSX/Vue bindings)
    for pattern in ["onSubmit=", "onSubmit:"] {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find(pattern) {
            let before = &line[..search_from + start];
            let element = tag_name_before(before);
            found.push((UiActionKind::Submit, element));
            search_from += start + pattern.len();
        }
    }
    // Vue @submit with optional modifiers (@submit.prevent, etc.)
    {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find("@submit") {
            let end = search_from + start + "@submit".len();
            let next = line[end..].chars().next();
            if next == Some('=') || next == Some('.') || next == Some(' ') || next == Some('\t') {
                let before = &line[..search_from + start];
                let element = tag_name_before(before);
                found.push((UiActionKind::Submit, element));
            }
            search_from = end + 1;
        }
    }

    // addEventListener('click', ...) or addEventListener("click", ...)
    for pattern in ["addEventListener('click',", "addEventListener(\"click\","] {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find(pattern) {
            let before = &line[..search_from + start];
            let element = receiver_before(before);
            found.push((UiActionKind::Click, element));
            search_from += start + pattern.len();
        }
    }

    // addEventListener('submit', ...) or addEventListener("submit", ...)
    for pattern in ["addEventListener('submit',", "addEventListener(\"submit\","] {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find(pattern) {
            let before = &line[..search_from + start];
            let element = receiver_before(before);
            found.push((UiActionKind::Submit, element));
            search_from += start + pattern.len();
        }
    }

    found
}

/// The name a binding falls back to when nothing in the source names one.
fn default_element(kind: UiActionKind) -> &'static str {
    match kind {
        UiActionKind::Click => "element",
        UiActionKind::Submit => "form",
    }
}

/// The tag open at the start of each line, when it opened on an earlier line.
///
/// JSX and Vue templates routinely put one attribute per line, so a binding
/// (`onClick={reset}`) sits on a line whose `<button` is above it. This walks
/// the file once, carrying the most recently opened tag across lines until its
/// closing `>`, and reports it per line. A tag that opened on the binding's own
/// line is found by [`tag_name_before`] instead, which wins because it is the
/// closer reading.
///
/// The walk is a heuristic, not a parser, and it is written to fail towards "no
/// tag" rather than towards a guess: quotes are skipped, `{}` raises a depth
/// that ignores `>` (so an arrow function's `=>` cannot close a tag), and a `<`
/// that is not followed by a letter is not a tag at all. A tag name is
/// lowercased, like [`tag_name_before`] does.
fn open_tag_by_line(text: &str) -> Vec<Option<String>> {
    let mut per_line = Vec::new();
    let mut open: Option<String> = None;
    let mut depth = 0_usize;
    let mut quote: Option<char> = None;
    for line in text.lines() {
        // What was open when this line began is what a binding on it belongs to.
        per_line.push(open.clone());
        let chars: Vec<char> = line.chars().collect();
        let mut index = 0;
        while index < chars.len() {
            let current = chars[index];
            if let Some(opened) = quote {
                if current == opened {
                    quote = None;
                }
                index += 1;
                continue;
            }
            if open.is_some() {
                match current {
                    '"' | '\'' | '`' => quote = Some(current),
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    '>' if depth == 0 => open = None,
                    _ => {}
                }
                index += 1;
                continue;
            }
            if current == '<' {
                let mut end = index + 1;
                while end < chars.len()
                    && (chars[end].is_ascii_alphanumeric()
                        || chars[end] == '_'
                        || chars[end] == '-'
                        || chars[end] == '.'
                        || chars[end] == ':')
                {
                    end += 1;
                }
                if end > index + 1 && chars[index + 1].is_ascii_alphabetic() {
                    open = Some(
                        chars[index + 1..end]
                            .iter()
                            .collect::<String>()
                            .to_lowercase(),
                    );
                    depth = 0;
                    index = end;
                    continue;
                }
            }
            index += 1;
        }
    }
    per_line
}

/// The tag name immediately before an attribute, if we're inside a tag.
fn tag_name_before(before: &str) -> Option<String> {
    let trimmed = before.trim_end();
    let after_lt = trimmed.rsplit_once('<')?.1;
    let name = after_lt.split_whitespace().next()?;
    if name.is_empty() || name.starts_with('/') {
        return None;
    }
    Some(name.to_lowercase())
}

/// The receiver before an `addEventListener` call.
fn receiver_before(before: &str) -> Option<String> {
    let trimmed = before.trim_end();
    let idx = trimmed.rfind(".addEventListener")?;
    let receiver_end = trimmed[..idx].trim_end();
    let receiver = receiver_end
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_' && c != '$')
        .next()?;
    if receiver.is_empty() {
        return None;
    }
    Some(receiver.to_lowercase())
}

/// Whether a resolved path is still inside the project root.
fn is_within_project(root: &Path, full: &Path) -> bool {
    let Ok(root_canon) = std::fs::canonicalize(root) else {
        return false;
    };
    let Ok(full_canon) = std::fs::canonicalize(full) else {
        return false;
    };
    full_canon.starts_with(&root_canon)
        && full_canon.components().count() > root_canon.components().count()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_domain::severity::Severity;

    #[test]
    fn a_project_with_no_frontend_produces_nothing() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-bridge-clean-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(temp.join("main.rs"), "fn main() {}").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery);
        assert!(bridge.is_empty());
        assert!(bridge.proposals().is_empty());
    }

    #[test]
    fn a_declared_click_without_runtime_evidence_is_inference() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-inference-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("App.tsx"),
            "<button onClick={handleSave}>Save</button>\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery);
        assert!(!bridge.is_empty());

        let proposals = bridge.proposals();
        assert_eq!(proposals.len(), 1);
        let proposal = &proposals[0];
        assert!(proposal.title().contains("click"));
        assert!(proposal.title().contains("button"));
        assert_eq!(proposal.severity(), Severity::MustFix);
        assert!(!proposal.critical());
        assert_eq!(proposal.evidence_class(), EvidenceClass::Inference);
        assert_eq!(proposal.requirements().actions(), &[ActionKind::ReadFile]);
    }

    #[test]
    fn a_declared_click_confirmed_by_browser_observation_becomes_observed_fact() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-observed-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("App.tsx"),
            "<button onClick={handleSave}>Save</button>\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery).with_evidence(UiRuntimeEvidence {
            elements: vec![ObservedElement {
                kind: ObservedElementKind::Button,
                label: "Save".to_owned(),
            }],
        });

        let proposals = bridge.proposals();
        assert_eq!(proposals.len(), 1);
        let proposal = &proposals[0];
        assert_eq!(proposal.evidence_class(), EvidenceClass::ObservedFact);
        assert_eq!(
            proposal.requirements().actions(),
            &[ActionKind::BrowserObservation]
        );
        assert_eq!(
            proposal.severity(),
            Severity::MustFix,
            "observing the element does not establish what the handler does, so the \
             severity is the same one the unobserved case gets and the evidence \
             class is what carries the difference"
        );
    }

    #[test]
    fn a_plain_div_without_event_handler_produces_nothing() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-negative-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(temp.join("App.tsx"), "<div>Hello</div>\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery);
        assert!(bridge.is_empty());
    }

    #[test]
    fn a_declared_submit_handler_is_detected() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-submit-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("Form.vue"),
            "<form @submit.prevent=\"handleSubmit\">\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery);
        let proposals = bridge.proposals();
        assert_eq!(proposals.len(), 1);
        assert!(proposals[0].title().contains("submit"));
    }

    #[test]
    fn not_checked_returns_skipped_for_inference_only() {
        let fingerprint = FingerprintId::generate();
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-not-checked-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("App.tsx"),
            "<button onClick={handleSave}>Save</button>\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery);
        let results = bridge.not_checked(&fingerprint);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, sure_domain::status::CheckStatus::Skipped);
    }

    #[test]
    fn nothing_this_module_builds_is_refused_and_the_plan_holds_everything() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-plan-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("App.tsx"),
            "<button onClick={handleSave}>Save</button>\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery);
        assert_eq!(bridge.proposals().len(), 1);

        let mut builder = PlanBuilder::new(
            sure_domain::execution::ExecutionMode::HostConfirmed,
            sure_domain::execution::ExecutionPermissions::inspect_only(),
        );
        bridge.add_to(&mut builder);

        assert!(builder.refused().is_empty());
        let schedule = builder.build();
        assert_eq!(schedule.len(), 1);
        assert!(schedule.duplicates().is_empty());
    }

    /// The two sentences a planned bridge check can carry, and which one the
    /// class picks.
    ///
    /// `P18-T004` made the observation class-dependent, and a class-dependent
    /// sentence with one of its branches never run is a sentence nobody has
    /// read: the unobserved shape is the one `UiActionBridge::of` produces, the
    /// observed one needs evidence a browser would supply, and the two must not
    /// claim the same thing about the handler.
    #[test]
    fn the_two_shapes_of_a_bridge_check_say_what_was_seen_and_what_was_not() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-observation-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("App.tsx"),
            "<button onClick={handleSave}>Save</button>\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();

        let observed = UiActionBridge::of(&discovery).with_evidence(UiRuntimeEvidence {
            elements: vec![ObservedElement {
                kind: ObservedElementKind::Button,
                label: "Save".to_owned(),
            }],
        });
        let detail = planned_detail(&observed);
        assert!(
            detail.contains("a browser saw a matching element on the page"),
            "an observed element is what the browser added, and the sentence has to \
             say it: {detail}"
        );
        assert!(
            detail.contains("what the action does when somebody uses it was not watched"),
            "seeing the element is not seeing the action work: {detail}"
        );

        let read = UiActionBridge::of(&discovery);
        let detail = planned_detail(&read);
        assert!(
            detail.contains("the binding was read in the source"),
            "nothing was observed about this one: {detail}"
        );
        assert!(
            !detail.contains("a browser saw"),
            "no browser ran for the static shape, so nothing may claim one did: {detail}"
        );
        assert!(
            detail.contains(&read.proposals()[0].reason().plain_description()),
            "the detail must name the place the proposal's own reason names: {detail}"
        );
    }

    /// The sentence the plan holds for a bridge's single check.
    fn planned_detail(bridge: &UiActionBridge) -> String {
        let mut builder = PlanBuilder::new(
            sure_domain::execution::ExecutionMode::HostConfirmed,
            sure_domain::execution::ExecutionPermissions::inspect_only(),
        );
        bridge.add_to(&mut builder);
        let schedule = builder.build();
        let CheckOperation::Precomputed(evidence) = schedule.checks()[0].operation() else {
            panic!("a bridge check that starts a process is not what this module plans");
        };
        evidence.detail().to_owned()
    }

    #[test]
    fn a_link_click_is_detected() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-link-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("Link.tsx"),
            "<a onClick={handleNavigate}>Go</a>\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery);
        let proposals = bridge.proposals();
        assert_eq!(proposals.len(), 1);
        assert!(proposals[0].title().contains("click"));
        assert!(proposals[0].title().contains("a"));
    }

    #[test]
    fn addeventlistener_click_is_detected() {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-addevent-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("script.js"),
            "document.getElementById('btn').addEventListener('click', handleClick);\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let bridge = UiActionBridge::of(&discovery);
        let proposals = bridge.proposals();
        assert_eq!(proposals.len(), 1);
        assert!(proposals[0].title().contains("click"));
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let temp = std::env::temp_dir().join(format!(
            "sure-ui-group-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        temp
    }

    fn proposals_for(root: &std::path::Path) -> Vec<crate::schedule::CheckProposal> {
        let discovery =
            crate::discover::discover(root, &crate::discover::DiscoverOptions::default()).unwrap();
        UiActionBridge::of(&discovery).proposals()
    }

    #[test]
    fn two_click_handlers_in_one_file_are_one_proposal_with_the_count() {
        let temp = scratch("two-clicks");
        std::fs::write(
            temp.join("App.tsx"),
            "<button onClick={save}>Save</button>\n<button onClick={cancel}>Cancel</button>\n",
        )
        .unwrap();
        let proposals = proposals_for(&temp);
        assert_eq!(proposals.len(), 1, "one file, one kind, one question");
        let title = proposals[0].title();
        assert!(title.contains("2 click handlers"), "{title}");
        assert!(title.contains("App.tsx"), "{title}");
        assert_eq!(proposals[0].severity(), Severity::MustFix);
        assert!(!proposals[0].critical());
        assert_eq!(proposals[0].evidence_class(), EvidenceClass::Inference);
        let anchor = proposals[0]
            .reason()
            .anchor()
            .expect("a group has an anchor");
        assert_eq!(anchor.location, "App.tsx");
        assert!(
            anchor.locator.contains("the 2 click handlers"),
            "{}",
            anchor.locator
        );
        assert!(anchor.locator.contains("set "), "{}", anchor.locator);
    }

    #[test]
    fn a_click_and_a_submit_in_one_file_are_two_groups() {
        let temp = scratch("click-submit");
        std::fs::write(
            temp.join("Form.tsx"),
            "<button onClick={save}>Save</button>\n<form onSubmit={submit}></form>\n",
        )
        .unwrap();
        let proposals = proposals_for(&temp);
        assert_eq!(proposals.len(), 2);
        let titles: Vec<&str> = proposals.iter().map(|proposal| proposal.title()).collect();
        assert!(
            titles.iter().any(|title| title.contains("click")),
            "{titles:?}"
        );
        assert!(
            titles.iter().any(|title| title.contains("submit")),
            "{titles:?}"
        );
    }

    #[test]
    fn the_group_digest_ignores_line_moves_and_changes_with_the_set() {
        let binding =
            "<button onClick={save}>Save</button>\n<button onClick={cancel}>Cancel</button>\n";
        let a = scratch("digest-a");
        std::fs::write(a.join("App.tsx"), binding).unwrap();
        let b = scratch("digest-b");
        // Same declarations, shifted down by a comment line: line numbers move,
        // the set does not.
        std::fs::write(b.join("App.tsx"), format!("// header\n{binding}")).unwrap();
        let c = scratch("digest-c");
        // One declaration replaced: same count, different set.
        std::fs::write(
            c.join("App.tsx"),
            "<button onClick={save}>Save</button>\n<button onClick={remove}>Remove</button>\n",
        )
        .unwrap();
        let locator = |root: &std::path::Path| {
            proposals_for(root)[0]
                .reason()
                .anchor()
                .expect("a group has an anchor")
                .locator
        };
        assert_eq!(
            locator(&a),
            locator(&b),
            "moving declarations is not a new set"
        );
        assert_ne!(
            locator(&a),
            locator(&c),
            "replacing a declaration is a new set"
        );
    }

    #[test]
    fn a_binding_on_its_own_line_belongs_to_the_tag_that_opened_above_it() {
        let temp = scratch("multiline-tag");
        std::fs::write(
            temp.join("App.tsx"),
            "<button\n  className=\"save\"\n  onClick={reset}\n>\n  Save\n</button>\n",
        )
        .unwrap();
        let proposals = proposals_for(&temp);
        assert_eq!(proposals.len(), 1);
        assert!(
            proposals[0].title().contains("on button"),
            "{}",
            proposals[0].title()
        );
    }

    #[test]
    fn an_arrow_function_in_the_open_tag_does_not_close_it() {
        // `=>` inside an earlier attribute's braces must not end the tag, or the
        // binding on the next line would lose the element it belongs to.
        let temp = scratch("arrow-tag");
        std::fs::write(
            temp.join("App.tsx"),
            "<div\n  onMouseDown={() => set(true)}\n  onClick={reset}\n>\n",
        )
        .unwrap();
        let proposals = proposals_for(&temp);
        assert!(
            proposals[0].title().contains("on div"),
            "{}",
            proposals[0].title()
        );
    }

    #[test]
    fn nested_tags_across_lines_name_the_innermost_open_tag() {
        let temp = scratch("nested-tags");
        std::fs::write(
            temp.join("App.tsx"),
            "<div className=\"row\">\n  <button\n    onClick={save}\n  >\n    Save\n  \
             </button>\n</div>\n",
        )
        .unwrap();
        let proposals = proposals_for(&temp);
        assert!(
            proposals[0].title().contains("on button"),
            "{}",
            proposals[0].title()
        );
    }

    #[test]
    fn a_binding_outside_any_tag_stays_unnamed() {
        let temp = scratch("props-object");
        std::fs::write(
            temp.join("App.tsx"),
            "const props = {\n  onClick: handleSave,\n};\n",
        )
        .unwrap();
        let proposals = proposals_for(&temp);
        assert_eq!(proposals.len(), 1);
        assert!(
            proposals[0].title().contains("on element"),
            "{}",
            proposals[0].title()
        );
    }

    #[test]
    fn a_tag_closed_before_the_binding_line_does_not_name_it() {
        // The submit binding below the closed button is not inside any tag; if
        // the walk leaked the button across the close, the title would say
        // "on button" for it too.
        let temp = scratch("closed-tag");
        std::fs::write(
            temp.join("App.tsx"),
            "<button onClick={a}>Go</button>\nconst props = {\n  onSubmit: b,\n};\n",
        )
        .unwrap();
        let proposals = proposals_for(&temp);
        assert_eq!(proposals.len(), 2);
        let titles: Vec<&str> = proposals.iter().map(|proposal| proposal.title()).collect();
        assert!(
            titles.iter().any(|title| title.contains("on button")),
            "{titles:?}"
        );
        assert!(
            titles.iter().any(|title| title.contains("on form")),
            "the submit outside any tag keeps the honest default: {titles:?}"
        );
    }

    #[test]
    fn a_group_is_observed_fact_only_when_every_declaration_was_observed() {
        let temp = scratch("observed-group");
        std::fs::write(
            temp.join("App.tsx"),
            "<button onClick={save}>Save</button>\n<button onClick={cancel}>Cancel</button>\n",
        )
        .unwrap();
        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let partial = UiActionBridge::of(&discovery).with_evidence(UiRuntimeEvidence {
            elements: vec![ObservedElement {
                kind: ObservedElementKind::Button,
                label: "Save".to_owned(),
            }],
        });
        assert_eq!(
            partial.proposals()[0].evidence_class(),
            EvidenceClass::Inference,
            "one unobserved declaration keeps the group an inference"
        );
        let full = UiActionBridge::of(&discovery).with_evidence(UiRuntimeEvidence {
            elements: vec![
                ObservedElement {
                    kind: ObservedElementKind::Button,
                    label: "Save".to_owned(),
                },
                ObservedElement {
                    kind: ObservedElementKind::Button,
                    label: "Cancel".to_owned(),
                },
            ],
        });
        assert_eq!(
            full.proposals()[0].evidence_class(),
            EvidenceClass::ObservedFact
        );
    }
}
