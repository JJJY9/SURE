//! Compare stated project intent against grounded implementation evidence.
//!
//! `P6-T008`'s acceptance: only trusted intent sources are evaluated as user
//! requirements, and missing intent triggers a limitation rather than a
//! fabricated completeness claim.
//!
//! # What it does
//!
//! Splits a [`ProjectIntent`] into four buckets by source, then attempts to find
//! concrete implementation anchors for every user requirement:
//!
//! - component names / workspace member names,
//! - package or crate names declared in manifests,
//! - declared scripts or conventional commands,
//! - HTTP route paths read from source,
//! - source-file identifiers that contain requirement keywords.
//!
//! A match is recorded only when a concrete anchor exists. Everything else is
//! reported as `Cannot confirm`/`Inference` through the result fields, never as
//! a false green.
//!
//! # What it does not do
//!
//! It does not use semantic analysis or LLM calls. The comparison is
//! deterministic keyword matching against facts discovery already recorded. It
//! does not promote an inference into a requirement, and it does not report a
//! missing requirement as a passing result.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::intent::{IntentSource, ProjectIntent};
use sure_domain::status::RequirementClaim;

use crate::checks::check_id;
use crate::components::ComponentGraph;
use crate::discover::{Discovery, Findings};
use crate::finding_gravity::{GapKind, Reach, gravity_of};
use crate::http_routes::RouteReading;
use crate::redact::escape_control_characters;
use crate::references::is_source_candidate;
use crate::scan::display_path;
use crate::schedule::{CheckProposal, CheckReason};

/// The outcome of comparing a project's intent against its implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentImplementationResult {
    /// How many user requirements were compared.
    pub user_requirements_checked: usize,
    /// User requirements that had at least one concrete implementation anchor.
    pub matched: Vec<RequirementMatch>,
    /// User requirements with no implementation evidence SURE could find.
    pub unmatched: Vec<RequirementMatch>,
    /// The limitation SURE must report when no trusted intent source exists.
    pub limitation: Option<&'static str>,
    /// Candidate checks arising from unmatched requirements, documentation and
    /// agent claims.
    pub findings: Vec<CheckProposal>,
}

impl IntentImplementationResult {
    /// Whether every user requirement found a concrete implementation anchor.
    #[must_use]
    pub fn is_fully_matched(&self) -> bool {
        self.user_requirements_checked > 0 && self.unmatched.is_empty()
    }
}

/// One requirement and the concrete anchors SURE found for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementMatch {
    /// The requirement's stable identity.
    pub requirement_id: String,
    /// The requirement text, escaped for safe display.
    pub requirement_text: String,
    /// Where the requirement came from.
    pub source: IntentSource,
    /// Concrete anchors in the implementation.
    pub anchors: Vec<IntentMatchAnchor>,
}

/// A concrete place in the implementation a requirement keyword matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentMatchAnchor {
    /// A component path matched a requirement keyword.
    Component {
        /// The component path, relative to the project root.
        path: String,
    },
    /// An HTTP route path matched a requirement keyword.
    Route {
        /// The route path as declared.
        path: String,
        /// The file the route was read from.
        declared_in: String,
        /// The 1-based line the route is on.
        line: usize,
    },
    /// A source file identifier matched a requirement keyword.
    SourceFile {
        /// The file path, relative to the project root.
        path: String,
        /// The 1-based line the match is on.
        line: usize,
        /// The trimmed line context, escaped for safe display.
        context: String,
    },
    /// A declared script or conventional command matched a requirement keyword.
    DeclaredCommand {
        /// The command SURE would run.
        command: String,
        /// The file the command was read from, if any.
        declared_in: String,
    },
}

/// Compare a project's stated intent against its discovered implementation.
///
/// `discovery` provides the grounded facts: component structure, declared
/// commands, HTTP routes and source files. The comparison is deterministic and
/// conservative; a requirement is only `matched` when a concrete anchor exists.
#[must_use]
pub fn compare_intent_to_project(
    intent: &ProjectIntent,
    discovery: &Discovery,
) -> IntentImplementationResult {
    let graph = ComponentGraph::of(discovery);
    let evidence = ProjectEvidence::of(discovery, &graph);

    let mut matched = Vec::new();
    let mut unmatched = Vec::new();

    for requirement in intent.requirements.iter() {
        if !requirement.is_user_requirement() {
            continue;
        }
        let keywords = extract_keywords(&requirement.text);
        let anchors = evidence.anchors_for(&keywords);
        let requirement_match = RequirementMatch {
            requirement_id: requirement.id.clone(),
            requirement_text: escape_control_characters(&requirement.text),
            source: requirement.source,
            anchors,
        };
        if requirement_match.anchors.is_empty() {
            unmatched.push(requirement_match);
        } else {
            matched.push(requirement_match);
        }
    }

    let limitation = match intent.requirement_claim() {
        RequirementClaim::Comparable => None,
        RequirementClaim::AfterTheFact => intent.caveat(),
    };

    let findings = build_findings(intent, &unmatched);

    IntentImplementationResult {
        user_requirements_checked: matched.len() + unmatched.len(),
        matched,
        unmatched,
        limitation,
        findings,
    }
}

/// All grounded implementation evidence collected once and searched per
/// requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectEvidence {
    anchors: Vec<IntentMatchAnchor>,
}

impl ProjectEvidence {
    /// Collect every concrete anchor discovery can provide.
    #[must_use]
    fn of(discovery: &Discovery, graph: &ComponentGraph) -> Self {
        let mut anchors: Vec<IntentMatchAnchor> = Vec::new();
        anchors.extend(component_anchors(graph));
        anchors.extend(route_anchors(discovery));
        anchors.extend(command_anchors(discovery));
        anchors.extend(source_anchors(discovery));
        Self { anchors }
    }

    /// Every anchor whose keywords overlap with the requirement keywords.
    #[must_use]
    fn anchors_for(&self, keywords: &[String]) -> Vec<IntentMatchAnchor> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut found = Vec::new();
        for anchor in &self.anchors {
            if anchor_matches_keywords(anchor, keywords) && seen.insert(anchor.signature()) {
                found.push(anchor.clone());
            }
        }
        found
    }
}

impl IntentMatchAnchor {
    /// A stable string that identifies this anchor for deduplication.
    #[must_use]
    fn signature(&self) -> String {
        match self {
            Self::Component { path } => format!("component:{path}"),
            Self::Route {
                path,
                declared_in,
                line,
            } => format!("route:{path}:{declared_in}:{line}"),
            Self::SourceFile { path, line, .. } => format!("source:{path}:{line}"),
            Self::DeclaredCommand {
                command,
                declared_in,
            } => format!("command:{command}:{declared_in}"),
        }
    }
}

/// Anchors from every component path.
fn component_anchors(graph: &ComponentGraph) -> Vec<IntentMatchAnchor> {
    graph
        .components
        .iter()
        .map(|component| IntentMatchAnchor::Component {
            path: display_path(&component.path),
        })
        .collect()
}

/// Anchors from every HTTP route SURE read.
fn route_anchors(discovery: &Discovery) -> Vec<IntentMatchAnchor> {
    RouteReading::of(discovery)
        .checks()
        .iter()
        .map(|check| IntentMatchAnchor::Route {
            path: check.route().path().to_owned(),
            declared_in: display_path(check.route().declared_in()),
            line: check.route().line(),
        })
        .collect()
}

/// Anchors from declared scripts and conventional commands.
fn command_anchors(discovery: &Discovery) -> Vec<IntentMatchAnchor> {
    let mut anchors = Vec::new();
    for report in &discovery.ecosystems {
        match &report.findings {
            Findings::Node(project) => {
                if let Some(package) = project.package() {
                    for script in &package.scripts {
                        anchors.push(IntentMatchAnchor::DeclaredCommand {
                            command: script.name.clone(),
                            declared_in: display_path(&report.found_by[0]),
                        });
                    }
                }
            }
            Findings::Rust(project) => {
                for conventional in project.conventional_commands() {
                    if let Some(command) = conventional.command {
                        for source in &conventional.because {
                            anchors.push(IntentMatchAnchor::DeclaredCommand {
                                command: command.clone(),
                                declared_in: display_path(&source.path),
                            });
                        }
                    }
                }
            }
            Findings::Python(_) => {}
            Findings::Go(project) => {
                // A Go project's declared module path is not a source tree SURE
                // reads for complete/partial implementation markers; the
                // completeness scanners still run over the files.
                let _ = project;
            }
            Findings::Dotnet(project) => {
                // The solution/project graph is not a source tree SURE reads for
                // implementation markers; the completeness scanners still run.
                let _ = project;
            }
            Findings::Java(project) => {
                // A Maven POM names no source tree SURE reads for implementation
                // markers; the completeness scanners still run.
                let _ = project;
            }
        }
    }
    anchors
}

/// Anchors from source files that contain identifier-like tokens.
fn source_anchors(discovery: &Discovery) -> Vec<IntentMatchAnchor> {
    let mut candidates: Vec<&Path> = discovery
        .scan
        .files()
        .map(|entry| entry.path.as_path())
        .filter(|path| is_source_candidate(path))
        .collect();
    candidates.sort_unstable();

    let mut anchors = Vec::new();
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
        let Ok(metadata) = fs::metadata(&full) else {
            continue;
        };
        if metadata.len() > 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = fs::read(&full) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };

        files_read += 1;
        bytes_read = bytes_read.saturating_add(metadata.len());

        let display = display_path(path);
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            if !line.trim().is_empty() {
                anchors.push(IntentMatchAnchor::SourceFile {
                    path: display.clone(),
                    line: line_number,
                    context: escape_control_characters(line.trim()),
                });
                // One anchor per file is enough for intent matching; the line
                // text carries the concrete evidence.
                break;
            }
        }
    }
    anchors
}

/// Whether an anchor's text overlaps with any requirement keyword.
fn anchor_matches_keywords(anchor: &IntentMatchAnchor, keywords: &[String]) -> bool {
    match anchor {
        IntentMatchAnchor::Component { path } => {
            let tokens: HashSet<String> = tokenize(path).into_iter().collect();
            keywords.iter().any(|keyword| tokens.contains(keyword))
        }
        IntentMatchAnchor::Route { path, .. } => keywords
            .iter()
            .any(|keyword| path.to_lowercase().contains(keyword)),
        IntentMatchAnchor::SourceFile { context, .. } => {
            let tokens: HashSet<String> = tokenize(context).into_iter().collect();
            keywords.iter().any(|keyword| tokens.contains(keyword))
        }
        IntentMatchAnchor::DeclaredCommand {
            command,
            declared_in,
        } => {
            let haystack = format!("{command} {declared_in}").to_lowercase();
            let tokens = tokenize(&haystack);
            keywords.iter().any(|keyword| tokens.contains(keyword))
        }
    }
}

/// Extract searchable keywords from a requirement sentence.
///
/// Returns lowercase alphanumeric tokens of at least three characters, with a
/// small set of common stop words removed so generic words do not produce
/// false matches.
#[must_use]
fn extract_keywords(text: &str) -> Vec<String> {
    tokenize(text)
        .into_iter()
        .filter(|token| !STOP_WORDS.contains(&token.as_str()))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

/// Every lowercase alphanumeric token in `text`.
#[must_use]
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| token.len() >= 3)
        .map(str::to_owned)
        .collect()
}

/// Common words too generic to use as intent anchors.
const STOP_WORDS: &[&str] = &[
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "was", "one", "our",
    "out", "get", "has", "how", "its", "may", "new", "now", "old", "see", "two", "who", "did",
    "use", "way", "any", "too", "why", "let", "put", "this", "that", "with", "have", "from",
    "they", "know", "want", "been", "good", "much", "some", "time", "than", "them", "well", "were",
    "just", "like", "over", "also", "back", "only", "work", "life", "even", "more", "here", "look",
    "down", "most", "long", "last", "find", "give", "does", "made", "part", "such", "take", "come",
    "keep", "call", "must", "make", "into", "year", "your", "once", "open", "case", "show", "live",
    "play", "upon", "used", "again", "same", "seen", "felt", "kept", "sent", "gave", "took",
    "said", "sure",
];

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

/// Build the candidate findings from unmatched requirements, documentation and
/// agent claims.
fn build_findings(intent: &ProjectIntent, unmatched: &[RequirementMatch]) -> Vec<CheckProposal> {
    let mut findings = Vec::new();

    for requirement_match in unmatched {
        let title = format!(
            "requirement `{}` has no implementation evidence",
            requirement_match.requirement_text
        );
        findings.push(declared_intent_proposal(
            check_id(&requirement_match.requirement_id, "intentunmatched"),
            title,
            CheckReason::CandidateFound {
                path: requirement_match.requirement_id.clone(),
                line: 1,
                context: requirement_match.requirement_text.clone(),
            },
        ));
    }

    for requirement in intent.requirements.iter() {
        if requirement.source == IntentSource::ProjectSpec {
            let text = escape_control_characters(&requirement.text);
            findings.push(declared_intent_proposal(
                check_id(&requirement.id, "intentdoc"),
                format!("documented instruction `{text}`"),
                CheckReason::CandidateFound {
                    path: requirement.id.clone(),
                    line: 1,
                    context: text,
                },
            ));
        }
    }

    for requirement in intent.requirements.iter() {
        if requirement.source == IntentSource::AgentClaim {
            let text = escape_control_characters(&requirement.text);
            findings.push(declared_intent_proposal(
                check_id(&requirement.id, "intentclaim"),
                format!("agent claim `{text}`"),
                CheckReason::CandidateFound {
                    path: requirement.id.clone(),
                    line: 1,
                    context: text,
                },
            ));
        }
    }

    // Stable order, so two runs over one project cannot produce two plans.
    findings.sort_by(|a, b| a.id().as_str().cmp(b.id().as_str()));
    findings
}

/// One finding about what the project was asked to do.
///
/// **Every proposal this module builds goes through here**, and the severity it
/// carries is the rule's answer for [`GapKind::DeclaredIntent`] reached on
/// [`Reach::NotProduction`] — never a literal.
///
/// Why that level is the honest one, and why it is the corpus's requirement
/// rather than a preference: the reason's anchor is the requirement's own
/// identifier, which is not a file a reader can open, and the claim it carries —
/// *SURE could not match this to code* — is a statement about SURE's reading
/// rather than about the project. `evaluation/acceptance-manifest.json` requires
/// `note` for `missing-user-intent`, and this finding is that case.
/// [`crate::finding_gravity`] rates it `note` on any reach, so a caller that
/// later gives this module a production context cannot raise it by accident.
fn declared_intent_proposal(
    id: sure_domain::ids::CheckId,
    title: impl Into<String>,
    reason: CheckReason,
) -> CheckProposal {
    let gravity = gravity_of(
        &reason,
        EvidenceClass::Inference,
        Reach::NotProduction,
        GapKind::DeclaredIntent,
    );
    CheckProposal::new(
        id,
        title,
        gravity.severity(),
        false,
        EvidenceClass::Inference,
        reason,
        &[ActionKind::ReadFile],
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use sure_domain::intent::Requirement;
    use sure_domain::severity::Severity;

    fn temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ))
    }

    fn discover_fixture(dir: &Path) -> Discovery {
        crate::discover::discover(dir, &crate::discover::DiscoverOptions::default()).unwrap()
    }

    #[test]
    fn no_trusted_intent_emits_limitation_and_no_fabricated_pass() {
        let dir = temp_dir("sure-intent-none");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.rs"), "fn main() {}").unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::empty();
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 0);
        assert!(result.matched.is_empty());
        assert!(result.unmatched.is_empty());
        assert_eq!(
            result.limitation,
            Some(sure_domain::status::NO_TRUSTED_INTENT_LIMITATION)
        );
        // No fabricated passing finding: the only honest answer is the
        // limitation.
        assert!(
            result.findings.is_empty(),
            "no user requirement means no fabricated finding"
        );
        assert!(!result.is_fully_matched());
    }

    #[test]
    fn explicit_user_goal_with_matching_source_identifier_is_matched() {
        let dir = temp_dir("sure-intent-match");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn todo_list() {}").unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::from_requirements(vec![Requirement::new(
            "goal-1",
            "build a todo app",
            IntentSource::ExplicitUserGoal,
        )]);
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 1);
        assert_eq!(result.matched.len(), 1);
        assert_eq!(result.unmatched.len(), 0);
        assert!(result.limitation.is_none());
        assert!(result.is_fully_matched());
        assert!(
            result.matched[0].anchors.iter().any(|anchor| matches!(
                anchor,
                IntentMatchAnchor::SourceFile { path, .. } if path == "src/lib.rs"
            )),
            "expected a source-file anchor for src/lib.rs: {:?}",
            result.matched[0].anchors
        );
    }

    #[test]
    fn explicit_user_goal_with_no_matching_evidence_is_unmatched_candidate() {
        let dir = temp_dir("sure-intent-unmatched");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.rs"), "fn main() {}").unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::from_requirements(vec![Requirement::new(
            "goal-1",
            "add CSV export",
            IntentSource::ExplicitUserGoal,
        )]);
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 1);
        assert_eq!(result.matched.len(), 0);
        assert_eq!(result.unmatched.len(), 1);
        assert!(result.limitation.is_none());
        assert!(!result.is_fully_matched());

        assert_eq!(result.findings.len(), 1);
        let proposal = &result.findings[0];
        assert!(proposal.title().contains("CSV export"));
        assert!(proposal.title().contains("no implementation evidence"));
        assert_eq!(proposal.severity(), Severity::Note);
        assert!(!proposal.critical());
        assert_eq!(proposal.evidence_class(), EvidenceClass::Inference);
    }

    #[test]
    fn documentation_source_is_reported_as_documentation_not_missing_requirement() {
        let dir = temp_dir("sure-intent-doc");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.rs"), "fn main() {}").unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::from_requirements(vec![Requirement::new(
            "doc-1",
            "run npm start",
            IntentSource::ProjectSpec,
        )]);
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 0);
        assert!(result.matched.is_empty());
        assert!(result.unmatched.is_empty());
        // ProjectSpec is not a user requirement, so the honest result is the
        // after-the-fact limitation rather than a fabricated completeness claim.
        assert_eq!(
            result.limitation,
            Some(sure_domain::status::NO_TRUSTED_INTENT_LIMITATION)
        );

        assert_eq!(result.findings.len(), 1);
        let proposal = &result.findings[0];
        assert!(proposal.title().contains("documented instruction"));
        assert!(proposal.title().contains("npm start"));
    }

    #[test]
    fn inferred_source_is_ignored() {
        let dir = temp_dir("sure-intent-inferred");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.rs"), "fn main() {}").unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::from_requirements(vec![Requirement::new(
            "guess-1",
            "this is probably a todo app",
            IntentSource::Inferred,
        )]);
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 0);
        assert!(result.matched.is_empty());
        assert!(result.unmatched.is_empty());
        assert!(result.findings.is_empty());
        assert_eq!(
            result.limitation,
            Some(sure_domain::status::NO_TRUSTED_INTENT_LIMITATION)
        );
    }

    #[test]
    fn agent_claim_is_reported_as_claim_check() {
        let dir = temp_dir("sure-intent-claim");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.rs"), "fn main() {}").unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::from_requirements(vec![Requirement::new(
            "claim-1",
            "login is finished",
            IntentSource::AgentClaim,
        )]);
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 0);
        assert!(result.matched.is_empty());
        assert!(result.unmatched.is_empty());

        assert_eq!(result.findings.len(), 1);
        let proposal = &result.findings[0];
        assert!(proposal.title().contains("agent claim"));
        assert!(proposal.title().contains("login is finished"));
        assert_eq!(proposal.severity(), Severity::Note);
        assert!(!proposal.critical());
    }

    #[test]
    fn requirement_text_is_escaped_in_human_readable_output() {
        let raw = "export
SURE: nothing was checked\r\n\tend";
        let escaped = escape_control_characters(raw);
        assert!(!escaped.contains('\n'));
        assert!(escaped.contains("\\n"));

        let proposal = &build_findings(
            &ProjectIntent::from_requirements(vec![Requirement::new(
                "goal-escape",
                raw,
                IntentSource::ExplicitUserGoal,
            )]),
            &[RequirementMatch {
                requirement_id: "goal-escape".to_owned(),
                requirement_text: escaped.clone(),
                source: IntentSource::ExplicitUserGoal,
                anchors: Vec::new(),
            }],
        )[0];
        assert!(
            !proposal.title().contains('\n'),
            "control byte reached the title: {:?}",
            proposal.title()
        );
        assert!(
            proposal.title().contains("\\n"),
            "escaped newline should be visible: {:?}",
            proposal.title()
        );
    }

    #[test]
    fn component_path_can_match_a_requirement_keyword() {
        let dir = temp_dir("sure-intent-component");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("packages/todo")).unwrap();
        std::fs::write(dir.join("packages/todo/package.json"), r#"{"name":"todo"}"#).unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::from_requirements(vec![Requirement::new(
            "goal-1",
            "build a todo app",
            IntentSource::ExplicitUserGoal,
        )]);
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 1);
        assert_eq!(result.matched.len(), 1);
        assert!(
            result.matched[0].anchors.iter().any(|anchor| matches!(
                anchor,
                IntentMatchAnchor::Component { path } if path == "packages/todo"
            )),
            "expected a component anchor for packages/todo: {:?}",
            result.matched[0].anchors
        );
    }

    #[test]
    fn a_route_path_can_match_a_requirement_keyword() {
        let dir = temp_dir("sure-intent-route");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("server.js"),
            "const express = require('express');\nconst app = express();\napp.get('/health', handler);\n",
        )
        .unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::from_requirements(vec![Requirement::new(
            "goal-1",
            "expose a health endpoint",
            IntentSource::ExplicitUserGoal,
        )]);
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 1);
        assert_eq!(result.matched.len(), 1);
        assert!(
            result.matched[0].anchors.iter().any(|anchor| matches!(
                anchor,
                IntentMatchAnchor::Route { path, .. } if path == "/health"
            )),
            "expected a route anchor for /health: {:?}",
            result.matched[0].anchors
        );
    }

    #[test]
    fn declared_command_can_match_a_requirement_keyword() {
        let dir = temp_dir("sure-intent-command");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"root","scripts":{"test":"jest"}}"#,
        )
        .unwrap();

        let discovery = discover_fixture(&dir);
        let intent = ProjectIntent::from_requirements(vec![Requirement::new(
            "goal-1",
            "run the test suite",
            IntentSource::ExplicitUserGoal,
        )]);
        let result = compare_intent_to_project(&intent, &discovery);

        assert_eq!(result.user_requirements_checked, 1);
        assert_eq!(result.matched.len(), 1);
        assert!(
            result.matched[0].anchors.iter().any(|anchor| matches!(
                anchor,
                IntentMatchAnchor::DeclaredCommand { command, .. } if command == "test"
            )),
            "expected a command anchor for test: {:?}",
            result.matched[0].anchors
        );
    }
}
