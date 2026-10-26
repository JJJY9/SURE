//! Portable Markdown and HTML reports for a [`ProjectVerdict`].
//!
//! Produces self-contained Markdown and HTML documents that can be saved to a
//! file, emailed, or viewed in a browser. No external resources or scripts are
//! required.

use sure_core::plain_language_finding::{PlainLanguageFinding, render_findings};
use sure_core::project_verdict::render_summary;
use sure_core::redact::escape_control_characters;
use sure_core::vocabulary::ProjectVerdict;

/// Escape a string for safe embedding in HTML text content and attributes.
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render a [`ProjectVerdict`] as a self-contained Markdown report.
///
/// Attacker-controlled text is escaped with [`escape_control_characters`]
/// before embedding. The output is deterministic for the same inputs.
#[must_use]
pub fn render_markdown(verdict: &ProjectVerdict) -> String {
    let mut out = String::new();

    // The summary carries the headline as its first line — see `render_summary`.
    // Printing the headline above it as well put the verdict sentence in the
    // report twice, with a blank line between the two copies.
    out.push_str("# SURE Report\n\n");
    out.push_str(&render_summary(verdict));
    out.push_str("\n\n");

    // After-the-fact caveat
    if verdict.must_caveat_requirements() {
        out.push_str("> ");
        out.push_str(sure_core::status::NO_TRUSTED_INTENT_LIMITATION);
        out.push_str("\n\n");
    }

    // Capability / support level
    out.push_str("## Support level\n\n");
    out.push_str(&verdict.capability.summary());
    out.push_str("\n\n");

    // AI-claim checks
    let claim_entries = sure_core::claim_report::render_claim_entries(&verdict.claim_checks);
    if !claim_entries.is_empty() {
        out.push_str("## AI claims\n\n");
        out.push_str(&claim_entries);
        out.push('\n');
    }

    // Findings
    let open: Vec<_> = verdict.open_findings().into_iter().cloned().collect();
    out.push_str("## Findings\n\n");
    if open.is_empty() {
        if verdict.not_checked.is_empty() {
            out.push_str("No unresolved findings.\n\n");
        } else {
            out.push_str("No unresolved findings from the checks that ran.\n\n");
        }
    } else {
        let plain = render_findings(&open);
        for finding in &plain {
            render_markdown_finding(&mut out, finding);
            out.push('\n');
        }
    }

    // Not-checked checks
    if !verdict.not_checked.is_empty() {
        out.push_str("## Could not check\n\n");
        for result in &verdict.not_checked {
            let title = escape_control_characters(&result.title);
            let reason = escape_control_characters(&result.not_checked_reason.map_or_else(
                || result.reason.clone(),
                |r| r.plain_explanation().to_owned(),
            ));
            out.push_str(&format!("- **{title}** — {reason}"));
            if result.critical {
                out.push_str(" **[critical]**");
            }
            out.push('\n');
        }
        out.push('\n');
    }

    // Totals
    let counts = verdict.aggregate.counts;
    out.push_str("## Totals\n\n");
    out.push_str(&format!("- Checked: {}\n", counts.checked()));
    out.push_str(&format!("- Skipped: {}\n", counts.skipped));
    out.push_str(&format!(
        "- Could not run: {}\n",
        counts.error + counts.unknown
    ));
    out.push_str(&format!("- Unresolved findings: {}\n", open.len()));

    out
}

fn render_markdown_finding(out: &mut String, finding: &PlainLanguageFinding) {
    out.push_str(&format!("### {}\n\n", finding.title));
    out.push_str(&format!("- **Severity:** {}\n", finding.severity_label));
    out.push_str(&format!("- **Status:** {}\n", finding.status_label));

    if finding.is_model_only {
        out.push_str("- **Source:** model or inference only — this may be wrong\n");
    }

    if !finding.what.is_empty() {
        out.push_str(&format!("\n**What is wrong:** {}\n", finding.what));
    }
    if !finding.impact.is_empty() {
        out.push_str(&format!("**What it means:** {}\n", finding.impact));
    }
    if !finding.next_action.is_empty() {
        out.push_str(&format!("**Next action:** {}\n", finding.next_action));
    }

    if !finding.evidence_anchors.is_empty() {
        out.push_str("\n**Where to look:**\n");
        for anchor in &finding.evidence_anchors {
            out.push_str(&format!(
                "- {} at `{}` ({})\n",
                anchor.subject, anchor.location, anchor.locator
            ));
        }
    }
}

/// Render a [`ProjectVerdict`] as a self-contained HTML report.
///
/// Attacker-controlled text is escaped with [`escape_control_characters`] and
/// then with [`escape_html`] before embedding. The output is deterministic for
/// the same inputs.
#[must_use]
pub fn render_html(verdict: &ProjectVerdict) -> String {
    let mut out = String::new();

    out.push_str("<!doctype html>\n");
    out.push_str("<html lang=\"en\">\n");
    out.push_str("<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>SURE Report</title>\n");
    out.push_str("<style>\n");
    out.push_str(HTML_STYLE);
    out.push_str("</style>\n");
    out.push_str("</head>\n");
    out.push_str("<body>\n");
    out.push_str("<header>\n");
    out.push_str("<h1>SURE Report</h1>\n");
    out.push_str("</header>\n");
    out.push_str("<main>\n");

    // Summary. `render_summary` begins with the aggregate headline, so the
    // summary *is* the headline and the sentences under it; the `<p>` that used
    // to stand above this block repeated that first sentence in the same page.
    out.push_str("<section id=\"summary\">\n");
    out.push_str("<h2>Summary</h2>\n");
    out.push_str("<pre>");
    out.push_str(&escape_html(&render_summary(verdict)));
    out.push_str("</pre>\n");

    if verdict.must_caveat_requirements() {
        out.push_str("<p class=\"caveat\">");
        out.push_str(&escape_html(
            sure_core::status::NO_TRUSTED_INTENT_LIMITATION,
        ));
        out.push_str("</p>\n");
    }
    out.push_str("</section>\n");

    // Support level
    out.push_str("<section id=\"support\">\n");
    out.push_str("<h2>Support level</h2>\n");
    out.push_str("<p>");
    out.push_str(&escape_html(&verdict.capability.summary()));
    out.push_str("</p>\n");
    out.push_str("</section>\n");

    // AI-claim checks
    if !verdict.claim_checks.is_empty() {
        out.push_str("<section id=\"claims\">\n");
        out.push_str("<h2>AI claims</h2>\n");
        out.push_str("<ul>\n");
        for claim in &verdict.claim_checks {
            let text = escape_html(&escape_control_characters(&claim.claim_text));
            let assessment = escape_html(claim.assessment.label());
            let reason = escape_html(&escape_control_characters(&claim_reason(claim)));
            out.push_str(&format!(
                "<li><strong>{text}</strong><br>{assessment}: {reason}</li>\n"
            ));
        }
        out.push_str("</ul>\n");
        out.push_str("</section>\n");
    }

    // Findings
    let open: Vec<_> = verdict.open_findings().into_iter().cloned().collect();
    out.push_str("<section id=\"findings\">\n");
    out.push_str("<h2>Findings</h2>\n");
    if open.is_empty() {
        if verdict.not_checked.is_empty() {
            out.push_str("<p>No unresolved findings.</p>\n");
        } else {
            out.push_str("<p>No unresolved findings from the checks that ran.</p>\n");
        }
    } else {
        let plain = render_findings(&open);
        out.push_str("<ul class=\"findings\">\n");
        for finding in &plain {
            render_html_finding(&mut out, finding);
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</section>\n");

    // Not-checked
    if !verdict.not_checked.is_empty() {
        out.push_str("<section id=\"not-checked\">\n");
        out.push_str("<h2>Could not check</h2>\n");
        out.push_str("<ul>\n");
        for result in &verdict.not_checked {
            let title = escape_html(&escape_control_characters(&result.title));
            let reason = escape_html(&escape_control_characters(
                &result.not_checked_reason.map_or_else(
                    || result.reason.clone(),
                    |r| r.plain_explanation().to_owned(),
                ),
            ));
            out.push_str(&format!("<li><strong>{title}</strong> — {reason}"));
            if result.critical {
                out.push_str(" <span class=\"critical\">[critical]</span>");
            }
            out.push_str("</li>\n");
        }
        out.push_str("</ul>\n");
        out.push_str("</section>\n");
    }

    // Totals
    let counts = verdict.aggregate.counts;
    out.push_str("<section id=\"totals\">\n");
    out.push_str("<h2>Totals</h2>\n");
    out.push_str("<ul>\n");
    out.push_str(&format!("<li>Checked: {}</li>\n", counts.checked()));
    out.push_str(&format!("<li>Skipped: {}</li>\n", counts.skipped));
    out.push_str(&format!(
        "<li>Could not run: {}</li>\n",
        counts.error + counts.unknown
    ));
    out.push_str(&format!("<li>Unresolved findings: {}</li>\n", open.len()));
    out.push_str("</ul>\n");
    out.push_str("</section>\n");

    out.push_str("</main>\n");
    out.push_str("</body>\n");
    out.push_str("</html>\n");

    out
}

fn claim_reason(claim: &sure_core::vocabulary::Claim) -> String {
    if !claim.reason.is_empty() {
        return claim.reason.clone();
    }
    match claim.assessment {
        sure_core::evidence::ClaimAssessment::Confirmed => {
            String::from("A recorded harness event supports this claim.")
        }
        sure_core::evidence::ClaimAssessment::Contradicted => {
            String::from("A recorded harness event contradicts this claim.")
        }
        sure_core::evidence::ClaimAssessment::CannotConfirm => {
            String::from("SURE has no recorded event that supports or contradicts this claim.")
        }
        sure_core::evidence::ClaimAssessment::NotCheckable => {
            if claim.claim_type.is_empty() {
                String::from("SURE does not know how to check this kind of claim.")
            } else {
                format!(
                    "SURE does not know how to check a '{}' claim.",
                    escape_control_characters(&claim.claim_type)
                )
            }
        }
    }
}

fn render_html_finding(out: &mut String, finding: &PlainLanguageFinding) {
    out.push_str("<li class=\"finding\">\n");
    out.push_str(&format!("<h3>{}</h3>\n", escape_html(&finding.title)));
    out.push_str("<dl>\n");
    out.push_str(&format!(
        "<dt>Severity</dt><dd>{}</dd>\n",
        escape_html(&finding.severity_label)
    ));
    out.push_str(&format!(
        "<dt>Status</dt><dd>{}</dd>\n",
        escape_html(&finding.status_label)
    ));
    if finding.is_model_only {
        out.push_str("<dt>Source</dt><dd>model or inference only — this may be wrong</dd>\n");
    }
    out.push_str("</dl>\n");

    if !finding.what.is_empty() {
        out.push_str(&format!(
            "<p><strong>What is wrong:</strong> {}</p>\n",
            escape_html(&finding.what)
        ));
    }
    if !finding.impact.is_empty() {
        out.push_str(&format!(
            "<p><strong>What it means:</strong> {}</p>\n",
            escape_html(&finding.impact)
        ));
    }
    if !finding.next_action.is_empty() {
        out.push_str(&format!(
            "<p><strong>Next action:</strong> {}</p>\n",
            escape_html(&finding.next_action)
        ));
    }

    if !finding.evidence_anchors.is_empty() {
        out.push_str("<h4>Where to look</h4>\n");
        out.push_str("<ul>\n");
        for anchor in &finding.evidence_anchors {
            out.push_str(&format!(
                "<li>{} at <code>{}</code> ({})</li>\n",
                escape_html(&anchor.subject),
                escape_html(&anchor.location),
                escape_html(&anchor.locator),
            ));
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</li>\n");
}

const HTML_STYLE: &str = r#"
:root {
  --bg: #f8f9fa;
  --fg: #212529;
  --accent: #0d6efd;
  --muted: #6c757d;
  --border: #dee2e6;
  --critical: #dc3545;
}
body {
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.6;
  max-width: 800px;
  margin: 0 auto;
  padding: 1rem;
  background: var(--bg);
  color: var(--fg);
}
header {
  border-bottom: 2px solid var(--accent);
  margin-bottom: 1.5rem;
  padding-bottom: 0.5rem;
}
h1 { font-size: 1.75rem; margin: 0; }
h2 { font-size: 1.25rem; margin-top: 1.5rem; }
h3 { font-size: 1.1rem; margin-top: 1rem; }
h4 { font-size: 1rem; margin-top: 0.75rem; color: var(--muted); }
pre {
  white-space: pre-wrap;
  background: #fff;
  border: 1px solid var(--border);
  padding: 0.75rem;
  border-radius: 0.25rem;
}
.caveat {
  background: #fff3cd;
  border: 1px solid #ffc107;
  padding: 0.75rem;
  border-radius: 0.25rem;
}
.findings { list-style: none; padding: 0; }
.finding {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 0.25rem;
  padding: 1rem;
  margin-bottom: 1rem;
}
.finding h3 { margin-top: 0; }
dl { display: grid; grid-template-columns: auto 1fr; gap: 0.25rem 1rem; }
dt { font-weight: bold; color: var(--muted); }
dd { margin: 0; }
.critical { color: var(--critical); font-weight: bold; }
code {
  background: #e9ecef;
  padding: 0.125rem 0.25rem;
  border-radius: 0.125rem;
  font-size: 0.9em;
}
@media (max-width: 600px) {
  body { padding: 0.75rem; }
  dl { grid-template-columns: 1fr; }
}
"#;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_core::capability::CapabilityReport;
    use sure_core::evidence::{
        AnchorSubject, ClaimAssessment, Evidence, EvidenceAnchor, EvidenceClass,
    };
    use sure_core::ids::{CheckId, ClaimId, FingerprintId};
    use sure_core::intent::ProjectIntent;
    use sure_core::severity::Severity;
    use sure_core::status::{
        Aggregate, AggregateSeverity, CheckResult, CheckStatus, CoverageSummary, NotCheckedReason,
        StatusCounts,
    };
    use sure_core::vocabulary::{
        AssessmentSource, Claim, FindingBuilder, FindingStatus, ProjectVerdict, SeverityRationale,
    };

    fn fingerprint() -> FingerprintId {
        FingerprintId::generate()
    }

    fn green_aggregate() -> Aggregate {
        Aggregate {
            severity: AggregateSeverity::Green,
            headline: AggregateSeverity::Green.headline().to_owned(),
            counts: StatusCounts::tally([CheckStatus::Pass]),
            blocking: Vec::new(),
            coverage: CoverageSummary {
                counts: StatusCounts::tally([CheckStatus::Pass]),
                critical_not_checked: Vec::new(),
                critical_errored: Vec::new(),
                critical_failed: Vec::new(),
                critical_out_of_scope: Vec::new(),
                critical_checked: 1,
            },
        }
    }

    fn a_finding(severity: Severity) -> sure_core::vocabulary::Finding {
        let fp = fingerprint();
        let source = if severity.blocks_hand_off() {
            AssessmentSource::DeterministicCheck
        } else {
            AssessmentSource::ObservedFact
        };
        let rationale = SeverityRationale::for_severity(severity).unwrap();
        FindingBuilder::new(source, rationale)
            .title("A finding")
            .severity(severity)
            .status(FindingStatus::Open)
            .explanation("Something is wrong.")
            .user_impact("It matters.")
            .next_step("Fix it.")
            .fingerprint(fp.clone())
            .evidence(vec![Evidence::new(
                EvidenceClass::ObservedFact,
                "evidence",
                EvidenceAnchor::new(AnchorSubject::File, "src/x.rs", "line 1"),
                Some(fp.clone()),
                severity,
            )])
            .build()
            .expect("valid finding")
    }

    fn build_verdict(
        aggregate: Aggregate,
        findings: Vec<sure_core::vocabulary::Finding>,
        not_checked: Vec<CheckResult>,
    ) -> ProjectVerdict {
        ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate,
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings,
            not_checked,
            claim_checks: Vec::new(),
        }
    }

    #[test]
    fn markdown_contains_headline_findings_and_caveat() {
        let verdict = build_verdict(
            green_aggregate(),
            vec![a_finding(Severity::ShouldFixFirst)],
            Vec::new(),
        );
        let md = render_markdown(&verdict);
        assert!(md.contains("# SURE Report"), "markdown must have headline");
        assert!(
            md.contains("Unresolved findings:"),
            "markdown must mention unresolved findings"
        );
        assert!(
            md.contains("cannot confirm that it matches your original request"),
            "markdown must include caveat"
        );
        assert!(md.contains("### A finding"), "finding title must appear");
        assert!(
            md.contains("Support level"),
            "support level section must appear"
        );
    }

    #[test]
    fn html_is_complete_document_with_doctype_and_title() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let html = render_html(&verdict);
        assert!(
            html.starts_with("<!doctype html>"),
            "html must start with doctype"
        );
        assert!(
            html.contains("<title>SURE Report</title>"),
            "html must have title"
        );
        assert!(html.contains("<header>"), "html must use semantic header");
        assert!(html.contains("<main>"), "html must use semantic main");
        assert!(
            html.contains("<section id=\"summary\">"),
            "html must have summary section"
        );
        assert!(html.contains("</html>"), "html must close html tag");
    }

    #[test]
    fn attacker_controlled_strings_are_escaped_in_html() {
        let fp = fingerprint();
        let finding = FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::BlocksHandOff,
        )
        .title("<script>alert(1)</script>")
        .severity(Severity::MustFix)
        .status(FindingStatus::Open)
        .explanation("Tab\there")
        .user_impact("Carriage\rreturn")
        .next_step("Bell\u{0007}character")
        .fingerprint(fp.clone())
        .evidence(vec![Evidence::new(
            EvidenceClass::ObservedFact,
            "evidence",
            EvidenceAnchor::new(AnchorSubject::File, "src/<x>.rs", "line\t1"),
            Some(fp.clone()),
            Severity::MustFix,
        )])
        .build()
        .expect("valid finding");

        let verdict = build_verdict(green_aggregate(), vec![finding], Vec::new());
        let html = render_html(&verdict);

        // HTML tags must not appear verbatim
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "script tag must not appear verbatim: {html}"
        );
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "script tag must be escaped: {html}"
        );

        // Control characters must be escaped
        assert!(!html.contains('\t'), "raw tab must not appear: {html:?}");
        assert!(!html.contains('\r'), "raw cr must not appear: {html:?}");
        assert!(!html.contains('\x07'), "raw bell must not appear: {html:?}");
    }

    #[test]
    fn attacker_controlled_strings_are_escaped_in_markdown() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "run\ntests",
            Severity::MustFix,
            true,
            NotCheckedReason::ExecutionNotAuthorized,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let md = render_markdown(&verdict);

        assert!(
            !md.contains("run\ntests"),
            "unescaped newline must not appear: {md:?}"
        );
        assert!(
            md.contains("run\\ntests"),
            "escaped newline should appear: {md}"
        );
    }

    #[test]
    fn must_fix_finding_says_not_ready() {
        let verdict = build_verdict(
            green_aggregate(),
            vec![a_finding(Severity::MustFix)],
            Vec::new(),
        );
        let md = render_markdown(&verdict);
        let html = render_html(&verdict);

        assert!(
            md.contains("not ready to hand off"),
            "markdown must say not ready: {md}"
        );
        assert!(
            html.contains("not ready to hand off"),
            "html must say not ready: {html}"
        );
    }

    #[test]
    fn not_checked_checks_appear_with_reason() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "run tests",
            Severity::MustFix,
            true,
            NotCheckedReason::ExecutionNotAuthorized,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let md = render_markdown(&verdict);
        let html = render_html(&verdict);

        assert!(
            md.contains("run tests"),
            "markdown must list not-checked title: {md}"
        );
        assert!(
            md.contains("ExecutionNotAuthorized") || md.contains("running your project's code"),
            "markdown must show reason: {md}"
        );
        assert!(
            html.contains("run tests"),
            "html must list not-checked title: {html}"
        );
        assert!(
            html.contains("[critical]"),
            "html must mark critical: {html}"
        );
    }

    #[test]
    fn report_is_deterministic() {
        let verdict = build_verdict(
            green_aggregate(),
            vec![a_finding(Severity::ShouldFixFirst)],
            Vec::new(),
        );
        let md_a = render_markdown(&verdict);
        let md_b = render_markdown(&verdict);
        assert_eq!(md_a, md_b, "markdown must be deterministic");

        let html_a = render_html(&verdict);
        let html_b = render_html(&verdict);
        assert_eq!(html_a, html_b, "html must be deterministic");
    }

    #[test]
    fn html_has_no_external_resources_or_scripts() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let html = render_html(&verdict);
        assert!(
            !html.contains("<script"),
            "html must not contain script tags: {html}"
        );
        assert!(
            !html.contains("onclick"),
            "html must not contain inline onclick: {html}"
        );
        assert!(
            !html.contains("http://") && !html.contains("https://"),
            "html must not reference external urls: {html}"
        );
    }

    #[test]
    fn caveat_is_absent_when_intent_is_trusted() {
        let intent = ProjectIntent::from_requirements(vec![sure_core::intent::Requirement::new(
            "r1",
            "build a thing",
            sure_core::intent::IntentSource::ExplicitUserGoal,
        )]);
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate: green_aggregate(),
            intent,
            capability: CapabilityReport::cli(),
            findings: Vec::new(),
            not_checked: Vec::new(),
            claim_checks: Vec::new(),
        };
        let md = render_markdown(&verdict);
        let html = render_html(&verdict);
        assert!(
            !md.contains("cannot confirm that it matches your original request"),
            "caveat must not appear in markdown: {md}"
        );
        assert!(
            !html.contains("cannot confirm that it matches your original request"),
            "caveat must not appear in html: {html}"
        );
    }

    #[test]
    fn empty_verdict_has_no_findings_and_no_not_checked() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let md = render_markdown(&verdict);
        let html = render_html(&verdict);

        assert!(
            md.contains("No unresolved findings."),
            "markdown must say no findings: {md}"
        );
        assert!(
            !md.contains("Could not check"),
            "markdown must not have not-checked section: {md}"
        );

        assert!(
            html.contains("No unresolved findings."),
            "html must say no findings: {html}"
        );
        assert!(
            !html.contains("id=\"not-checked\""),
            "html must not have not-checked section: {html}"
        );
    }

    #[test]
    fn reduced_coverage_caveat_appears_when_analysis_provider_is_disabled() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "semantic intent match",
            Severity::ShouldFixFirst,
            true,
            NotCheckedReason::AnalysisProviderDisabled,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let md = render_markdown(&verdict);
        let html = render_html(&verdict);

        assert!(
            md.contains("Model-backed analysis is disabled"),
            "markdown should note reduced coverage: {md}"
        );
        assert!(
            md.contains("deterministic checks only"),
            "markdown should say coverage is limited to deterministic checks: {md}"
        );
        assert!(
            html.contains("Model-backed analysis is disabled"),
            "html should note reduced coverage: {html}"
        );
        assert!(
            html.contains("semantic intent match"),
            "html should list the disabled check: {html}"
        );
    }

    fn a_claim(assessment: ClaimAssessment, text: &str) -> Claim {
        Claim {
            id: ClaimId::generate(),
            claim_text: text.to_owned(),
            claim_type: "test_ran".to_owned(),
            assessment,
            reason: String::from("A recorded harness event supports this claim."),
            evidence: Vec::new(),
            session: None,
        }
    }

    #[test]
    fn markdown_claim_section_appears_when_claim_checks_exist() {
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate: green_aggregate(),
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings: Vec::new(),
            not_checked: Vec::new(),
            claim_checks: vec![a_claim(ClaimAssessment::Confirmed, "I ran the tests")],
        };
        let md = render_markdown(&verdict);
        assert!(md.contains("## AI claims"), "{md}");
        assert!(md.contains("I ran the tests"), "{md}");
        assert!(md.contains("Confirmed"), "{md}");
    }

    #[test]
    fn html_claim_section_is_escaped() {
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate: green_aggregate(),
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings: Vec::new(),
            not_checked: Vec::new(),
            claim_checks: vec![a_claim(
                ClaimAssessment::Confirmed,
                "I ran the tests<script>",
            )],
        };
        let html = render_html(&verdict);
        assert!(html.contains("id=\"claims\""), "{html}");
        assert!(
            !html.contains("I ran the tests<script>"),
            "unescaped script tag must not appear: {html}"
        );
        assert!(html.contains("I ran the tests&lt;script&gt;"), "{html}");
    }
}
