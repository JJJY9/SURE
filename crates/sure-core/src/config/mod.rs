//! `sure.yaml`: what a project asks SURE to do.
//!
//! A parsed [`Config`] is **a request, not a grant**. The file it comes from is
//! controlled by the project being checked, which may be controlled by the same
//! AI whose work is under evaluation, so `docs/architecture/CONFIG_AUTHORITY.md`
//! treats it as untrusted input. This module's job is to read it truthfully:
//! every setting that would widen what SURE may do is reported by
//! [`Config::requested_privileges`], and the authority layer resolves those
//! against the user's own configuration before any of them takes effect.
//!
//! Three properties hold here, and each is covered by tests:
//!
//! 1. **An invalid file stops the run.** There is no fallback to defaults. A
//!    file SURE could not understand is not the same as a file that was absent,
//!    and quietly using defaults would apply settings the user did not choose.
//! 2. **Nothing is silently dropped.** Unknown settings and contradictory ones
//!    are errors, because a setting that was ignored looks exactly like one that
//!    was applied.
//! 3. **No credential passes through.** The model has no field that accepts
//!    one, a credential-shaped key stops the read, and any value that reaches a
//!    message is redacted first.

mod values;

pub mod authority;
pub mod error;
pub mod services;

pub use authority::{Authority, ExecutionSettings, Layer, Privilege, Resolved};
pub use error::{ConfigError, ErrorKind, Location};
pub use services::{Launcher, ServiceDeclaration};
pub use values::{
    AnalysisProvider, CheckPreference, PrivacyMode, ProjectRequest, ProtectionMode,
    RedactionConfig, ReportFormat, ScopeReduction,
};

use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::redact;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use sure_domain::execution::ExecutionMode;
use sure_domain::intent::IntentSource;

/// Why `privacy.mode: cloud_enhanced` is refused.
const CLOUD_ENHANCED_EXPLANATION: &str = "Cloud-enhanced analysis and sync are \
     described in the privacy documentation as a future mode, and nothing in this release \
     implements them. Accepting the setting would let a project file claim a privacy \
     arrangement SURE does not actually provide.";

/// What to write instead of `privacy.mode: cloud_enhanced`.
const CLOUD_ENHANCED_INSTEAD: &str = "Use `local_first` to keep evidence here and allow \
     external analysis only where it is configured, or `fully_local` to send nothing out at all.";

/// Why `protection.mode: custom` is refused.
///
/// `pub(crate)` because the decision path says the same thing when the value
/// reaches it anyway: one value, one explanation, in both places a user can
/// meet it (`crate::hook_protection`).
pub(crate) const CUSTOM_PROTECTION_EXPLANATION: &str = "Custom protection rules need a rule \
     editor and a rule format, neither of which exists in this release. Accepting the setting \
     would leave the project believing it had protections that were never applied.";

/// What to write instead of `protection.mode: custom`.
pub(crate) const CUSTOM_PROTECTION_INSTEAD: &str = "Use `standard` or `strict`; both are \
     implemented and are described in `docs/security/PROTECTION_MODE.md`.";

/// Why a provider setting cannot be combined with `provider: disabled`.
const DISABLED_PROVIDER_EXPLANATION: &str = "No model is consulted when the provider is \
     disabled, so the setting could never take effect. Leaving it in place would suggest \
     analysis is configured when it is not.";

/// Why `privacy.mode: fully_local` excludes the named external providers.
const FULLY_LOCAL_EXPLANATION: &str = "Fully-local means no project content leaves this \
     machine. Both of the named external providers send what they are given to a service.";

/// Why a permission cannot be granted under `inspect_only`.
const INSPECT_ONLY_EXPLANATION: &str = "`inspect_only` runs none of the project's code, so \
     nothing could ever use this permission. It would read as an allowance SURE does not have.";

/// Privacy settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfig {
    /// How much of the project's activity may be kept.
    pub mode: PrivacyMode,
    /// Whether full prompts, responses and terminal output are stored.
    ///
    /// Off by default, and opt-in, per `docs/security/PRIVACY.md`.
    pub full_recording: bool,
    /// Whether usage data may be sent anywhere. There is no telemetry in this
    /// release, so `true` is a request rather than a behaviour.
    ///
    /// Off by default, and opt-in, per `docs/security/PRIVACY.md`.
    pub telemetry: bool,
    /// How many days a full recording is kept, when `full_recording` is on.
    ///
    /// `None` — the value a file that does not name this setting has — means
    /// "whatever this layer above me allows, or
    /// [`crate::full_recording::DEFAULT_FULL_RECORDING_RETENTION_DAYS`] if
    /// nobody named one". It is `Option` rather than a plain number with a
    /// default for exactly that reason: a file that says nothing and a file
    /// that says `3` are different statements, and only the second one is a
    /// choice the user made. Folding them together would let a project that
    /// mentioned nothing override a user who asked for 30 days.
    ///
    /// This is a *restriction*, not a privilege, and it resolves the way
    /// protection and privacy mode do — towards less retention — with one
    /// asymmetry those two do not have: the user may name **any** number of
    /// days, including one larger than the default, because a person may
    /// decide to keep their own machine's records for longer. A project file
    /// may only ever shorten what the user set; naming a longer period is a
    /// refused escalation ([`ProjectRequest::ExtendedRetention`]), because
    /// "recording more is not running more" and a repository the user merely
    /// opened may not extend how long their own activity is kept. See
    /// [`crate::config::authority::Authority::full_recording_retention_days`].
    pub full_recording_retention_days: Option<i64>,
}

/// Protection settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectionConfig {
    /// How firmly SURE intervenes before a risky action.
    pub mode: ProtectionMode,
}

/// Execution trust settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionConfig {
    /// How much of the project's code may run.
    ///
    /// `ExecutionMode` deliberately has no `Default`, so the mode has to be
    /// named here rather than inherited. Host execution without an explicit
    /// grant is a bug, not a default
    /// (`docs/architecture/EXECUTION_SAFETY.md`).
    pub mode: ExecutionMode,
    /// Whether dependencies may be installed.
    pub allow_dependency_install: bool,
    /// Whether checks may reach the network.
    pub allow_network: bool,
    /// Whether SURE may change files inside the project: write them, or delete
    /// them.
    ///
    /// The key that makes
    /// [`Permission::WriteProject`](sure_domain::execution::Permission::WriteProject)
    /// reachable, and with it the protection mode's own rule about a change.
    /// Without a grant the mode is never consulted for a write or a delete —
    /// `decide` refuses on the missing permission first — so `standard` and
    /// `strict` answer an ordinary change identically and every sentence
    /// `docs/security/PROTECTION_MODE.md` writes about *which* changes `strict`
    /// holds describes nothing a run can reach.
    ///
    /// **A user's own file is the only layer that can grant this.** It is a
    /// [`ProjectRequest`] like the two above, so a project's `sure.yaml` that
    /// names it leaves a refused escalation rather than an authorisation: a
    /// repository the user merely opened does not get to decide that the agent
    /// working in it may rewrite that repository.
    pub allow_project_write: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            // Inspect-only, per `docs/architecture/EXECUTION_SAFETY.md`: host
            // execution without an explicit grant is a bug, not a default.
            mode: ExecutionMode::InspectOnly,
            allow_dependency_install: false,
            allow_network: false,
            // And a change to the project's files without an explicit grant is
            // the same kind of bug: SURE does not edit a project unasked.
            allow_project_write: false,
        }
    }
}

/// Model and analysis provider settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    /// Which provider, if any, may be consulted.
    pub provider: AnalysisProvider,
    /// The endpoint for a provider that needs one.
    pub endpoint: Option<String>,
    /// The model name for a provider that needs one.
    pub model: Option<String>,
    /// The command for the local-command provider.
    ///
    /// The first element is the program and the rest are arguments, one element
    /// per argument. SURE does not split a string into a command line, so this
    /// must be written as a YAML list.
    pub command: Option<Vec<String>>,
}

/// What the project says it is for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectIntentConfig {
    /// A goal written directly into the configuration file.
    pub goal: Option<String>,
    /// A path, relative to the project, to a specification document.
    pub spec_path: Option<String>,
}

/// Which optional checks the project wants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChecksConfig {
    /// Whether the project's own test suite is part of the plan.
    pub existing_tests: bool,
    /// Whether local services may be started to check them.
    pub start_local_services: CheckPreference,
    /// Whether the interface may be checked in a real browser.
    pub browser_probe: CheckPreference,
    /// The local services this project declares, each one a launcher SURE knows
    /// rather than a command line.
    ///
    /// **A list of declarations and not of commands**, which is the whole of
    /// what [`services`] is about. Each entry becomes at most two checks — start
    /// it, and look at a page on it — and the two `checks.*` preferences above
    /// govern whether either is planned. What a project declares here is a
    /// request; the execution mode and the permissions come from the user's own
    /// settings, exactly as they do for every other check in the plan.
    ///
    /// Empty by default, and this is a **setting a project may only add to**:
    /// it can ask for a check that would not otherwise be planned, and it cannot
    /// move the mode under which that check would run.
    pub services: Vec<ServiceDeclaration>,
}

impl Default for ChecksConfig {
    fn default() -> Self {
        Self {
            existing_tests: true,
            start_local_services: CheckPreference::default(),
            browser_probe: CheckPreference::default(),
            services: Vec::new(),
        }
    }
}

/// What the scan reads, as a person decides it.
///
/// **Only the user's own settings file may fill this in.** An exclusion narrows
/// what SURE looks at, and the project being checked may be controlled by the AI
/// whose work is under evaluation (ADR 0011): a project file that could exclude
/// `src/` would be a way to hide the evidence a finding would come from.
/// [`Authority::load`](crate::config::authority::Authority::load) refuses a
/// project file that names this section.
///
/// The excludes are keyed by project, because a person's reason for not reading
/// `out/` in one repository says nothing about another. Paths are relative to
/// the project root.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    /// Paths the user asked SURE not to read, keyed by project root.
    ///
    /// A matching project root's list names project-relative paths; naming a
    /// directory leaves out everything inside it. The scan reports each excluded
    /// path as a declared scope skip rather than dropping it silently.
    pub exclude: BTreeMap<String, Vec<String>>,
}

/// How reports are written out.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportConfig {
    /// Human-readable or machine-readable.
    pub format: ReportFormat,
}

/// The settings a project asks SURE to use.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Privacy and recording.
    pub privacy: PrivacyConfig,
    /// Pre-action protection.
    pub protection: ProtectionConfig,
    /// Execution trust.
    pub execution: ExecutionConfig,
    /// Model and analysis provider.
    pub analysis: AnalysisConfig,
    /// What the project says it is for.
    pub project_intent: ProjectIntentConfig,
    /// Optional checks.
    pub checks: ChecksConfig,
    /// Report output.
    pub report: ReportConfig,
    /// Extra redaction rules.
    pub redaction: RedactionConfig,
    /// What the scan reads, as the person decided it.
    pub scan: ScanConfig,
}

/// Where a [`LoadedConfig`] came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// No configuration file was present, so every setting is a default.
    NoFile,
    /// The settings were read from this file.
    File(PathBuf),
}

impl ConfigSource {
    /// Whether a file was read.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

/// A configuration and the record of where it came from.
///
/// The provenance is not decoration. A report that says "running tests was
/// turned off" is only useful if it can also say whether the user turned it off
/// or the project did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
    /// The settings.
    pub config: Config,
    /// Where they came from.
    pub source: ConfigSource,
    /// The path SURE looked at, whether or not it existed.
    pub searched: PathBuf,
}

impl Config {
    /// The file SURE reads from a project.
    pub const FILE_NAME: &'static str = "sure.yaml";

    /// A near-miss name that is worth an explicit error rather than silence.
    pub const NEAR_MISS_FILE_NAME: &'static str = "sure.yml";

    /// Parse a configuration from YAML text.
    ///
    /// A file that is empty, or contains only comments, is not an error: it
    /// declares no settings, which is exactly what the defaults describe.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] for text that is not YAML, YAML that is not a
    /// set of settings, a setting SURE does not know, a value it does not
    /// accept, a credential-shaped name, or a combination of settings that
    /// cannot all take effect.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        // Editors on Windows write a byte-order mark by default. A parser
        // reading it as content would reject the whole file, and the user would
        // be told their configuration is malformed when it is not.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);

        let value: Value = serde_yaml_ng::from_str(text).map_err(malformed)?;
        match &value {
            Value::Null => return Ok(Self::default()),
            Value::Mapping(_) => {}
            other => {
                return Err(ConfigError::new(ErrorKind::NotSettings {
                    shape: shape_of(other),
                }));
            }
        }

        if let Some(setting) = credential_setting(&value) {
            return Err(ConfigError::new(ErrorKind::Credential { setting }));
        }

        let config: Self = serde_yaml_ng::from_str(text).map_err(unacceptable)?;
        config.validate()?;
        Ok(config)
    }

    /// Read `sure.yaml` from a project.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if the file is present but cannot be used, or
    /// if a file named `sure.yml` is present instead. A missing file is not an
    /// error — it means the project has declared nothing, and the defaults are
    /// reported as [`ConfigSource::NoFile`] so a report can say so.
    pub fn load(project_root: &Path) -> Result<LoadedConfig, ConfigError> {
        Self::load_file(&project_root.join(Self::FILE_NAME))
    }

    /// Read a `sure.yaml` at exactly this path.
    ///
    /// The same file, read from somewhere other than a project root — the
    /// user's own configuration lives in the platform's config directory and is
    /// the same format, so it is read by the same code rather than by a second
    /// reader that would drift from this one.
    ///
    /// The near-miss check follows the *file name*, not the directory: a
    /// `sure.yml` beside the path SURE was told to read is the same mistake
    /// wherever that path is.
    ///
    /// # Errors
    ///
    /// As [`Config::load`].
    pub fn load_file(path: &Path) -> Result<LoadedConfig, ConfigError> {
        // The read decides, rather than a separate `is_file` probe. A probe asks
        // a different question from the one that matters, and the two can
        // disagree: a directory, a locked file or a denied path all exist but
        // cannot be read, and treating those as "no configuration file" would
        // run with defaults while the user believes their settings are in force.
        let Some(text) = read_if_present(path)? else {
            if let Some(near_miss) = near_miss_beside(path) {
                // Silently ignoring this file is the worst option available:
                // the user believes their settings are in force and SURE is
                // running with defaults.
                return Err(ConfigError::new(ErrorKind::WrongFileName {
                    found: near_miss.clone(),
                    expected: path.to_path_buf(),
                })
                .at_file(&near_miss));
            }
            return Ok(LoadedConfig {
                config: Self::default(),
                source: ConfigSource::NoFile,
                searched: path.to_path_buf(),
            });
        };

        let config = Self::from_yaml(&text).map_err(|error| error.at_file(path))?;
        Ok(LoadedConfig {
            config,
            source: ConfigSource::File(path.to_path_buf()),
            searched: path.to_path_buf(),
        })
    }

    /// The list of behaviours this file asks for that it cannot grant.
    ///
    /// Empty for a configuration that asks for nothing beyond reading. The
    /// authority layer decides what to do with each; nothing here takes effect
    /// on its own.
    #[must_use]
    pub fn requested_privileges(&self) -> Vec<ProjectRequest> {
        let mut requests = Vec::new();
        if self.execution.mode != ExecutionMode::InspectOnly {
            requests.push(ProjectRequest::RunProjectCode);
        }
        if self.execution.allow_dependency_install {
            requests.push(ProjectRequest::InstallDependencies);
        }
        if self.execution.allow_network {
            requests.push(ProjectRequest::Network);
        }
        if self.execution.allow_project_write {
            requests.push(ProjectRequest::WriteProject);
        }
        if self.privacy.full_recording {
            requests.push(ProjectRequest::FullRecording);
        }
        if self.privacy.telemetry {
            requests.push(ProjectRequest::Telemetry);
        }
        if self.analysis.provider.is_external() {
            requests.push(ProjectRequest::ExternalAnalysis);
        }
        requests
    }

    /// The settings that make SURE check less than it otherwise would.
    ///
    /// These are permitted — a project may switch off checks it does not want —
    /// but the report must state them, so that "every check passed" cannot be
    /// read as "everything was checked".
    #[must_use]
    pub fn scope_reductions(&self) -> Vec<ScopeReduction> {
        let mut reductions = Vec::new();
        if !self.checks.existing_tests {
            reductions.push(ScopeReduction::ExistingTestsDisabled);
        }
        if self.checks.start_local_services.disables() {
            reductions.push(ScopeReduction::LocalServicesDisabled);
        }
        if self.checks.browser_probe.disables() {
            reductions.push(ScopeReduction::BrowserProbeDisabled);
        }
        reductions
    }

    /// The trust level to attach to a goal read from a project configuration
    /// file.
    ///
    /// Always [`IntentSource::ProjectSpec`], which is documentation, not a user
    /// requirement: a file inside the project can be written by the same agent
    /// whose work is being checked. This is why the constant is here rather
    /// than left to each caller — a goal read from `sure.yaml` must never
    /// become the standard against which "everything you asked for is done" is
    /// claimed.
    #[must_use]
    pub const fn goal_source() -> IntentSource {
        IntentSource::ProjectSpec
    }

    /// Reject combinations that cannot all take effect.
    fn validate(&self) -> Result<(), ConfigError> {
        self.validate_available_features()?;
        self.validate_analysis()?;
        self.validate_privacy_and_analysis()?;
        self.validate_execution()?;
        self.validate_intent()?;
        self.validate_redaction()
    }

    /// Build a [`crate::redact::Redactor`] from the built-in detectors plus the
    /// rules configured in this file.
    ///
    /// The configuration is already validated before this is called, so the
    /// regex patterns compile.
    #[must_use]
    pub fn redactor(&self) -> crate::redact::Redactor {
        let mut redactor = crate::redact::Redactor::new();
        for secret in &self.redaction.literals {
            redactor.add_literal_secret(secret.clone());
        }
        for pattern in &self.redaction.patterns {
            // Validation already proved this compiles; expect is unreachable.
            #[allow(
                clippy::expect_used,
                reason = "validated in Config::validate_redaction"
            )]
            let compiled = Regex::new(pattern).expect("validated redaction pattern");
            redactor.add_pattern(compiled);
        }
        redactor
    }

    /// Compile every configured redaction pattern so that a bad pattern stops
    /// the run rather than failing silently later.
    fn validate_redaction(&self) -> Result<(), ConfigError> {
        for (index, pattern) in self.redaction.patterns.iter().enumerate() {
            if let Err(error) = Regex::new(pattern) {
                return Err(ConfigError::new(ErrorKind::InvalidPattern {
                    setting: format!("redaction.patterns[{index}]"),
                    message: error.to_string(),
                }));
            }
        }
        Ok(())
    }

    /// Modes documented as user-facing but not implemented in this release.
    fn validate_available_features(&self) -> Result<(), ConfigError> {
        if !self.privacy.mode.is_available() {
            return Err(ConfigError::new(ErrorKind::NotAvailable {
                name: "privacy.mode".to_owned(),
                value: self.privacy.mode.as_str().to_owned(),
                explanation: CLOUD_ENHANCED_EXPLANATION,
                instead: CLOUD_ENHANCED_INSTEAD,
            }));
        }
        if !self.protection.mode.is_available() {
            return Err(ConfigError::new(ErrorKind::NotAvailable {
                name: "protection.mode".to_owned(),
                value: self.protection.mode.as_str().to_owned(),
                explanation: CUSTOM_PROTECTION_EXPLANATION,
                instead: CUSTOM_PROTECTION_INSTEAD,
            }));
        }
        Ok(())
    }

    /// Why a command setting cannot be combined with a provider other than
    /// local-command.
    const NON_LOCAL_COMMAND_EXPLANATION: &str = "A command is only used by the \
         local-command provider. With any other provider the setting could never \
         take effect.";

    /// Provider settings that could never take effect, and endpoints that
    /// carry a credential.
    fn validate_analysis(&self) -> Result<(), ConfigError> {
        if !self.analysis.provider.uses_a_model() {
            for (name, present) in [
                ("analysis.endpoint", self.analysis.endpoint.is_some()),
                ("analysis.model", self.analysis.model.is_some()),
                ("analysis.command", self.analysis.command.is_some()),
            ] {
                if present {
                    return Err(ConfigError::new(ErrorKind::Contradiction {
                        first: "analysis.provider".to_owned(),
                        second: name.to_owned(),
                        explanation: DISABLED_PROVIDER_EXPLANATION,
                    }));
                }
            }
        }

        if self.analysis.provider != AnalysisProvider::LocalCommand
            && self.analysis.command.is_some()
        {
            return Err(ConfigError::new(ErrorKind::Contradiction {
                first: "analysis.provider".to_owned(),
                second: "analysis.command".to_owned(),
                explanation: Self::NON_LOCAL_COMMAND_EXPLANATION,
            }));
        }

        if let Some(endpoint) = &self.analysis.endpoint {
            if has_userinfo(endpoint) {
                // The value is deliberately not repeated, not even redacted:
                // there is no reason for a credential to reach an error message
                // at all when the setting itself is the problem.
                return Err(ConfigError::new(ErrorKind::Credential {
                    setting: "analysis.endpoint".to_owned(),
                }));
            }
            if !is_absolute_http_url(endpoint) {
                return Err(ConfigError::new(ErrorKind::BadValue {
                    name: Some("analysis.endpoint".to_owned()),
                    value: redact::redact_for_diagnostic(endpoint),
                    expected: vec!["a URL beginning with https:// or http://".to_owned()],
                    suggestion: None,
                }));
            }
        }
        Ok(())
    }

    /// A privacy mode that promises less exposure than the provider delivers,
    /// and a retention period that is not a period.
    fn validate_privacy_and_analysis(&self) -> Result<(), ConfigError> {
        if !self.privacy.mode.allows_external_analysis() && self.analysis.provider.is_external() {
            return Err(ConfigError::new(ErrorKind::Contradiction {
                first: "privacy.mode".to_owned(),
                second: "analysis.provider".to_owned(),
                explanation: FULLY_LOCAL_EXPLANATION,
            }));
        }
        if let Some(days) = self.privacy.full_recording_retention_days
            && days < 0
        {
            return Err(ConfigError::new(ErrorKind::BadValue {
                name: Some("privacy.full_recording_retention_days".to_owned()),
                value: days.to_string(),
                expected: vec![String::from("0 or more days")],
                suggestion: Some(String::from("0")),
            }));
        }
        Ok(())
    }

    /// Permissions that the chosen execution mode can never use.
    fn validate_execution(&self) -> Result<(), ConfigError> {
        if self.execution.mode != ExecutionMode::InspectOnly {
            return Ok(());
        }
        for (name, granted) in [
            (
                "execution.allow_dependency_install",
                self.execution.allow_dependency_install,
            ),
            ("execution.allow_network", self.execution.allow_network),
        ] {
            if granted {
                return Err(ConfigError::new(ErrorKind::Contradiction {
                    first: "execution.mode".to_owned(),
                    second: name.to_owned(),
                    explanation: INSPECT_ONLY_EXPLANATION,
                }));
            }
        }
        Ok(())
    }

    /// A goal that is not a goal, and a path that leaves the project.
    fn validate_intent(&self) -> Result<(), ConfigError> {
        if let Some(goal) = &self.project_intent.goal
            && goal.trim().is_empty()
        {
            return Err(ConfigError::new(ErrorKind::BadValue {
                name: Some("project_intent.goal".to_owned()),
                value: String::new(),
                expected: vec![
                    "a description of what the project is for, or no goal at all".to_owned(),
                ],
                suggestion: None,
            }));
        }
        if let Some(spec_path) = &self.project_intent.spec_path
            && !is_inside_project(spec_path)
        {
            return Err(ConfigError::new(ErrorKind::OutsideProject {
                name: "project_intent.spec_path".to_owned(),
                value: redact::redact_for_diagnostic(spec_path),
            }));
        }
        Ok(())
    }
}

/// What a YAML document is, when it is not a set of settings.
const fn shape_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "empty",
        Value::Bool(_) => "a single true-or-false value",
        Value::Number(_) => "a single number",
        Value::String(_) => "a single value",
        Value::Sequence(_) => "a list",
        Value::Mapping(_) => "a set of settings",
        Value::Tagged(_) => "a tagged value",
    }
}

/// The `sure.yml` beside `path`, when that file exists and `path` does not.
///
/// A path with no file name, or a file name that is not the one SURE reads, has
/// no near-miss: `sure.yml` is only a mistake as a *spelling* of `sure.yaml`.
fn near_miss_beside(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    if name != Config::FILE_NAME {
        return None;
    }
    let near_miss = path.with_file_name(Config::NEAR_MISS_FILE_NAME);
    near_miss.is_file().then_some(near_miss)
}

/// Read a configuration file, or report that it is not there.
///
/// `Ok(None)` means the file is absent, which is not a failure. Every other
/// outcome — including a path that exists but cannot be read as a file — is
/// returned as an error rather than folded into "absent".
fn read_if_present(path: &Path) -> Result<Option<String>, ConfigError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ConfigError::new(ErrorKind::Unreadable {
                // The operating system describes a directory as an access
                // failure, which sends the user looking for a permission
                // problem they do not have.
                message: if path.is_dir() {
                    "it is a directory, not a file".to_owned()
                } else {
                    error.to_string()
                },
            })
            .at_file(path));
        }
    };
    let text =
        String::from_utf8(bytes).map_err(|_| ConfigError::new(ErrorKind::NotUtf8).at_file(path))?;
    Ok(Some(text))
}

/// Turn a YAML parse failure into a [`ConfigError`].
///
/// A failure to parse is not always a syntax problem: the parser is also what
/// refuses a setting written twice, and that deserves its own message rather
/// than being reported as broken YAML.
fn malformed(error: serde_yaml_ng::Error) -> ConfigError {
    let location = error
        .location()
        .map(|l| Location::new(l.line(), l.column()));
    let message = parser_message(&error.to_string());
    let (path, tail) = split_path(&message);
    let kind = classify(path, tail).unwrap_or(ErrorKind::Malformed { message });
    let error = ConfigError::new(kind);
    match location {
        Some(location) => error.at(location),
        None => error,
    }
}

/// Turn a deserialization failure into a [`ConfigError`].
fn unacceptable(error: serde_yaml_ng::Error) -> ConfigError {
    let location = error
        .location()
        .map(|l| Location::new(l.line(), l.column()));
    let message = parser_message(&error.to_string());
    let (path, tail) = split_path(&message);
    let kind = classify(path, tail).unwrap_or_else(|| ErrorKind::BadValue {
        name: path.map(str::to_owned),
        value: tail.to_owned(),
        expected: Vec::new(),
        suggestion: None,
    });
    let error = ConfigError::new(kind);
    match location {
        Some(location) => error.at(location),
        None => error,
    }
}

/// Split the `some.setting: ` prefix serde puts in front of its own message.
///
/// The prefix is what makes a failure attributable: without it a user is told
/// a value is wrong without being told which setting holds it.
fn split_path(message: &str) -> (Option<&str>, &str) {
    match message.split_once(": ") {
        Some((head, tail)) if looks_like_setting_path(head) => (Some(head), tail),
        _ => (None, message),
    }
}

/// Whether the text before a colon names a setting rather than being prose.
fn looks_like_setting_path(head: &str) -> bool {
    !head.is_empty()
        && head.len() <= 128
        && head.starts_with(|c: char| c.is_ascii_alphabetic())
        && head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Recognise the failures SURE has a specific message for.
///
/// Reading another crate's prose is a real coupling, taken on deliberately:
/// without it a user is told "unknown field" and left to guess the spelling or
/// the file position. It is also safe to get wrong — anything not recognised
/// falls back to the parser's own words, which are still accurate, just less
/// helpful. `serde_error_shapes_are_what_this_classifier_expects` pins each
/// shape, so a dependency upgrade shows up as a failing test rather than as a
/// quietly worse message.
fn classify(path: Option<&str>, tail: &str) -> Option<ErrorKind> {
    let lower = tail.trim_start().to_ascii_lowercase();
    let tokens = quoted(tail);
    let under = |name: &str| match path {
        Some(parent) => format!("{parent}.{name}"),
        None => name.to_owned(),
    };

    if lower.starts_with("unknown field") {
        let field = tokens.first()?;
        let expected = tokens[1..].to_vec();
        return Some(ErrorKind::UnknownSetting {
            name: under(field),
            suggestion: closest(field, &expected).map(str::to_owned),
            expected,
        });
    }

    if lower.starts_with("unknown variant") {
        let value = tokens.first()?.clone();
        let expected = tokens[1..].to_vec();
        return Some(ErrorKind::BadValue {
            name: path.map(str::to_owned),
            suggestion: closest(&value, &expected).map(str::to_owned),
            value,
            expected,
        });
    }

    if lower.starts_with("duplicate entry with key") {
        return Some(ErrorKind::RepeatedSetting {
            name: under(tokens.first()?),
        });
    }

    if lower.starts_with("invalid type") {
        let (value, expected) = invalid_type(tail)?;
        return Some(ErrorKind::BadValue {
            name: path.map(str::to_owned),
            value,
            expected: plain_expectation(&expected),
            suggestion: None,
        });
    }

    None
}

/// Read `invalid type: <what it was>, expected <what it wanted>`.
fn invalid_type(tail: &str) -> Option<(String, String)> {
    let (_, rest) = tail.split_once(": ")?;
    let (found, expected) = rest.split_once(", expected ")?;
    let value = quoted(found)
        .into_iter()
        .next()
        .unwrap_or_else(|| found.trim().to_owned());
    Some((value, expected.trim().to_owned()))
}

/// Rewrite serde's description of what it wanted into words a user can act on.
fn plain_expectation(expected: &str) -> Vec<String> {
    let lower = expected.to_ascii_lowercase();
    if lower.contains("boolean") {
        // YAML 1.1 read `yes`, `no`, `on` and `off` as booleans; YAML 1.2 does
        // not, so a user carrying the habit writes a string and is told the
        // types do not match. Naming the two values settles it in one line.
        return vec!["true".to_owned(), "false".to_owned()];
    }
    if lower.starts_with("struct ") {
        return vec!["a group of settings".to_owned()];
    }
    if lower == "a string" || lower == "string" {
        return vec!["text".to_owned()];
    }
    vec![expected.to_owned()]
}

/// Every quoted span in a message, in order.
///
/// The two delimiters are not interchangeable: serde quotes names in backticks
/// and values in double quotes, while the YAML parser quotes a repeated key
/// name in double quotes.
fn quoted(message: &str) -> Vec<String> {
    let backticked = spans(message, '`');
    if backticked.is_empty() {
        return spans(message, '"');
    }
    backticked
}

/// The text between each pair of `delimiter` characters.
fn spans(message: &str, delimiter: char) -> Vec<String> {
    message
        .split(delimiter)
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The parser's description of a failure, without the position it appends.
///
/// The position is carried in [`ConfigError::location`], and a message that
/// stated it twice would look like two separate problems.
fn parser_message(text: &str) -> String {
    match text.find(" at line ") {
        Some(index) => text[..index].trim_end().to_owned(),
        None => text.trim().to_owned(),
    }
}

/// The closest of `candidates` to `input`, when one is close enough to be a
/// typo rather than a different word.
fn closest<'a>(input: &str, candidates: &'a [String]) -> Option<&'a str> {
    let limit = (input.chars().count() / 3).max(1);
    candidates
        .iter()
        .map(|candidate| (edit_distance(input, candidate), candidate))
        .filter(|(distance, _)| *distance <= limit)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate.as_str())
}

/// Levenshtein distance, counted in characters so that non-ASCII names do not
/// inflate the result.
fn edit_distance(left: &str, right: &str) -> usize {
    let right_chars: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right_chars.len()).collect();
    let mut current: Vec<usize> = vec![0; right_chars.len() + 1];

    for (row, left_char) in left.chars().enumerate() {
        current[0] = row + 1;
        for (column, right_char) in right_chars.iter().enumerate() {
            let substitution = previous[column] + usize::from(left_char != *right_char);
            current[column + 1] = substitution
                .min(previous[column + 1] + 1)
                .min(current[column] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right_chars.len()]
}

/// The dotted name of the first setting whose name looks like a credential.
///
/// This runs on the parsed document rather than on the typed settings, because
/// `deny_unknown_fields` reports an unrecognised name without saying whether it
/// looked like a secret — and the message for a secret has to be different.
fn credential_setting(value: &Value) -> Option<String> {
    fn walk(value: &Value, path: &mut Vec<String>) -> Option<String> {
        match value {
            Value::Mapping(mapping) => {
                for (key, child) in mapping {
                    let Value::String(name) = key else {
                        continue;
                    };
                    if redact::looks_like_credential_name(name) {
                        path.push(name.clone());
                        return Some(path.join("."));
                    }
                    path.push(name.clone());
                    if let Some(found) = walk(child, path) {
                        return Some(found);
                    }
                    path.pop();
                }
                None
            }
            Value::Sequence(items) => items.iter().find_map(|item| walk(item, path)),
            _ => None,
        }
    }
    walk(value, &mut Vec::new())
}

/// Whether a URL's authority carries a username or password.
fn has_userinfo(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
}

/// Whether the text is an absolute `http` or `https` URL SURE can hand to a
/// provider.
fn is_absolute_http_url(text: &str) -> bool {
    let rest = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"));
    match rest {
        Some(rest) => {
            !rest.is_empty() && !rest.starts_with('/') && !text.chars().any(char::is_whitespace)
        }
        None => false,
    }
}

/// Whether a project-relative path stays inside the project.
fn is_inside_project(text: &str) -> bool {
    let path = Path::new(text);
    if path.as_os_str().is_empty() {
        return false;
    }
    !path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn error_from(text: &str) -> ConfigError {
        Config::from_yaml(text).expect_err("this configuration should not be accepted")
    }

    #[test]
    fn the_default_configuration_is_the_safe_one() {
        let config = Config::default();
        assert_eq!(config.privacy.mode, PrivacyMode::LocalFirst);
        assert!(!config.privacy.full_recording);
        assert!(!config.privacy.telemetry);
        assert_eq!(config.protection.mode, ProtectionMode::Standard);
        assert_eq!(config.execution.mode, ExecutionMode::InspectOnly);
        assert!(!config.execution.allow_dependency_install);
        assert!(!config.execution.allow_network);
        assert_eq!(config.analysis.provider, AnalysisProvider::Disabled);
        assert!(config.analysis.endpoint.is_none());
        assert!(config.analysis.command.is_none());
        assert!(config.project_intent.goal.is_none());
        assert!(config.checks.existing_tests);
        assert_eq!(config.report.format, ReportFormat::Human);
        assert!(
            config.requested_privileges().is_empty(),
            "the default configuration asks for nothing"
        );
        assert!(config.scope_reductions().is_empty());
    }

    #[test]
    fn an_empty_file_is_the_default_configuration() {
        for text in ["", "   \n", "# only a comment\n", "---\n"] {
            assert_eq!(
                Config::from_yaml(text).expect("an empty document declares no settings"),
                Config::default(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_byte_order_mark_does_not_make_the_file_malformed() {
        // Windows editors add one by default; treating it as content would tell
        // the user their file is broken when it is not.
        let text = "\u{feff}report:\n  format: json\n";
        let config = Config::from_yaml(text).expect("a BOM is not content");
        assert_eq!(config.report.format, ReportFormat::Json);
    }

    #[test]
    fn every_documented_section_parses() {
        let text = "\
privacy:
  mode: local_first
  full_recording: false
  telemetry: false

protection:
  mode: strict

execution:
  mode: host_confirmed
  allow_dependency_install: true
  allow_network: true

analysis:
  provider: openai_compatible
  endpoint: https://models.example.com/v1
  model: example-large

project_intent:
  goal: A local bookmark manager.
  spec_path: docs/spec.md

checks:
  existing_tests: false
  start_local_services: never
  browser_probe: always

report:
  format: json
";
        let config = Config::from_yaml(text).expect("the documented shape must parse");
        assert_eq!(config.privacy.mode, PrivacyMode::LocalFirst);
        assert_eq!(config.protection.mode, ProtectionMode::Strict);
        assert_eq!(config.execution.mode, ExecutionMode::HostConfirmed);
        assert!(config.execution.allow_dependency_install);
        assert!(config.execution.allow_network);
        assert_eq!(config.analysis.provider, AnalysisProvider::OpenAiCompatible);
        assert_eq!(
            config.analysis.endpoint.as_deref(),
            Some("https://models.example.com/v1")
        );
        assert_eq!(config.analysis.model.as_deref(), Some("example-large"));
        assert_eq!(
            config.project_intent.goal.as_deref(),
            Some("A local bookmark manager.")
        );
        assert_eq!(
            config.project_intent.spec_path.as_deref(),
            Some("docs/spec.md")
        );
        assert!(!config.checks.existing_tests);
        assert_eq!(config.checks.start_local_services, CheckPreference::Never);
        assert_eq!(config.checks.browser_probe, CheckPreference::Always);
        assert_eq!(config.report.format, ReportFormat::Json);
    }

    #[test]
    fn redaction_rules_parse_and_build_a_redactor() {
        let text = "\
redaction:
  literals:
    - project-internal-secret
    - another-secret
  patterns:
    - \\bsecret-\\d{4,}\\b
";
        let config = Config::from_yaml(text).expect("redaction settings must parse");
        assert_eq!(
            config.redaction.literals,
            vec![
                "project-internal-secret".to_owned(),
                "another-secret".to_owned()
            ]
        );
        assert_eq!(
            config.redaction.patterns,
            vec![r"\bsecret-\d{4,}\b".to_owned()]
        );

        let redactor = config.redactor();
        assert_eq!(redactor.redact("project-internal-secret here"), "*** here");
        assert_eq!(redactor.redact("token secret-1234"), "token ***");
    }

    #[test]
    fn an_invalid_redaction_pattern_is_refused() {
        // The pattern is quoted so YAML parses it as a string before regex
        // validation sees it; an unquoted '(' can be misread by the YAML parser.
        let error = error_from("redaction:\n  patterns:\n    - \"(\"\n");
        assert!(
            matches!(error.kind(), ErrorKind::InvalidPattern { setting, .. } if setting == "redaction.patterns[0]"),
            "{:?}",
            error.kind()
        );
    }

    #[test]
    fn a_partial_file_keeps_the_defaults_it_does_not_mention() {
        let config = Config::from_yaml("report:\n  format: json\n").expect("parse");
        assert_eq!(config.report.format, ReportFormat::Json);
        assert_eq!(config.privacy.mode, PrivacyMode::LocalFirst);
        assert_eq!(config.execution.mode, ExecutionMode::InspectOnly);
    }

    #[test]
    fn settings_survive_being_written_out_and_read_back() {
        // `sure config` prints these, and a printed configuration that does not
        // read back as itself would be a report of settings that are not the
        // settings in force.
        let original = Config::from_yaml(
            "privacy:\n  mode: fully_local\nexecution:\n  mode: container\nreport:\n  format: json\n",
        )
        .expect("parse");
        let text = serde_yaml_ng::to_string(&original).expect("serialize");
        let back = Config::from_yaml(&text).expect("re-parse");
        assert_eq!(back, original, "written out as:\n{text}");
    }

    // --- what the file asks for ------------------------------------------

    #[test]
    fn every_privileged_setting_is_reported_as_a_request() {
        // The completeness property that matters: there is no way to turn one of
        // these on without it appearing in the list the authority layer reads.
        let cases: &[(&str, ProjectRequest)] = &[
            (
                "execution:\n  mode: host_confirmed\n",
                ProjectRequest::RunProjectCode,
            ),
            (
                "execution:\n  mode: container\n",
                ProjectRequest::RunProjectCode,
            ),
            (
                "execution:\n  mode: host_confirmed\n  allow_dependency_install: true\n",
                ProjectRequest::InstallDependencies,
            ),
            (
                "execution:\n  allow_network: true\n  mode: host_confirmed\n",
                ProjectRequest::Network,
            ),
            (
                "privacy:\n  full_recording: true\n",
                ProjectRequest::FullRecording,
            ),
            ("privacy:\n  telemetry: true\n", ProjectRequest::Telemetry),
            (
                "analysis:\n  provider: claude_cli\n",
                ProjectRequest::ExternalAnalysis,
            ),
            (
                "analysis:\n  provider: openai_compatible\n  endpoint: https://m.example.com/v1\n",
                ProjectRequest::ExternalAnalysis,
            ),
        ];
        for (text, expected) in cases {
            let config = Config::from_yaml(text).unwrap_or_else(|error| {
                panic!("{text} should parse, got {error}");
            });
            assert!(
                config.requested_privileges().contains(expected),
                "{text} did not report {expected:?}: got {:?}",
                config.requested_privileges()
            );
        }
    }

    #[test]
    fn a_local_command_provider_is_not_reported_as_external() {
        // The command runs here. Whether it calls out is not something SURE can
        // see, and claiming either way would be a guess.
        let config = Config::from_yaml("analysis:\n  provider: local_command\n").expect("parse");
        assert!(
            !config
                .requested_privileges()
                .contains(&ProjectRequest::ExternalAnalysis)
        );
        assert_eq!(config.analysis.provider, AnalysisProvider::LocalCommand);
    }

    #[test]
    fn a_local_command_provider_can_carry_a_command_list() {
        // A command must be a list, one element per argument, so that SURE never
        // has to split a command line.
        let config =
            Config::from_yaml("analysis:\n  provider: local_command\n  command: [echo, hello]\n")
                .expect("parse");
        assert_eq!(config.analysis.provider, AnalysisProvider::LocalCommand);
        assert_eq!(
            config.analysis.command,
            Some(vec!["echo".to_owned(), "hello".to_owned()])
        );
    }

    #[test]
    fn switching_a_check_off_is_reported_as_a_reduction_in_scope() {
        let config = Config::from_yaml(
            "checks:\n  existing_tests: false\n  start_local_services: never\n  browser_probe: never\n",
        )
        .expect("parse");
        assert_eq!(
            config.scope_reductions(),
            vec![
                ScopeReduction::ExistingTestsDisabled,
                ScopeReduction::LocalServicesDisabled,
                ScopeReduction::BrowserProbeDisabled,
            ]
        );
    }

    #[test]
    fn a_goal_from_a_project_file_is_documentation_never_a_user_requirement() {
        let config =
            Config::from_yaml("project_intent:\n  goal: Ship the thing.\n").expect("parse");
        assert!(config.project_intent.goal.is_some());
        assert_eq!(Config::goal_source(), IntentSource::ProjectSpec);
        assert!(
            !Config::goal_source().is_user_requirement(),
            "a file inside the project may have been written by the agent being checked"
        );
    }

    // --- refusals ---------------------------------------------------------

    #[test]
    fn an_unknown_setting_is_refused_with_the_alternatives() {
        let error = error_from("execution:\n  modee: inspect_only\n");
        match error.kind() {
            ErrorKind::UnknownSetting {
                name,
                expected,
                suggestion,
            } => {
                assert_eq!(name, "execution.modee", "the message must name the setting");
                assert!(expected.contains(&"mode".to_owned()), "{expected:?}");
                assert_eq!(suggestion.as_deref(), Some("mode"));
            }
            other => panic!("expected an unknown setting, got {other:?}"),
        }
        let text = error.to_string();
        assert!(text.contains("Did you mean `mode`"), "{text}");
        assert!(text.contains("Settings available here"), "{text}");
    }

    #[test]
    fn an_unknown_setting_at_the_top_level_has_no_parent_to_name() {
        let error = error_from("excecution:\n  mode: inspect_only\n");
        match error.kind() {
            ErrorKind::UnknownSetting {
                name, suggestion, ..
            } => {
                assert_eq!(name, "excecution");
                assert_eq!(suggestion.as_deref(), Some("execution"));
            }
            other => panic!("expected an unknown setting, got {other:?}"),
        }
    }

    /// Classify a raw parser message the way the loader would.
    fn classified(raw: &str) -> Option<ErrorKind> {
        let message = parser_message(raw);
        let (path, tail) = split_path(&message);
        classify(path, tail)
    }

    #[test]
    fn serde_error_shapes_are_what_this_classifier_expects() {
        // Reading another crate's prose is a real coupling. This pins each
        // shape: if a serde upgrade changes the wording, the classifier falls
        // back to the parser's own words — accurate, but without the naming and
        // the "did you mean" line — and this test fails so that the regression
        // is a decision rather than a surprise.
        for (text, expected_name) in [
            ("execution:\n  modee: inspect_only\n", "execution.modee"),
            ("excecution:\n  mode: inspect_only\n", "excecution"),
        ] {
            let raw = serde_yaml_ng::from_str::<Config>(text)
                .expect_err("must fail")
                .to_string();
            match classified(&raw) {
                Some(ErrorKind::UnknownSetting { name, .. }) => {
                    assert_eq!(name, expected_name, "serde said {raw:?}");
                }
                other => panic!("serde said {raw:?}, which classified as {other:?}"),
            }
        }

        let raw = serde_yaml_ng::from_str::<Config>("report:\n  format: hman\n")
            .expect_err("must fail")
            .to_string();
        match classified(&raw) {
            Some(ErrorKind::BadValue { name, expected, .. }) => {
                assert_eq!(name.as_deref(), Some("report.format"), "serde said {raw:?}");
                assert!(expected.contains(&"human".to_owned()), "{expected:?}");
            }
            other => panic!("serde said {raw:?}, which classified as {other:?}"),
        }

        // The parser, not serde, is what refuses a key written twice, and it
        // says so in a different shape.
        let raw = serde_yaml_ng::from_str::<Value>("report:\n  format: json\n  format: human\n")
            .expect_err("must fail")
            .to_string();
        match classified(&raw) {
            Some(ErrorKind::RepeatedSetting { name }) => {
                assert_eq!(name, "report.format", "the parser said {raw:?}");
            }
            other => panic!("the parser said {raw:?}, which classified as {other:?}"),
        }
    }

    #[test]
    fn an_unrecognised_value_is_refused_with_the_alternatives() {
        let error = error_from("execution:\n  mode: host-confimed\n");
        match error.kind() {
            ErrorKind::BadValue {
                name,
                expected,
                suggestion,
                ..
            } => {
                assert_eq!(name.as_deref(), Some("execution.mode"));
                assert!(
                    expected.contains(&"host_confirmed".to_owned()),
                    "{expected:?}"
                );
                assert_eq!(suggestion.as_deref(), Some("host_confirmed"));
            }
            other => panic!("expected a bad value, got {other:?}"),
        }
        let text = error.to_string();
        assert!(text.contains("host_confirmed"), "{text}");
    }

    #[test]
    fn a_yaml_boolean_is_reported_as_the_two_values_that_work() {
        // YAML 1.1 read `yes`, `no`, `on` and `off` as booleans; YAML 1.2 does
        // not. A user carrying the older habit writes a string, and "invalid
        // type: string" leaves them to work out why.
        for word in ["yes", "no", "on", "off", "maybe"] {
            let error = error_from(&format!("checks:\n  existing_tests: {word}\n"));
            match error.kind() {
                ErrorKind::BadValue {
                    name,
                    expected,
                    value,
                    ..
                } => {
                    assert_eq!(name.as_deref(), Some("checks.existing_tests"));
                    assert_eq!(value, word);
                    assert_eq!(expected, &["true".to_owned(), "false".to_owned()]);
                }
                other => panic!("{word} gave {other:?}"),
            }
            let text = error.to_string();
            assert!(text.contains("Use one of: true, false"), "{text}");
        }
    }

    #[test]
    fn a_group_of_settings_written_as_a_value_is_described_in_plain_words() {
        let error = error_from("privacy: local_first\n");
        match error.kind() {
            ErrorKind::BadValue {
                name,
                value,
                expected,
                ..
            } => {
                assert_eq!(name.as_deref(), Some("privacy"));
                assert_eq!(value, "local_first");
                assert_eq!(expected, &["a group of settings".to_owned()]);
            }
            other => panic!("expected a bad value, got {other:?}"),
        }
        let text = error.to_string();
        assert!(
            !text.contains("struct "),
            "Rust jargon reached the user:\n{text}"
        );
    }

    #[test]
    fn a_typo_in_a_value_is_offered_a_correction() {
        let error = error_from("report:\n  format: hman\n");
        let text = error.to_string();
        assert!(text.contains("Did you mean \"human\""), "{text}");
    }

    #[test]
    fn a_document_that_is_not_settings_is_refused() {
        for (text, expected_shape) in [
            ("- one\n- two\n", "a list"),
            ("just a string\n", "a single value"),
            ("42\n", "a single number"),
            ("true\n", "a single true-or-false value"),
        ] {
            let error = error_from(text);
            match error.kind() {
                ErrorKind::NotSettings { shape } => assert_eq!(*shape, expected_shape),
                other => panic!("{text:?} gave {other:?}"),
            }
        }
    }

    #[test]
    fn malformed_yaml_reports_where_it_went_wrong() {
        let error = error_from("privacy:\n  mode: local_first\n   bad_indent: true\n");
        assert!(
            matches!(error.kind(), ErrorKind::Malformed { .. }),
            "{:?}",
            error.kind()
        );
        assert!(
            error.location().is_some(),
            "the parser knows the position and the user needs it"
        );
        let text = error.to_string();
        assert!(text.contains("line "), "{text}");
        // The position is reported once, not twice.
        assert_eq!(text.matches("line ").count(), 1, "{text}");
    }

    #[test]
    fn a_repeated_setting_is_not_resolved_by_taking_the_last_one() {
        // Last-one-wins is how a stricter setting gets silently replaced by a
        // looser one further down the file.
        let error = error_from("report:\n  format: json\n  format: human\n");
        match error.kind() {
            ErrorKind::RepeatedSetting { name } => assert_eq!(name, "report.format"),
            other => panic!("expected a repeated setting, got {other:?}"),
        }
        let text = error.to_string();
        assert!(text.contains("more than once"), "{text}");
        assert!(text.contains("report.format"), "{text}");
    }

    #[test]
    fn a_mode_this_release_does_not_implement_is_refused_rather_than_accepted() {
        let error = error_from("privacy:\n  mode: cloud_enhanced\n");
        match error.kind() {
            ErrorKind::NotAvailable { name, value, .. } => {
                assert_eq!(name, "privacy.mode");
                assert_eq!(value, "cloud_enhanced");
            }
            other => panic!("expected NotAvailable, got {other:?}"),
        }

        let error = error_from("protection:\n  mode: custom\n");
        match error.kind() {
            ErrorKind::NotAvailable { name, .. } => assert_eq!(name, "protection.mode"),
            other => panic!("expected NotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn a_provider_setting_that_could_not_take_effect_is_refused() {
        let error = error_from("analysis:\n  endpoint: https://models.example.com/v1\n");
        match error.kind() {
            ErrorKind::Contradiction { first, second, .. } => {
                assert_eq!(first, "analysis.provider");
                assert_eq!(second, "analysis.endpoint");
            }
            other => panic!("expected a contradiction, got {other:?}"),
        }

        let error = error_from("analysis:\n  model: example-large\n");
        assert!(matches!(
            error.kind(),
            ErrorKind::Contradiction { second, .. } if second == "analysis.model"
        ));

        let error = error_from("analysis:\n  command: [echo, hello]\n");
        assert!(matches!(
            error.kind(),
            ErrorKind::Contradiction { second, .. } if second == "analysis.command"
        ));
    }

    #[test]
    fn fully_local_cannot_be_combined_with_an_external_provider() {
        for provider in ["claude_cli", "openai_compatible"] {
            let text = format!(
                "privacy:\n  mode: fully_local\nanalysis:\n  provider: {provider}\n  endpoint: https://m.example.com/v1\n"
            );
            let error = error_from(&text);
            let message = error.to_string();
            assert!(
                matches!(error.kind(), ErrorKind::Contradiction { .. }),
                "{provider} gave {message}"
            );
            assert!(message.contains("Fully-local"), "{message}");
        }
        // The local command is allowed: it runs on this machine.
        Config::from_yaml("privacy:\n  mode: fully_local\nanalysis:\n  provider: local_command\n")
            .expect("a local command does not send anything by itself");
    }

    #[test]
    fn inspect_only_cannot_carry_permissions_it_could_never_use() {
        for setting in ["allow_dependency_install", "allow_network"] {
            let text = format!("execution:\n  {setting}: true\n");
            let error = error_from(&text);
            match error.kind() {
                ErrorKind::Contradiction { first, second, .. } => {
                    assert_eq!(first, "execution.mode");
                    assert_eq!(second, &format!("execution.{setting}"));
                }
                other => panic!("{setting} gave {other:?}"),
            }
        }
    }

    #[test]
    fn a_path_that_leaves_the_project_is_refused() {
        for path in [
            "../elsewhere/spec.md",
            "/etc/spec.md",
            "docs/../../elsewhere/spec.md",
            "",
        ] {
            let text = format!("project_intent:\n  spec_path: \"{path}\"\n");
            let error = error_from(&text);
            assert!(
                matches!(error.kind(), ErrorKind::OutsideProject { .. }),
                "{path:?} gave {:?}",
                error.kind()
            );
        }
        // A Windows drive-qualified path is refused on the same grounds — and
        // this assertion is Windows-only, because its *premise* is. On Unix
        // there are no drive prefixes at all: `C:/secrets/spec.md` parses as the
        // relative path `C:/secrets/spec.md` and stays inside the project, so
        // the correct answer there is the one the last line of this test gives
        // for `docs/spec.md`. Asserting the Windows answer on Unix is asserting
        // one platform's syntax onto another, and it was failing in CI.
        //
        // The Unix absolute-path case is already covered above by `/etc/spec.md`
        // and the parent-directory escape by `../elsewhere/spec.md`.
        #[cfg(windows)]
        {
            let error = error_from("project_intent:\n  spec_path: \"C:/secrets/spec.md\"\n");
            assert!(matches!(error.kind(), ErrorKind::OutsideProject { .. }));
        }

        // A path inside the project is fine.
        Config::from_yaml("project_intent:\n  spec_path: docs/spec.md\n").expect("an inside path");
    }

    #[test]
    fn an_empty_goal_is_not_a_goal() {
        let error = error_from("project_intent:\n  goal: \"   \"\n");
        assert!(matches!(error.kind(), ErrorKind::BadValue { .. }));
    }

    #[test]
    fn an_endpoint_that_is_not_a_url_is_refused() {
        for endpoint in [
            "models.example.com/v1",
            "ftp://models.example.com",
            "https://",
        ] {
            let text =
                format!("analysis:\n  provider: openai_compatible\n  endpoint: \"{endpoint}\"\n");
            let error = error_from(&text);
            assert!(
                matches!(error.kind(), ErrorKind::BadValue { .. }),
                "{endpoint} gave {:?}",
                error.kind()
            );
        }
    }

    // --- secrets ----------------------------------------------------------

    #[test]
    fn a_credential_in_the_project_file_is_refused_and_never_printed() {
        let text = "\
analysis:
  provider: openai_compatible
  api_key: sk-abcdefghijklmnopqrstuvwxyz01
  endpoint: https://models.example.com/v1
";
        let error = error_from(text);
        match error.kind() {
            ErrorKind::Credential { setting } => assert_eq!(setting, "analysis.api_key"),
            other => panic!("expected a credential error, got {other:?}"),
        }
        let message = error.to_string();
        assert!(
            !message.contains("sk-abcdefghijklmnopqrstuvwxyz01"),
            "the value must not reach the message:\n{message}"
        );
        assert!(message.contains("analysis.api_key"), "{message}");
    }

    #[test]
    fn a_credential_hidden_in_a_nested_list_is_still_found() {
        let text = "checks:\n  - name: a\n    access_token: ghp_abcdefghijklmnopqrstuvwxyz01\n";
        let error = error_from(text);
        match error.kind() {
            ErrorKind::Credential { setting } => assert_eq!(setting, "checks.access_token"),
            other => panic!("expected a credential error, got {other:?}"),
        }
        assert!(!error.to_string().contains("ghp_"));
    }

    #[test]
    fn a_password_in_a_provider_endpoint_is_refused_and_never_printed() {
        let text = "\
analysis:
  provider: openai_compatible
  endpoint: https://service-account:hunter2@models.example.com/v1
";
        let error = error_from(text);
        assert!(matches!(error.kind(), ErrorKind::Credential { .. }));
        let message = error.to_string();
        assert!(!message.contains("hunter2"), "{message}");
        assert!(!message.contains("service-account"), "{message}");
    }

    #[test]
    fn a_credential_is_reported_before_the_setting_is_rejected_for_being_unknown() {
        // `api_key` is both unrecognised and credential-shaped. The credential
        // message is the one that tells the user where the value belongs.
        let error = error_from("analysis:\n  password: hunter2\n");
        assert!(
            matches!(error.kind(), ErrorKind::Credential { .. }),
            "{:?}",
            error.kind()
        );
    }

    // --- the reference file ----------------------------------------------

    #[test]
    fn the_documented_example_configuration_is_one_sure_accepts() {
        // `sure.example.yaml` is the reference users copy. If the model and the
        // example drift apart, the documentation starts describing a file SURE
        // refuses — and nothing else would catch that.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("sure.example.yaml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let config = Config::from_yaml(&text)
            .unwrap_or_else(|error| panic!("{} is not accepted:\n{error}", path.display()));
        assert_eq!(
            config,
            Config::default(),
            "the example must be the defaults"
        );
    }

    // --- reading a named file that is not a project root ------------------

    /// A directory under the workspace's git-ignored `target/tmp`, unique to this
    /// test binary.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("config file name")
            .join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    #[test]
    fn the_near_miss_check_follows_the_file_name_not_the_directory() {
        // `sure.yml` is only a mistake as a *spelling* of `sure.yaml`. A caller
        // that asked SURE to read some other file has not misspelled anything,
        // and reporting the `sure.yml` beside it would be an error about a file
        // nobody asked for. That makes this a contract of the public
        // `Config::load_file` rather than a detail of reading a project root.
        let dir = scratch_dir("near-miss");
        let near_miss = dir.join(Config::NEAR_MISS_FILE_NAME);
        std::fs::write(&near_miss, "report:\n  format: json\n").expect("write the near miss");

        let error = Config::load_file(&dir.join(Config::FILE_NAME))
            .expect_err("the file the user meant to write must be named, not passed over");
        match error.kind() {
            ErrorKind::WrongFileName { found, expected } => {
                assert_eq!(found, &near_miss);
                assert_eq!(expected.file_name(), Some(Config::FILE_NAME.as_ref()));
            }
            other => panic!("expected a wrong file name, got {other:?}"),
        }

        // A different name is not a misspelling of `sure.yaml`, and the file
        // beside it is none of this read's business.
        for name in ["config.yaml", "settings.yaml", "sure.toml"] {
            let loaded = Config::load_file(&dir.join(name))
                .unwrap_or_else(|error| panic!("{name} is not a spelling mistake:\n{error}"));
            assert_eq!(loaded.source, ConfigSource::NoFile, "{name}");
            assert_eq!(loaded.config, Config::default(), "{name}");
            assert_eq!(loaded.searched, dir.join(name));
        }

        // A caller that asks for `sure.yml` by name means `sure.yml`.
        let loaded = Config::load_file(&near_miss).expect("this file is one SURE accepts");
        assert_eq!(loaded.source, ConfigSource::File(near_miss.clone()));
        assert_eq!(loaded.config.report.format, ReportFormat::Json);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- helpers ----------------------------------------------------------

    #[test]
    fn suggestions_only_appear_when_the_name_is_close_enough() {
        let candidates = vec!["mode".to_owned(), "provider".to_owned()];
        assert_eq!(closest("modee", &candidates), Some("mode"));
        assert_eq!(closest("provder", &candidates), Some("provider"));
        assert_eq!(
            closest("something else entirely", &candidates),
            None,
            "a suggestion that is not close invites the user to make a change they did not mean"
        );
    }

    #[test]
    fn edit_distance_is_counted_in_characters() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("same", "same"), 0);
        // One character differs, though it costs two bytes; a byte-wise
        // distance would call this two and could push a suggestion out of range.
        assert_eq!(edit_distance("ünï", "üni"), 1);
    }

    #[test]
    fn url_and_path_helpers_answer_the_questions_they_are_asked() {
        assert!(has_userinfo("https://u:p@h/v"));
        assert!(!has_userinfo("https://h/v"));
        assert!(!has_userinfo("https://h/v?x=y@z"));
        assert!(is_absolute_http_url("https://h/v"));
        assert!(is_absolute_http_url("http://h"));
        assert!(!is_absolute_http_url("https://"));
        assert!(!is_absolute_http_url("https://h/v with a space"));

        assert!(is_inside_project("docs/spec.md"));
        assert!(is_inside_project("spec.md"));
        assert!(!is_inside_project(".."));
        assert!(!is_inside_project("a/../b"));
        assert!(!is_inside_project(""));
    }
}
