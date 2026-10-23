//! Runtime abstraction for model-backed or command-backed analysis.
//!
//! Deterministic checks live in [`crate::checks`] and do not use this module.
//! This provider is only consulted when a check explicitly asks for analysis,
//! and the default [`AnalysisProvider`](crate::config::AnalysisProvider) is
//! [`Disabled`](crate::config::AnalysisProvider::Disabled), so a run that never
//! configures a provider never instantiates one.
//!
//! The abstraction is intentionally thin: it is one trait, one request/response
//! pair, and one factory. The check engine stays in [`crate::checks`]; this
//! module only gives that engine a uniform door to call when a check decides it
//! needs model input.

use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{AnalysisConfig, AnalysisProvider};
use crate::process::{Cancellation, Limits, Outcome, ProcessRequest, Termination};
use sure_domain::ids::{CheckId, FingerprintId};
use sure_domain::severity::Severity;
use sure_domain::status::{CheckResult, NotCheckedReason};

/// How long a local-command analysis may run before it is stopped.
///
/// A minute is long enough for a small wrapper script and short enough that a
/// hanging command does not hold a check indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// How many bytes SURE keeps from each stream of a local-command analysis.
const DEFAULT_OUTPUT_BYTES: usize = 64 * 1024;

/// A request for analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisRequest<'a> {
    /// The prompt or question the check wants answered.
    pub prompt: &'a str,
}

/// The response from an analysis provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisResponse {
    /// The provider's answer, as text.
    pub text: String,
}

impl AnalysisResponse {
    /// Wrap `text` as a response.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

/// Why analysis could not be performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisError {
    /// The provider is disabled.
    Disabled,
    /// No command was configured for the local-command provider.
    MissingCommand,
    /// The local command could not be run or did not finish cleanly.
    LocalCommandFailed {
        /// What went wrong, in plain words.
        message: String,
    },
    /// The Claude CLI provider could not run or did not finish cleanly.
    ClaudeCliFailed {
        /// What went wrong, in plain words.
        message: String,
    },
    /// The OpenAI-compatible provider could not complete the request.
    OpenAiCompatibleFailed {
        /// What went wrong, in plain words.
        message: String,
    },
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "Analysis is disabled."),
            Self::MissingCommand => write!(
                f,
                "The local-command provider needs a command, but none was configured."
            ),
            Self::LocalCommandFailed { message } => {
                write!(f, "The local command failed: {message}")
            }
            Self::ClaudeCliFailed { message } => {
                write!(f, "The Claude CLI provider failed: {message}")
            }
            Self::OpenAiCompatibleFailed { message } => {
                write!(f, "The OpenAI-compatible provider failed: {message}")
            }
        }
    }
}

impl std::error::Error for AnalysisError {}

/// Something that can perform model-backed or command-backed analysis.
pub trait Analyzer: Send + Sync {
    /// Perform analysis for `request`.
    ///
    /// # Errors
    ///
    /// Returns [`AnalysisError::Disabled`] when the provider is disabled, or a
    /// provider-specific error when the provider could not produce an answer.
    fn analyze(&self, request: AnalysisRequest<'_>) -> Result<AnalysisResponse, AnalysisError>;
}

/// Provider that refuses every request.
///
/// This is the runtime partner of
/// [`AnalysisProvider::Disabled`](crate::config::AnalysisProvider::Disabled).
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledAnalyzer;

impl Analyzer for DisabledAnalyzer {
    fn analyze(&self, _request: AnalysisRequest<'_>) -> Result<AnalysisResponse, AnalysisError> {
        Err(AnalysisError::Disabled)
    }
}

/// Provider that runs a configured local command and returns its output.
///
/// The configured command is run in the project root. The prompt from the
/// request is appended as the final argument, so a wrapper script can read it
/// without any shell being involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCommandAnalyzer {
    program: OsString,
    arguments: Vec<OsString>,
    working_directory: PathBuf,
}

impl LocalCommandAnalyzer {
    /// Build a provider that runs `command` in `working_directory`.
    ///
    /// `command` must contain at least one element: the program to run. The
    /// remaining elements are passed as arguments, in order, before the prompt.
    ///
    /// # Errors
    ///
    /// Returns [`AnalysisError::MissingCommand`] when `command` is empty.
    #[must_use]
    pub fn new(command: Vec<String>, working_directory: impl Into<PathBuf>) -> Self {
        let mut parts = command.into_iter();
        let program = parts.next().map_or_else(OsString::new, Into::into);
        let arguments: Vec<OsString> = parts.map(Into::into).collect();
        Self {
            program,
            arguments,
            working_directory: working_directory.into(),
        }
    }
}

impl Analyzer for LocalCommandAnalyzer {
    fn analyze(&self, request: AnalysisRequest<'_>) -> Result<AnalysisResponse, AnalysisError> {
        let cancellation = Cancellation::new();
        let limits = Limits::new(DEFAULT_TIMEOUT, DEFAULT_OUTPUT_BYTES, DEFAULT_OUTPUT_BYTES);

        let mut arguments = self.arguments.clone();
        arguments.push(prepare_prompt(request.prompt).into());

        let process_request =
            ProcessRequest::new(&self.program, &self.working_directory, limits, cancellation)
                .with_arguments(arguments);

        let outcome = crate::process::run(&process_request).map_err(|error| {
            AnalysisError::LocalCommandFailed {
                message: error.to_string(),
            }
        })?;

        local_command_response(outcome)
    }
}

/// Turn a finished local command into an analysis response or error.
fn local_command_response(outcome: Outcome) -> Result<AnalysisResponse, AnalysisError> {
    match outcome.termination() {
        Termination::Exited { code: Some(0) } => Ok(AnalysisResponse::new(crate::redact::redact(
            &outcome.stdout().text_lossy(),
        ))),
        Termination::Exited { code: Some(code) } => {
            let stderr = crate::redact::redact(&outcome.stderr().text_lossy());
            Err(AnalysisError::LocalCommandFailed {
                message: format!("exited with code {code}: {stderr}"),
            })
        }
        Termination::Exited { code: None } => Err(AnalysisError::LocalCommandFailed {
            message: "exited without a code".to_owned(),
        }),
        Termination::TimedOut { .. } => Err(AnalysisError::LocalCommandFailed {
            message: "timed out".to_owned(),
        }),
        Termination::Cancelled { .. } => Err(AnalysisError::LocalCommandFailed {
            message: "was cancelled".to_owned(),
        }),
        Termination::CancelledBeforeStart => Err(AnalysisError::LocalCommandFailed {
            message: "was cancelled before it started".to_owned(),
        }),
    }
}

/// Strip secrets from a prompt before it is handed to a provider.
///
/// External providers must not receive raw secrets, and a local command may log
/// its arguments. Redacting here keeps the secret out of both places.
fn prepare_prompt(prompt: &str) -> String {
    crate::redact::redact(prompt)
}

/// Provider that invokes the user-installed Anthropic Claude CLI.
///
/// The provider runs `claude -p <prompt>` in the project root. The prompt is
/// redacted before it leaves SURE, and both stdout and stderr are bounded so
/// a runaway CLI cannot fill memory. The returned text is a model assessment,
/// not deterministic evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeCliAnalyzer {
    program: OsString,
    working_directory: PathBuf,
}

impl ClaudeCliAnalyzer {
    /// Build a provider that runs `claude` in `working_directory`.
    #[must_use]
    pub fn new(working_directory: impl Into<PathBuf>) -> Self {
        Self {
            program: "claude".into(),
            working_directory: working_directory.into(),
        }
    }

    #[cfg(test)]
    fn with_program(program: impl Into<OsString>, working_directory: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            working_directory: working_directory.into(),
        }
    }
}

impl Analyzer for ClaudeCliAnalyzer {
    fn analyze(&self, request: AnalysisRequest<'_>) -> Result<AnalysisResponse, AnalysisError> {
        let cancellation = Cancellation::new();
        let limits = Limits::new(DEFAULT_TIMEOUT, DEFAULT_OUTPUT_BYTES, DEFAULT_OUTPUT_BYTES);

        let prompt = prepare_prompt(request.prompt);
        let arguments: Vec<OsString> = vec!["-p".into(), prompt.into()];

        let process_request =
            ProcessRequest::new(&self.program, &self.working_directory, limits, cancellation)
                .with_arguments(arguments);

        let outcome = crate::process::run(&process_request).map_err(|error| {
            AnalysisError::ClaudeCliFailed {
                message: error.to_string(),
            }
        })?;

        claude_cli_response(outcome)
    }
}

/// Turn a finished Claude CLI run into an analysis response or error.
fn claude_cli_response(outcome: Outcome) -> Result<AnalysisResponse, AnalysisError> {
    match outcome.termination() {
        Termination::Exited { code: Some(0) } => {
            Ok(AnalysisResponse::new(outcome.stdout().text_lossy()))
        }
        Termination::Exited { code: Some(code) } => {
            let stderr = outcome.stderr().text_lossy();
            Err(AnalysisError::ClaudeCliFailed {
                message: format!("exited with code {code}: {stderr}"),
            })
        }
        Termination::Exited { code: None } => Err(AnalysisError::ClaudeCliFailed {
            message: "exited without a code".to_owned(),
        }),
        Termination::TimedOut { .. } => Err(AnalysisError::ClaudeCliFailed {
            message: "timed out".to_owned(),
        }),
        Termination::Cancelled { .. } => Err(AnalysisError::ClaudeCliFailed {
            message: "was cancelled".to_owned(),
        }),
        Termination::CancelledBeforeStart => Err(AnalysisError::ClaudeCliFailed {
            message: "was cancelled before it started".to_owned(),
        }),
    }
}

/// How long the OpenAI-compatible provider waits for a response.
const OPENAI_TIMEOUT: Duration = Duration::from_secs(60);

/// How many bytes the OpenAI-compatible provider reads from a response.
const OPENAI_RESPONSE_BYTES: usize = 64 * 1024;

/// Environment variable that holds the API key for the OpenAI-compatible provider.
const OPENAI_API_KEY_VAR: &str = "SURE_OPENAI_API_KEY";

/// Provider that calls a user-configured OpenAI-compatible endpoint directly.
///
/// SURE does not proxy the request: it is sent from this machine to the endpoint
/// the user configured. The prompt is redacted before it leaves SURE, and the
/// API key is read from an environment variable rather than from any project-
/// controlled file.
#[cfg_attr(not(test), derive(Clone, PartialEq, Eq))]
pub struct OpenAiCompatibleAnalyzer {
    endpoint: String,
    model: Option<String>,
    /// An optional API key used in tests so that `std::env::set_var`, which is
    /// `unsafe` in edition 2024 and forbidden in this workspace, is not needed.
    api_key: Option<String>,
    #[cfg(test)]
    transport: Option<Box<TransportFn>>,
}

#[cfg(test)]
type TransportFn =
    dyn Fn(&str, &str, &str, &str) -> Result<(u16, String), AnalysisError> + Send + Sync;

impl fmt::Debug for OpenAiCompatibleAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiCompatibleAnalyzer")
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "***"))
            .finish()
    }
}

impl OpenAiCompatibleAnalyzer {
    /// Build a provider that calls `endpoint` with the configured `model`.
    ///
    /// The API key is read from [`OPENAI_API_KEY_VAR`] when the provider runs.
    #[must_use]
    pub fn new(endpoint: String, model: Option<String>) -> Self {
        Self {
            endpoint,
            model,
            api_key: None,
            #[cfg(test)]
            transport: None,
        }
    }

    /// Build a provider with an injected transport for tests.
    #[cfg(test)]
    fn with_transport(
        endpoint: String,
        model: Option<String>,
        api_key: String,
        transport: impl Fn(&str, &str, &str, &str) -> Result<(u16, String), AnalysisError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            endpoint,
            model,
            api_key: Some(api_key),
            transport: Some(Box::new(transport)),
        }
    }

    fn send_request(
        &self,
        model: &str,
        api_key: &str,
        prompt: &str,
    ) -> Result<(u16, String), AnalysisError> {
        #[cfg(test)]
        if let Some(transport) = &self.transport {
            return transport(&self.endpoint, model, api_key, prompt);
        }
        send_openai_request(&self.endpoint, model, api_key, prompt)
    }
}

impl Analyzer for OpenAiCompatibleAnalyzer {
    fn analyze(&self, request: AnalysisRequest<'_>) -> Result<AnalysisResponse, AnalysisError> {
        if self.endpoint.is_empty() {
            return Err(openai_failed(
                "endpoint is not configured; set `analysis.endpoint` in your SURE settings file",
            ));
        }
        let Some(model) = self.model.as_ref() else {
            return Err(openai_failed(
                "model is not configured; set `analysis.model` in your SURE settings file",
            ));
        };
        let api_key = self
            .api_key
            .clone()
            .or_else(|| std::env::var(OPENAI_API_KEY_VAR).ok())
            .ok_or_else(|| {
                openai_failed(
                    "API key is not configured; set SURE_OPENAI_API_KEY in the environment that \
                     starts SURE",
                )
            })?;
        let prompt = prepare_prompt(request.prompt);

        let (status, body) = self
            .send_request(model, &api_key, &prompt)
            .map_err(redact_openai_error)?;

        if !(200..300).contains(&status) {
            return Err(openai_failed(format!("server returned HTTP {status}")));
        }

        parse_openai_response(&body).map(AnalysisResponse::new)
    }
}

/// Build an [`AnalysisError::OpenAiCompatibleFailed`] with a redacted message.
fn openai_failed(message: impl Into<String>) -> AnalysisError {
    AnalysisError::OpenAiCompatibleFailed {
        message: crate::redact::redact_for_diagnostic(&message.into()),
    }
}

/// Redact a provider error before it leaves this module.
fn redact_openai_error(error: AnalysisError) -> AnalysisError {
    match error {
        AnalysisError::OpenAiCompatibleFailed { message } => openai_failed(message),
        other => other,
    }
}

/// Send a chat-completions request to an OpenAI-compatible endpoint.
fn send_openai_request(
    endpoint: &str,
    model: &str,
    api_key: &str,
    prompt: &str,
) -> Result<(u16, String), AnalysisError> {
    let request_body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": prompt}]
    });

    let agent = ureq::AgentBuilder::new().timeout(OPENAI_TIMEOUT).build();

    match agent
        .post(endpoint)
        .set("Authorization", &format!("Bearer {api_key}"))
        .set("Content-Type", "application/json")
        .send_json(&request_body)
    {
        Ok(response) => {
            let status = response.status();
            let body = read_limited_body(response)?;
            Ok((status, body))
        }
        Err(ureq::Error::Status(code, _)) => Ok((code, String::new())),
        Err(ureq::Error::Transport(error)) => {
            Err(openai_failed(format!("request failed: {error}")))
        }
    }
}

/// Read up to [`OPENAI_RESPONSE_BYTES`] from `response`.
fn read_limited_body(response: ureq::Response) -> Result<String, AnalysisError> {
    let reader = response.into_reader();
    let mut limited = reader.take(OPENAI_RESPONSE_BYTES as u64);
    let mut body = Vec::new();
    limited
        .read_to_end(&mut body)
        .map_err(|error| openai_failed(format!("could not read response: {error}")))?;
    String::from_utf8(body)
        .map_err(|error| openai_failed(format!("response was not valid UTF-8: {error}")))
}

/// Extract the assistant message content from an OpenAI-compatible response body.
fn parse_openai_response(body: &str) -> Result<String, AnalysisError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| openai_failed(format!("response was not valid JSON: {error}")))?;
    let content = value
        .get("choices")
        .and_then(|choices| choices.as_array())
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .ok_or_else(|| openai_failed("response did not contain assistant content"))?;
    Ok(content.to_owned())
}

/// Build the analyzer described by `config`.
///
/// `project_root` is the working directory for the local-command provider.
///
/// # Errors
///
/// Returns [`AnalysisError::MissingCommand`] when the local-command provider is
/// chosen but no command is configured.
pub fn build(
    config: &AnalysisConfig,
    project_root: &Path,
) -> Result<Box<dyn Analyzer>, AnalysisError> {
    match config.provider {
        AnalysisProvider::Disabled => Ok(Box::new(DisabledAnalyzer)),
        AnalysisProvider::LocalCommand => {
            let Some(command) = &config.command else {
                return Err(AnalysisError::MissingCommand);
            };
            Ok(Box::new(LocalCommandAnalyzer::new(
                command.clone(),
                project_root,
            )))
        }
        AnalysisProvider::ClaudeCli => Ok(Box::new(ClaudeCliAnalyzer::new(project_root))),
        AnalysisProvider::OpenAiCompatible => Ok(Box::new(OpenAiCompatibleAnalyzer::new(
            config.endpoint.clone().unwrap_or_default(),
            config.model.clone(),
        ))),
    }
}

/// Build a [`CheckResult`] for a check that could not run because analysis is disabled.
///
/// This is the honest way to record a model-backed check when the configured
/// provider is [`AnalysisProvider::Disabled`]: the check is skipped, the reason
/// says the provider is missing, and the result blocks green when the check was
/// critical. The check engine stays independent of the provider — it only calls
/// this helper after the provider itself returns [`AnalysisError::Disabled`].
#[must_use]
pub fn disabled_result(
    id: CheckId,
    title: impl Into<String>,
    severity: Severity,
    critical: bool,
    fingerprint: FingerprintId,
) -> CheckResult {
    CheckResult::not_run(
        id,
        title,
        severity,
        critical,
        NotCheckedReason::AnalysisProviderDisabled,
        fingerprint,
    )
    .with_reason("No analysis provider is configured.".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::AnalysisConfig;

    fn request(prompt: &str) -> AnalysisRequest<'_> {
        AnalysisRequest { prompt }
    }

    /// A command that echoes its last argument, portable across Windows and Unix.
    fn echo_command() -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd".to_owned(), "/c".to_owned(), "echo".to_owned()]
        } else {
            vec!["echo".to_owned()]
        }
    }

    /// A program that prints the arguments it is given, in the one form each
    /// platform starts by itself.
    ///
    /// [`echo_command`] is a command *line* and begins with `cmd /c` on Windows.
    /// `ClaudeCliAnalyzer` takes a program, not a command line, and SURE's
    /// process runner completes a bare name to `.exe` and nothing else — so
    /// there is no `echo` to name on Windows, where echoing is a command
    /// interpreter builtin rather than a program. Naming one anyway is how the
    /// two tests below came to pass under a shell that had `echo.exe` on `PATH`
    /// (Git Bash) and fail under one that did not (PowerShell): a green result
    /// that depended on which shell ran the suite.
    ///
    /// So those tests write the smallest real program each platform does start —
    /// a batch file on Windows, a shell script elsewhere — under the workspace's
    /// git-ignored `target/tmp`, and name it by its full path.
    ///
    /// **A directory of this call's own, and the program written into place.**
    /// This used to be one fixed path — `target/tmp/claude-cli-analyzer/echo` —
    /// built and `fs::write`n by every call, with
    /// [`claude_cli_analyzer_runs_program_and_returns_stdout`] and
    /// [`claude_cli_analyzer_redacts_prompt_before_passing_it`] as two
    /// independent tests that both call it. Under cargo's parallel test threads
    /// one of them could be running that program while the other truncated and
    /// rewrote the very file it was running from, and on 2026-09-20 it was. Run
    /// `35512888372` — commit `8342764`, `rust (ubuntu-latest)`, `cargo test
    /// --workspace --no-fail-fast` — failed in
    /// `analysis_provider::tests::claude_cli_analyzer_runs_program_and_returns_stdout`
    /// at `crates/sure-core/src/analysis_provider/mod.rs:591:44` with
    /// `the echoing program: Os { code: 26, kind: ExecutableFileBusy, message:
    /// "Text file busy" }`. The panic message is the `expect` on the `fs::write`
    /// at that column, so the errno came back from the **write** side: the
    /// `open(O_WRONLY|O_CREAT|O_TRUNC)` was refused because the inode it would
    /// have truncated was, at that moment, the text of a process the other test
    /// was running. The directory is now unique per call by `create_dir`
    /// rather than by its name, which is the pattern the rest of this crate's
    /// test modules already keep (`commands.rs`'s and `mcp.rs`'s
    /// `a_store_of_our_own` say so in as many words), and the program is written
    /// by [`sure_testkit::write_program`], which writes under a temporary name,
    /// closes it and renames it into place — so the executed path is never the
    /// path an in-flight write holds open. See `sure-testkit`'s `program` module
    /// for the kernel rule both halves rest on.
    fn echoing_program() -> PathBuf {
        let directory = a_directory_of_our_own();

        #[cfg(windows)]
        let (program, contents) = (directory.join("echo.cmd"), "@echo off\r\necho %*\r\n");
        #[cfg(not(windows))]
        let (program, contents) = (directory.join("echo"), "#!/bin/sh\necho \"$@\"\n");

        sure_testkit::write_program(&program, contents.as_bytes(), 0o755)
            .expect("the echoing program");

        program
    }

    /// A scratch directory this call can call its own, under the workspace's
    /// git-ignored `target/tmp`.
    ///
    /// Unique by construction rather than by name-collision, by way of
    /// `sure_testkit::scratch`, which holds the reasoning these helpers used to
    /// repeat: a run's directory is named for its process id and each call's
    /// directory for a counter only that process can advance, so two calls — in
    /// this process or in another one — cannot be handed the same directory and
    /// overwrite each other's program.
    fn a_directory_of_our_own() -> PathBuf {
        sure_testkit::scratch::directory("claude-cli-analyzer", "run")
    }

    /// A command that exits with a non-zero code, portable across Windows and Unix.
    fn failing_command() -> Vec<String> {
        if cfg!(windows) {
            vec![
                "cmd".to_owned(),
                "/c".to_owned(),
                "exit".to_owned(),
                "7".to_owned(),
            ]
        } else {
            vec!["false".to_owned()]
        }
    }

    #[test]
    fn disabled_analyzer_refuses_every_request() {
        let analyzer = DisabledAnalyzer;
        let error = analyzer.analyze(request("anything")).unwrap_err();
        assert_eq!(error, AnalysisError::Disabled);
        assert!(error.to_string().contains("disabled"));
    }

    #[test]
    fn local_command_analyzer_runs_command_and_returns_stdout() {
        let temp = std::env::temp_dir();
        let analyzer = LocalCommandAnalyzer::new(echo_command(), &temp);

        let response = analyzer.analyze(request("hello from sure")).unwrap();

        assert!(response.text.contains("hello from sure"));
    }

    #[test]
    fn local_command_analyzer_reports_non_zero_exit_as_failure() {
        let temp = std::env::temp_dir();
        let analyzer = LocalCommandAnalyzer::new(failing_command(), &temp);

        let error = analyzer.analyze(request("ignored")).unwrap_err();
        assert!(matches!(error, AnalysisError::LocalCommandFailed { .. }));
        let message = error.to_string();
        assert!(
            message.contains("exited") || message.contains("failed"),
            "{message}"
        );
    }

    fn require_analyzer(result: Result<Box<dyn Analyzer>, AnalysisError>) -> Box<dyn Analyzer> {
        match result {
            Ok(analyzer) => analyzer,
            Err(error) => panic!("expected an analyzer, got {error}"),
        }
    }

    fn require_error(result: Result<Box<dyn Analyzer>, AnalysisError>) -> AnalysisError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("expected an error, got an analyzer"),
        }
    }

    fn temp_root() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn build_dispatches_to_disabled() {
        let config = AnalysisConfig {
            provider: AnalysisProvider::Disabled,
            ..AnalysisConfig::default()
        };
        let root = temp_root();
        let analyzer = require_analyzer(build(&config, &root));
        let error = analyzer.analyze(request("x")).unwrap_err();
        assert_eq!(error, AnalysisError::Disabled);
    }

    #[test]
    fn build_dispatches_to_local_command() {
        let config = AnalysisConfig {
            provider: AnalysisProvider::LocalCommand,
            command: Some(echo_command()),
            ..AnalysisConfig::default()
        };
        let root = temp_root();
        let analyzer = require_analyzer(build(&config, &root));
        let response = analyzer.analyze(request(" dispatched ")).unwrap();
        assert!(response.text.contains(" dispatched "));
    }

    #[test]
    fn build_local_command_without_command_is_missing_command() {
        let config = AnalysisConfig {
            provider: AnalysisProvider::LocalCommand,
            command: None,
            ..AnalysisConfig::default()
        };
        let root = temp_root();
        let error = require_error(build(&config, &root));
        assert_eq!(error, AnalysisError::MissingCommand);
    }

    #[test]
    fn build_dispatches_to_claude_cli() {
        let config = AnalysisConfig {
            provider: AnalysisProvider::ClaudeCli,
            ..AnalysisConfig::default()
        };
        let root = temp_root();
        let analyzer = require_analyzer(build(&config, &root));
        // The default program is `claude`, which is not expected to be installed
        // in test environments. The analyzer must report a provider failure, not
        // a placeholder.
        let error = analyzer.analyze(request("x")).unwrap_err();
        assert!(matches!(error, AnalysisError::ClaudeCliFailed { .. }));
        let message = error.to_string();
        assert!(
            message.contains("failed") || message.contains("claude"),
            "{message}"
        );
    }

    #[test]
    fn claude_cli_analyzer_runs_program_and_returns_stdout() {
        let program = echoing_program();
        let analyzer =
            ClaudeCliAnalyzer::with_program(&program, program.parent().expect("a parent"));

        let response = analyzer.analyze(request("hello from claude")).unwrap();

        assert!(response.text.contains("hello from claude"));
    }

    #[test]
    fn claude_cli_analyzer_redacts_prompt_before_passing_it() {
        let program = echoing_program();
        let analyzer =
            ClaudeCliAnalyzer::with_program(&program, program.parent().expect("a parent"));

        let response = analyzer
            .analyze(request("token sk-abcdefghijklmnopqrstuvwxyz01"))
            .unwrap();

        assert!(!response.text.contains("sk-abcdefghijklmnopqrstuvwxyz01"));
        assert!(response.text.contains("***"));
    }

    #[test]
    fn build_dispatches_to_openai_compatible() {
        let config = AnalysisConfig {
            provider: AnalysisProvider::OpenAiCompatible,
            endpoint: Some("https://models.example.com/v1".to_owned()),
            model: Some("test-model".to_owned()),
            ..AnalysisConfig::default()
        };
        let root = temp_root();
        let analyzer = require_analyzer(build(&config, &root));
        // Without the env-var credential and without a test transport, the
        // provider cannot succeed. The important thing is that `build` returns
        // the OpenAI-compatible analyzer and that it reports provider-specific
        // failures rather than a placeholder.
        let error = analyzer.analyze(request("x")).unwrap_err();
        assert!(
            matches!(error, AnalysisError::OpenAiCompatibleFailed { .. }),
            "expected OpenAiCompatibleFailed, got {error}"
        );
    }

    #[test]
    fn openai_compatible_analyzer_returns_assistant_content() {
        let analyzer = OpenAiCompatibleAnalyzer::with_transport(
            "https://models.example.com/v1".to_owned(),
            Some("test-model".to_owned()),
            "sk-fake12345678901234567890".to_owned(),
            |_endpoint, model, api_key, prompt| {
                assert_eq!(model, "test-model");
                assert_eq!(api_key, "sk-fake12345678901234567890");
                assert_eq!(prompt, "hello");
                Ok((
                    200,
                    r#"{"choices":[{"message":{"role":"assistant","content":"hi there"}}]}"#
                        .to_owned(),
                ))
            },
        );

        let response = analyzer.analyze(request("hello")).unwrap();

        assert_eq!(response.text, "hi there");
    }

    #[test]
    fn openai_compatible_analyzer_redacts_prompt_before_sending() {
        let secret_prompt = "token sk-abcdefghijklmnopqrstuvwxyz01";
        let analyzer = OpenAiCompatibleAnalyzer::with_transport(
            "https://models.example.com/v1".to_owned(),
            Some("test-model".to_owned()),
            "sk-fake".to_owned(),
            |_endpoint, _model, _api_key, prompt| {
                assert!(
                    !prompt.contains("sk-abcdefghijklmnopqrstuvwxyz01"),
                    "prompt was not redacted: {prompt}"
                );
                assert!(
                    prompt.contains("***"),
                    "prompt should show redaction: {prompt}"
                );
                Ok((
                    200,
                    r#"{"choices":[{"message":{"role":"assistant","content":"ok"}}]}"#.to_owned(),
                ))
            },
        );

        let response = analyzer.analyze(request(secret_prompt)).unwrap();

        assert_eq!(response.text, "ok");
    }

    #[test]
    fn openai_compatible_analyzer_does_not_leak_api_key() {
        let secret_key = "sk-fake12345678901234567890";
        let analyzer = OpenAiCompatibleAnalyzer::with_transport(
            "https://models.example.com/v1".to_owned(),
            Some("test-model".to_owned()),
            secret_key.to_owned(),
            move |_endpoint, _model, api_key, _prompt| {
                assert_eq!(api_key, secret_key);
                Ok((
                    200,
                    r#"{"choices":[{"message":{"role":"assistant","content":"acknowledged"}}]}"#
                        .to_owned(),
                ))
            },
        );

        let response = analyzer.analyze(request("hello")).unwrap();

        assert!(!response.text.contains(secret_key));
    }

    #[test]
    fn openai_compatible_analyzer_redacts_api_key_in_error_messages() {
        let secret_key = "sk-fake12345678901234567890";
        let analyzer = OpenAiCompatibleAnalyzer::with_transport(
            "https://models.example.com/v1".to_owned(),
            Some("test-model".to_owned()),
            secret_key.to_owned(),
            move |_endpoint, _model, _api_key, _prompt| {
                Err(AnalysisError::OpenAiCompatibleFailed {
                    message: format!("server rejected key {secret_key}"),
                })
            },
        );

        let error = analyzer.analyze(request("hello")).unwrap_err();

        let message = error.to_string();
        assert!(
            matches!(error, AnalysisError::OpenAiCompatibleFailed { .. }),
            "{message}"
        );
        assert!(!message.contains(secret_key), "key leaked: {message}");
        assert!(
            message.contains("***"),
            "message should be redacted: {message}"
        );
    }

    #[test]
    fn openai_compatible_analyzer_reports_non_2xx_as_failed() {
        let analyzer = OpenAiCompatibleAnalyzer::with_transport(
            "https://models.example.com/v1".to_owned(),
            Some("test-model".to_owned()),
            "sk-fake".to_owned(),
            |_endpoint, _model, _api_key, _prompt| Ok((503, String::new())),
        );

        let error = analyzer.analyze(request("x")).unwrap_err();

        assert!(matches!(
            error,
            AnalysisError::OpenAiCompatibleFailed { .. }
        ));
        assert!(error.to_string().contains("503"), "{error}");
    }

    #[test]
    fn openai_compatible_analyzer_reports_missing_api_key() {
        let analyzer = OpenAiCompatibleAnalyzer::new(
            "https://models.example.com/v1".to_owned(),
            Some("test-model".to_owned()),
        );

        let error = analyzer.analyze(request("x")).unwrap_err();

        assert!(matches!(
            error,
            AnalysisError::OpenAiCompatibleFailed { .. }
        ));
        assert!(error.to_string().contains("API key"), "{error}");
    }

    #[test]
    fn openai_compatible_analyzer_reports_missing_model() {
        let analyzer = OpenAiCompatibleAnalyzer::with_transport(
            "https://models.example.com/v1".to_owned(),
            None,
            "sk-fake".to_owned(),
            |_endpoint, _model, _api_key, _prompt| {
                panic!("transport should not be called without a model")
            },
        );

        let error = analyzer.analyze(request("x")).unwrap_err();

        assert!(matches!(
            error,
            AnalysisError::OpenAiCompatibleFailed { .. }
        ));
        assert!(error.to_string().contains("model"), "{error}");
    }

    #[test]
    fn openai_compatible_analyzer_reports_missing_endpoint() {
        let analyzer = OpenAiCompatibleAnalyzer::with_transport(
            String::new(),
            Some("test-model".to_owned()),
            "sk-fake".to_owned(),
            |_endpoint, _model, _api_key, _prompt| {
                panic!("transport should not be called without an endpoint")
            },
        );

        let error = analyzer.analyze(request("x")).unwrap_err();

        assert!(matches!(
            error,
            AnalysisError::OpenAiCompatibleFailed { .. }
        ));
        assert!(error.to_string().contains("endpoint"), "{error}");
    }

    #[test]
    fn deterministic_checks_need_no_provider() {
        // The whole point of the abstraction: a check that does not ask for
        // analysis never builds a provider. This test proves the default config
        // builds the disabled provider and that provider is safe to ignore.
        let config = AnalysisConfig::default();
        assert_eq!(config.provider, AnalysisProvider::Disabled);
        let root = temp_root();
        let analyzer = require_analyzer(build(&config, &root));
        assert_eq!(
            analyzer.analyze(request("x")).unwrap_err(),
            AnalysisError::Disabled
        );
    }

    #[test]
    fn disabled_result_records_analysis_provider_disabled_reason() {
        let fp = FingerprintId::generate();
        let id = CheckId::generate();
        let result = disabled_result(
            id.clone(),
            "semantic intent match",
            Severity::ShouldFixFirst,
            true,
            fp.clone(),
        );

        assert_eq!(result.id, id);
        assert_eq!(result.title, "semantic intent match");
        assert_eq!(result.status, sure_domain::status::CheckStatus::Skipped);
        assert_eq!(
            result.not_checked_reason,
            Some(NotCheckedReason::AnalysisProviderDisabled)
        );
        assert!(
            result.reason.contains("analysis provider"),
            "reason should explain the provider is missing: {}",
            result.reason
        );
        assert!(
            result.blocks_green(),
            "a critical model-backed check that could not run must block green"
        );
    }
}
