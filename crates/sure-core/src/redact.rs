//! Keeping secrets out of anything SURE prints or stores.
//!
//! This sits at the crate root rather than inside [`crate::config`] because
//! redaction is not a config concern: [`crate::diagnostics`] applies it to
//! every field of every recorded line, and the full-recording path will apply
//! it to captured process output. Config was simply its first caller.
//!
//! The primary defence is structural, not this module: [`crate::config::Config`]
//! has no field that accepts a credential, a project-controlled `sure.yaml` may
//! not carry one (`docs/architecture/CONFIG_AUTHORITY.md`), and a diagnostic
//! field cannot be built from a credential without going through
//! [`crate::diagnostics::Field`]. Redaction is the second line — it covers the
//! value a user pasted into a field that *is* allowed, such as a provider
//! endpoint.
//!
//! `docs/security/SECRET_REDACTION.md` is explicit that detection is imperfect,
//! and this code does not pretend otherwise. It recognises a fixed list of
//! credential shapes and a fixed list of credential-ish names. It will miss
//! secrets written in shapes nobody has thought of yet, which is why the
//! structural rules above matter more than the patterns below.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// What a redacted span is replaced with.
pub const REDACTED: &str = "***";

/// Name fragments that mark a setting as holding a credential rather than a
/// value.
///
/// Comparison is on the alphanumeric characters only, lowercased, so
/// `api_key`, `apiKey`, `API-KEY` and `api key` all match. The fragments are
/// deliberately long enough not to fire on ordinary setting names: `auth`
/// alone would match `author`, and `key` alone would match almost anything.
const CREDENTIAL_NAME_FRAGMENTS: &[&str] = &[
    "apikey",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "token",
    "credential",
    "privatekey",
    "publickey",
    "accesskey",
    "authkey",
    "authheader",
    "authorization",
    "bearer",
    "clientsecret",
    "sessionkey",
    "signingkey",
];

/// Token shapes worth recognising, as `(prefix, minimum body length)`.
///
/// The minimums are the real ones: `sk-` credentials are never three
/// characters long, and requiring a plausible length is what keeps a sentence
/// containing "risk-free" from being redacted into nonsense.
const TOKEN_SHAPES: &[(&str, usize)] = &[
    ("sk-", 16),
    ("ghp_", 20),
    ("gho_", 20),
    ("ghu_", 20),
    ("ghs_", 20),
    ("ghr_", 20),
    ("github_pat_", 20),
    ("xoxb-", 10),
    ("xoxp-", 10),
    ("xoxa-", 10),
    ("xoxr-", 10),
    ("xoxs-", 10),
    ("ya29.", 20),
    ("AKIA", 16),
    ("ASIA", 16),
    ("eyJ", 30),
];

/// A redaction engine that can be configured with extra literals and patterns.
///
/// The engine always applies the built-in detectors (URL authorities,
/// credential-shaped assignments, known token prefixes). User-supplied
/// literals and regex patterns are applied on top.
#[derive(Debug, Clone)]
pub struct Redactor {
    /// Literal strings that should be redacted wherever they appear.
    literal_secrets: Vec<String>,
    /// Compiled regex patterns whose matches should be redacted.
    patterns: Vec<Regex>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// Build a redactor with only the built-in detectors active.
    #[must_use]
    pub fn new() -> Self {
        Self {
            literal_secrets: Vec::new(),
            patterns: Vec::new(),
        }
    }

    /// Add a literal secret to redact.
    ///
    /// Longer literals are matched first so that a short literal that is a
    /// substring of a longer one does not leave a fragment of the longer one
    /// visible.
    pub fn add_literal_secret(&mut self, secret: impl Into<String>) {
        self.literal_secrets.push(secret.into());
        self.literal_secrets
            .sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        self.literal_secrets.dedup();
    }

    /// Add a compiled regex pattern to redact.
    pub fn add_pattern(&mut self, pattern: Regex) {
        self.patterns.push(pattern);
    }

    /// Add a regex pattern from a string.
    ///
    /// # Errors
    ///
    /// Returns [`regex::Error`] if `pattern` is not a valid regular expression.
    pub fn add_pattern_str(&mut self, pattern: &str) -> Result<(), regex::Error> {
        self.patterns.push(Regex::new(pattern)?);
        Ok(())
    }

    /// Remove secrets from a value, leaving everything else exactly as it was.
    ///
    /// Passes, in order:
    ///
    /// 1. a password inside a URL authority, `https://user:secret@host` → `***@host`;
    /// 2. the value of anything assigned to a credential-ish name, `api_key=...`;
    /// 3. user-configured literal secrets;
    /// 4. user-configured regex patterns;
    /// 5. PEM-encoded private key blocks;
    /// 6. a run of characters matching a known token shape.
    ///
    /// Line structure is left alone, because a caller may be redacting a block
    /// of output rather than a single field. [`redact_for_diagnostic`] is this
    /// plus escaping, and is what a caller that is building one line of prose
    /// wants.
    #[must_use]
    pub fn redact(&self, value: &str) -> String {
        let value = redact_url_authorities(value);
        let value = redact_assignments(&value);
        let value = self.redact_literals(&value);
        let value = self.redact_patterns(&value);
        let value = redact_pem_blocks(&value);
        redact_tokens(&value)
    }

    /// Render a value for a diagnostic without risking a secret in the output.
    ///
    /// [`redact`], then control characters escaped, so a value cannot forge
    /// structure in a multi-line message by containing newlines of its own.
    #[must_use]
    pub fn redact_for_diagnostic(&self, value: &str) -> String {
        escape_control_characters(&self.redact(value))
    }

    /// Redact every string in a JSON-like value while preserving its shape.
    ///
    /// Keys are left alone: they are the document's structure, and a key that
    /// had been rewritten would fail a schema check and read as a malformed
    /// document rather than as a redacted one. Values of every type are walked,
    /// and only strings can change — redaction never turns a string into a
    /// number or a list into an object, which is why validating after redacting
    /// is safe.
    #[must_use]
    pub fn redact_value(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.redact(text)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.redact_value(item)).collect())
            }
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), self.redact_value(value)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Replace every configured literal secret with [`REDACTED`].
    fn redact_literals(&self, text: &str) -> String {
        if self.literal_secrets.is_empty() {
            return text.to_owned();
        }
        let mut out = text.to_owned();
        for secret in &self.literal_secrets {
            if secret.is_empty() {
                continue;
            }
            out = out.split(secret).collect::<Vec<_>>().join(REDACTED);
        }
        out
    }

    /// Replace every match of a configured regex pattern with [`REDACTED`].
    fn redact_patterns(&self, text: &str) -> String {
        if self.patterns.is_empty() {
            return text.to_owned();
        }
        let mut out = text.to_owned();
        for pattern in &self.patterns {
            out = pattern.replace_all(&out, REDACTED).into_owned();
        }
        out
    }
}

/// The default redactor used by the free functions.
///
/// This is built once and includes the built-in detectors. It does not include
/// any user-configured literals or patterns; those require a [`Redactor`] built
/// from configuration.
static DEFAULT_REDACTOR: LazyLock<Redactor> = LazyLock::new(Redactor::new);

/// Remove secrets from a value using the default redactor.
///
/// See [`Redactor::redact`] for the exact passes.
#[must_use]
pub fn redact(value: &str) -> String {
    DEFAULT_REDACTOR.redact(value)
}

/// Render a value for a diagnostic using the default redactor.
#[must_use]
pub fn redact_for_diagnostic(value: &str) -> String {
    DEFAULT_REDACTOR.redact_for_diagnostic(value)
}

/// Redact every string in a JSON-like value using the default redactor.
#[must_use]
pub fn redact_value(value: &Value) -> Value {
    DEFAULT_REDACTOR.redact_value(value)
}

/// Whether a setting name looks like it holds a credential.
#[must_use]
pub fn looks_like_credential_name(name: &str) -> bool {
    let normalised: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    CREDENTIAL_NAME_FRAGMENTS
        .iter()
        .any(|fragment| normalised.contains(fragment))
}

/// Replace the userinfo of every `scheme://user:pass@host` with [`REDACTED`].
fn redact_url_authorities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find("://") {
        let (before, after) = rest.split_at(index + 3);
        out.push_str(before);
        // The authority ends at the first `/`, `?`, `#` or whitespace.
        let end = after
            .find(['/', '?', '#'])
            .or_else(|| after.find(char::is_whitespace))
            .unwrap_or(after.len());
        let (authority, tail) = after.split_at(end);
        match authority.find('@') {
            Some(at) => {
                out.push_str(REDACTED);
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Replace the value of `name=value` when `name` names a credential.
///
/// Only `=` is treated as an assignment here. YAML's `key: value` separator is
/// not included on purpose: this function runs over values that have already
/// been extracted from a parsed file, never over raw YAML text, so a colon in
/// the middle of a value is far more likely to be part of a URL or a timestamp
/// than an assignment.
fn redact_assignments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find('=') {
        let equals = cursor + offset;
        let start = name_start(text, equals);
        // Everything up to and including the `=` is copied verbatim either way,
        // so a name that begins before `cursor` is still reproduced correctly.
        out.push_str(&text[cursor..=equals]);
        if start < equals && looks_like_credential_name(&text[start..equals]) {
            out.push_str(REDACTED);
            cursor = value_end(text, equals + 1);
        } else {
            cursor = equals + 1;
        }
    }
    out.push_str(&text[cursor..]);
    out
}

/// Walk back from an `=` to the start of the name in front of it.
fn name_start(text: &str, equals: usize) -> usize {
    let mut start = equals;
    for (index, ch) in text[..equals].char_indices().rev() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            start = index;
        } else {
            break;
        }
    }
    start
}

/// Where the value of an assignment ends: at a separator that cannot appear
/// inside a token, or at the end of the string.
fn value_end(text: &str, from: usize) -> usize {
    text[from..]
        .find(['&', ';', ',', '"', '\'', '#', ' '])
        .map_or(text.len(), |offset| from + offset)
}

/// Replace PEM-encoded private key blocks with [`REDACTED`].
///
/// Detects blocks beginning with `-----BEGIN` and ending with `-----END`,
/// including the common `PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`,
/// `DSA PRIVATE KEY`, `OPENSSH PRIVATE KEY` and `ENCRYPTED PRIVATE KEY`
/// variants. The entire block, including the markers, is replaced so that no
/// hint of the key type or its base64 body survives.
///
/// Certificates and other non-private-key PEM blocks are left readable, because
/// a public certificate is not a secret.
fn redact_pem_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let (before, after) = rest.split_at(start);
        out.push_str(before);

        // Extract the label so we only redact private-key blocks.
        let label_start = "-----BEGIN ".len();
        let label_end = after[label_start..]
            .find("-----")
            .map(|n| label_start + n)
            .unwrap_or(after.len());
        let label = &after[label_start..label_end];
        let is_private_key = label.to_ascii_uppercase().contains("PRIVATE KEY");

        if let Some(end) = after.find("-----END ") {
            // Find the end of the closing line.
            let closing_start = end;
            let after_closing = &after[closing_start..];
            let closing_end = after_closing
                .find('\n')
                .map(|n| closing_start + n + 1)
                .unwrap_or(after.len());
            if is_private_key {
                out.push_str(REDACTED);
            } else {
                out.push_str(&after[..closing_end]);
            }
            rest = &after[closing_end..];
        } else {
            // An unterminated BEGIN block: redact the rest only if it is a private key.
            if is_private_key {
                out.push_str(REDACTED);
                break;
            }
            // For non-private-key blocks, copy the BEGIN line and continue scanning.
            let line_end = after.find('\n').map(|n| n + 1).unwrap_or(after.len());
            out.push_str(&after[..line_end]);
            rest = &after[line_end..];
        }
    }
    out.push_str(rest);
    out
}

/// Replace runs of characters that match a known credential shape.
fn redact_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let bytes = text.as_bytes();
    while cursor < bytes.len() {
        // A prefix only counts at a token boundary, so `ask-...` inside a word
        // is left alone.
        let at_boundary = cursor == 0 || !bytes[cursor - 1].is_ascii_alphanumeric();
        if at_boundary {
            if let Some(length) = token_length(&text[cursor..]) {
                out.push_str(REDACTED);
                cursor += length;
                continue;
            }
            if let Some(length) = bearer_token_length(&text[cursor..], &mut out) {
                out.push_str(REDACTED);
                cursor += length;
                continue;
            }
        }
        let ch = text[cursor..].chars().next().unwrap_or('\u{0}');
        out.push(ch);
        cursor += ch.len_utf8();
    }
    out
}

/// Length of a known credential shape at the start of `rest`, if any.
fn token_length(rest: &str) -> Option<usize> {
    for (prefix, minimum) in TOKEN_SHAPES {
        let Some(body) = rest.strip_prefix(prefix) else {
            continue;
        };
        let length = body
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
            .count();
        if length >= *minimum {
            return Some(prefix.len() + length);
        }
    }
    None
}

/// Length of the token after a `Bearer ` prefix, if `rest` starts with one.
///
/// The scheme word is copied to `out` first, so an `Authorization: Bearer x`
/// header stays readable while the credential disappears.
fn bearer_token_length(rest: &str, out: &mut String) -> Option<usize> {
    let lower = rest.get(..7)?.to_ascii_lowercase();
    if lower != "bearer " {
        return None;
    }
    let body = rest[7..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
        .count();
    if body < 8 {
        return None;
    }
    out.push_str(&rest[..7]);
    Some(7 + body)
}

/// Render control characters as escapes so a value cannot add lines to a
/// message, or start a new "line" that looks like it came from SURE.
///
/// Shared with [`crate::diagnostics::Field`], which escapes quotes and
/// backslashes as well and needs the same treatment of the newline in the
/// middle of a value.
pub fn escape_control_characters(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch == '\n' {
            out.push_str("\\n");
        } else if ch == '\r' {
            out.push_str("\\r");
        } else if ch == '\t' {
            out.push_str("\\t");
        } else if ch.is_control() {
            out.push_str(&format!("\\u{{{:04x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

/// The most characters of one source line an evidence excerpt keeps.
pub const EVIDENCE_EXCERPT_CHARS: usize = 240;

/// Escape controls and keep at most [`EVIDENCE_EXCERPT_CHARS`] characters.
///
/// Heuristic detectors quote the line a candidate stands on. A minified bundle
/// or a generated file is one line of megabytes, and storing it whole turned a
/// real project's report into 26 MB of machine text and put the whole bundle in
/// a finding's context (measured 2026-11-11, the `app` mini-program's
/// `.tmp/cloudcenter-*.js`). The excerpt keeps the first
/// [`EVIDENCE_EXCERPT_CHARS`] characters of the line — enough to find it again
/// — and marks that it was cut. The cut happens on the source text and escaping
/// after it, so a cut can never split an escape sequence; escapes inside the
/// kept prefix may make the stored string slightly longer than the bound.
#[must_use]
pub fn evidence_excerpt(line: &str) -> String {
    let trimmed = line.trim();
    let kept: String = trimmed.chars().take(EVIDENCE_EXCERPT_CHARS).collect();
    let cut = kept.chars().count() < trimmed.chars().count();
    let mut escaped = escape_control_characters(&kept);
    if cut {
        escaped.push('…');
    }
    escaped
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_password_in_a_url_does_not_survive() {
        let redacted = redact_for_diagnostic("https://alice:hunter2@api.example.com/v1");
        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(!redacted.contains("alice"), "{redacted}");
        assert_eq!(redacted, "https://***@api.example.com/v1");
    }

    #[test]
    fn an_evidence_excerpt_keeps_the_start_and_marks_the_cut() {
        let short = "path: '/pages/home/index'";
        assert_eq!(evidence_excerpt(short), short);

        let minified = "x".repeat(10_000);
        let excerpt = evidence_excerpt(&minified);
        assert_eq!(excerpt.chars().count(), EVIDENCE_EXCERPT_CHARS + 1);
        assert!(excerpt.ends_with('…'));

        // Escaping happens before the cut, so a control character near the
        // boundary cannot be split into half an escape sequence.
        let controls = "a".repeat(EVIDENCE_EXCERPT_CHARS - 1) + "\n" + &"b".repeat(10);
        let excerpt = evidence_excerpt(&controls);
        assert!(excerpt.contains("\\n"));
        assert!(!excerpt.contains('\n'));
    }

    #[test]
    fn a_url_without_credentials_is_left_readable() {
        // Diagnostics are for people. Redacting a harmless endpoint would make
        // the message useless and teach users to ignore the *** marker.
        assert_eq!(
            redact_for_diagnostic("https://api.example.com/v1"),
            "https://api.example.com/v1"
        );
        assert_eq!(
            redact_for_diagnostic("https://api.example.com/v1?stream=true"),
            "https://api.example.com/v1?stream=true"
        );
    }

    #[test]
    fn an_assigned_secret_is_replaced_but_the_name_is_kept() {
        let redacted = redact_for_diagnostic("api_key=abcdef1234567890");
        assert_eq!(redacted, "api_key=***");

        let in_query = redact_for_diagnostic("https://h/v1?api_key=abcdef1234567890&x=1");
        assert!(!in_query.contains("abcdef1234567890"), "{in_query}");
        assert!(in_query.contains("api_key=***"), "{in_query}");
        assert!(in_query.contains("x=1"), "{in_query}");

        // Known gap, stated rather than implied: a flag whose value is a
        // separate argument is not covered. Treating `name value` as an
        // assignment would redact "is" out of "--api-key is required", and the
        // structural rule — the config model has no credential field — is what
        // actually protects this file, not the pattern list.
        let separated = redact_for_diagnostic("--api-key abcdef1234567890");
        assert_eq!(separated, "--api-key abcdef1234567890");
    }

    #[test]
    fn known_token_shapes_are_replaced() {
        for secret in [
            "sk-abcdefghijklmnopqrstuvwxyz01",
            "ghp_abcdefghijklmnopqrstuvwxyz01",
            "github_pat_abcdefghijklmnopqrstuv",
            "AKIAIOSFODNN7EXAMPLE",
            "xoxb-123456789012-abcdefghijkl",
            "ya29.abcdefghijklmnopqrstuvwx",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ] {
            let redacted = redact_for_diagnostic(secret);
            assert_eq!(redacted, REDACTED, "{secret} was not recognised");
        }
    }

    #[test]
    fn an_authorization_header_keeps_its_scheme_word() {
        let redacted = redact_for_diagnostic("Authorization: Bearer abcdef1234567890");
        assert!(!redacted.contains("abcdef1234567890"), "{redacted}");
        assert!(redacted.contains("Bearer"), "{redacted}");
    }

    #[test]
    fn ordinary_prose_is_not_mangled() {
        // False positives are a real cost: a diagnostic nobody can read is a
        // diagnostic nobody acts on. `SECRET_REDACTION.md` asks for these to be
        // tested as well as the patterns themselves.
        for harmless in [
            "https://api.example.com/v1/models",
            "run the project's own commands",
            "inspect_only",
            "a task-free afternoon",
            "risk assessment",
            "the tokenizer settings",
            "project_intent.spec_path",
            "must_fix",
            "session_state_file",
            "public_key_notes",
        ] {
            assert_eq!(
                redact_for_diagnostic(harmless),
                harmless,
                "{harmless} should have been left alone"
            );
        }
    }

    #[test]
    fn a_too_short_run_after_a_prefix_is_not_a_token() {
        // `sk-1` is not a credential and redacting it would be noise.
        assert_eq!(redact_for_diagnostic("sk-1"), "sk-1");
        assert_eq!(redact_for_diagnostic("AKIA123"), "AKIA123");
    }

    #[test]
    fn a_prefix_inside_a_word_is_not_a_token_boundary() {
        let word = "risk-adjusted-abcdefghijklmnopqrstuvwxyz";
        assert_eq!(redact_for_diagnostic(word), word);
    }

    #[test]
    fn a_value_cannot_forge_extra_lines_in_a_message() {
        let redacted = redact_for_diagnostic("first\nSURE: nothing was checked\r\n\tend");
        assert!(!redacted.contains('\n'), "{redacted:?}");
        assert!(!redacted.contains('\r'), "{redacted:?}");
        assert_eq!(redacted, "first\\nSURE: nothing was checked\\r\\n\\tend");
    }

    #[test]
    fn credential_shaped_names_are_recognised_in_every_spelling() {
        for name in [
            "api_key",
            "apiKey",
            "API-KEY",
            "api key",
            "secret",
            "client_secret",
            "password",
            "PASSWD",
            "access_token",
            "github_token",
            "credentials",
            "private_key",
            "authorization",
        ] {
            assert!(
                looks_like_credential_name(name),
                "{name} should look like a credential"
            );
        }
    }

    #[test]
    fn ordinary_setting_names_are_not_flagged_as_credentials() {
        // Every name `sure.yaml` accepts, plus a few plausible neighbours. If a
        // real setting ever matches, users would be told their harmless setting
        // is a secret and would learn to distrust the warning.
        for name in [
            "privacy",
            "protection",
            "execution",
            "analysis",
            "project_intent",
            "checks",
            "report",
            "mode",
            "full_recording",
            "telemetry",
            "allow_dependency_install",
            "allow_network",
            "provider",
            "endpoint",
            "model",
            "goal",
            "spec_path",
            "existing_tests",
            "start_local_services",
            "browser_probe",
            "format",
            "author",
            "description",
            "notebook_name",
            "output_directory",
        ] {
            assert!(
                !looks_like_credential_name(name),
                "{name} is not a credential and must not be reported as one"
            );
        }
    }

    // --- configured redaction ------------------------------------------------

    #[test]
    fn a_configured_literal_secret_is_redacted_everywhere() {
        let mut redactor = Redactor::new();
        redactor.add_literal_secret("my-super-secret-value");

        let redacted = redactor.redact("prefix my-super-secret-value suffix");
        assert!(!redacted.contains("my-super-secret-value"), "{redacted}");
        assert_eq!(redacted, "prefix *** suffix");
    }

    #[test]
    fn a_configured_regex_pattern_is_redacted() {
        let mut redactor = Redactor::new();
        redactor
            .add_pattern_str(r"\bsecret-\d{4,}\b")
            .expect("valid regex");

        let redacted = redactor.redact("token secret-1234 and secret-999999");
        assert_eq!(redacted, "token *** and ***");
    }

    #[test]
    fn longer_literals_are_redacted_before_shorter_ones() {
        let mut redactor = Redactor::new();
        redactor.add_literal_secret("abc");
        redactor.add_literal_secret("abcdef");

        let redacted = redactor.redact("abcdef");
        assert_eq!(redacted, "***");
    }

    #[test]
    fn configured_rules_stack_with_built_in_detectors() {
        let mut redactor = Redactor::new();
        redactor.add_literal_secret("custom-secret");

        let redacted =
            redactor.redact("custom-secret and sk-abcdefghijklmnopqrstuvwxyz01 are both gone");
        assert!(!redacted.contains("custom-secret"), "{redacted}");
        assert!(
            !redacted.contains("sk-abcdefghijklmnopqrstuvwxyz01"),
            "{redacted}"
        );
        assert_eq!(redacted, "*** and *** are both gone");
    }

    // --- common secret formats -----------------------------------------------

    #[test]
    fn a_pem_private_key_block_is_fully_redacted() {
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MqK8k7f5l2EwkK4p\n-----END RSA PRIVATE KEY-----";
        let redacted = redact(key);
        assert!(!redacted.contains("MIIEpAIB"), "{redacted}");
        assert!(!redacted.contains("BEGIN RSA PRIVATE KEY"), "{redacted}");
        assert_eq!(redacted, REDACTED);
    }

    #[test]
    fn pem_variants_are_all_redacted() {
        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
        ] {
            let key = format!("-----BEGIN {label}-----\nabc\n-----END {label}-----");
            let redacted = redact(&key);
            assert_eq!(redacted, REDACTED, "{label} was not redacted");
        }
    }

    #[test]
    fn a_password_in_a_connection_string_is_redacted() {
        let redacted = redact("Server=myserver;Database=mydb;Password=hunter2;User Id=alice;");
        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(redacted.contains("Password=***"), "{redacted}");
        assert!(redacted.contains("Server=myserver"), "{redacted}");
    }

    #[test]
    fn a_bearer_token_is_redacted() {
        let redacted = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0");
        assert!(!redacted.contains("eyJhbGci"), "{redacted}");
        assert!(redacted.contains("Bearer ***"), "{redacted}");
    }

    #[test]
    fn an_api_key_is_redacted() {
        let redacted = redact("api-key: sk-abcdefghijklmnopqrstuvwxyz01");
        assert_eq!(redacted, "api-key: ***");
    }

    // --- false positives -----------------------------------------------------

    #[test]
    fn harmless_strings_that_look_a_bit_like_secrets_are_left_alone() {
        for harmless in [
            "ask-me-anything",
            "risk-free trial",
            "tokenize this sentence",
            "the key to success",
            "pass the salt",
            "my password is not here",
            "public_key_notes",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        ] {
            assert_eq!(
                redact(harmless),
                harmless,
                "{harmless} should not have been redacted"
            );
        }
    }

    #[test]
    fn a_short_random_looking_string_is_not_an_api_key() {
        assert_eq!(redact("key: abc123"), "key: abc123");
    }

    // --- structured redaction ------------------------------------------------

    #[test]
    fn structured_redaction_preserves_json_shape() {
        let document = serde_json::json!({
            "status": "open",
            "severity": "must_fix",
            "count": 3,
            "flags": [true, false, null],
            "nested": {"title": "risk-free", "secret": "sk-abcdefghijklmnopqrstuvwxyz01"},
        });
        let redacted = redact_value(&document);
        assert_eq!(redacted["count"], document["count"]);
        assert_eq!(redacted["flags"], document["flags"]);
        assert_eq!(redacted["nested"]["title"], json!("risk-free"));
        assert_eq!(redacted["nested"]["secret"], json!("***"));
    }

    #[test]
    fn structured_redaction_redacts_nested_secrets() {
        let document = serde_json::json!({
            "level1": {
                "level2": {
                    "token": "ghp_abcdefghijklmnopqrstuvwxyz01",
                    "url": "https://user:pass@example.com"
                }
            }
        });
        let redacted = redact_value(&document);
        assert_eq!(redacted["level1"]["level2"]["token"], json!("***"));
        assert_eq!(
            redacted["level1"]["level2"]["url"],
            json!("https://***@example.com")
        );
    }

    #[test]
    fn a_redactor_can_redact_a_json_value_with_configured_literals() {
        let mut redactor = Redactor::new();
        redactor.add_literal_secret("project-internal-secret");
        let document = serde_json::json!({
            "message": "project-internal-secret is in the payload",
            "nested": {"key": "project-internal-secret"},
        });
        let redacted = redactor.redact_value(&document);
        assert_eq!(redacted["message"], json!("*** is in the payload"));
        assert_eq!(redacted["nested"]["key"], json!("***"));
    }
}
