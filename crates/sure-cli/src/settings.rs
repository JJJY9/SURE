//! `sure config set`: writing one setting into the file only a person can write.
//!
//! # Why this command exists
//!
//! `P13-T009` settled which settings can grant what, and the answer left a hole
//! this command fills. Full recording and every execution mode other than
//! `inspect_only` are granted by the user's own settings file **and by nothing
//! else** — a checked project's `sure.yaml` may ask for them and can never grant
//! them (`Layer::can_grant`, `Authority::full_recording`,
//! `Authority::execution_mode`). On Windows that file is
//! `%APPDATA%\SURE\sure.yaml`, and before this task nothing in the build created
//! it, wrote it, or told a person it existed. The correct answer and the
//! reachable answer had come apart: SURE would report a setting as not in force
//! and give no way to put it in force that a user could find from the command
//! line.
//!
//! So this module writes that one file, on request, with a person's own words.
//! It writes **nothing else**: not the project's `sure.yaml` (which it may not
//! edit at all — see [`refuse_a_project_file`]), not the store, and not any file
//! the caller did not name through `sure_core::paths`.
//!
//! # What it will and will not write
//!
//! Every setting in this release falls into one of three groups, and the line
//! between them is *whether a value in the user's own file reaches anything*:
//!
//! * **Writable** ([`WRITABLE`]): the settings `Authority` arbitrates out of the
//!   user's own file, every one of which some other command then reads —
//!   `execution.*` reaches the pipeline's authorisation, `privacy.full_recording`
//!   and the retention reach the recording rules, `privacy.mode` and
//!   `protection.mode` reach the report and the hook's consent record.
//! * **Refused with a reason** ([`NOT_WRITABLE`]): settings that exist in
//!   `sure.yaml` and that this release reads from the *checked project's* file
//!   (or from nowhere at all), so writing them here would be a file that looks
//!   like a decision and is not one. `privacy.telemetry` is the sharpest case:
//!   nothing implements it, and the task that owns this command requires it to be
//!   refused rather than written silently.
//! * **Refused as unknown**: a name this build does not know, with the writable
//!   names listed, so that a typo is a refusal rather than a created file.
//!
//! # How the file is edited
//!
//! As **text**, one key at a time, never by re-rendering the document. A person's
//! settings file is one they wrote by hand, with comments explaining why they
//! chose what they chose; parsing it into a value and printing it back would
//! silently delete every one of those comments. So the edit finds the line the
//! setting is on and changes that line, and the whole file is compared afterwards
//! against the document that *should* have resulted:
//!
//! 1. the existing file is read and parsed by [`Config::from_yaml`] — the
//!    product's only reader — so a file this build cannot use is refused before
//!    anything is written to it;
//! 2. the edit is made as text;
//! 3. the result is parsed again, and compared leaf by leaf with the original
//!    document with exactly one leaf changed ([`with_leaf_set`]);
//! 4. the same reader is asked to accept the result, and its own words are the
//!    refusal if it does not.
//!
//! Step 3 is the one that makes a text editor safe here. A line-oriented edit can
//! land in the wrong block, and if it does, the two documents differ somewhere
//! else and the command refuses without writing — a visible refusal rather than a
//! settings file that says something the person did not ask for.
//!
//! # What the person is told
//!
//! Three sentences, and they are the acceptance criterion: one for a write, one
//! for a no-op, and one for a refusal. A person can tell a write from a no-op
//! without opening the file, and every one of the three names the file in the
//! operating system's own terms — `Path::display`, which on Windows is the path
//! Explorer shows.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value as Json, json};
use serde_yaml_ng::{Mapping, Value};
use sure_core::config::{
    AnalysisProvider, Authority, Config, PrivacyMode, ProjectRequest, ProtectionMode,
};
use sure_core::execution::ExecutionMode;
use sure_core::paths::Paths;

use crate::commands::Named;
use crate::grants::Grants;
use crate::report::{Report, SettingsChange, SettingsOutcome};

/// A setting that may be written into the user's own file.
struct Setting {
    /// The name a person types, `group.name`.
    name: &'static str,
    /// The path into the document, outermost key first.
    path: &'static [&'static str],
    /// What kind of value it takes.
    kind: Kind,
    /// What it decides, in the words the confirmation uses.
    decides: &'static str,
}

/// What a setting's value may be.
enum Kind {
    /// `true` or `false`.
    Flag,
    /// One of a closed set, read from the enum that defines it rather than
    /// listed here — a second list would be a second answer to "which words does
    /// this release accept".
    OneOf(fn() -> Vec<&'static str>),
    /// A whole number of days. Whether it may be negative is not decided here:
    /// `Config::from_yaml` refuses a negative retention with its own words, and
    /// one rule for that is better than two that agree today.
    Days,
}

/// The settings `sure config set` may write.
///
/// Every one of them is arbitrated out of the user's own file by
/// `sure_core::config::authority`, and every one of them reaches something: this
/// list is not "the settings SURE has" but "the settings that are the user's own
/// to decide". A name that is missing from here is refused, and
/// `every_writable_setting_is_one_the_product_reads_from_the_users_own_file`
/// checks the other direction — that nothing on this list is dead.
const WRITABLE: &[Setting] = &[
    Setting {
        name: "execution.mode",
        path: &["execution", "mode"],
        kind: Kind::OneOf(execution_modes),
        decides: "whether SURE may run any of a project's own code, and how",
    },
    Setting {
        name: "execution.allow_dependency_install",
        path: &["execution", "allow_dependency_install"],
        kind: Kind::Flag,
        decides: "whether a check may install the project's dependencies",
    },
    Setting {
        name: "execution.allow_network",
        path: &["execution", "allow_network"],
        kind: Kind::Flag,
        decides: "whether a check may reach the network",
    },
    Setting {
        name: "execution.allow_project_write",
        path: &["execution", "allow_project_write"],
        kind: Kind::Flag,
        decides: "whether SURE may change files inside the project it is checking",
    },
    Setting {
        name: "privacy.full_recording",
        path: &["privacy", "full_recording"],
        kind: Kind::Flag,
        decides: "whether a full recording of a session may be kept",
    },
    Setting {
        name: "privacy.full_recording_retention_days",
        path: &["privacy", "full_recording_retention_days"],
        kind: Kind::Days,
        decides: "how many days recorded content is kept for",
    },
    Setting {
        name: "privacy.mode",
        path: &["privacy", "mode"],
        kind: Kind::OneOf(privacy_modes),
        decides: "what may leave this machine, and what a model may be shown",
    },
    Setting {
        name: "analysis.provider",
        path: &["analysis", "provider"],
        kind: Kind::OneOf(analysis_providers),
        decides: "which analysis provider a run may consult when the project names none; a \
                  project's own file naming one is the one in force",
    },
    Setting {
        name: "protection.mode",
        path: &["protection", "mode"],
        kind: Kind::OneOf(protection_modes),
        decides: "how much SURE intervenes before a dangerous action",
    },
];

fn execution_modes() -> Vec<&'static str> {
    ExecutionMode::ALL
        .iter()
        .map(|mode| mode.as_str())
        .collect()
}

fn privacy_modes() -> Vec<&'static str> {
    PrivacyMode::ALL.iter().map(|mode| mode.as_str()).collect()
}

fn analysis_providers() -> Vec<&'static str> {
    AnalysisProvider::ALL.iter().map(|p| p.as_str()).collect()
}

fn protection_modes() -> Vec<&'static str> {
    ProtectionMode::ALL
        .iter()
        .map(|mode| mode.as_str())
        .collect()
}

/// Settings this build knows and this command will not write, with the reason.
///
/// A trailing `.` is a family: every setting under that group. The reasons are
/// short because they are read in a terminal, and each one says *where the value
/// really comes from* rather than only that the answer is no.
const NOT_WRITABLE: &[(&str, &str)] = &[
    (
        "privacy.telemetry",
        "nothing in this release implements telemetry. No code path sends usage data anywhere, so \
         this setting could not take effect whatever it said, and SURE will not write a setting \
         that does nothing: the file would look like a decision you had made.",
    ),
    (
        "analysis.endpoint",
        "written by editing your settings file rather than by this command: `sure config set` \
         writes settings that are a word, a flag or a number of days, and the endpoint, model and \
         command are none of those. `analysis.provider` is writable.",
    ),
    (
        "analysis.model",
        "written by editing your settings file rather than by this command: `sure config set` \
         writes settings that are a word, a flag or a number of days, and the endpoint, model and \
         command are none of those. `analysis.provider` is writable.",
    ),
    (
        "analysis.command",
        "written by editing your settings file rather than by this command: `sure config set` \
         writes settings that are a word, a flag or a number of days, and the endpoint, model and \
         command are none of those. `analysis.provider` is writable.",
    ),
    (
        "project_intent.",
        "the goal and the spec path a run compares a project against are read from the checked \
         project's own sure.yaml. A goal found in a file is documentation rather than a \
         requirement — the agent whose work is being checked can write that file — and the place \
         for your own words is `sure check --goal`.",
    ),
    (
        "checks.",
        "which optional checks run is read from the checked project's own sure.yaml: a project \
         may switch its own checks off, and this release does not read them from your file.",
    ),
    (
        "report.",
        "the format of a report is decided by `--format` on the command line, and nothing in this \
         release reads this setting from any settings file.",
    ),
    (
        "redaction.",
        "the redaction that runs is the built-in one. Nothing in this release builds a redactor \
         from a settings file, so these rules would change nothing.",
    ),
];

/// What a request costs a person to grant, for a report that has to say so.
///
/// The setting a refusal in [`crate::grants`] points at, and the `sure config set`
/// line that would write it. `value` is `None` where no single value grants the
/// request — a longer retention is any number larger than the one allowed, so
/// there is nothing to quote — and the whole hint is `None` where *no* setting
/// grants it in this release.
pub struct GrantHint {
    /// The setting that decides it.
    pub setting: &'static str,
    /// The value that would grant it, when one value would.
    pub value: Option<&'static str>,
}

/// The setting that would grant a request a run refused.
#[must_use]
pub fn grant_hint(request: ProjectRequest) -> Option<GrantHint> {
    let (setting, value) = match request {
        ProjectRequest::RunProjectCode => ("execution.mode", Some("host_confirmed")),
        ProjectRequest::InstallDependencies => ("execution.allow_dependency_install", Some("true")),
        ProjectRequest::Network => ("execution.allow_network", Some("true")),
        ProjectRequest::WriteProject => ("execution.allow_project_write", Some("true")),
        ProjectRequest::FullRecording => ("privacy.full_recording", Some("true")),
        ProjectRequest::ExtendedRetention => ("privacy.full_recording_retention_days", None),
        // Neither of these has a setting that would grant it. The provider in
        // effect is the project's, so a user's file naming a provider changes
        // nothing; and telemetry is implemented by nothing at all. A hint here
        // would send a person to write a setting that would not work, which is
        // the failure this whole module is written to avoid.
        ProjectRequest::ExternalAnalysis | ProjectRequest::Telemetry => return None,
    };
    Some(GrantHint { setting, value })
}

/// `sure config set SETTING VALUE`.
///
/// # Errors
///
/// None: every failure is a [`Report`], because a command that could not write
/// still has to answer in the shape a caller reads.
#[must_use]
pub fn set(setting: &str, value: &str, named: Named<'_>) -> Report {
    let project = match std::env::current_dir() {
        Ok(project) => project,
        Err(error) => {
            return refused(
                setting,
                value,
                &PathBuf::new(),
                "SURE could not work out which directory it is running in, so it could not tell \
                 which project's settings to read alongside your own.",
                Some(error.to_string()),
            );
        }
    };
    match Paths::discover_with(named.store, named.settings_file) {
        Ok(paths) => set_with(&paths, &project, setting, value),
        Err(error) => refused(setting, value, &PathBuf::new(), &error.to_string(), None),
    }
}

/// The same, with the locations and the project given rather than discovered.
#[must_use]
pub fn set_with(paths: &Paths, project: &Path, setting: &str, value: &str) -> Report {
    let file = paths.user_config_file();

    // Before anything is read or written: the file this command writes must not
    // be one the project being judged could write. It is the same rule
    // `crate::check` and `crate::hook` apply to the file they *read*, and here it
    // is stronger still — this command is the one that creates it, so a project
    // that could name this file could have SURE write itself a grant. See
    // `Paths::ensure_settings_outside`.
    if let Err(error) = paths.ensure_settings_outside(project) {
        return refused(setting, value, &file, &error.to_string(), None);
    }

    // The setting, before the file: a name this build does not know is refused
    // without reading anything, and a setting that is not the user's own is
    // refused here, which is what makes "a request that names a project-level
    // setting is refused rather than written into the project" true by
    // construction rather than by care.
    let writable = match classify(setting) {
        Ok(writable) => writable,
        Err(reason) => {
            return refused(
                setting,
                value,
                &file,
                &reason,
                Some(format!(
                    "This build writes these settings: {}",
                    writable_names().join(", ")
                )),
            );
        }
    };

    // The value, before the file, so that a value SURE cannot write is not
    // reported as a problem with a file SURE has not looked at yet.
    let (parsed, rendered) = match scalar(value, &writable.kind) {
        Ok(scalar) => scalar,
        Err(reason) => return refused(setting, value, &file, &reason, None),
    };

    let existing = match fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return refused(
                setting,
                value,
                &file,
                "SURE could not read your settings file, so it will not write it.",
                Some(error.to_string()),
            );
        }
    };

    // The file as it is, read by the product's own reader. A file this build
    // cannot use is refused rather than edited: writing a new setting into it
    // would leave a file that still does not work, and the person would have
    // been told their setting was written.
    let before = match Config::from_yaml(&existing) {
        Ok(_) => match serde_yaml_ng::from_str::<Value>(&existing) {
            Ok(value) => value,
            Err(error) => {
                return refused(
                    setting,
                    value,
                    &file,
                    "SURE could not read your settings file as a document, so it will not edit \
                     it.",
                    Some(error.to_string()),
                );
            }
        },
        Err(error) => {
            return refused(
                setting,
                value,
                &file,
                "Your settings file is already one this build cannot use, and every run refuses \
                 it. SURE will not add a setting to a file that does not work: fix it first, and \
                 the refusal below says what is wrong with it.",
                Some(error.at_file(&file).to_string()),
            );
        }
    };

    let already = current(&before, writable.path);
    let changed = match &already {
        Some(current) => current != &parsed,
        // The key is absent, so the answer is what SURE does unasked. Writing a
        // value that is already the default would create or grow a file to say
        // something that was true before it existed, which is a change to a
        // person's file that changes nothing else.
        None => default_of(writable.path).as_ref() != Some(&parsed),
    };

    if !changed {
        let (grants, grants_error) = read_back_parts(read_back(project, &file));
        return Report::Settings(Box::new(SettingsChange {
            command: "config set",
            setting: setting.to_owned(),
            value: rendered,
            settings_file: file.display().to_string(),
            outcome: SettingsOutcome::AlreadySaid,
            grants,
            grants_error,
        }));
    }

    let candidate = match edited(&existing, writable.path, &rendered) {
        Ok(text) => text,
        Err(reason) => {
            return refused(
                setting,
                value,
                &file,
                &format!(
                    "SURE will not risk a settings file it cannot predict: {reason}. Nothing was \
                     written, and the file is exactly as it was."
                ),
                None,
            );
        }
    };

    // The line edit is checked against the document it was supposed to produce.
    // A line-oriented editor can land in the wrong block, and this is where that
    // stops: the two documents are compared, and a difference anywhere but the
    // one setting is a refusal rather than a write.
    let expected = with_leaf_set(&before, writable.path, &parsed);
    match serde_yaml_ng::from_str::<Value>(&candidate) {
        Ok(after) if after == expected => {}
        Ok(_) => {
            return refused(
                setting,
                value,
                &file,
                "SURE's edit would have changed something other than that one setting, so it was \
                 not made. Nothing was written.",
                None,
            );
        }
        Err(error) => {
            return refused(
                setting,
                value,
                &file,
                "SURE's edit did not leave a document it can read, so it was not made. Nothing \
                 was written.",
                Some(error.to_string()),
            );
        }
    }

    // The product's own reader has the last word on whether this file is one a
    // run can use — including the values it refuses (`cloud_enhanced`,
    // `custom`) and the combinations it refuses. Its words are the refusal.
    if let Err(error) = Config::from_yaml(&candidate) {
        return refused(
            setting,
            value,
            &file,
            &format!(
                "SURE refuses that value, so nothing was written. `{}` decides {}",
                setting, writable.decides
            ),
            Some(error.at_file(&file).to_string()),
        );
    }

    if let Err(error) = write(&file, &candidate) {
        return refused(
            setting,
            value,
            &file,
            "SURE could not write your settings file. Nothing was changed.",
            Some(error),
        );
    }

    let (grants, grants_error) = read_back_parts(read_back(project, &file));
    Report::Settings(Box::new(SettingsChange {
        command: "config set",
        setting: setting.to_owned(),
        value: rendered,
        settings_file: file.display().to_string(),
        outcome: SettingsOutcome::Written,
        grants,
        grants_error,
    }))
}

/// Write the text, and let no reader see half of a file.
///
/// Next to the file rather than over it, then renamed, so that a crash or a full
/// disk leaves the settings file a person had rather than a truncated one. The
/// temporary file is removed on the way out whichever way it went: a refusal that
/// left a `.new` beside somebody's settings file would be litter that changes
/// what a backup or a directory listing shows.
fn write(file: &Path, text: &str) -> Result<(), String> {
    let parent = file
        .parent()
        .ok_or_else(|| format!("{} has no directory to write into.", file.display()))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = file.with_extension("yaml.sure-new");
    fs::write(&temporary, text)
        .map_err(|error| format!("SURE could not write {}: {error}", temporary.display()))?;
    match fs::rename(&temporary, file) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(format!(
                "SURE could not put {} in place: {error}",
                file.display()
            ))
        }
    }
}

/// Read the settings back through the reader the product uses.
///
/// The whole of the acceptance criterion "what the command writes is read back by
/// the same reader the product uses": this is [`Authority::load`], the function
/// every run and every hook calls, against the file that was just written — and
/// what it returns is what a run will report.
fn read_back(project: &Path, file: &Path) -> Result<Grants, String> {
    let authority =
        Authority::load(project, file).map_err(|error| error.at_file(file).to_string())?;
    Ok(Grants::of(&authority, file))
}

/// The reading-back result as the pair the report carries.
///
/// `Ok` and `Err` cannot both happen and the two `Option`s make that visible in
/// the type, which is the point: a renderer that sees `None` for both knows the
/// command never got far enough to read anything back, and one that sees an
/// error knows the file may have changed and the answer did not.
fn read_back_parts(read: Result<Grants, String>) -> (Option<Grants>, Option<String>) {
    match read {
        Ok(grants) => (Some(grants), None),
        Err(error) => (None, Some(error)),
    }
}

/// The setting a name refers to, or the reason this build will not write it.
fn classify(name: &str) -> Result<&'static Setting, String> {
    if let Some(setting) = WRITABLE.iter().find(|setting| setting.name == name) {
        return Ok(setting);
    }
    for (prefix, reason) in NOT_WRITABLE {
        if name == *prefix || name.starts_with(prefix) && prefix.ends_with('.') {
            return Err(format!(
                "`{name}` is not a setting your own file decides: {reason}"
            ));
        }
    }
    Err(format!(
        "`{name}` is not a setting this build knows. SURE will not create a file to hold a \
         setting it does not read."
    ))
}

/// The names this command writes, in one list a refusal can print.
fn writable_names() -> Vec<&'static str> {
    WRITABLE.iter().map(|setting| setting.name).collect()
}

/// The value as a YAML scalar, or the reason it is not one.
///
/// A value is one line, one scalar, and of the setting's kind. The kind check is
/// not the final word on whether the *value* is acceptable — `Config::from_yaml`
/// is, and its refusal is in the product's own words — but it is the final word
/// on whether this command can write it at all, and it is what turns
/// `sure config set privacy.mode yes` into a sentence about the three words that
/// would have worked.
fn scalar(text: &str, kind: &Kind) -> Result<(Value, String), String> {
    if text.contains(['\n', '\r']) {
        return Err(
            "A setting's value is one line. SURE will not write a value that could become a \
             setting of its own when the file is read back."
                .to_owned(),
        );
    }
    let parsed: Value = serde_yaml_ng::from_str(text)
        .map_err(|error| format!("`{text}` is not a value SURE can write: {error}"))?;
    match kind {
        Kind::Flag => {
            if !matches!(parsed, Value::Bool(_)) {
                return Err(format!(
                    "`{text}` is not a true-or-false setting. Write `true` or `false`."
                ));
            }
        }
        Kind::OneOf(values) => {
            let Value::String(word) = &parsed else {
                return Err(format!(
                    "`{text}` is not one of the words this setting accepts: {}.",
                    values().join(", ")
                ));
            };
            if !values().contains(&word.as_str()) {
                return Err(format!(
                    "`{text}` is not one of the words this setting accepts: {}.",
                    values().join(", ")
                ));
            }
        }
        Kind::Days => {
            let number = match &parsed {
                Value::Number(number) => number.as_i64(),
                _ => None,
            };
            if number.is_none() {
                return Err(format!(
                    "`{text}` is not a whole number of days. Write a number, such as `7`."
                ));
            }
        }
    }
    let rendered = serde_yaml_ng::to_string(&parsed)
        .map_err(|error| format!("`{text}` could not be written back as YAML: {error}"))?
        .trim_end_matches(['\n', '\r'])
        .to_owned();
    Ok((parsed, rendered))
}

/// The value the document holds at a path, if it holds one.
///
/// `None` covers both "the key is absent" and "something on the way is not a
/// mapping". The second is not the same fact as the first — a file with
/// `execution: host_confirmed` says something this command cannot edit — and the
/// edit that follows refuses it, because the document it produces would not match
/// the document it was supposed to.
fn current(document: &Value, path: &[&str]) -> Option<Value> {
    let mut cursor = document;
    for key in path {
        let Value::Mapping(map) = cursor else {
            return None;
        };
        cursor = map.get(Value::String((*key).to_owned()))?;
    }
    Some(cursor.clone())
}

/// What SURE does when no file says anything about this setting.
///
/// Read out of `Config::default()` rather than written here, so that the value
/// this command calls "already true" is the value the product would really use.
/// `None` means the setting has no default to compare against — the file names a
/// number of days or it names nothing, and naming nothing is not the same as
/// naming a number — so writing one is a change even when the number written
/// happens to be the one SURE would have used.
fn default_of(path: &[&str]) -> Option<Value> {
    let default = serde_yaml_ng::to_value(Config::default()).ok()?;
    let value = current(&default, path)?;
    (!value.is_null()).then_some(value)
}

/// The document with one leaf set, for comparison with an edit's result.
///
/// This is the intent the text edit is checked against, so it is deliberately
/// dumb: it builds the mapping it was asked for and says nothing about whether
/// the result is a plausible settings file. `Config::from_yaml` answers that
/// question separately, and the two answers together are what "the edit did
/// exactly this and the result is usable" means.
fn with_leaf_set(document: &Value, path: &[&str], value: &Value) -> Value {
    let mut root = if document.is_mapping() {
        document.clone()
    } else {
        Value::Mapping(Mapping::new())
    };
    let mut cursor = &mut root;
    for (index, key) in path.iter().enumerate() {
        let Value::Mapping(map) = cursor else {
            return root;
        };
        let key = Value::String((*key).to_owned());
        if index + 1 == path.len() {
            map.insert(key, value.clone());
            return root;
        }
        if !map.contains_key(&key) {
            map.insert(key.clone(), Value::Mapping(Mapping::new()));
        }
        let Some(entry) = map.get_mut(&key) else {
            return root;
        };
        if !entry.is_mapping() {
            *entry = Value::Mapping(Mapping::new());
        }
        cursor = entry;
    }
    root
}

/// The file's text with one setting written into it, comments and all.
///
/// # Errors
///
/// A sentence saying which shape of file this command will not edit. Every one of
/// them means "nothing was written": the shapes it refuses are the ones where a
/// line-oriented edit could not be sure which key it was changing.
fn edited(text: &str, path: &[&str], rendered: &str) -> Result<String, String> {
    let [outer, inner] = path else {
        return Err(format!(
            "SURE writes settings one group at a time, and {} is not in that shape.",
            path.join(".")
        ));
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
    let newline = if text.contains("\r\n") { "\r" } else { "" };
    // `split` leaves an empty element for a trailing newline. Kept, so that the
    // file keeps its own line ending convention and a file that ended without a
    // trailing newline still does.
    let tail = lines.pop().unwrap_or_default();

    let inner_text = format!("{inner}:");
    let outer_text = format!("{outer}:");

    let block = lines.iter().position(|line| {
        !line.starts_with([' ', '\t', '#']) && line.trim_end_matches('\r') == outer_text
    });

    let Some(start) = block else {
        // A line that starts with this group's name but is indented is a key
        // inside another block, and appending a second top-level group would
        // change what that other block means. Refused, with nothing written.
        if lines
            .iter()
            .any(|line| line.starts_with([' ', '\t']) && line.trim_start().starts_with(&outer_text))
        {
            return Err(format!(
                "`{outer}:` is written inside another block in your file, and SURE will not add a \
                 second `{outer}:` at the top level."
            ));
        }
        return Ok(append_block(&lines, &tail, outer, inner, rendered, newline));
    };

    let head = lines[start].trim_end_matches('\r');
    let rest = head[outer_text.len()..].trim_start();
    if !rest.is_empty() && !rest.starts_with('#') {
        return Err(format!(
            "`{outer}:` has a value on the same line in your file. SURE edits the block form it \
             can read back, so it will not rewrite that line."
        ));
    }

    // The block runs until the next line that starts at the left margin. Blank
    // lines and comments stay inside it, because that is how a person lays out a
    // settings file and neither changes what it means.
    let end = lines
        .iter()
        .skip(start + 1)
        .position(|line| {
            let trimmed = line.trim_end_matches('\r');
            !trimmed.trim().is_empty() && !trimmed.starts_with([' ', '\t'])
        })
        .map_or(lines.len(), |offset| start + 1 + offset);

    let indent_of = |line: &str| line.len() - line.trim_start_matches([' ', '\t']).len();
    let inner_indent = lines[start + 1..end]
        .iter()
        .filter(|line| {
            let trimmed = line.trim_start_matches([' ', '\t']).trim_end_matches('\r');
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|line| indent_of(line))
        .min();
    let indent = inner_indent.unwrap_or(2);

    let found = lines[start + 1..end].iter().position(|line| {
        let trimmed = line.trim_start_matches([' ', '\t']).trim_end_matches('\r');
        indent_of(line) == indent && trimmed.starts_with(&inner_text)
    });

    match found {
        Some(offset) => {
            let index = start + 1 + offset;
            let line = lines[index].clone();
            let key_end = indent + inner_text.len();
            let value_rest = line[key_end..].trim_start();
            // A `#` that follows whitespace begins a comment, and the comment is
            // part of what the person wrote. The value is replaced and the
            // comment is kept, character for character, including the spacing
            // between them. A `#` with no whitespace before it is not a comment
            // in YAML either, so the two rules agree rather than being two.
            //
            // `None` means the whole rest of the line was the value, and then
            // there is nothing to keep: appending it would produce
            // `mode: host_confirmedinspect_only`, which parses, is a different
            // setting from the one asked for, and would be caught by the
            // comparison below rather than by a user.
            let comment = value_rest
                .char_indices()
                .find(|(index, character)| {
                    *character == '#'
                        && *index > 0
                        && value_rest.as_bytes()[index - 1].is_ascii_whitespace()
                })
                .map_or("", |(index, _)| &value_rest[index - 1..]);
            let ending = if line.ends_with('\r') { "\r" } else { "" };
            lines[index] = format!(
                "{}{inner_text} {rendered}{comment}{ending}",
                &line[..indent]
            );
        }
        None => {
            let at = lines[start + 1..end]
                .iter()
                .rposition(|line| !line.trim().is_empty())
                .map_or(start + 1, |offset| start + 2 + offset);
            lines.insert(
                at,
                format!("{}{inner_text} {rendered}{newline}", " ".repeat(indent)),
            );
        }
    }

    lines.push(tail);
    Ok(lines.join("\n"))
}

/// The whole file with a new group at the end, for a file that has none.
fn append_block(
    lines: &[String],
    tail: &str,
    outer: &str,
    inner: &str,
    rendered: &str,
    newline: &str,
) -> String {
    let mut lines: Vec<String> = lines
        .iter()
        .map(|line| line.trim_end_matches('\r').to_owned())
        .collect();
    // A file that holds nothing but blank lines and comments becomes the file
    // that holds the setting. Rewriting the blank lines rather than appending to
    // them is not a loss: they said nothing.
    let blank = lines
        .iter()
        .all(|line| line.trim().is_empty() || line.trim_start().starts_with('#'));
    if !blank && !lines.is_empty() {
        lines.push(String::new());
    } else if blank {
        lines.clear();
    }
    lines.push(format!("{outer}:"));
    lines.push(format!("  {inner}: {rendered}"));
    let mut text = lines.join("\n");
    if !tail.is_empty() || !text.is_empty() {
        text.push_str(newline);
        text.push('\n');
    }
    text
}

/// Build a refusal: nothing was written, here is why, and here is the file.
fn refused(setting: &str, value: &str, file: &Path, what: &str, detail: Option<String>) -> Report {
    Report::Settings(Box::new(SettingsChange {
        command: "config set",
        setting: setting.to_owned(),
        value: value.to_owned(),
        settings_file: file.display().to_string(),
        outcome: SettingsOutcome::Refused {
            what: what.to_owned(),
            detail,
        },
        grants: None,
        grants_error: None,
    }))
}

/// Write the human form.
///
/// # Errors
///
/// Any failure from `out`.
pub fn human(change: &SettingsChange, out: &mut impl Write) -> io::Result<()> {
    // The three openings, and they are the acceptance criterion: a person can
    // tell a write from a no-op from a refusal at a glance, without opening the
    // file and without reading the rest of the report.
    match &change.outcome {
        SettingsOutcome::Written => {
            writeln!(out, "sure config set wrote your settings file.")?;
        }
        SettingsOutcome::AlreadySaid => {
            writeln!(out, "sure config set wrote nothing.")?;
        }
        SettingsOutcome::Refused { .. } => {
            writeln!(out, "sure config set wrote nothing, and here is why.")?;
        }
    }
    writeln!(out)?;
    writeln!(out, "  Setting    {}", change.setting)?;
    match &change.outcome {
        SettingsOutcome::Written => writeln!(out, "  Written    {}", change.value)?,
        SettingsOutcome::AlreadySaid => {
            writeln!(out, "  Already    {}", change.value)?;
        }
        SettingsOutcome::Refused { .. } => writeln!(out, "  Asked for  {}", change.value)?,
    }
    writeln!(out, "  File       {}", change.settings_file)?;
    writeln!(out)?;

    match &change.outcome {
        SettingsOutcome::Written => {
            writeln!(
                out,
                "That file is your own, and it is the only one that can grant this: a project's \
                 sure.yaml may ask for something and can never grant itself anything, because a \
                 file the agent under test can write cannot be the authority for what SURE may \
                 do. It is outside every project you check."
            )?;
        }
        SettingsOutcome::AlreadySaid => {
            writeln!(
                out,
                "That file already said this, so it was left exactly as it was — not rewritten, \
                 not reformatted, and its comments are all still there. This is not a failure: \
                 what you asked for was already true."
            )?;
        }
        SettingsOutcome::Refused { what, detail } => {
            writeln!(out, "{what}")?;
            if let Some(detail) = detail {
                writeln!(out)?;
                writeln!(out, "{detail}")?;
            }
            writeln!(out)?;
            writeln!(
                out,
                "Nothing was written, so your settings file is exactly as it was."
            )?;
        }
    }
    writeln!(out)?;

    if let Some(grants) = &change.grants {
        grants.human(out)?;
    } else if let Some(error) = &change.grants_error {
        // The write happened and the reading back did not. Saying nothing would
        // leave a person assuming the setting is in force, so the sentence says
        // which half did not happen.
        writeln!(
            out,
            "SURE could not read the settings back to show you what is now in force: {error}"
        )?;
        writeln!(out)?;
    }

    let status = match change.outcome {
        SettingsOutcome::Written | SettingsOutcome::AlreadySaid => crate::report::exit::OK,
        SettingsOutcome::Refused { .. } => crate::report::exit::FAILED,
    };
    match &change.outcome {
        SettingsOutcome::Refused { .. } => writeln!(
            out,
            "SURE exited with status {status}, which is what it returns when it tried and did \
             not finish. That is not the same as a command this build cannot carry out: the \
             command was understood, and the answer is that this build will not write it."
        ),
        _ => writeln!(
            out,
            "SURE exited with status {status}, which is what it returns when it did what it was \
             asked. A run started after this one reports the setting as in force."
        ),
    }
}

/// The same answer as facts, for the response frame.
#[must_use]
pub fn machine(change: &SettingsChange) -> Json {
    let (state, what) = match &change.outcome {
        SettingsOutcome::Written => ("written", Json::Null),
        SettingsOutcome::AlreadySaid => ("already_said", Json::Null),
        SettingsOutcome::Refused { what, .. } => ("refused", Json::String(what.clone())),
    };
    let mut details = json!({
        "setting": change.setting,
        "value": change.value,
        "settings_file": change.settings_file,
        "state": state,
        "what": what,
    });
    if let SettingsOutcome::Refused { detail, .. } = &change.outcome {
        details["detail"] = match detail {
            Some(detail) => Json::String(detail.clone()),
            None => Json::Null,
        };
    }
    details["granted"] = match &change.grants {
        Some(grants) => grants.machine(),
        None => Json::Null,
    };
    details["granted_error"] = match &change.grants_error {
        Some(error) => Json::String(error.clone()),
        None => Json::Null,
    };
    details
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory = sure_testkit::scratch::directory("sure config set", name);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn paths_for(directory: &Path) -> Paths {
        Paths::from_roots(directory.join("data"), directory.join("config")).unwrap()
    }

    /// A `sure config set` that writes into a file of this test's own.
    fn set_in(directory: &Path, setting: &str, value: &str) -> Report {
        let paths = paths_for(directory);
        set_with(&paths, &directory.join("project"), setting, value)
    }

    fn text_of(report: &Report) -> String {
        report.human_text()
    }

    fn file_of(directory: &Path) -> PathBuf {
        directory.join("config").join("sure.yaml")
    }

    /// The whole point of the command: a setting only the user's own file can
    /// make, written from nothing, and read back as being in force.
    ///
    /// The directory holding the settings file has no file in it at all when this
    /// starts, which is the state every machine begins in — the state the task
    /// says had no writer and no reader a person could reach.
    #[test]
    fn a_setting_only_the_users_own_file_can_make_is_written_from_nothing() {
        let directory = scratch("from-nothing");
        let report = set_in(&directory, "execution.mode", "host_confirmed");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        assert_eq!(change.outcome, SettingsOutcome::Written);
        let grants = change.grants.as_ref().expect("the settings were read back");
        assert_eq!(grants.execution_mode, ExecutionMode::HostConfirmed);
        assert!(!grants.nothing_granted());

        // The file really is there, and what is in it is what a person would have
        // written by hand.
        let text = std::fs::read_to_string(file_of(&directory)).unwrap();
        assert!(text.contains("execution:"));
        assert!(text.contains("mode: host_confirmed"), "{text}");

        // And the reader the product uses agrees, from the file alone.
        let authority = Authority::load(&directory.join("project"), &file_of(&directory)).unwrap();
        assert_eq!(authority.execution_mode(), ExecutionMode::HostConfirmed);
    }

    /// The three sentences, and that they differ.
    #[test]
    fn a_write_a_no_op_and_a_refusal_are_three_different_sentences() {
        let directory = scratch("three-sentences");
        let written = text_of(&set_in(&directory, "execution.mode", "host_confirmed"));
        let already = text_of(&set_in(&directory, "execution.mode", "host_confirmed"));
        let refused = text_of(&set_in(&directory, "privacy.telemetry", "false"));

        assert!(written.starts_with("sure config set wrote your settings file."));
        assert!(already.starts_with("sure config set wrote nothing."));
        assert!(refused.starts_with("sure config set wrote nothing, and here is why."));
        assert_ne!(written, already);
        // The second run really was a no-op: the file still says what the first
        // run wrote, and running it a third time with a different value does
        // change the file — so the no-op above was a decision rather than a
        // command that never writes anything.
        assert!(
            std::fs::read_to_string(file_of(&directory))
                .unwrap()
                .contains("host_confirmed")
        );
        let third = text_of(&set_in(&directory, "execution.mode", "inspect_only"));
        assert!(third.contains("Written"));
        assert!(
            std::fs::read_to_string(file_of(&directory))
                .unwrap()
                .contains("inspect_only")
        );
    }

    /// A refusal writes nothing at all — including when the refusal is a value
    /// this release does not implement.
    #[test]
    fn a_refused_value_or_setting_leaves_the_file_alone() {
        let directory = scratch("refused");
        let report = set_in(&directory, "privacy.mode", "cloud_enhanced");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        let SettingsOutcome::Refused { what, detail } = &change.outcome else {
            panic!("a mode this release does not implement was written");
        };
        assert!(what.contains("refuses that value"), "{what}");
        assert!(
            detail
                .as_deref()
                .unwrap_or_default()
                .contains("cloud_enhanced"),
            "the product's own reason is not in the refusal: {detail:?}"
        );
        assert!(!file_of(&directory).exists());

        // Nothing was created for a no-op either: a setting already at its
        // default is not a reason to create a file.
        let report = set_in(&directory, "privacy.full_recording", "false");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        assert_eq!(change.outcome, SettingsOutcome::AlreadySaid);
        assert!(!file_of(&directory).exists());
    }

    /// 该通道存在的理由:没有项目文件的机器上,用户自己的分析 provider 必须
    /// 可经 `config set` 写入(权威仲裁在项目未指定时取用户层值)。
    #[test]
    fn the_users_own_analysis_provider_is_writable() {
        let directory = scratch("analysis-provider");
        let report = set_in(&directory, "analysis.provider", "local_command");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        assert_eq!(change.outcome, SettingsOutcome::Written);
        let after = std::fs::read_to_string(file_of(&directory)).unwrap();
        assert!(after.contains("provider: local_command"), "{after}");
    }

    /// A file with comments and other settings is edited, not rewritten.
    #[test]
    fn an_edit_keeps_every_other_line_of_the_file() {
        let directory = scratch("keeps-lines");
        let file = file_of(&directory);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let before = "# my settings\nexecution:\n  # why: I run tests by hand\n  mode: inspect_only\n  allow_network: false\n\nprivacy:\n  mode: fully_local\n";
        std::fs::write(&file, before).unwrap();

        let report = set_in(&directory, "execution.mode", "host_confirmed");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        assert_eq!(change.outcome, SettingsOutcome::Written);

        let after = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            after,
            before.replace("mode: inspect_only", "mode: host_confirmed"),
            "the file was not edited in place:\n{after}"
        );
    }

    /// A no-op leaves the file byte-for-byte as it was, spelling and all.
    #[test]
    fn a_no_op_does_not_rewrite_a_differently_spelled_value() {
        let directory = scratch("no-op-spelling");
        let file = file_of(&directory);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let before = "privacy:\n  full_recording: True\n";
        std::fs::write(&file, before).unwrap();
        let report = set_in(&directory, "privacy.full_recording", "true");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        assert_eq!(change.outcome, SettingsOutcome::AlreadySaid);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    /// A file whose settings are not in the shape this editor handles is refused
    /// rather than edited.
    #[test]
    fn a_file_in_another_shape_is_refused_rather_than_edited() {
        let directory = scratch("other-shape");
        let file = file_of(&directory);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let before = "execution: {mode: inspect_only}\n";
        std::fs::write(&file, before).unwrap();
        let report = set_in(&directory, "execution.mode", "host_confirmed");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        assert!(
            matches!(change.outcome, SettingsOutcome::Refused { .. }),
            "{:?}",
            change.outcome
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    /// A file this build cannot use is refused, with the reader's own words.
    #[test]
    fn a_file_the_product_cannot_read_is_not_edited() {
        let directory = scratch("unreadable");
        let file = file_of(&directory);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let before = "execution:\n  mode: inspect_only\n  allow_network: true\n";
        std::fs::write(&file, before).unwrap();
        // Refused on its own terms: inspect_only with the network allowed is a
        // combination `Config::from_yaml` rejects (`ErrorKind::Contradiction`),
        // so this file is not one a run can use and it is not one SURE will add
        // a setting to — adding one would leave a file that still does not work,
        // with the person told their setting was written.
        let report = set_in(&directory, "privacy.full_recording", "true");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        let SettingsOutcome::Refused { what, detail } = &change.outcome else {
            panic!("{:?}", change.outcome);
        };
        assert!(what.contains("already one this build cannot use"), "{what}");
        assert!(detail.is_some(), "the reader's reason is not quoted");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    /// A project-level setting is refused, and the project's file is untouched.
    #[test]
    fn a_project_level_setting_is_refused_and_no_project_file_is_written() {
        let directory = scratch("project-level");
        let project = directory.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let project_file = project.join("sure.yaml");
        std::fs::write(&project_file, "checks:\n  existing_tests: false\n").unwrap();

        let paths = paths_for(&directory);
        for (setting, value) in [
            ("project_intent.goal", "a bookmark manager"),
            ("checks.existing_tests", "true"),
            ("report.format", "json"),
            ("redaction.literals", "secret"),
        ] {
            let report = set_with(&paths, &project, setting, value);
            let Report::Settings(change) = &report else {
                panic!("{report:?}");
            };
            assert!(
                matches!(change.outcome, SettingsOutcome::Refused { .. }),
                "{setting} was written"
            );
            assert!(!file_of(&directory).exists(), "{setting} created a file");
        }
        assert_eq!(
            std::fs::read_to_string(&project_file).unwrap(),
            "checks:\n  existing_tests: false\n"
        );
    }

    /// A settings file inside the project is refused, as a run's is.
    #[test]
    fn a_settings_file_inside_the_project_is_refused() {
        let directory = scratch("inside-project");
        let project = directory.join("project");
        let config = project.join("config");
        std::fs::create_dir_all(&config).unwrap();
        let paths = Paths::from_roots(directory.join("data"), config).unwrap();
        let report = set_with(&paths, &project, "execution.mode", "host_confirmed");
        let Report::Settings(change) = &report else {
            panic!("{report:?}");
        };
        assert!(matches!(change.outcome, SettingsOutcome::Refused { .. }));
        assert!(!project.join("config").join("sure.yaml").exists());
    }

    /// Every hint points at a setting this command will really write, with a
    /// value it will really accept.
    #[test]
    fn every_hint_points_at_a_writable_setting() {
        for request in ProjectRequest::ALL {
            let Some(hint) = grant_hint(*request) else {
                continue;
            };
            let setting = match classify(hint.setting) {
                Ok(setting) => setting,
                Err(reason) => panic!("{request:?} points at {}: {reason}", hint.setting),
            };
            if let Some(value) = hint.value {
                assert!(
                    scalar(value, &setting.kind).is_ok(),
                    "{request:?} points at {} = {value}, which this command would refuse",
                    hint.setting
                );
            }
        }
    }

    /// Every writable setting is one of the names the user's own file decides.
    ///
    /// The claim this pins is the one that makes the command worth having: each
    /// name here is arbitrated out of the user's own file by `Authority`, so a
    /// value written here is a value a run reads. The check is a comparison with
    /// the product's own accessors rather than with a list written here — a
    /// setting added to the table without a reader, or a reader added without a
    /// way to write it, shows up as a failure rather than as a gap.
    #[test]
    fn every_writable_setting_is_one_the_product_reads_from_the_users_own_file() {
        let user = Config::from_yaml(
            "execution:\n  mode: host_confirmed\n  allow_dependency_install: true\n  \
             allow_network: true\n  allow_project_write: true\nprivacy:\n  mode: fully_local\n  \
             full_recording: true\n  full_recording_retention_days: 11\nprotection:\n  \
             mode: strict\nanalysis:\n  provider: local_command\n",
        )
        .unwrap();
        let authority = Authority::new(
            Some(sure_core::config::LoadedConfig {
                config: user,
                source: sure_core::config::ConfigSource::File(PathBuf::from("sure.yaml")),
                searched: PathBuf::from("sure.yaml"),
            }),
            sure_core::config::LoadedConfig {
                config: Config::default(),
                source: sure_core::config::ConfigSource::NoFile,
                searched: PathBuf::from("sure.yaml"),
            },
        );

        for setting in WRITABLE {
            let moved = match setting.name {
                "execution.mode" => authority.execution_mode() == ExecutionMode::HostConfirmed,
                "execution.allow_dependency_install" => {
                    authority.permissions().install_dependencies
                }
                "execution.allow_network" => authority.permissions().network,
                "execution.allow_project_write" => authority.permissions().write_project,
                "privacy.full_recording" => authority.full_recording(),
                "privacy.full_recording_retention_days" => {
                    authority.full_recording_retention_days().value == 11
                }
                "privacy.mode" => authority.privacy_mode().value == PrivacyMode::FullyLocal,
                "protection.mode" => authority.protection().value == ProtectionMode::Strict,
                "analysis.provider" => {
                    authority.analysis().value.provider == AnalysisProvider::LocalCommand
                }
                other => panic!("{other} is writable and this test does not know what reads it"),
            };
            assert!(moved, "{} is writable and changes nothing", setting.name);
        }
    }
}
