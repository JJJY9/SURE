//! `sure config show`: the settings in effect and which layer chose each one.
//!
//! The endpoint, model and command of an analysis provider are shown as *set*
//! or *not set*, never as values. The store's own rule is that a diagnostic
//! never has a secret to handle; a `config show` that printed them would make
//! this the first command whose output could carry one.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sure_core::config::authority::{Authority, Layer, Resolved};
use sure_core::config::{Config, ConfigSource, LoadedConfig};
use sure_core::paths::Paths;

use crate::commands::Named;
use crate::report::{Failed, Report};

/// One line of the settings table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingRow {
    /// The setting's stable name.
    pub name: &'static str,
    /// What is in force, as a person reads it.
    pub value: String,
    /// The layer that chose it: your settings, project sure.yaml, or default.
    pub source: &'static str,
}

/// What `sure config show` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigShowReport {
    /// The user's settings file this run would read.
    pub user_file: PathBuf,
    /// Whether that file is there and was read.
    pub user_file_present: bool,
    /// The project named on the command line, if any.
    pub project: Option<PathBuf>,
    /// Whether the project's `sure.yaml` is there and was read.
    pub project_file_present: bool,
    /// The settings in effect, in a stable order.
    pub settings: Vec<SettingRow>,
    /// Project requests that could not be granted, in plain language.
    pub refused: Vec<String>,
}

impl ConfigShowReport {
    /// What a script reads.
    #[must_use]
    pub fn machine(&self) -> Value {
        json!({
            "user_settings": {
                "path": self.user_file.display().to_string(),
                "present": self.user_file_present,
            },
            "project": self.project.as_ref().map(|path| path.display().to_string()),
            "project_settings": {
                "path": self.project.as_ref().map(|path| path.join(Config::FILE_NAME).display().to_string()),
                "present": self.project_file_present,
            },
            "settings": self.settings.iter().map(|row| json!({
                "name": row.name,
                "value": row.value,
                "source": row.source,
            })).collect::<Vec<_>>(),
            "refused": self.refused,
        })
    }

    /// Write the human form.
    ///
    /// # Errors
    ///
    /// Any failure from `out`.
    pub fn human(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(out, "SURE settings in effect")?;
        writeln!(out)?;
        writeln!(
            out,
            "  user settings   {} ({})",
            self.user_file.display(),
            if self.user_file_present {
                "read"
            } else {
                "not present"
            }
        )?;
        match &self.project {
            Some(project) => writeln!(
                out,
                "  project         {} ({})",
                project.display(),
                if self.project_file_present {
                    "sure.yaml read"
                } else {
                    "no sure.yaml"
                }
            )?,
            None => writeln!(
                out,
                "  project         no project named; project layer not read"
            )?,
        }
        writeln!(out)?;
        writeln!(out, "  {:<38} {:<28} from", "setting", "value")?;
        for row in &self.settings {
            writeln!(out, "  {:<38} {:<28} {}", row.name, row.value, row.source)?;
        }
        if !self.refused.is_empty() {
            writeln!(out)?;
            writeln!(
                out,
                "Requests the project layer made that no layer could grant:"
            )?;
            for line in &self.refused {
                writeln!(out, "  - {line}")?;
            }
        }
        Ok(())
    }
}

/// Run `sure config show`.
#[must_use]
pub fn show(project: Option<&Path>, named: Named<'_>) -> Report {
    match build(project, named) {
        Ok(report) => Report::ConfigShow(Box::new(report)),
        Err(detail) => Report::Failed(Box::new(Failed {
            command: "config show",
            what: "No configuration was read.",
            detail,
        })),
    }
}

fn build(project: Option<&Path>, named: Named<'_>) -> Result<ConfigShowReport, String> {
    let paths = Paths::discover_with(named.store, named.settings_file)
        .map_err(|error| error.to_string())?;
    let user_file = paths.user_config_file();

    let project = project
        .map(|path| {
            if !path.is_absolute() {
                return Err(format!(
                    "The project directory was given as \"{}\", which is not an absolute path.",
                    path.display()
                ));
            }
            if !path.is_dir() {
                return Err(format!("There is nothing at \"{}\".", path.display()));
            }
            Ok(path.to_path_buf())
        })
        .transpose()?;

    let authority = match &project {
        Some(path) => {
            paths
                .ensure_settings_outside(path)
                .map_err(|error| error.to_string())?;
            Authority::load(path, &user_file).map_err(|error| error.to_string())?
        }
        None => {
            let user = Config::load_file(&user_file).map_err(|error| error.to_string())?;
            let user = user.source.is_file().then_some(user);
            Authority::new(
                user,
                LoadedConfig {
                    config: Config::default(),
                    source: ConfigSource::NoFile,
                    searched: PathBuf::new(),
                },
            )
        }
    };

    let mut settings = Vec::new();
    let permissions = authority.permissions();
    let user_named_execution = authority
        .user()
        .is_some_and(|config| config.execution.mode.runs_project_code());
    settings.push(row(
        "execution.mode",
        authority.execution_mode().as_str().to_owned(),
        if user_named_execution {
            "your settings"
        } else {
            "default"
        },
    ));
    settings.push(flag(
        "execution.run_project_code",
        permissions.run_project_code,
    ));
    settings.push(flag(
        "execution.install_dependencies",
        permissions.install_dependencies,
    ));
    settings.push(flag("execution.network", permissions.network));
    settings.push(flag("execution.write_project", permissions.write_project));
    settings.push(flag(
        "execution.connect_service",
        permissions.connect_service,
    ));

    let privacy = authority.privacy_mode();
    settings.push(resolved("privacy.mode", privacy.value.as_str(), &privacy));
    settings.push(flag("privacy.full_recording", authority.full_recording()));
    let retention = authority.full_recording_retention_days();
    settings.push(resolved(
        "privacy.full_recording_retention_days",
        &retention.value.to_string(),
        &retention,
    ));

    let protection = authority.protection();
    settings.push(resolved(
        "protection.mode",
        protection.value.as_str(),
        &protection,
    ));

    let analysis = authority.analysis();
    settings.push(resolved(
        "analysis.provider",
        analysis.value.provider.as_str(),
        &analysis,
    ));
    settings.push(analysis_field(
        "analysis.endpoint",
        analysis.value.endpoint.is_some(),
        &analysis,
    ));
    settings.push(analysis_field(
        "analysis.model",
        analysis.value.model.is_some(),
        &analysis,
    ));
    settings.push(analysis_field(
        "analysis.command",
        analysis.value.command.is_some(),
        &analysis,
    ));

    let refused = authority
        .privileges()
        .into_iter()
        .filter(|privilege| privilege.is_refused_escalation())
        .map(|privilege| {
            let asked_by = privilege
                .asked_by
                .iter()
                .map(|layer| layer.plain_description())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} — asked by {asked_by}", privilege.request.as_str())
        })
        .collect();

    Ok(ConfigShowReport {
        user_file,
        user_file_present: authority.user_file().is_some(),
        project,
        project_file_present: authority.project_file().source.is_file(),
        settings,
        refused,
    })
}

fn row(name: &'static str, value: String, source: &'static str) -> SettingRow {
    SettingRow {
        name,
        value,
        source,
    }
}

fn flag(name: &'static str, value: bool) -> SettingRow {
    row(
        name,
        if value { "true" } else { "false" }.to_owned(),
        if value { "your settings" } else { "default" },
    )
}

fn source(by: Option<Layer>) -> &'static str {
    match by {
        Some(Layer::User) => "your settings",
        Some(Layer::Project) => "project sure.yaml",
        None => "default",
    }
}

fn resolved<T>(name: &'static str, value: &str, resolved: &Resolved<T>) -> SettingRow {
    row(name, value.to_owned(), source(resolved.by))
}

fn analysis_field(
    name: &'static str,
    present: bool,
    resolved: &Resolved<sure_core::config::AnalysisConfig>,
) -> SettingRow {
    row(
        name,
        if present {
            "set (value hidden)".to_owned()
        } else {
            "not set".to_owned()
        },
        if present {
            source(resolved.by)
        } else {
            "default"
        },
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::commands::Named;
    use std::fs;

    fn write(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, text).unwrap();
    }

    fn human(report: &ConfigShowReport) -> String {
        let mut out = Vec::new();
        report.human(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn config_show_hides_provider_values_and_names_the_layer_that_chose_each_setting() {
        let directory = sure_testkit::scratch::directory("sure config show", "layers");
        let settings = directory.join("sure.yaml");
        write(
            &settings,
            "execution:\n  mode: inspect_only\nanalysis:\n  provider: openai_compatible\n  endpoint: https://example.invalid/secret-token\n  model: secret-model\n",
        );
        let project = directory.join("project");
        write(
            &project.join(Config::FILE_NAME),
            "execution:\n  mode: host_confirmed\nprotection:\n  mode: strict\n",
        );

        let report = build(
            Some(&project),
            Named {
                store: None,
                settings_file: Some(&settings),
            },
        )
        .unwrap();
        let human = human(&report);
        let machine = report.machine().to_string();

        assert!(human.contains("protection.mode"), "{human}");
        assert!(human.contains("project sure.yaml"), "{human}");
        assert!(human.contains("set (value hidden)"), "{human}");
        assert!(human.contains("run_project_code"), "{human}");
        assert!(
            report
                .refused
                .iter()
                .any(|line| line.contains("run_project_code")),
            "{:?}",
            report.refused
        );
        for secret in ["secret-token", "secret-model"] {
            assert!(
                !human.contains(secret),
                "config show leaked {secret}: {human}"
            );
            assert!(
                !machine.contains(secret),
                "config show leaked {secret}: {machine}"
            );
        }
    }

    #[test]
    fn config_show_without_a_project_does_not_read_a_project_layer() {
        let directory = sure_testkit::scratch::directory("sure config show", "user-only");
        let settings = directory.join("sure.yaml");
        write(
            &settings,
            "analysis:\n  provider: openai_compatible\n  endpoint: https://example.invalid/endpoint\n  model: model-name\n",
        );

        let report = build(
            None,
            Named {
                store: None,
                settings_file: Some(&settings),
            },
        )
        .unwrap();
        assert!(report.project.is_none());
        assert!(!report.project_file_present);
        let human = human(&report);
        assert!(human.contains("no project named"), "{human}");
        assert!(!human.contains("example.invalid"), "{human}");
        assert!(!human.contains("model-name"), "{human}");
    }

    #[test]
    fn config_show_refuses_a_settings_file_inside_the_project() {
        let directory = sure_testkit::scratch::directory("sure config show", "inside");
        let project = directory.join("project");
        let settings = project.join("sure.yaml");
        write(
            &settings,
            "execution:
  mode: inspect_only
",
        );
        let error = build(
            Some(&project),
            Named {
                store: None,
                settings_file: Some(&settings),
            },
        )
        .unwrap_err();
        assert!(
            error.to_lowercase().contains("inside") || error.to_lowercase().contains("settings"),
            "{error}"
        );
    }

    #[test]
    fn config_show_refuses_a_relative_project_path() {
        let error = build(
            Some(Path::new("relative")),
            Named::store(Path::new("store")),
        )
        .unwrap_err();
        assert!(error.contains("not an absolute path"), "{error}");
    }
}
