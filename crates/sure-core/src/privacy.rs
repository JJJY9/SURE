//! What a run says about privacy, and about models, in the words a user reads.
//!
//! `docs/architecture/PRIVACY_AND_MODEL_STRATEGY.md` is the authoritative
//! statement of what the three privacy modes mean. This module is the other
//! half of it: the part a *run* has to make about the configuration it is
//! actually under, and about whether a model was consulted.
//!
//! # Why the mode here is not the mode a file names
//!
//! [`PrivacyMode`] is read in exactly one place that a user can see, and the
//! value it reports is [`Authority::privacy_mode`]'s — the arbitrated one.
//! A project file may ask for a behaviour and cannot grant itself one
//! (`docs/architecture/CONFIG_AUTHORITY.md`, ADR 0002, ADR 0011), so reporting
//! the value from the project's own `sure.yaml` would be a false statement about
//! the user's policy: worse than saying nothing, because it would read as an
//! answer.
//!
//! [`PrivacyStatement::project_mode`] carries what the project's own settings
//! come to as well, and the renderers use it for one purpose only — to say, when
//! the two differ, that the stricter one is the one in effect and that the
//! project's could not have been otherwise. It is never the reported mode.
//!
//! # Why model use is read from the run and not from a constant
//!
//! The tempting sentence is a constant: "no check in this build asks for
//! model-backed analysis, so no model was consulted". It is true today, and it
//! is the shape of statement this product exists to refuse — the day a check
//! does ask, a constant would keep saying the reassuring thing. So
//! [`ModelUse`] is read from the run's own record of stage 8, the one stage that
//! would ask a model, and the answer changes with the code rather than with
//! nobody's memory. `crate::pipeline::Pipeline::model_assessment` documents what
//! that stage records.
//!
//! # What this module will not say
//!
//! Nothing here is a claim about a model's behaviour. A privacy claim about what
//! a model received is not a fact SURE can establish, and asking the model is
//! not evidence about the model. Every sentence below is a fact about this run's
//! configuration and this run's own record.

use crate::config::{AnalysisProvider, Authority, Layer, PrivacyMode};
use crate::pipeline::{PipelineOutcome, Stage, StageOutcome};

/// What one run's configuration says about privacy and about model use.
///
/// Built from an [`Authority`] by [`PrivacyStatement::of`], which is the only
/// constructor: a statement assembled field by field at a call site could take
/// the mode from the project's file and read as though it had been arbitrated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyStatement {
    /// The privacy mode in effect, after arbitration between the two layers.
    ///
    /// [`Authority::privacy_mode`]'s value: `fully_local` beats `local_first`
    /// whichever layer wrote it, and a mode this release does not implement can
    /// never be the result.
    pub mode: PrivacyMode,
    /// The most trusted layer whose file named a mode stricter than the
    /// default, or `None` when neither file did.
    ///
    /// `None` is "nothing beyond the default", never "SURE did not work it
    /// out" — `Resolved::by`'s distinction, carried here so that a renderer
    /// cannot blur the two into one sentence.
    pub mode_set_by: Option<Layer>,
    /// What this project's own settings come to: what its `sure.yaml` declares,
    /// which is the default when it declares nothing.
    ///
    /// Reported only so that a run can say the project's own settings were not
    /// the ones that decided. It is never the mode in effect.
    pub project_mode: PrivacyMode,
    /// The analysis provider this run's configuration names.
    ///
    /// [`Authority::analysis`]'s provider: a provider the project's own file
    /// names is the one in force, and when the project names none the user's
    /// own file's is. It is what the run *names*, not a statement that
    /// anything was sent, and not a statement about a model.
    pub provider: AnalysisProvider,
}

impl PrivacyStatement {
    /// Read the statement for one run's configuration.
    #[must_use]
    pub fn of(authority: &Authority) -> Self {
        let mode = authority.privacy_mode();
        Self {
            mode: mode.value,
            mode_set_by: mode.by,
            project_mode: authority.project().privacy.mode,
            provider: authority.analysis().value.provider,
        }
    }

    /// Whether anything about this project may leave this machine under the mode
    /// in effect.
    #[must_use]
    pub const fn allows_external_analysis(&self) -> bool {
        self.mode.allows_external_analysis()
    }

    /// Whether the project's own settings asked for a mode other than the one in
    /// effect.
    ///
    /// The rule is a maximum, so this can only be true in one direction: the
    /// user's own settings being stricter than the project's. It can never be
    /// true of a project that asked for *more* privacy than the user configured,
    /// because the stricter value is then both the project's and the mode in
    /// effect. `the_two_settings_can_only_differ_in_one_direction` pins that,
    /// because the sentence the renderer writes for this case depends on it.
    #[must_use]
    pub const fn project_settings_differ(&self) -> bool {
        self.project_mode as u8 != self.mode as u8
    }

    /// What the mode in effect permits and forbids, in one sentence.
    #[must_use]
    pub const fn mode_plain_words(&self) -> &'static str {
        mode_plain_words(self.mode)
    }

    /// Where the mode in effect came from, in one sentence.
    #[must_use]
    pub const fn mode_set_by_plain_words(&self) -> &'static str {
        match self.mode_set_by {
            Some(Layer::User) => "Your own SURE settings, outside this project, set it.",
            Some(Layer::Project) => {
                "This project's own sure.yaml set it. A project may ask for more privacy than \
                 you configured; it cannot ask for less."
            }
            // `None` is "nothing beyond the default", which is a different
            // answer from "SURE did not look" and is the one a reader needs.
            None => {
                "Nothing set this: it is what SURE does when no settings file asks for \
                     something stricter."
            }
        }
    }
}

/// What the three privacy modes mean, in the words a user reads.
///
/// The same three sentences are frozen in
/// `docs/architecture/PRIVACY_AND_MODEL_STRATEGY.md`, and
/// `the_three_modes_say_what_the_document_says_they_say` fails if the two drift.
/// The unavailable mode is described rather than omitted: a user who has read
/// about `cloud_enhanced` somewhere is owed the sentence that says SURE does not
/// implement it, in the same place as the two that work.
#[must_use]
pub const fn mode_plain_words(mode: PrivacyMode) -> &'static str {
    match mode {
        PrivacyMode::LocalFirst => {
            "Evidence stays on this machine. External analysis is allowed only where your own \
             settings configure it, and nothing is sent by a check that does not ask for it."
        }
        PrivacyMode::FullyLocal => {
            "Nothing about this project is sent to any external service, whether or not a \
             provider is configured."
        }
        PrivacyMode::CloudEnhanced => {
            "External analysis and sync, explicitly enabled. This release does not implement it, \
             and it is refused rather than accepted: write `local_first` to allow external \
             analysis only where it is configured, or `fully_local` to send nothing out at all."
        }
    }
}

/// What a run did about models, as that run's own record says.
///
/// Not a claim about what a model received, and not a claim about what a service
/// did with anything. It is the run's record of the one stage that would ask a
/// model, read here so that a report cannot keep saying "no model was consulted"
/// after the build changes to consult one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelUse {
    /// No provider is configured, so no model can be consulted.
    NoProvider,
    /// A provider is configured and this run asked it nothing about the project.
    NothingAsked {
        /// The provider the run's configuration names.
        provider: AnalysisProvider,
    },
    /// A provider is configured and SURE could not use it.
    ///
    /// A fault in the configuration rather than a scope limit, and no model was
    /// consulted either way.
    ProviderUnusable {
        /// The provider the run's configuration names.
        provider: AnalysisProvider,
    },
    /// The stage that asks a model did its work for this run.
    ///
    /// This is the one state in which a model may have been consulted, and it is
    /// read from stage 8's own outcome rather than inferred from the
    /// configuration: the stage is the only thing in this build that would ask
    /// one, so its doing the work is the record that one was asked.
    Consulted {
        /// The provider the run's configuration names.
        provider: AnalysisProvider,
    },
    /// This run's record does not establish whether a model was consulted.
    ///
    /// A run that stopped before the stage that asks one, or an outcome this
    /// build does not recognise. SURE reports neither answer rather than
    /// guessing between them: "no model was consulted" is a claim, and a run
    /// that cannot support it must not make it.
    CannotConfirm {
        /// The provider the run's configuration names.
        provider: AnalysisProvider,
    },
}

impl ModelUse {
    /// Read stage 8's own record.
    ///
    /// `provider` is the provider the run's configuration names; the run's
    /// record decides everything else.
    #[must_use]
    pub fn of(provider: AnalysisProvider, run: &PipelineOutcome) -> Self {
        // With no provider configured, no model can be consulted, and that is a
        // fact about the configuration rather than about how far the run got —
        // so it is the answer even for a run that stopped at its first stage.
        if provider == AnalysisProvider::Disabled {
            return Self::NoProvider;
        }

        // A run that stopped before this stage leaves it recorded as
        // `NotPartOfWork` — the same variant stage 8 writes when it ran and
        // found nothing to ask. The variant alone cannot tell "nothing was
        // asked" from "the run never got there", and reading it as the first
        // would be exactly the false reassurance this type exists to refuse.
        // `stopped_at` is the record that tells them apart.
        if run
            .stopped_at
            .is_some_and(|stage| stage.number() <= Stage::ModelAssessment.number())
        {
            return Self::CannotConfirm { provider };
        }

        // The stage is recorded once per stage by construction, so this is total.
        let outcome = &run.stage(Stage::ModelAssessment).outcome;
        match outcome {
            StageOutcome::Ran { .. } => Self::Consulted { provider },
            StageOutcome::NotPartOfWork { .. } => Self::NothingAsked { provider },
            // The one not-run reason this stage produces of its own accord: a
            // provider that is configured and that SURE could not build.
            StageOutcome::NotRun {
                reason: Some(crate::status::NotCheckedReason::AnalysisProviderDisabled),
                ..
            } => Self::ProviderUnusable { provider },
            // Everything else, including the `Unfinished` record a run that
            // stopped *in* this stage leaves. An outcome this build does not
            // recognise is reported as one it cannot read rather than as the
            // reassuring half.
            StageOutcome::NotRun { .. } | StageOutcome::Unfinished { .. } => {
                Self::CannotConfirm { provider }
            }
        }
    }

    /// The provider the run's configuration names.
    #[must_use]
    pub const fn provider(self) -> AnalysisProvider {
        match self {
            Self::NoProvider => AnalysisProvider::Disabled,
            Self::NothingAsked { provider }
            | Self::ProviderUnusable { provider }
            | Self::Consulted { provider }
            | Self::CannotConfirm { provider } => provider,
        }
    }

    /// Whether a model was consulted about this project.
    ///
    /// `false` for every state but [`Self::Consulted`] — including
    /// [`Self::CannotConfirm`], which is why this is not the field a script
    /// should read on its own. `as_str` is: a boolean has no room for "cannot
    /// tell", and `false` reads as "nothing was sent".
    #[must_use]
    pub const fn a_model_was_consulted(self) -> bool {
        matches!(self, Self::Consulted { .. })
    }

    /// The stable wire name, for the machine frame.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoProvider => "no_provider",
            Self::NothingAsked { .. } => "nothing_asked",
            Self::ProviderUnusable { .. } => "provider_unusable",
            Self::Consulted { .. } => "consulted",
            Self::CannotConfirm { .. } => "cannot_confirm",
        }
    }

    /// The sentence a person reads, in the report's own voice.
    ///
    /// Every arm says what happened *and* why, because the answer a user needs
    /// is not "no" but "no, because".
    #[must_use]
    pub fn plain_explanation(self) -> String {
        match self {
            Self::NoProvider => "No model was consulted: no analysis provider is configured \
                                 (`analysis.provider` is `disabled`). The deterministic checks \
                                 are unaffected."
                .to_owned(),
            Self::NothingAsked { provider } => format!(
                "No model was consulted. The `{}` provider is named by this run's settings, and \
                 nothing in this run asked it about the project: no check in this build asks for \
                 model-backed analysis.",
                provider.as_str()
            ),
            Self::ProviderUnusable { provider } => format!(
                "No model was consulted. The `{}` provider is named by this run's settings and \
                 SURE could not use it, so nothing was sent. This is a configuration fault, and \
                 it is recorded as one.",
                provider.as_str()
            ),
            Self::Consulted { provider } => format!(
                "A model was consulted about this project through the `{}` provider. Anything it \
                 said is an assessment and not a fact: it cannot by itself make a finding \
                 blocking.",
                provider.as_str()
            ),
            Self::CannotConfirm { provider } => format!(
                "SURE cannot say whether a model was consulted. The `{}` provider is named by \
                 this run's settings, and this run's own record does not say the stage that asks \
                 one did its work — so SURE reports neither answer rather than claiming a model \
                 was not used when it cannot tell.",
                provider.as_str()
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::{Config, ConfigSource, ExecutionSettings, LoadedConfig};
    use crate::pipeline::{Pipeline, Purpose, StageRecord};
    use std::path::{Path, PathBuf};

    // --- the statement ----------------------------------------------------

    fn loaded(text: &str, from: &str) -> LoadedConfig {
        // An empty string is the fixture for "this file declares nothing",
        // built as the default rather than parsed, so that the test is about the
        // arbitration and not about what an empty YAML document parses to.
        let config = if text.trim().is_empty() {
            Config::default()
        } else {
            Config::from_yaml(text)
                .unwrap_or_else(|error| panic!("this fixture should parse:\n{error}"))
        };
        LoadedConfig {
            config,
            source: ConfigSource::File(PathBuf::from(from)),
            searched: PathBuf::from(from),
        }
    }

    fn both(user: &str, project: &str) -> PrivacyStatement {
        PrivacyStatement::of(&Authority::new(
            Some(loaded(user, "user/sure.yaml")),
            loaded(project, "project/sure.yaml"),
        ))
    }

    #[test]
    fn the_mode_in_effect_is_the_arbitrated_one_and_never_the_projects() {
        // The criterion this module exists for. The same project file, byte for
        // byte, reports a different mode depending on the user's own settings
        // outside the project — which is the only way a run's statement about
        // the user's policy can be true.
        let project = "privacy:\n  mode: local_first\n";
        let alone = both("", project);
        assert_eq!(alone.mode, PrivacyMode::LocalFirst);
        assert_eq!(alone.project_mode, PrivacyMode::LocalFirst);
        assert!(!alone.project_settings_differ());

        let overridden = both("privacy:\n  mode: fully_local\n", project);
        assert_eq!(
            overridden.mode,
            PrivacyMode::FullyLocal,
            "the project's own file decided the mode in effect"
        );
        assert_eq!(overridden.mode_set_by, Some(Layer::User));
        assert!(!overridden.allows_external_analysis());
        assert!(overridden.project_settings_differ());

        // The other direction: a project asking for more than the user
        // configured is not escalation. It becomes the mode in effect, the
        // project is named as the one that set it, and there is nothing
        // "overridden" to report — the project's settings and the mode in
        // effect agree, because the stricter one is both.
        let strengthened = both("", "privacy:\n  mode: fully_local\n");
        assert_eq!(strengthened.mode, PrivacyMode::FullyLocal);
        assert_eq!(strengthened.mode_set_by, Some(Layer::Project));
        assert_eq!(strengthened.project_mode, PrivacyMode::FullyLocal);
        assert!(!strengthened.project_settings_differ());

        // A project asking for *less* than the user set cannot lower it, and the
        // reported mode is the user's.
        let weakened = both(
            "privacy:\n  mode: fully_local\n",
            "privacy:\n  mode: local_first\n",
        );
        assert_eq!(weakened.mode, PrivacyMode::FullyLocal);
        assert_eq!(weakened.mode_set_by, Some(Layer::User));
        assert!(weakened.project_settings_differ());
    }

    #[test]
    fn the_two_settings_can_only_differ_in_one_direction() {
        // Because the rule is a maximum, a divergence between the project's own
        // settings and the mode in effect is always the user being stricter.
        // The renderer's sentence depends on that, so it is pinned rather than
        // reasoned about: if this ever changes, the sentence becomes a lie.
        let mut differed = 0;
        for user in [
            "",
            "privacy:\n  mode: local_first\n",
            "privacy:\n  mode: fully_local\n",
        ] {
            for project in [
                "",
                "privacy:\n  mode: local_first\n",
                "privacy:\n  mode: fully_local\n",
            ] {
                let statement = both(user, project);
                if statement.project_settings_differ() {
                    differed += 1;
                    assert!(
                        statement.mode == PrivacyMode::FullyLocal,
                        "a divergence that is not the user being stricter: {user:?} / {project:?}"
                    );
                    assert_eq!(statement.mode_set_by, Some(Layer::User));
                }
            }
        }
        // Two of these nine: a user file that says `fully_local`, against a
        // project that says `local_first` and against one that says nothing at
        // all — the project's settings come to `local_first` either way. The
        // count is written down so that a change in the rule shows up here
        // rather than in a sentence a user reads.
        assert_eq!(
            differed, 2,
            "the divergences in these nine are the two user-stricter cases"
        );
    }

    #[test]
    fn a_project_that_says_nothing_is_not_reported_as_having_decided() {
        // `None` is "nothing beyond the default" and not "SURE did not look",
        // and the sentence a reader gets has to be the first of those.
        for statement in [both("", ""), both("", "privacy:\n  mode: local_first\n")] {
            assert_eq!(statement.mode, PrivacyMode::LocalFirst);
            assert_eq!(statement.mode_set_by, None);
            assert!(
                statement
                    .mode_set_by_plain_words()
                    .contains("Nothing set this"),
                "{}",
                statement.mode_set_by_plain_words()
            );
            assert!(statement.allows_external_analysis());
        }
    }

    #[test]
    fn the_provider_reported_is_the_one_the_run_consults() {
        // The run reads the project's own settings — `check::run_with` builds
        // the pipeline from that file — so a statement taken from anywhere else
        // would name a provider nothing consults.
        let statement = both(
            "analysis:\n  provider: claude_cli\n",
            "analysis:\n  provider: local_command\n  command: [echo, hello]\n",
        );
        assert_eq!(statement.provider, AnalysisProvider::LocalCommand);
        assert!(!statement.provider.is_external());
        assert!(statement.provider.uses_a_model());
        // And the mode in effect is still the arbitrated one, so the two halves
        // of one statement cannot come from different files without a test
        // noticing.
        assert_eq!(statement.mode, PrivacyMode::LocalFirst);
    }

    #[test]
    fn the_mode_reported_is_always_one_this_release_implements() {
        // A statement that named a mode no code enforces would be the false
        // guarantee `PrivacyMode::is_available` exists to refuse. Checked over
        // every combination the two layers can produce.
        for user in [
            "",
            "privacy:\n  mode: local_first\n",
            "privacy:\n  mode: fully_local\n",
        ] {
            for project in [
                "",
                "privacy:\n  mode: local_first\n",
                "privacy:\n  mode: fully_local\n",
            ] {
                let statement = both(user, project);
                assert!(
                    statement.mode.is_available(),
                    "user {user:?} with project {project:?} reported {:?}",
                    statement.mode
                );
            }
        }
    }

    // --- model use --------------------------------------------------------

    /// A pipeline run that stopped at its first stage, for the states that are
    /// about a run rather than about a configuration.
    ///
    /// The project does not exist, so discovery fails and the run stops before
    /// anything is read, planned or executed — which is the honest fixture for
    /// "this run never reached the stage that asks a model".
    fn stopped_run() -> PipelineOutcome {
        // A runner that cannot start anything. The project does not exist, so
        // this run never reaches the plan at all; the runner is here because the
        // type asks for one, and it is one that provably starts nothing.
        let stop = crate::process::Cancellation::new();
        stop.cancel();
        let runner = crate::planned_check_runner::ProcessRunner::new(stop);
        Pipeline {
            project: Path::new("this-project-does-not-exist"),
            purpose: Purpose::Check,
            config: &Config::default(),
            execution: ExecutionSettings::inspect_only(),
            store: None,
            goal: None,
            analysis: Default::default(),
            runner: &runner,
        }
        .run()
    }

    #[test]
    fn no_provider_configured_is_no_provider_whatever_the_run_did() {
        let run = stopped_run();
        assert_eq!(
            ModelUse::of(AnalysisProvider::Disabled, &run),
            ModelUse::NoProvider
        );
        assert!(!ModelUse::NoProvider.a_model_was_consulted());
        assert_eq!(ModelUse::NoProvider.as_str(), "no_provider");
    }

    #[test]
    fn a_run_that_stopped_before_the_model_stage_does_not_claim_a_model_was_not_used() {
        // The honest-limit case. A run that never reached stage 8 has no record
        // of what stage 8 did, and "no model was consulted" would be a claim
        // this run cannot support.
        let run = stopped_run();
        assert!(run.stopped_at.is_some(), "this fixture should not finish");
        let use_ = ModelUse::of(AnalysisProvider::ClaudeCli, &run);
        assert_eq!(
            use_,
            ModelUse::CannotConfirm {
                provider: AnalysisProvider::ClaudeCli
            }
        );
        assert!(!use_.a_model_was_consulted());
        assert!(use_.plain_explanation().contains("cannot say"));
        assert_eq!(use_.as_str(), "cannot_confirm");
    }

    /// The four ways stage 8 can end, as records, so that the mapping is checked
    /// without a project that could produce each one.
    fn outcome(record: StageOutcome) -> PipelineOutcome {
        let mut run = stopped_run();
        run.stopped_at = None;
        run.stages[Stage::ModelAssessment.number() as usize - 1] = StageRecord {
            stage: Stage::ModelAssessment,
            outcome: record,
        };
        run
    }

    #[test]
    fn every_way_stage_eight_can_end_has_one_answer() {
        use crate::status::NotCheckedReason;

        let ran = outcome(StageOutcome::Ran {
            detail: "a provider answered.".to_owned(),
        });
        assert_eq!(
            ModelUse::of(AnalysisProvider::OpenAiCompatible, &ran),
            ModelUse::Consulted {
                provider: AnalysisProvider::OpenAiCompatible
            }
        );
        assert!(ModelUse::of(AnalysisProvider::OpenAiCompatible, &ran).a_model_was_consulted());
        assert_eq!(
            ModelUse::of(AnalysisProvider::OpenAiCompatible, &ran).as_str(),
            "consulted"
        );

        let nothing = outcome(StageOutcome::NotPartOfWork {
            detail: "no planned check asks for model-backed analysis in this build.".to_owned(),
        });
        assert_eq!(
            ModelUse::of(AnalysisProvider::ClaudeCli, &nothing),
            ModelUse::NothingAsked {
                provider: AnalysisProvider::ClaudeCli
            }
        );
        assert!(!ModelUse::of(AnalysisProvider::ClaudeCli, &nothing).a_model_was_consulted());

        let unusable = outcome(StageOutcome::NotRun {
            reason: Some(NotCheckedReason::AnalysisProviderDisabled),
            detail: "SURE could not build the configured model provider".to_owned(),
        });
        assert_eq!(
            ModelUse::of(AnalysisProvider::LocalCommand, &unusable),
            ModelUse::ProviderUnusable {
                provider: AnalysisProvider::LocalCommand
            }
        );
        assert!(!ModelUse::of(AnalysisProvider::LocalCommand, &unusable).a_model_was_consulted());

        let unfinished = outcome(StageOutcome::Unfinished {
            detail: "the run stopped.".to_owned(),
        });
        assert!(matches!(
            ModelUse::of(AnalysisProvider::ClaudeCli, &unfinished),
            ModelUse::CannotConfirm { .. }
        ));
    }

    #[test]
    fn every_state_says_what_it_means_and_which_provider_it_is_about() {
        for state in [
            ModelUse::NoProvider,
            ModelUse::NothingAsked {
                provider: AnalysisProvider::ClaudeCli,
            },
            ModelUse::ProviderUnusable {
                provider: AnalysisProvider::OpenAiCompatible,
            },
            ModelUse::Consulted {
                provider: AnalysisProvider::LocalCommand,
            },
            ModelUse::CannotConfirm {
                provider: AnalysisProvider::ClaudeCli,
            },
        ] {
            let text = state.plain_explanation();
            assert!(!text.is_empty(), "{state:?}");
            assert!(
                text.chars().next().is_some_and(char::is_uppercase),
                "{state:?}: {text}"
            );
            assert!(text.ends_with('.'), "{state:?}: {text}");
            assert!(!state.as_str().contains(' '), "{state:?}");
            if let ModelUse::NoProvider = state {
                continue;
            }
            assert!(
                text.contains(state.provider().as_str()),
                "the sentence does not name the provider: {text}"
            );
        }
    }

    // --- the document -----------------------------------------------------

    #[test]
    fn the_three_modes_say_what_the_document_says_they_say() {
        // A transcription of §The three modes in
        // `docs/architecture/PRIVACY_AND_MODEL_STRATEGY.md`, in that document's
        // order, because the document is what a user reads and this is what a
        // build does. The predicates are the ones the code enforces, and the
        // document is read here rather than copied so that a doc that stopped
        // naming a mode fails a test rather than drifting.
        let cases: &[(PrivacyMode, bool, bool)] = &[
            (PrivacyMode::LocalFirst, true, true),
            (PrivacyMode::FullyLocal, true, false),
            (PrivacyMode::CloudEnhanced, false, true),
        ];
        assert_eq!(cases.len(), PrivacyMode::ALL.len(), "a mode has no row");
        for (mode, available, external) in cases {
            assert_eq!(mode.is_available(), *available, "{mode:?} availability");
            assert_eq!(
                mode.allows_external_analysis(),
                *external,
                "{mode:?} external analysis"
            );
        }

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docs")
            .join("architecture")
            .join("PRIVACY_AND_MODEL_STRATEGY.md");
        let document = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        for mode in PrivacyMode::ALL {
            assert!(
                document.contains(mode.as_str()),
                "{} does not name `{}`",
                path.display(),
                mode.as_str()
            );
        }
        assert!(
            document.contains("local-only alternative"),
            "the document does not state what to write instead of an unavailable mode"
        );
    }

    #[test]
    fn the_document_and_this_module_describe_a_mode_the_same_way() {
        // Two statements of one rule, so they are checked against each other
        // rather than kept in step by hand.
        for mode in PrivacyMode::ALL {
            let sentence = mode_plain_words(*mode);
            assert!(!sentence.is_empty(), "{mode:?}");
            assert!(
                sentence.chars().next().is_some_and(char::is_uppercase),
                "{mode:?}: {sentence}"
            );
        }
        assert!(mode_plain_words(PrivacyMode::CloudEnhanced).contains("does not implement"));
        assert!(mode_plain_words(PrivacyMode::FullyLocal).contains("Nothing about this project"));
    }
}
