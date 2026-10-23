//! Which layer of configuration a setting came from, and what a lower layer is
//! allowed to do with it.
//!
//! # The order, and the one rule
//!
//! `docs/architecture/CONFIG_AUTHORITY.md` puts the user above the project,
//! because the project being checked may be controlled by the same AI whose work
//! SURE is evaluating. This module is that order, and the rule that follows from
//! it:
//!
//! > A layer cannot widen what a layer above it allows, and cannot weaken a
//! > restriction a layer above it imposed.
//!
//! # Why this is not a merge
//!
//! The obvious shape — fold the project's settings into the user's, field by
//! field, keeping whichever is safer — was rejected in ADR 0011, and it is worth
//! restating here because it is the thing a reader expects to find. A merge
//! reinterprets intent: a user who did not mention a setting has not expressed a
//! preference to be maximised, and the merged result cannot be reported back to
//! them in terms of the files they wrote. So there is no `Authority::effective()
//! -> Config`.
//!
//! What there is instead is three answers that *are* well defined:
//!
//! 1. [`Authority::privileges`] — every behaviour any layer asked for, and who,
//!    if anyone, was able to grant it. A project file that asks for network
//!    access produces a recorded refusal, not a granted permission and not
//!    silence.
//! 2. [`Authority::protection`] and [`Authority::privacy_mode`] — restrictions,
//!    where the answer is the stricter of the two layers, because taking the
//!    stricter restriction never turns a statement into a permission.
//! 3. [`Authority::execution`] — the mode in force and the permissions the
//!    configuration grants, as one value. The mode is the user's own and a
//!    project file cannot move it in either direction; a fuller statement of the
//!    rule, and of why "the stricter of the two" is not available for it, is on
//!    [`Authority::execution_mode`].
//!
//! What is left of a project file is read from the project's own settings: the
//! project is the authority on which of its own checks apply, what its own goal
//! is, and how its own components fit together. `Config::scope_reductions` is
//! read that way, and it is *reported* rather than overridden — a project
//! turning a check off cannot be told apart from one that never mentioned it when
//! the value it names is the default, so a claim that the user's file overrode
//! it would be a claim SURE cannot support.
//!
//! # The highest authority is not a file
//!
//! Rank 1 in `CONFIG_AUTHORITY.md` is the person at the keyboard approving the
//! current action. That is not configuration and does not live here:
//! `ConsentGrantor::InteractiveUser` is where it is recorded, and
//! `docs/architecture/CLI.md` reserves status 4 for a decision that comes out of
//! it. When that exists it is applied *on top of* this, which is why
//! [`Authority::permissions`] says what the configuration grants rather than what
//! may happen.

use std::path::Path;

use sure_domain::execution::{ConsentGrantor, ExecutionMode, ExecutionPermissions};
use sure_domain::variants::variants;

use super::values::{AnalysisProvider, PrivacyMode, ProjectRequest, ProtectionMode};
use super::{AnalysisConfig, Config, ConfigError, LoadedConfig};
use crate::full_recording::DEFAULT_FULL_RECORDING_RETENTION_DAYS;

/// One layer of configuration.
///
/// Ordered by authority, most trusted first. There is no `Default` or `Policy`
/// variant: a default is not a file that asked for something, and organization
/// policy does not exist in this release — adding either as a variant would give
/// callers a source they could name but never obtain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// The user's own settings, outside the project.
    User,
    /// `sure.yaml` at the root of the project being checked.
    Project,
}

variants!(
    /// Every layer, most trusted first.
    Layer { User, Project }
);

impl Layer {
    /// The stable name, for a report or a frame.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }

    /// Where this layer's settings are read from, in the user's words.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::User => "your own SURE settings, outside this project",
            Self::Project => "this project's own sure.yaml",
        }
    }

    /// Whether this layer is allowed to grant a privileged behaviour.
    ///
    /// The whole of `CONFIG_AUTHORITY.md` in one predicate. It is written as a
    /// match rather than as `self == Self::User` so that adding a layer forces
    /// the question to be answered instead of defaulting to "no".
    #[must_use]
    pub const fn can_grant(self) -> bool {
        match self {
            Self::User => true,
            Self::Project => false,
        }
    }
}

/// A setting two layers could each have set, and what decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved<T> {
    /// The value in effect.
    pub value: T,
    /// The most trusted layer that chose the value in effect by naming
    /// something other than the default, or `None` when no layer did.
    ///
    /// `None` is not "unknown": a layer that did not name a value chose what
    /// SURE does anyway, which is what every one of these settings defaults to.
    ///
    /// For [`Authority::protection`] and [`Authority::privacy_mode`] — the two
    /// restrictions both layers can only make firmer — "named something other
    /// than the default" and "asked for something stricter" are the same
    /// sentence, and this field has always meant the firmer of the two values.
    /// [`Authority::full_recording_retention_days`] is the one user of this type
    /// where they come apart, because the *user* may also name a duration
    /// longer than the default while a project may not. There `by` names the
    /// layer whose number is in effect, whoever that is; what a project may not
    /// do is name the number in the first place, and a project's attempt to do
    /// so is a [`Privilege`] rather than a value here.
    pub by: Option<Layer>,
}

impl<T> Resolved<T> {
    /// Whether the value in effect is the one SURE would have used unasked.
    #[must_use]
    pub const fn is_default(&self) -> bool {
        self.by.is_none()
    }
}

/// One behaviour a configuration file asked for, and what came of it.
///
/// A refusal is a value, not a missing entry. A file that asked for network
/// access and did not get it leaves this behind, so a report can say what was
/// asked for; dropping it would make "the project asked and was refused" and
/// "the project asked for nothing" the same list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privilege {
    /// What was asked for.
    pub request: ProjectRequest,
    /// Every layer whose file asks for it, most trusted first.
    pub asked_by: Vec<Layer>,
    /// Who was able to grant it, or `None` when nobody was.
    pub granted_by: Option<ConsentGrantor>,
}

impl Privilege {
    /// Whether the request was granted.
    #[must_use]
    pub const fn is_granted(&self) -> bool {
        self.granted_by.is_some()
    }

    /// Whether this is a project's request that no higher layer agreed to.
    ///
    /// The escalation `docs/architecture/CONFIG_AUTHORITY.md` exists to prevent,
    /// named so that a caller reporting it does not have to reassemble the
    /// condition and get it subtly wrong.
    #[must_use]
    pub fn is_refused_escalation(&self) -> bool {
        !self.is_granted() && self.asked_by.contains(&Layer::Project)
    }
}

/// What SURE may do in a run, and how: the two execution answers together.
///
/// One type rather than two arguments, because
/// [`sure_domain::execution::decide`] reads both and a caller that passed a
/// permission set from one file with a mode from another would be describing a
/// build that does not exist. `Authority::execution` is the only thing that
/// builds one, so the two halves come from the same read of the same two files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSettings {
    /// The mode in force, from [`Authority::execution_mode`].
    pub mode: ExecutionMode,
    /// The permissions the configuration grants, from [`Authority::permissions`].
    pub permissions: ExecutionPermissions,
}

impl ExecutionSettings {
    /// What SURE runs under unasked: inspection, and nothing more.
    ///
    /// The value a caller uses when it has no configuration to read — the
    /// failure arm of a hook, or a test that is about something else. It is not
    /// a `Default`: `ExecutionMode` has none on purpose
    /// (`docs/architecture/EXECUTION_SAFETY.md`), and a `Default` here would put
    /// the same value back within reach of a derive.
    #[must_use]
    pub const fn inspect_only() -> Self {
        Self {
            mode: ExecutionMode::InspectOnly,
            permissions: ExecutionPermissions::inspect_only(),
        }
    }
}

/// The configuration files in force, and what they are allowed to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    user: Option<LoadedConfig>,
    project: LoadedConfig,
}

impl Authority {
    /// Read the user's configuration and the project's.
    ///
    /// `user_config` is a path rather than a [`crate::paths::Paths`] so that this
    /// module stays about authority and not about where files live; a caller gets
    /// the path from `Paths::user_config_file`. A file that is not there is not
    /// an error — it means the user has declared nothing, which is the ordinary
    /// case — and the result says which of the two happened.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] for either file, naming the file. One bad file
    /// stops the read: running with defaults while the user believes their
    /// settings are in force is the failure both readers exist to prevent.
    pub fn load(project_root: &Path, user_config: &Path) -> Result<Self, ConfigError> {
        let user = Config::load_file(user_config)?;
        let project = Config::load(project_root)?;
        Ok(Self {
            user: user.source.is_file().then_some(user),
            project,
        })
    }

    /// Build from settings already read.
    ///
    /// For a caller that has them — a test, or a command reporting on the files
    /// it read — and for [`Authority::load`] itself.
    #[must_use]
    pub const fn new(user: Option<LoadedConfig>, project: LoadedConfig) -> Self {
        Self { user, project }
    }

    /// The project's settings.
    ///
    /// Every privileged setting in them is inert; see [`Authority::privileges`]
    /// for what any of them amount to.
    #[must_use]
    pub const fn project(&self) -> &Config {
        &self.project.config
    }

    /// The project's settings and where they came from.
    #[must_use]
    pub const fn project_file(&self) -> &LoadedConfig {
        &self.project
    }

    /// The user's settings, or `None` when the user has no configuration file.
    ///
    /// `None` and "a file that declares nothing" are different answers, and this
    /// is what keeps them apart: the first means SURE found no file, the second
    /// means it read one and it was empty.
    #[must_use]
    pub const fn user(&self) -> Option<&Config> {
        match &self.user {
            Some(loaded) => Some(&loaded.config),
            None => None,
        }
    }

    /// The user's settings and where they came from, if any.
    #[must_use]
    pub const fn user_file(&self) -> Option<&LoadedConfig> {
        self.user.as_ref()
    }

    /// Every privileged behaviour either layer asked for, and what came of it.
    ///
    /// In [`ProjectRequest::ALL`] order, so two runs over the same two files
    /// produce the same list and a report reads the same way twice.
    #[must_use]
    pub fn privileges(&self) -> Vec<Privilege> {
        let user = match &self.user {
            Some(loaded) => loaded.config.requested_privileges(),
            None => Vec::new(),
        };
        let project = self.project.config.requested_privileges();

        let mut privileges: Vec<Privilege> = ProjectRequest::ALL
            .iter()
            .copied()
            .filter_map(|request| {
                let mut asked_by = Vec::new();
                if user.contains(&request) {
                    asked_by.push(Layer::User);
                }
                if project.contains(&request) {
                    asked_by.push(Layer::Project);
                }
                // A request appears here only if somebody asked, and the list is
                // built most trusted first, so the first entry is the strongest
                // layer that asked.
                let granted_by = asked_by
                    .first()
                    .filter(|layer| layer.can_grant())
                    .map(|_| ConsentGrantor::UserConfiguration);
                (!asked_by.is_empty()).then_some(Privilege {
                    request,
                    asked_by,
                    granted_by,
                })
            })
            .collect();

        // `ProjectRequest::ExtendedRetention` is the one request neither file
        // can be asked about on its own: a project naming 30 days has asked for
        // nothing when the user already allows 30, and has asked for more than
        // they allowed when the user allows 7 or said nothing at all. It is
        // therefore decided here, from both files, and appended — which is also
        // where `ProjectRequest::ALL` puts it, so the list stays in the order
        // this method documents.
        if let Some(escalation) = self.retention_escalation() {
            privileges.push(escalation);
        }
        privileges
    }

    /// The project's request to keep data for longer than the user allows.
    ///
    /// `None` when the project named no duration, or named one no longer than
    /// the ceiling. The ceiling is the user's own number of days, or the default
    /// when the user named none — a repository the user merely opened is not a
    /// reason to keep their activity for longer than SURE would have kept it
    /// unasked.
    ///
    /// Recorded whether or not `privacy.full_recording` is on, and that is not
    /// an oversight: the two settings are separate, a project may set them in
    /// either order, and a build that recorded this only when recording happened
    /// to be enabled would make "asked and refused" and "never asked" the same
    /// list for as long as the boolean stayed off.
    fn retention_escalation(&self) -> Option<Privilege> {
        let project = self.project.config.privacy.full_recording_retention_days?;
        (project > self.retention_ceiling_days()).then_some(Privilege {
            request: ProjectRequest::ExtendedRetention,
            asked_by: vec![Layer::Project],
            granted_by: None,
        })
    }

    /// The most days of full recording the user has allowed.
    ///
    /// The user's own setting when there is one, and
    /// [`DEFAULT_FULL_RECORDING_RETENTION_DAYS`] when there is not. Only
    /// [`Authority::full_recording_retention_days`] and
    /// [`Authority::retention_escalation`] read it, so that the ceiling the
    /// project is measured against cannot drift from the value in effect.
    fn retention_ceiling_days(&self) -> i64 {
        self.user
            .as_ref()
            .and_then(|loaded| loaded.config.privacy.full_recording_retention_days)
            .unwrap_or(DEFAULT_FULL_RECORDING_RETENTION_DAYS)
    }

    /// How long a full recording is kept, in days.
    ///
    /// # Why this is not [`Authority::protection`] with a different rank
    ///
    /// Protection and privacy mode are symmetric: "stricter" means the same
    /// thing to both layers, so the stricter of the two wins and `resolve` is
    /// the whole of the rule. Retention is not symmetric, and this method is the
    /// difference:
    ///
    /// - the **user** may name any number of days, including one larger than the
    ///   default, because deciding to keep one's own machine's records for
    ///   longer is a person's decision about their own data;
    /// - the **project** may only ever shorten what the user allowed. Naming a
    ///   longer period raises the value in effect by nothing at all, and leaves
    ///   a refused [`ProjectRequest::ExtendedRetention`] behind in
    ///   [`Authority::privileges`] — a refusal, not a clamp that silently keeps
    ///   the shorter period while reporting the longer one.
    ///
    /// `docs/architecture/CONFIG_AUTHORITY.md` states the general rule this is
    /// an instance of: a lower-authority source cannot weaken a higher-authority
    /// restriction. The comment beside the `full_recording` test in this module
    /// says the same thing about recording at all — recording more is not
    /// running more — and keeping it longer is recording more.
    ///
    /// # What a user sees
    ///
    /// The default when no file names a duration: `3`, for
    /// [`DEFAULT_FULL_RECORDING_RETENTION_DAYS`]'s reason, with `by: None`,
    /// which is `Resolved`'s way of saying "nothing beyond what SURE does
    /// anyway". When the two layers disagree the answer is the shorter period
    /// and `by` names the layer that decided it.
    #[must_use]
    pub fn full_recording_retention_days(&self) -> Resolved<i64> {
        let user = self
            .user
            .as_ref()
            .and_then(|loaded| loaded.config.privacy.full_recording_retention_days);

        if let Some(days) = self.project.config.privacy.full_recording_retention_days
            && days < self.retention_ceiling_days()
        {
            return Resolved {
                value: days,
                by: Some(Layer::Project),
            };
        }

        match user {
            Some(days) if days != DEFAULT_FULL_RECORDING_RETENTION_DAYS => Resolved {
                value: days,
                by: Some(Layer::User),
            },
            _ => Resolved {
                value: DEFAULT_FULL_RECORDING_RETENTION_DAYS,
                by: None,
            },
        }
    }

    /// Whether a full recording of a session may be written.
    ///
    /// # Why this is not `privacy.full_recording` read from either file
    ///
    /// Recording more is not running more, so `full_recording` is a request and
    /// not a restriction: it is decided by [`Layer::can_grant`] and not by
    /// [`resolve`]. Reading it from the project's file alone would let a
    /// repository the user merely opened turn the recording of their own
    /// machine's activity on; reading it from `resolve` would be worse, because
    /// `resolve` takes the stricter value and a project's `true` would then be
    /// reported as an escalation that had already happened rather than as a
    /// request that was refused.
    ///
    /// So the answer is [`Authority::privilege`]'s answer: true exactly when a
    /// layer that can grant it asked for it, which is the user's own file.
    /// A project's `true` leaves a refused [`ProjectRequest::FullRecording`] in
    /// [`Authority::privileges`] instead — a refusal a report can print.
    ///
    /// This is the boolean in front of [`Authority::full_recording_retention_days`],
    /// and the two are separate settings: turning recording on and keeping it
    /// longer are different asks, and both are refused to the project.
    #[must_use]
    pub fn full_recording(&self) -> bool {
        self.privilege(ProjectRequest::FullRecording)
            .is_some_and(|privilege| privilege.is_granted())
    }

    /// The request with this name, as it was resolved.
    ///
    /// `None` when no layer asked for it.
    #[must_use]
    pub fn privilege(&self, request: ProjectRequest) -> Option<Privilege> {
        self.privileges()
            .into_iter()
            .find(|privilege| privilege.request == request)
    }

    /// The permissions the configuration grants.
    ///
    /// Not the answer to whether an action may run: that is
    /// `sure_domain::execution::decide`, which also needs a mode and treats an
    /// unclassifiable command as needing its own consent in every mode. What this
    /// answers is the narrower question the authority layer owns — which
    /// permissions a *file* was allowed to hand over.
    ///
    /// The mode itself is not a permission. A project asking for
    /// `host_confirmed` gets no entry here, because the mode is the project's
    /// preference about what SURE would do with permissions it does not have.
    #[must_use]
    pub fn permissions(&self) -> ExecutionPermissions {
        let mut permissions = ExecutionPermissions::inspect_only();
        for privilege in self.privileges() {
            if !privilege.is_granted() {
                continue;
            }
            if let Some(permission) = privilege.request.permission() {
                permissions.set(permission, true);
            }
        }
        permissions
    }

    /// The execution mode in force: the user's own, and nothing else's.
    ///
    /// # The rule
    ///
    /// `execution.mode` is read from the user's file when the user's file named
    /// a mode that runs project code, and is [`ExecutionMode::InspectOnly`]
    /// otherwise. **A project file cannot move it in either direction.**
    ///
    /// # Where the rule comes from
    ///
    /// Four statements in this repository, which agree with each other:
    ///
    /// - `docs/architecture/CONFIG_AUTHORITY.md` lists, under what a project may
    ///   not do silently, "enable host execution if the user did not allow it".
    /// - `docs/architecture/CONFIG_REFERENCE.md` says of
    ///   `execution.mode: host_confirmed` that it "is a request to run project
    ///   code; it does not grant it".
    /// - [`Config::requested_privileges`] is that sentence as code: a mode other
    ///   than `inspect_only` becomes
    ///   [`ProjectRequest::RunProjectCode`](super::values::ProjectRequest::RunProjectCode),
    ///   which is a request like any other and is granted only by
    ///   [`Layer::can_grant`]'s one layer.
    /// - `a_project_file_cannot_grant_itself_anything` in this module's tests
    ///   asserts the consequence: a project file asking for everything at once,
    ///   `host_confirmed` included, leaves
    ///   [`Authority::permissions`] equal to
    ///   [`ExecutionPermissions::inspect_only`].
    ///
    /// # Why the project cannot lower it either
    ///
    /// The tempting second half — "the stricter of the two modes wins" — is not
    /// available here, and the reason is the reason ADR 0011 rejected a merge.
    /// [`ExecutionConfig::default`] is `inspect_only` and
    /// [`ExecutionMode`] has no `Default` on purpose, so a project file that
    /// never mentioned its mode and one that wrote `mode: inspect_only` produce
    /// the same field. A rule that took the stricter mode would let the *silence*
    /// of any `sure.yaml` at all void a grant the user made, which is
    /// `a_higher_layer_request_is_not_downgraded_by_a_silent_project` turned
    /// around. Lowering what SURE does is not an escalation, but it is not a
    /// decision this layer can attribute to a file either, so it is not taken:
    /// the mode is a request, and only the user's file can make it.
    ///
    /// # What a user sees
    ///
    /// A project asking for `host_confirmed` is not silent about it: it leaves a
    /// refused [`ProjectRequest::RunProjectCode`](super::values::ProjectRequest::RunProjectCode)
    /// in [`Authority::privileges`], so a report can say what was asked for. This
    /// method answers only what is in force.
    ///
    /// [`ExecutionConfig::default`]: super::ExecutionConfig
    #[must_use]
    pub fn execution_mode(&self) -> ExecutionMode {
        // The permission is what is granted or refused; the mode is what the
        // user's own file said to do with it. Both come from the same list, so
        // the two cannot disagree about who asked.
        if !self.permissions().run_project_code {
            return ExecutionMode::InspectOnly;
        }
        self.user()
            .map(|config| config.execution.mode)
            .filter(|mode| mode.runs_project_code())
            .unwrap_or(ExecutionMode::InspectOnly)
    }

    /// The execution settings in force: the mode and the permissions together.
    ///
    /// The pair [`sure_domain::execution::decide`] needs, from one read of the
    /// two files, so that a decision cannot be taken under one file's mode and
    /// another's permission set. The rule for each half is on
    /// [`Authority::execution_mode`] and [`Authority::permissions`]; what this
    /// adds is that they are answered together.
    #[must_use]
    pub fn execution(&self) -> ExecutionSettings {
        ExecutionSettings {
            mode: self.execution_mode(),
            permissions: self.permissions(),
        }
    }

    /// The protection in effect: the firmer of the two layers.
    ///
    /// A project may ask for *more* protection than the user configured, and the
    /// layer that asked is reported so a user can see where it came from. It may
    /// not ask for less: `standard` in a project file cannot lower a `strict`
    /// the user set, and the value here is `strict`.
    #[must_use]
    pub fn protection(&self) -> Resolved<ProtectionMode> {
        resolve(
            [
                (
                    Layer::User,
                    self.user
                        .as_ref()
                        .map(|loaded| loaded.config.protection.mode),
                ),
                (Layer::Project, Some(self.project.config.protection.mode)),
            ],
            ProtectionMode::default(),
            protection_rank,
        )
    }

    /// The analysis settings in force, arbitrated between the two files.
    ///
    /// # The rule
    ///
    /// A provider the project's own file names is the one in force — it is the
    /// project's request, and whether that request can act is what
    /// [`ProjectRequest::ExternalAnalysis`] and the user's grant settle.
    /// When the project names none — the ordinary case for a project that
    /// never wrote a `sure.yaml` — the user's own file may name one, and what
    /// it names is in force. This is the one analysis question the user's file
    /// *decides* rather than merely allows, and the layer order says why:
    /// [`Layer::User`] is the most trusted layer, and it is the layer
    /// [`Layer::can_grant`] says may hand a behaviour to a run at all.
    ///
    /// A project file cannot *veto* the user's own provider by naming
    /// `disabled`: disabling is the absence of a request rather than a
    /// request, and a layer that can grant nothing elsewhere in this module
    /// cannot take anything away here either.
    #[must_use]
    pub fn analysis(&self) -> Resolved<AnalysisConfig> {
        let names_analysis = |config: &Config| {
            config.analysis.provider != AnalysisProvider::Disabled
                || config.analysis.endpoint.is_some()
                || config.analysis.model.is_some()
                || config.analysis.command.is_some()
        };
        if names_analysis(&self.project.config) {
            return Resolved {
                value: self.project.config.analysis.clone(),
                by: Some(Layer::Project),
            };
        }
        match self.user() {
            Some(user) if names_analysis(user) => Resolved {
                value: user.analysis.clone(),
                by: Some(Layer::User),
            },
            _ => Resolved {
                value: AnalysisConfig::default(),
                by: None,
            },
        }
    }

    /// The privacy mode in effect: the stricter of the two layers.
    ///
    /// `fully_local` wins over `local_first` whichever layer wrote it, because
    /// sending less out is never the escalation. ADR 0002 puts authority for
    /// privacy outside the project and lets a project ask for a behaviour; this
    /// is the same rule seen from the other side, where the behaviour a project
    /// may add on its own is the one that gives something up.
    #[must_use]
    pub fn privacy_mode(&self) -> Resolved<PrivacyMode> {
        resolve(
            [
                (
                    Layer::User,
                    self.user.as_ref().map(|loaded| loaded.config.privacy.mode),
                ),
                (Layer::Project, Some(self.project.config.privacy.mode)),
            ],
            PrivacyMode::default(),
            privacy_rank,
        )
    }
}

/// How firmly a protection mode intervenes, for comparing two of them.
///
/// A match rather than a derived `Ord`: the declaration order in `values.rs` is
/// the order a user reads the values in, which happens to agree today and has no
/// reason to keep agreeing.
///
/// `Custom` is not accepted in a file in this release
/// (`ProtectionMode::is_available`). It ranks highest anyway: a value SURE does
/// not implement is not a reason to relax anything, and the safe direction for an
/// unreachable input is the firmer answer.
const fn protection_rank(mode: ProtectionMode) -> u8 {
    match mode {
        ProtectionMode::Standard => 0,
        ProtectionMode::Strict => 1,
        ProtectionMode::Custom => 2,
    }
}

/// How much of a project's activity SURE may keep, for comparing two privacy
/// modes. Higher keeps more here.
///
/// `CloudEnhanced` sends more out than either available mode and is refused in a
/// file (`PrivacyMode::is_available`); it ranks lowest so that an unreachable
/// input can never be the reason a stricter setting is dropped.
const fn privacy_rank(mode: PrivacyMode) -> u8 {
    match mode {
        PrivacyMode::CloudEnhanced => 0,
        PrivacyMode::LocalFirst => 1,
        PrivacyMode::FullyLocal => 2,
    }
}

/// Take the strictest value any layer set, and remember which layer set it.
///
/// `by` is `Some` exactly when the value in effect is firmer than the default,
/// and names the most trusted layer that asked for it. A layer absent from
/// `layers` — because there is no user file — cannot win.
fn resolve<T: Copy>(
    layers: [(Layer, Option<T>); 2],
    default: T,
    rank: impl Fn(T) -> u8,
) -> Resolved<T> {
    let mut strictest: Option<(Layer, T)> = None;
    for (layer, value) in layers {
        let Some(value) = value else { continue };
        // Strictly greater, so a tie keeps the more trusted layer already held.
        if strictest.is_none_or(|(_, current)| rank(value) > rank(current)) {
            strictest = Some((layer, value));
        }
    }
    match strictest {
        Some((layer, value)) if rank(value) > rank(default) => Resolved {
            value,
            by: Some(layer),
        },
        _ => Resolved {
            value: default,
            by: None,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::ConfigSource;
    use std::path::PathBuf;
    use sure_domain::execution::Permission;

    /// A layer that was read from a file, as both layers are in practice.
    fn loaded(text: &str, from: &str) -> LoadedConfig {
        LoadedConfig {
            config: Config::from_yaml(text)
                .unwrap_or_else(|error| panic!("this fixture should parse:\n{error}")),
            source: ConfigSource::File(PathBuf::from(from)),
            searched: PathBuf::from(from),
        }
    }

    /// Both layers, the user's file present.
    fn both(user: &str, project: &str) -> Authority {
        Authority::new(
            Some(loaded(user, "user/sure.yaml")),
            loaded(project, "project/sure.yaml"),
        )
    }

    /// The project alone: an ordinary user has no SURE configuration file.
    fn project_only(project: &str) -> Authority {
        Authority::new(None, loaded(project, "project/sure.yaml"))
    }

    /// Everything a project file can ask for, asked for at once.
    ///
    /// The retention number is here and is longer than
    /// [`DEFAULT_FULL_RECORDING_RETENTION_DAYS`], which is what makes it a
    /// request at all: the user in this fixture has no file, so the ceiling is
    /// SURE's own default and a project naming thirty days has asked to keep the
    /// user's activity for longer than they allowed. A project naming *fewer*
    /// days has asked for nothing, and belongs in the tests below rather than
    /// here.
    const ASKS_FOR_EVERYTHING: &str = "\
execution:
  mode: host_confirmed
  allow_dependency_install: true
  allow_network: true
  allow_project_write: true
privacy:
  full_recording: true
  telemetry: true
  full_recording_retention_days: 30
analysis:
  provider: claude_cli
";

    #[test]
    fn the_users_own_analysis_provider_is_in_force_when_the_project_names_none() {
        // 常规项目没有 sure.yaml:用户在自己文件里指定分析通道后,检查必须
        // 真的用它——这是"用户直接指定"通道存在的原因(MiQi 面板场景)。
        let authority = both(
            "analysis:\n  provider: local_command\n  command: [\"echo\", \"x\"]\n",
            "",
        );
        let analysis = authority.analysis();
        assert_eq!(analysis.value.provider, AnalysisProvider::LocalCommand);
        assert_eq!(analysis.by, Some(Layer::User));
    }

    #[test]
    fn a_projects_own_analysis_provider_wins_over_the_users() {
        // 项目自己也指定时,项目值在效(用户层不静默改写项目所请求的通道;
        // 请求能否行动另由 ExternalAnalysis 的授予决定)。
        let authority = both(
            "analysis:\n  provider: local_command\n",
            "analysis:\n  provider: claude_cli\n",
        );
        let analysis = authority.analysis();
        assert_eq!(analysis.value.provider, AnalysisProvider::ClaudeCli);
        assert_eq!(analysis.by, Some(Layer::Project));
    }

    #[test]
    fn a_project_cannot_veto_the_users_analysis_by_naming_disabled() {
        // disabled 是"没有请求"而不是请求;项目层在本模块里什么都授予不了,
        // 自然也收不走用户赋予自己的东西。
        let authority = both(
            "analysis:\n  provider: local_command\n",
            "analysis:\n  provider: disabled\n",
        );
        let analysis = authority.analysis();
        assert_eq!(analysis.value.provider, AnalysisProvider::LocalCommand);
        assert_eq!(analysis.by, Some(Layer::User));
    }

    #[test]
    fn no_file_naming_analysis_keeps_the_default() {
        let authority = both("", "");
        assert_eq!(
            authority.analysis().value.provider,
            AnalysisProvider::Disabled
        );
        assert_eq!(authority.analysis().by, None);
        let alone = project_only("");
        assert_eq!(alone.analysis().by, None);
    }

    #[test]
    fn a_project_file_cannot_grant_itself_anything() {
        // The criterion this module exists for. Every request a project can
        // make, made at once, granted by nobody.
        let authority = project_only(ASKS_FOR_EVERYTHING);
        let privileges = authority.privileges();

        assert_eq!(
            privileges.len(),
            ProjectRequest::ALL.len(),
            "a file asking for everything must leave every request on the record, \
             got {privileges:?}"
        );
        assert!(
            privileges.iter().all(Privilege::is_refused_escalation),
            "a project granted itself something: {privileges:?}"
        );
        assert_eq!(
            authority.permissions(),
            ExecutionPermissions::inspect_only(),
            "a project file widened what SURE may do"
        );
    }

    #[test]
    fn a_project_file_cannot_choose_the_execution_mode() {
        // `execution.mode: host_confirmed` in a project file is a request, so it
        // is refused like every other request — and the mode in force is the one
        // a project file cannot produce.
        let authority = project_only(ASKS_FOR_EVERYTHING);

        assert_eq!(
            authority.execution_mode(),
            ExecutionMode::InspectOnly,
            "a project file moved the execution mode"
        );
        let ask = authority
            .privilege(ProjectRequest::RunProjectCode)
            .expect("the project asked to run its own code and left no record");
        assert!(ask.is_refused_escalation(), "the ask was granted: {ask:?}");
    }

    #[test]
    fn the_users_own_mode_is_the_one_in_force() {
        // The other direction, so the test above is not satisfied by a build
        // that never runs anything. The project asks for a mode of its own and
        // gets the user's, which is the whole rule: the mode is the user's file's
        // to name, including when the project names a different one.
        let authority = both(
            "execution:\n  mode: container\n",
            "execution:\n  mode: host_confirmed\n",
        );

        assert_eq!(authority.execution_mode(), ExecutionMode::Container);
        assert!(
            authority
                .privilege(ProjectRequest::RunProjectCode)
                .is_some(),
            "both layers asked to run project code and the list is empty"
        );
    }

    #[test]
    fn a_project_file_cannot_lower_the_mode_the_user_chose() {
        // The half of the rule that is easy to get wrong. Taking the stricter of
        // the two modes would read as the safe answer and is not available: a
        // project that never mentioned its mode is `inspect_only` too
        // (`ExecutionConfig::default`), so the stricter-of-the-two rule would let
        // the silence of any `sure.yaml` at all void the user's grant. Nothing a
        // project file can write moves this value, in either direction.
        let authority = both(
            "execution:\n  mode: host_confirmed\n",
            "execution:\n  mode: inspect_only\n",
        );

        assert_eq!(authority.execution_mode(), ExecutionMode::HostConfirmed);
    }

    #[test]
    fn a_project_file_cannot_turn_on_full_recording() {
        // Recording more is not running more, so this is a request and not a
        // restriction: the stricter-of-the-two rule does not reach it, and the
        // refused ask is on the record rather than dropped.
        let refused = project_only(ASKS_FOR_EVERYTHING);
        assert!(
            !refused.full_recording(),
            "a project file turned full recording on"
        );
        assert!(
            refused
                .privilege(ProjectRequest::FullRecording)
                .is_some_and(|privilege| privilege.is_refused_escalation()),
            "the project asked to record everything and left no record"
        );

        let granted = both("privacy:\n  full_recording: true\n", "");
        assert!(
            granted.full_recording(),
            "the user's own file asked for a full recording and did not get one"
        );
    }

    #[test]
    fn a_user_file_grants_only_what_it_asks_for() {
        // The other direction, so that the test above is not satisfied by a
        // module that refuses everything.
        let authority = both(
            "execution:\n  mode: host_confirmed\n  allow_network: true\n",
            "execution:\n  mode: host_confirmed\n  allow_dependency_install: true\n",
        );

        assert_eq!(
            authority.privilege(ProjectRequest::Network),
            Some(Privilege {
                request: ProjectRequest::Network,
                asked_by: vec![Layer::User],
                granted_by: Some(ConsentGrantor::UserConfiguration),
            })
        );

        let install = authority
            .privilege(ProjectRequest::InstallDependencies)
            .expect("the project asked for an install and left no record");
        assert!(!install.is_granted());
        assert!(install.is_refused_escalation());

        let permissions = authority.permissions();
        assert!(
            permissions.allows(Permission::Network),
            "the user's own file asked for the network and did not get it"
        );
        assert!(
            !permissions.allows(Permission::InstallDependencies),
            "the project asked for an install and was given it"
        );
    }

    #[test]
    fn asking_for_what_the_user_also_asked_for_is_not_an_escalation() {
        // A project and its user agreeing is the ordinary case, and it must not
        // be reported as an attempt. Both askers are kept, so a report can say
        // who agreed rather than only that it was allowed.
        let authority = both(
            "execution:\n  mode: host_confirmed\n  allow_network: true\n",
            "execution:\n  mode: host_confirmed\n  allow_network: true\n",
        );
        let network = authority
            .privilege(ProjectRequest::Network)
            .expect("both layers asked");

        assert_eq!(network.asked_by, vec![Layer::User, Layer::Project]);
        assert!(network.is_granted());
        assert!(!network.is_refused_escalation());
    }

    #[test]
    fn a_higher_layer_request_is_not_downgraded_by_a_silent_project() {
        // The user granted the network and the project said nothing about it. The
        // permission stands: a project that does not mention a setting has not
        // expressed an opinion about it.
        let authority = both(
            "execution:\n  mode: host_confirmed\n  allow_network: true\n",
            "",
        );
        let network = authority
            .privilege(ProjectRequest::Network)
            .expect("the user asked");
        assert_eq!(network.asked_by, vec![Layer::User]);
        assert!(network.is_granted());
        assert!(authority.permissions().allows(Permission::Network));
    }

    #[test]
    fn when_both_layers_ask_for_the_same_thing_the_user_is_named() {
        // A report that attributed a strict setting to the project when the
        // user's own file asked for it too would send the user to read a file
        // they had already agreed with, looking for a decision that was theirs.
        let authority = both(
            "protection:\n  mode: strict\n",
            "protection:\n  mode: strict\n",
        );
        assert_eq!(authority.protection().value, ProtectionMode::Strict);
        assert_eq!(authority.protection().by, Some(Layer::User));
    }

    #[test]
    fn a_project_cannot_lower_the_protection_the_user_set() {
        // "Project config may not weaken user protection", and the value that
        // proves it is the effective one rather than the reported one.
        let authority = both(
            "protection:\n  mode: strict\n",
            "protection:\n  mode: standard\n",
        );
        let protection = authority.protection();

        assert_eq!(protection.value, ProtectionMode::Strict);
        assert_eq!(protection.by, Some(Layer::User));
        assert!(!protection.is_default());
    }

    #[test]
    fn a_project_may_strengthen_protection_and_is_named_as_the_reason() {
        // The asymmetric half. Asking for *more* protection is not escalation,
        // and a report that could not say which layer imposed it would leave the
        // user wondering why a run became slower and more interruptive.
        let authority = both("", "protection:\n  mode: strict\n");
        assert_eq!(authority.protection().value, ProtectionMode::Strict);
        assert_eq!(authority.protection().by, Some(Layer::Project));
    }

    #[test]
    fn the_stricter_privacy_mode_wins_and_the_layer_that_set_it_is_named() {
        // Privacy resolves the way protection does, and the direction that
        // matters is the opposite one: here the stricter value is the one that
        // discloses less, so nothing below the user moves the resolved mode
        // toward the network.
        //
        // Note what the first row does *not* claim. `local_first` is the default
        // and it does allow external analysis where one is configured; it is the
        // stricter of the two available modes only relative to nothing being
        // said at all. Saying "no content leaves" is `fully_local`, and that is a
        // setting rather than an assumption.
        let cases: &[(&str, &str, PrivacyMode, Option<Layer>)] = &[
            ("", "", PrivacyMode::LocalFirst, None),
            (
                "",
                "privacy:\n  mode: fully_local\n",
                PrivacyMode::FullyLocal,
                Some(Layer::Project),
            ),
            (
                "privacy:\n  mode: fully_local\n",
                "privacy:\n  mode: local_first\n",
                PrivacyMode::FullyLocal,
                Some(Layer::User),
            ),
            (
                "privacy:\n  mode: fully_local\n",
                "",
                PrivacyMode::FullyLocal,
                Some(Layer::User),
            ),
        ];
        for (user, project, value, by) in cases {
            let resolved = both(user, project).privacy_mode();
            assert_eq!(
                (resolved.value, resolved.by),
                (*value, *by),
                "user {user:?} with project {project:?} resolved to {resolved:?}"
            );
        }
    }

    #[test]
    fn nothing_asked_for_means_the_default_and_says_so() {
        // `by: None` has to mean "nothing beyond the default", not "SURE did not
        // work it out". A report that could not tell those apart would be unable
        // to say whether it had looked.
        for authority in [project_only(""), both("", "")] {
            assert_eq!(authority.protection().value, ProtectionMode::Standard);
            assert!(authority.protection().is_default());
            assert_eq!(authority.privacy_mode().value, PrivacyMode::LocalFirst);
            assert!(authority.privacy_mode().is_default());
            assert!(authority.privileges().is_empty());
            assert_eq!(
                authority.permissions(),
                ExecutionPermissions::inspect_only()
            );
        }
    }

    #[test]
    fn only_the_user_layer_can_grant() {
        // Written against `Layer::ALL` so that a third layer added later has to
        // answer this question rather than inheriting an assumption.
        assert_eq!(Layer::ALL.len(), 2);
        for layer in Layer::ALL {
            assert_eq!(
                layer.can_grant(),
                *layer == Layer::User,
                "{layer:?} answered the question differently from the documented order"
            );
        }
    }

    #[test]
    fn a_request_nobody_made_is_not_in_the_list() {
        // The list is what was asked for, not a menu of what could have been. A
        // report that printed all six every time would bury the one that
        // mattered.
        let authority = project_only("execution:\n  mode: host_confirmed\n");
        assert_eq!(authority.privileges().len(), 1);
        assert!(authority.privilege(ProjectRequest::Telemetry).is_none());
        assert!(authority.privilege(ProjectRequest::Network).is_none());
        assert!(
            authority
                .privilege(ProjectRequest::ExtendedRetention)
                .is_none(),
            "a file that named no duration asked for nothing about retention"
        );
    }

    #[test]
    fn a_project_may_shorten_the_retention_and_is_named_as_the_reason() {
        // How long a recording is kept is a restriction, like protection and
        // privacy mode, and it resolves the way those do: towards less. A
        // project that asks for less is obeyed, and the answer says which file
        // decided it.
        let authority = both(
            "privacy:\n  full_recording_retention_days: 30\n",
            "privacy:\n  full_recording_retention_days: 7\n",
        );

        let resolved = authority.full_recording_retention_days();
        assert_eq!(resolved.value, 7);
        assert_eq!(resolved.by, Some(Layer::Project));
        assert!(
            authority
                .privilege(ProjectRequest::ExtendedRetention)
                .is_none(),
            "a project that shortened the period was recorded as asking for more"
        );
    }

    #[test]
    fn a_project_cannot_extend_the_retention_and_is_refused_rather_than_clamped() {
        // The criterion this setting was added for. A repository the user merely
        // opened may not decide how long their own activity is kept: "recording
        // more is not running more", and keeping it longer is the same kind of
        // request.
        //
        // The user has no file in this fixture, so the ceiling is SURE's own
        // default. What the project asked for is on the record as a **refusal**,
        // and the number in effect is the shorter one. A clamp that silently
        // kept the shorter period while reporting the longer one would be worse
        // than either answer: the user would be told their records were kept for
        // thirty days and they would not be.
        let authority = project_only("privacy:\n  full_recording_retention_days: 30\n");

        let resolved = authority.full_recording_retention_days();
        assert_eq!(resolved.value, DEFAULT_FULL_RECORDING_RETENTION_DAYS);
        assert_eq!(resolved.by, None);
        let escalation = authority
            .privilege(ProjectRequest::ExtendedRetention)
            .expect(
                "a project asked to keep the user's activity for longer, and nothing recorded it",
            );
        assert_eq!(escalation.asked_by, vec![Layer::Project]);
        assert_eq!(escalation.granted_by, None);
        assert!(escalation.is_refused_escalation());
        assert!(!escalation.is_granted());
    }

    #[test]
    fn the_user_may_keep_their_own_records_for_longer_than_the_default() {
        // The asymmetry, and the reason this is not `Authority::protection` with
        // a different rank. Deciding to keep one's own machine's records for
        // longer is a person's decision about their own data; a file in somebody
        // else's repository is not a person deciding anything about theirs.
        let authority = both("privacy:\n  full_recording_retention_days: 365\n", "");

        let resolved = authority.full_recording_retention_days();
        assert_eq!(resolved.value, 365);
        assert_eq!(resolved.by, Some(Layer::User));
        assert!(authority.privileges().is_empty());
    }

    #[test]
    fn a_project_naming_the_users_own_number_has_asked_for_nothing() {
        // The boundary of `ExtendedRetention`, and the reason it is the one
        // request `Config::requested_privileges` cannot produce: whether a file
        // has made it is a fact about that file *and the one above it*. A
        // project naming exactly what the user allowed is not an escalation, and
        // the layer that decided the number is the user's.
        let authority = both(
            "privacy:\n  full_recording_retention_days: 30\n",
            "privacy:\n  full_recording_retention_days: 30\n",
        );

        assert_eq!(authority.full_recording_retention_days().value, 30);
        assert_eq!(
            authority.full_recording_retention_days().by,
            Some(Layer::User)
        );
        assert!(
            authority
                .privilege(ProjectRequest::ExtendedRetention)
                .is_none(),
            "a project that named the user's own number was refused as an escalation"
        );

        // One more day, and it is an escalation again — so the line is exactly
        // where the ceiling is, and not a day to either side of it.
        let one_more = both(
            "privacy:\n  full_recording_retention_days: 30\n",
            "privacy:\n  full_recording_retention_days: 31\n",
        );
        assert_eq!(one_more.full_recording_retention_days().value, 30);
        assert_eq!(
            one_more.full_recording_retention_days().by,
            Some(Layer::User)
        );
        assert!(
            one_more
                .privilege(ProjectRequest::ExtendedRetention)
                .is_some_and(|privilege| privilege.is_refused_escalation()),
            "31 days against a user ceiling of 30 was not refused"
        );
    }

    #[test]
    fn nothing_naming_a_duration_means_the_default_and_says_so() {
        // What a user sees when the value is absent, which is the ordinary case
        // and the one every other test in this file would otherwise be a special
        // case of. `by: None` is `Resolved`'s way of saying "nothing beyond what
        // SURE does anyway": no file decided this, and a report that named a
        // layer would be telling the user they had chosen something.
        for authority in [project_only(""), both("", "")] {
            let resolved = authority.full_recording_retention_days();
            assert_eq!(resolved.value, DEFAULT_FULL_RECORDING_RETENTION_DAYS);
            assert!(resolved.is_default());
            assert_eq!(resolved.by, None);
            assert!(authority.privileges().is_empty());
        }

        // And the distinction the whole setting turns on, in one fixture: a
        // project that asks to *record* more asks for nothing about how long it
        // is kept, so it leaves `FullRecording` on the record and no
        // `ExtendedRetention` beside it. Deciding whether content is kept and
        // deciding how long it is kept are two questions with two answers, which
        // is why `privacy.full_recording` was not the answer to this criterion.
        let recording_more = project_only("privacy:\n  full_recording: true\n");
        let resolved = recording_more.full_recording_retention_days();
        assert_eq!(resolved.value, DEFAULT_FULL_RECORDING_RETENTION_DAYS);
        assert_eq!(resolved.by, None);
        assert!(
            recording_more
                .privilege(ProjectRequest::FullRecording)
                .is_some_and(|privilege| privilege.is_refused_escalation()),
            "a project asking to record content was not refused"
        );
        assert!(
            recording_more
                .privilege(ProjectRequest::ExtendedRetention)
                .is_none(),
            "asking to record was read as asking to keep it for longer"
        );
    }

    #[test]
    fn a_project_can_shorten_to_zero_and_that_is_not_a_request_for_less_than_nothing() {
        // Zero is a value a file may name — `Config::validate` allows it, and it
        // means "keep this until the moment it is written" — and it shortens, so
        // it is obeyed rather than refused. The case is worth its own test
        // because it is the one where "the project asked for less" and "the
        // project asked for nothing" are easiest to confuse.
        let authority = both("", "privacy:\n  full_recording_retention_days: 0\n");
        assert_eq!(authority.full_recording_retention_days().value, 0);
        assert_eq!(
            authority.full_recording_retention_days().by,
            Some(Layer::Project)
        );
        assert!(authority.privileges().is_empty());
    }

    #[test]
    fn the_privileges_are_in_a_fixed_order() {
        // Two runs over the same files must read the same way, and a report is
        // read by people and compared by machines.
        let authority = both(
            "execution:\n  mode: host_confirmed\n  allow_network: true\nprivacy:\n  telemetry: true\n",
            "execution:\n  mode: host_confirmed\n  allow_dependency_install: true\n",
        );
        let order: Vec<ProjectRequest> = authority
            .privileges()
            .into_iter()
            .map(|privilege| privilege.request)
            .collect();
        assert_eq!(
            order,
            vec![
                ProjectRequest::RunProjectCode,
                ProjectRequest::InstallDependencies,
                ProjectRequest::Network,
                ProjectRequest::Telemetry,
            ]
        );
    }

    #[test]
    fn a_user_file_that_is_not_there_is_not_a_file_that_declared_nothing() {
        // "You have no settings" and "your settings are empty" are different
        // sentences, and a report has to be able to say which one is true.
        let none = project_only("");
        assert!(none.user().is_none());
        assert!(none.user_file().is_none());

        let empty = both("", "");
        assert!(empty.user().is_some());
        assert!(empty.user_file().is_some());
    }

    #[test]
    fn a_refusal_keeps_the_request_that_was_refused() {
        // Dropping refused requests would make "asked and refused" and "never
        // asked" the same list, which is the shape of report this product exists
        // to replace.
        let authority = project_only("privacy:\n  full_recording: true\n");
        let recording = authority
            .privilege(ProjectRequest::FullRecording)
            .expect("full_recording was asked for and left no record");
        assert_eq!(recording.asked_by, vec![Layer::Project]);
        assert_eq!(recording.granted_by, None);
        assert!(recording.is_refused_escalation());
        assert!(
            authority.privilege(ProjectRequest::Telemetry).is_none(),
            "nothing asked for telemetry"
        );
    }

    #[test]
    fn asking_for_something_that_is_not_a_permission_grants_no_permission() {
        // Recording more is not running more. A granted `full_recording` or
        // `telemetry` must not appear in the permission set as though it were
        // execution authority.
        let authority = both(
            "privacy:\n  mode: fully_local\n  full_recording: true\n",
            "",
        );
        assert!(authority.privilege(ProjectRequest::FullRecording).is_some());
        assert_eq!(
            authority.permissions(),
            ExecutionPermissions::inspect_only()
        );
    }

    /// A directory under the workspace's git-ignored `target/tmp`, unique to this
    /// test binary, for the tests that need files on disk.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("config authority")
            .join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    #[test]
    fn both_files_are_read_from_where_they_were_asked_for() {
        // The one test that goes through `Authority::load`, because the wiring it
        // holds is invisible to every test that builds an `Authority` directly:
        // an `Authority` that found the user's file and then discarded it would
        // pass all of them and silently ignore the user's own settings.
        let dir = scratch_dir("load");
        let project_root = dir.join("project");
        std::fs::create_dir_all(&project_root).expect("create the project directory");
        let user_config = dir.join("sure.yaml");
        std::fs::write(
            &user_config,
            "execution:\n  mode: host_confirmed\n  allow_network: true\n",
        )
        .expect("write the user's file");
        std::fs::write(
            project_root.join(Config::FILE_NAME),
            "execution:\n  mode: host_confirmed\n",
        )
        .expect("write the project's file");

        let authority = Authority::load(&project_root, &user_config)
            .expect("both files are there and both are valid");

        assert!(
            authority.user().is_some(),
            "the user's own file was found and then not used"
        );
        assert!(
            authority.permissions().allows(Permission::Network),
            "the user's file granted the network and the grant did not arrive"
        );
        assert_eq!(
            authority
                .privilege(ProjectRequest::Network)
                .expect("the user asked for the network")
                .asked_by,
            vec![Layer::User],
            "the project never asked, so only the user is on the record"
        );
        assert!(
            authority
                .privilege(ProjectRequest::RunProjectCode)
                .is_some_and(|privilege| privilege.is_granted()),
            "the mode the user's own file set did not count as a grant"
        );

        // Failing to clean up must not turn a passing test into a failing one;
        // Windows keeps directory handles open longer than Unix does.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_project_with_no_configuration_files_at_all_declares_nothing() {
        // Absence is not failure. A user who has configured nothing must get
        // defaults rather than an error, and the answer must say so.
        let dir = scratch_dir("absent");
        let root = dir.join("empty-project");
        let authority = Authority::load(&root, &dir.join(Config::FILE_NAME))
            .expect("nothing to read is not a failure");

        assert!(authority.user().is_none());
        assert!(authority.project().requested_privileges().is_empty());
        assert!(authority.privileges().is_empty());
        assert_eq!(
            authority.permissions(),
            ExecutionPermissions::inspect_only()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_project_file_cannot_weaken_a_user_restriction_in_either_direction() {
        // Both restrictions at once, weakened from below, resolved to what the
        // user set. This is the sentence in `CONFIG_AUTHORITY.md` — "a
        // lower-authority source cannot weaken a higher-authority safety/privacy
        // restriction" — rather than either half of it.
        let authority = both(
            "protection:\n  mode: strict\nprivacy:\n  mode: fully_local\n",
            "protection:\n  mode: standard\nprivacy:\n  mode: local_first\n",
        );
        assert_eq!(authority.protection().value, ProtectionMode::Strict);
        assert_eq!(authority.protection().by, Some(Layer::User));
        assert_eq!(authority.privacy_mode().value, PrivacyMode::FullyLocal);
        assert_eq!(authority.privacy_mode().by, Some(Layer::User));
    }
}
