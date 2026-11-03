//! What a scan did not look at, and why.
//!
//! A scanner that walks a project and returns a list of files has told you
//! nothing about the files it did not return. If a directory could not be read,
//! or was left out because it was too deep, or the walk stopped at a limit, the
//! list is shorter and nothing in it says so — and every later stage that
//! reasons over the list inherits the loss without being able to see it. A
//! verdict built on that list is the exact failure this product exists to
//! prevent: a green result that means "nothing was found" when it should mean
//! "nothing was looked at".
//!
//! So a skip is a **value**, and it is carried alongside the entries rather than
//! being logged and dropped. [`Skipped`] is what the scanner returns instead of
//! silence.
//!
//! # Two kinds of skip, and only one of them is a loss
//!
//! Most skips are the scan's declared scope. `.git` is not project content,
//! `node_modules` is somebody else's code, `target/` is regenerable, and
//! `__pycache__` is a cache. Those are reported so a person can see what was
//! left out and disagree, but nothing was lost by leaving them out.
//!
//! The rest are losses: a directory SURE could not list, one deeper than the
//! depth limit, the point at which the entry budget ran out, a link it declined
//! to follow. Anything could have been in there. [`SkipReason::loses_coverage`]
//! is the predicate that separates them, and [`Scan::is_complete`] is the one
//! question a caller has to answer before treating a scan as the whole project.
//!
//! Both predicates are written as full matches over the enum rather than one
//! being the negation of the other. A `!is_by_design()` would answer for a
//! variant nobody thought about, and the answer it gave would be "not a loss"
//! — the quiet direction.
//!
//! [`Scan::is_complete`]: super::Scan::is_complete

use std::path::PathBuf;

use sure_domain::variants::variants;

/// Why the scanner did not look at something.
///
/// The names are the four categories P2-T001's first acceptance criterion
/// names — version control, vendored code, build output and caches — plus the
/// ways a scan can stop early, and two kinds of entry that are not files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// The version-control system's own storage: `.git`, `.svn`, `.hg`.
    VersionControl,
    /// Code installed from somewhere else: `node_modules`, `vendor`, `.venv`.
    ///
    /// Not project content, and usually the largest thing in the tree by a wide
    /// margin. Leaving it in would make a scan of a small project take as long
    /// as a scan of its whole dependency closure.
    Vendored,
    /// Where a build writes: `target`, `dist`, `build`.
    ///
    /// These are outputs. They can be produced again from what is left, and
    /// including them would make the project's apparent shape change every time
    /// somebody compiled it.
    BuildOutput,
    /// A cache: `__pycache__`, `.pytest_cache`, `.DS_Store`.
    Cache,
    /// `.sure`, which is SURE's own regenerable cache inside the project.
    ///
    /// Skipped for a reason the other caches do not have. A fingerprint taken
    /// over a tree that contains SURE's own output changes when SURE runs, so
    /// checking a project would change the thing being checked and the second
    /// check would be of a different project state than the first.
    SureCache,
    /// A path the person asked SURE not to read, in their own settings.
    ///
    /// **Only the user's configuration can produce this** (`scan.exclude`, keyed
    /// by project); a project file that names the setting is refused when the
    /// configuration is loaded (ADR 0011). It is a declared scope skip, not a
    /// loss — but it is reported like every other skip, because a scan that
    /// silently stopped reading a path would leave a reader unable to tell
    /// "nothing was there" from "nobody looked".
    UserExcluded,
    /// Deeper than [`ScanOptions::max_depth`] allows.
    ///
    /// [`ScanOptions::max_depth`]: super::ScanOptions::max_depth
    TooDeep,
    /// The scan had already listed as many entries as it will in one run.
    ///
    /// The reason is recorded once, at the directory where it stopped. Nothing
    /// past that point is in the scan at all, so the skip list is a partial
    /// account of what was missed rather than a complete one — which is why
    /// this reason is a loss and why [`Scan::is_complete`] exists rather than a
    /// caller counting.
    ///
    /// [`Scan::is_complete`]: super::Scan::is_complete
    OutOfBudget,
    /// A symbolic link, a Windows junction, or another reparse point.
    ///
    /// Never followed. Following one is how a scan leaves the project it was
    /// asked to look at: a link is a promise about a location, and the location
    /// it names can be anywhere, including outside the tree the user believes
    /// is being read.
    NotFollowed,
    /// The operating system would not list it, or would not say what it is.
    Unreadable,
    /// Neither a regular file nor a directory: a socket, a device or a pipe.
    ///
    /// Reachable on Unix. This scanner reads no file contents, so an entry like
    /// this is not a file the project has; it is a thing living in the
    /// directory.
    SpecialFile,
}

variants!(
    /// Every reason a scanner may decline to look at something.
    SkipReason {
        VersionControl,
        Vendored,
        BuildOutput,
        Cache,
        SureCache,
        UserExcluded,
        TooDeep,
        OutOfBudget,
        NotFollowed,
        Unreadable,
        SpecialFile,
    }
);

impl SkipReason {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VersionControl => "version_control",
            Self::Vendored => "vendored",
            Self::BuildOutput => "build_output",
            Self::Cache => "cache",
            Self::SureCache => "sure_cache",
            Self::UserExcluded => "user_excluded",
            Self::TooDeep => "too_deep",
            Self::OutOfBudget => "out_of_budget",
            Self::NotFollowed => "not_followed",
            Self::Unreadable => "unreadable",
            Self::SpecialFile => "special_file",
        }
    }

    /// Whether leaving this out is part of what the scan said it would do.
    ///
    /// True for the five categories a person would name if asked "what does
    /// SURE not look at?" — the four kinds of non-project content, plus SURE's
    /// own cache.
    #[must_use]
    pub const fn is_by_design(self) -> bool {
        match self {
            Self::VersionControl
            | Self::Vendored
            | Self::BuildOutput
            | Self::Cache
            | Self::SureCache
            | Self::UserExcluded => true,
            Self::TooDeep
            | Self::OutOfBudget
            | Self::NotFollowed
            | Self::Unreadable
            | Self::SpecialFile => false,
        }
    }

    /// Whether something could have been missed because of this.
    ///
    /// True for everything the scan did not choose to leave out. Note that
    /// `NotFollowed` and `SpecialFile` count: what a link points at is not in
    /// the scan even though the link is, and a named pipe is still an entry
    /// that exists and is not in the list.
    ///
    /// This is deliberately not `!self.is_by_design()`. See the module comment.
    #[must_use]
    pub const fn loses_coverage(self) -> bool {
        match self {
            Self::VersionControl
            | Self::Vendored
            | Self::BuildOutput
            | Self::Cache
            | Self::SureCache
            | Self::UserExcluded => false,
            Self::TooDeep
            | Self::OutOfBudget
            | Self::NotFollowed
            | Self::Unreadable
            | Self::SpecialFile => true,
        }
    }

    /// Why this is not project content, in words for someone who does not know
    /// the tool that made it.
    ///
    /// Written to complete the sentence "SURE did not look at *x* because it
    /// …", which is why every one of these starts with a verb.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::VersionControl => {
                "is the version-control system's own storage, not part of the project"
            }
            Self::Vendored => {
                "holds code the project downloaded from somewhere else rather than code written here"
            }
            Self::BuildOutput => "is where a build puts its output, and it can be produced again",
            Self::Cache => "is a cache, and it can be produced again",
            Self::SureCache => {
                "is SURE's own cache inside the project, and reading it would make a check depend on SURE's previous runs"
            }
            Self::UserExcluded => "is a path your SURE settings asked the scan to leave out",
            Self::TooDeep => "is deeper inside the project than SURE looks in one run",
            Self::OutOfBudget => {
                "is where SURE stopped, having listed as many files and folders as it will in one run"
            }
            Self::NotFollowed => {
                "is a link, and following one is how a scan leaves the project it was asked to look at"
            }
            Self::Unreadable => "could not be listed",
            Self::SpecialFile => {
                "is not a regular file or folder — it is a socket, a device or a pipe"
            }
        }
    }
}

/// One thing the scanner did not look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Where it is, relative to the scan root, with `/` separators.
    pub path: PathBuf,
    /// Why it was not looked at.
    pub reason: SkipReason,
    /// What the operating system said, when the operating system is the one
    /// that said no.
    ///
    /// Only ever set for [`SkipReason::Unreadable`]. It is the operating
    /// system's own sentence — "Access is denied." on Windows, "Permission
    /// denied" on Unix — and it is carried rather than paraphrased because the
    /// paraphrase is where the reason a user could act on gets lost.
    pub detail: Option<String>,
}

impl Skipped {
    /// The path as text, with `/` on every platform.
    #[must_use]
    pub fn display_path(&self) -> String {
        crate::scan::display_path(&self.path)
    }

    /// One sentence for a person, saying what was not looked at and why.
    #[must_use]
    pub fn plain_description(&self) -> String {
        let mut text = format!(
            "SURE did not look at {} because it {}",
            self.display_path(),
            self.reason.plain_description()
        );
        if let Some(detail) = &self.detail {
            text.push_str(". The operating system said: ");
            text.push_str(detail);
        }
        text.push('.');
        text
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_answers_both_questions_consistently() {
        // The two predicates are written as two full matches, so this is the
        // test that catches one of them being edited without the other.
        for &reason in SkipReason::ALL {
            assert_ne!(
                reason.is_by_design(),
                reason.loses_coverage(),
                "{reason:?} is either a declared part of the scan or a loss, not both and not neither"
            );
        }
    }

    #[test]
    fn the_four_categories_the_task_names_are_all_by_design() {
        // P2-T001's first acceptance criterion names VCS, vendor, build and
        // cache. Each has to exist as a reason, or "ignores them appropriately"
        // could be satisfied by ignoring none of them and reporting nothing.
        for reason in [
            SkipReason::VersionControl,
            SkipReason::Vendored,
            SkipReason::BuildOutput,
            SkipReason::Cache,
        ] {
            assert!(reason.is_by_design(), "{reason:?} must be by design");
        }
    }

    #[test]
    fn everything_that_could_hide_project_content_is_a_loss() {
        for reason in [
            SkipReason::TooDeep,
            SkipReason::OutOfBudget,
            SkipReason::NotFollowed,
            SkipReason::Unreadable,
            SkipReason::SpecialFile,
        ] {
            assert!(reason.loses_coverage(), "{reason:?} must count as a loss");
        }
    }

    #[test]
    fn a_link_is_a_loss_even_though_it_is_a_decision() {
        // Not following a link is deliberate, and it is still a loss: what the
        // link points at is not in the scan. Classifying it as "by design"
        // because the scanner chose it would be the scanner grading its own
        // decision.
        assert!(SkipReason::NotFollowed.loses_coverage());
        assert!(!SkipReason::NotFollowed.is_by_design());
    }

    #[test]
    fn every_reason_has_its_own_name_and_description() {
        // A description that reads well is not enough — two reasons sharing one
        // would make the report unable to say which happened.
        let mut names: Vec<&str> = SkipReason::ALL.iter().map(|r| r.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two reasons share a wire name");

        let mut texts: Vec<&str> = SkipReason::ALL
            .iter()
            .map(|r| r.plain_description())
            .collect();
        texts.sort_unstable();
        let count = texts.len();
        texts.dedup();
        assert_eq!(texts.len(), count, "two reasons share a description");

        for &reason in SkipReason::ALL {
            assert!(
                !reason.plain_description().is_empty(),
                "{reason:?} has no description"
            );
            // The sentence is "… because it {description}", so a description
            // that does not start with a verb reads as a non-sentence.
            assert!(
                !reason.plain_description().starts_with(' '),
                "{reason:?} has a padded description"
            );
        }
    }

    #[test]
    fn a_skip_with_nothing_from_the_operating_system_reads_as_one_sentence() {
        let skipped = Skipped {
            path: PathBuf::from("src/generated"),
            reason: SkipReason::TooDeep,
            detail: None,
        };
        assert_eq!(
            skipped.plain_description(),
            "SURE did not look at src/generated because it is deeper inside the project than SURE looks in one run."
        );
    }

    #[test]
    fn a_skip_the_operating_system_caused_quotes_the_operating_system() {
        // The paraphrase is where the actionable part is lost: "Access is
        // denied" tells a user to fix a permission, and "could not be listed"
        // does not.
        let skipped = Skipped {
            path: PathBuf::from("locked"),
            reason: SkipReason::Unreadable,
            detail: Some("Access is denied. (os error 5)".to_owned()),
        };
        let text = skipped.plain_description();
        assert!(text.contains("could not be listed"), "{text}");
        assert!(text.contains("Access is denied. (os error 5)"), "{text}");
    }
}
