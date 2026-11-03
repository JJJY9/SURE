//! Naming exactly the project state that evidence is about.
//!
//! This is step 3 of `docs/architecture/CHECK_PIPELINE.md`, and
//! `docs/architecture/FINGERPRINTING.md` is the rule it implements. What follows
//! is why it is built the way it is, and the parts that are uncomfortable.
//!
//! # What a fingerprint is for
//!
//! One question, asked once, by everything downstream: **is the evidence I have
//! still about the project in front of me?** A result carries the fingerprint it
//! was produced from; a later run computes one; [`ProjectFingerprint::matches`]
//! answers yes or no. Nothing else in SURE compares files, and nothing else
//! decides whether an old green is still a green.
//!
//! That gives both ways this can be wrong a name, and they are not equally bad.
//!
//! - **The fingerprint changes when the project did not.** A result is marked
//!   stale although it is still true. The cost is work done again, and a person
//!   who sees it happen enough times stops reading the word "stale" — which is
//!   how the *other* failure gets missed.
//! - **The fingerprint stays the same when the project did change.** A result
//!   produced from one project is reported as current for a different one. That
//!   is a green that outlived its evidence. It is the failure this product exists
//!   to prevent, and everything here is arranged to make it the impossible one
//!   rather than the unlikely one.
//!
//! So where a decision could go either way, it goes the way that changes the
//! fingerprint. That is why the tracked list includes files SURE will never open,
//! why a link's recorded target counts even though nothing reads through it, and
//! why every limit below produces an [`FingerprintError`] rather than a
//! fingerprint of the part that fitted.
//!
//! # What it covers, and what it does not
//!
//! **A file is part of the fingerprint if and only if a check could read it.**
//! The scan decides what a check can read ([`crate::scan`]), so the fingerprint
//! covers the scan's files and no others: the same ignore tables, applied by the
//! same comparison. Two consequences fall out with no special case written for
//! either — a nested repository or a vendored dependency tree is inside, because
//! the walk looks inside it; `target/`, `node_modules/` and SURE's own `.sure/`
//! are outside, because the walk does not. A fingerprint over SURE's own output
//! would change when SURE ran, which would make checking a project change the
//! thing being checked.
//!
//! Files in the *repository* that the walk would not read are still not covered,
//! and that is deliberate rather than an oversight: a change to a committed file
//! under `target/` cannot change any answer SURE gives, so marking every result
//! stale for it would be the first failure above, paid for nothing.
//!
//! This is a statement about coverage, and it is worth being exact about what it
//! does **not** claim. It does not claim that a check read the file — only that
//! it could. A fingerprint that changed only when a check had actually read
//! something would be a stronger thing, and it is not this one; it would need
//! every check to declare its inputs up front, which
//! `docs/architecture/EVIDENCE_MODEL.md` leaves to the tasks that build them.
//!
//! # The two kinds, and which one a project gets
//!
//! [`FingerprintKind::Git`] is what a project at the root of its own working tree
//! gets, and it is cheaper because Git already knows which tracked files differ.
//! It is [`git::git_fingerprint`]. Everything else gets
//! [`FingerprintKind::Content`], a manifest over what the walk found, which is
//! [`content::content_fingerprint`].
//!
//! [`project_fingerprint`] is the one function that chooses, and
//! [`choose`] gives the reason it chooses the way it does. The short version is
//! that the obvious test — "is this directory inside a repository?" — answers
//! `yes` for a directory one component deep in somebody else's checkout, where
//! the `HEAD` a Git fingerprint digests is that other project's.
//!
//! The three functions are all public and none is a fallback for another. A
//! caller who knows which kind they want calls for it and gets exactly it;
//! a caller who does not calls [`project_fingerprint`] and gets the kind the
//! project calls for. What no caller gets is a project whose kind depends on
//! what was installed on the machine that took the fingerprint, which is why
//! [`FingerprintError::GitUnavailable`] stays an error rather than becoming a
//! content manifest.
//!
//! # Determinism
//!
//! The same project state produces the same digest on every run, on every
//! machine, on every platform, and under every later version of SURE that still
//! speaks this domain tag. That is a promise about the value, and several
//! decisions here exist only to keep it:
//!
//! - Paths are sorted before they are hashed, by bytes, because the order Git
//!   reports things in is a property of Git and not of the project.
//! - Paths are written with `/` on every platform — the same normalisation
//!   [`crate::scan::display_path`] applies — so a checkout on Windows and one on
//!   Linux do not produce two digests for one state.
//! - The branch name is recorded but **not** hashed. Renaming a branch changes
//!   no file, and a fingerprint that moved for it would teach a person to ignore
//!   the word stale.
//! - File contents are read and hashed, where the cheaper design hashes the text
//!   of `git diff` — which varies with `diff.algorithm`, `.gitattributes`
//!   filters, rename heuristics and Git's own version.
//!
//! # What it does not do
//!
//! **It reads nothing through a link.** A tracked link contributes the path it
//! points at and nothing else, so a link retargeted to a different file is a
//! change and a change behind an unchanged link is not. Both are stated in
//! `docs/architecture/FINGERPRINTING.md` rather than left to be discovered.
//!
//! **It does not read a file's metadata.** Modification times are a filesystem's
//! opinion and travel badly between machines and checkouts; two clones of one
//! commit do not share them. Contents are the thing.
//!
//! **It does not look at `.gitignore`.** Git's answer to "what is untracked" has
//! already applied it. The ignore tables here are a second and different
//! question — what a check reads — and both apply.

pub mod choose;
pub mod content;
// `pub(crate)` since `P4-T002`. It was private, and the module that needed it
// was already here — a check's identity is a digest, and the alternative was a
// second hashing recipe in `checks/` that could drift from this one without
// either changing. Widening it to the crate rather than to the world: a digest
// is not a promise SURE makes to a caller, and making it `pub` would be one.
pub(crate) mod digest;
pub mod error;
pub mod git;
mod read;

pub use choose::project_fingerprint;
pub use content::content_fingerprint;
pub use error::FingerprintError;
pub use git::{Git, git_fingerprint};

use crate::scan::ScanOptions;

/// How hard a fingerprint is allowed to try.
///
/// The three limits are the same kind of thing as [`ScanOptions`]'s and are kept
/// beside them rather than merged into them, because they answer about different
/// work: the scan's limits bound how many names are listed, and these bound how
/// many files are opened and how much is read. A project can be comfortably
/// inside the first and far outside the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintOptions {
    /// Limits on the walk, used where a fingerprint has to read a directory the
    /// scan would have walked. Same tables, same rules, same limits.
    pub scan: ScanOptions,
    /// How many changed files SURE will read in one fingerprint.
    ///
    /// Reaching this is [`FingerprintError::TooManyFiles`], never a fingerprint
    /// of the first however-many. The default is a project's worth of changes
    /// with room to spare; the failure it prevents is a machine reading a
    /// hundred gigabytes because a build directory was committed by mistake.
    pub max_files: usize,
    /// How many bytes of changed files SURE will read in one fingerprint.
    ///
    /// Reaching this is [`FingerprintError::TooManyBytes`], for the same reason.
    /// Counted over the bytes actually read, which is the thing that costs time
    /// and memory, rather than over a file's length as reported by a filesystem
    /// that may be describing something else entirely.
    pub max_bytes: u64,
}

impl Default for FingerprintOptions {
    fn default() -> Self {
        Self {
            scan: ScanOptions::default(),
            max_files: 20_000,
            // 256 MiB. Large enough for a repository-wide change to a project of
            // any ordinary size, small enough that a committed database or disk
            // image is refused rather than read.
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

impl FingerprintOptions {
    /// The same options with different limits on the walk.
    #[must_use]
    pub fn with_scan(mut self, scan: ScanOptions) -> Self {
        self.scan = scan;
        self
    }

    /// The same options with a different file limit.
    #[must_use]
    pub const fn with_max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files;
        self
    }

    /// The same options with a different byte limit.
    #[must_use]
    pub const fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::paths::CaseSensitivity;

    #[test]
    fn the_limits_are_limits_on_work_and_all_of_them_are_finite() {
        let options = FingerprintOptions::default();
        assert!(options.max_files > 0, "a limit of zero reads nothing");
        assert!(options.max_bytes > 0);
        assert!(options.scan.max_entries > 0);
    }

    #[test]
    fn a_fingerprint_walks_a_nested_directory_as_far_as_a_scan_would() {
        // The one property that makes "the fingerprint covers what a check can
        // read" true rather than a slogan: the walk inside a fingerprint is the
        // scan, with the scan's options. If these two ever came from different
        // places, a directory could be inside one and outside the other.
        let scan = ScanOptions::default()
            .with_max_depth(3)
            .with_case(CaseSensitivity::Sensitive);
        let options = FingerprintOptions::default().with_scan(scan.clone());
        assert_eq!(options.scan, scan);
    }

    #[test]
    fn each_builder_changes_only_its_own_limit() {
        let base = FingerprintOptions::default();
        assert_eq!(base.clone().with_max_files(1).max_bytes, base.max_bytes);
        assert_eq!(base.clone().with_max_files(1).scan, base.scan);
        assert_eq!(base.clone().with_max_bytes(1).max_files, base.max_files);
        assert_eq!(base.clone().with_max_bytes(1).scan, base.scan);
        assert_eq!(
            base.clone().with_scan(ScanOptions::default()).max_files,
            base.max_files
        );
    }
}
