//! Fingerprinting a project that is not under version control, by reading it.
//!
//! This is the other kind, and the one that needs nothing but the project
//! itself: no Git, no repository, no history. It walks the project and hashes
//! what it finds.
//!
//! # What it is for
//!
//! [`crate::fingerprint::git_fingerprint`] gets its precision from Git — Git
//! knows which tracked files differ from `HEAD`, so SURE does not have to read
//! them to find out. A project with no repository has no such answer available,
//! and a manifest over its files is the only thing that can be computed. It is
//! more expensive than the Git kind and covers strictly more: every readable
//! file, not only the changed ones.
//!
//! It is also the escape hatch for a project that **is** in a repository and
//! should not be fingerprinted by it. There are two such cases, and they are
//! named in [`crate::fingerprint::project_fingerprint`], which is where the
//! choice between the kinds is made.
//!
//! # The rules it inherits rather than restates
//!
//! The coverage rule is the same one: **a file is part of the fingerprint if and
//! only if a check could read it.** The walk is [`crate::scan`] — the same
//! tables, the same comparison, the same limits — so "generated and vendored
//! churn is excluded" is not a claim made here and checked somewhere else; it is
//! the same decision, made once. `node_modules`, `target/`, `vendor/`, `dist/`,
//! `__pycache__` and SURE's own `.sure/` are out for the reason the scan records
//! beside each of them.
//!
//! What is at each path is [`crate::fingerprint::read`]'s answer, the same one
//! the Git kind uses. A link means the same thing in both, and a pipe is
//! described and never opened in both, because it is one implementation rather
//! than two that agree today.
//!
//! # A link is in the manifest, and the scan did not put it there
//!
//! The scan skips links — [`SkipReason::NotFollowed`] — because a check does not
//! read through one, and it reports the skip as a **loss** because a link could
//! have been hiding project content. This module does not treat it as a loss: it
//! resolves the skip into the same [`Contents::Link`] the Git kind records.
//!
//! Leaving it out would be the dangerous direction. A link is a path in the
//! project and its target is the whole of what it is, so retargeting one is a
//! change to the project; a manifest that ignored links would keep the same
//! digest through that change and report evidence about the old state as current
//! for the new one. The Git kind already refuses to make that mistake — a
//! tracked link is recorded by its target even though nothing reads through it —
//! and this is the same decision.
//!
//! Every other loss the walk reports **is** a loss here: a directory that could
//! not be listed, a level the depth limit stopped, the point the entry budget
//! ran out, a file that could not be read, a pipe met inside a directory. Those
//! all mean the manifest would describe part of the project while reading like a
//! description of the whole of it, so they are [`FingerprintError::IncompleteTree`]
//! rather than a shorter digest.
//!
//! [`SkipReason::NotFollowed`]: crate::scan::SkipReason::NotFollowed
//! [`Contents::Link`]: crate::fingerprint::read::Contents

use std::fs;
use std::path::{Path, PathBuf};

use sure_domain::vocabulary::ProjectFingerprint;

use crate::scan::{SkipReason, scan};

use super::FingerprintOptions;
use super::digest::Digest;
use super::error::FingerprintError;
use super::read::{Reader, display_path};

/// The name of this kind of fingerprint, and the version of what goes into it.
///
/// Different from the Git kind's on purpose: the two are different questions
/// asked of the same project, and a digest of one must never be mistaken for a
/// digest of the other. See [`super::digest`].
const DOMAIN: &str = "sure.content-fingerprint.v1";

/// Fingerprint a project by reading its files.
///
/// # Errors
///
/// - [`FingerprintError::NotAbsolute`] — a relative root would make the stored
///   value mean different things on different days.
/// - [`FingerprintError::IncompleteTree`] — the walk lost something. A manifest
///   over part of a project is not a manifest over the project.
/// - [`FingerprintError::Unreadable`], [`FingerprintError::TooManyFiles`],
///   [`FingerprintError::TooManyBytes`] — the limits and the filesystem.
///
/// # Examples
///
/// ```no_run
/// use sure_core::fingerprint::{FingerprintOptions, content_fingerprint};
///
/// # fn main() -> Result<(), sure_core::fingerprint::FingerprintError> {
/// let fingerprint = content_fingerprint(
///     std::path::Path::new(r"C:\work\project"),
///     &FingerprintOptions::default(),
/// )?;
/// println!("{}", fingerprint.digest);
/// # Ok(())
/// # }
/// ```
pub fn content_fingerprint(
    root: &Path,
    options: &FingerprintOptions,
) -> Result<ProjectFingerprint, FingerprintError> {
    if !root.is_absolute() {
        return Err(FingerprintError::NotAbsolute {
            root: root.to_path_buf(),
        });
    }

    let walked =
        scan(root, options.scan.clone()).map_err(|error| FingerprintError::Unreadable {
            path: root.to_path_buf(),
            message: error.to_string(),
        })?;

    // Everything the walk found, and the links it declined to follow, as one
    // list. Collected before anything is read so that the two sources can be
    // merged and sorted together: a file and a link are two things at two paths,
    // and the digest must not depend on which list they arrived in.
    //
    // Each path is paired with the text that goes into the digest here rather
    // than at the sort and again at the hash, so that a comparison is a string
    // comparison and not an allocation per comparison.
    let mut paths: Vec<(String, PathBuf)> = Vec::new();
    for entry in walked.files() {
        paths.push((display_path(&entry.path), entry.path.clone()));
    }
    for skipped in walked.skipped() {
        match skipped.reason {
            // A link is content. See the module comment for why this is not a
            // loss here when the scan records it as one.
            SkipReason::NotFollowed => {
                paths.push((display_path(&skipped.path), skipped.path.clone()));
            }
            reason if reason.loses_coverage() => {
                return Err(FingerprintError::IncompleteTree {
                    path: skipped.path.clone(),
                    // The whole sentence, not `SkipReason`'s clause: this is the
                    // same error the nested-directory walk in
                    // [`super::read`] produces for the same situation, and two
                    // spellings of one refusal would be read as two refusals.
                    detail: skipped.plain_description(),
                });
            }
            // The declared scope: `.git`, `node_modules`, build output, caches.
            // Left out on purpose, which is what makes the second acceptance
            // criterion true rather than hopeful.
            _ => {}
        }
    }

    // Sorted by the text that goes into the digest rather than by the paths
    // themselves, so that the order is the one the digest can see. The walk's
    // own order is fixed, but it is fixed by the scanner's implementation and
    // not by the project — the same reason the Git kind sorts what Git printed.
    // The sort is stable, so two paths that normalise to the same text keep the
    // walk's order, which is fixed too.
    paths.sort_by(|(left, _), (right, _)| left.cmp(right));

    let mut reader = Reader::new(options, DOMAIN);
    let mut digest = Digest::new(DOMAIN);
    digest.field("manifest");
    for (display, relative) in &paths {
        let entry = root.join(relative);
        let found = fs::symlink_metadata(&entry).map_err(|error| FingerprintError::Unreadable {
            path: relative.clone(),
            message: error.to_string(),
        })?;
        let contents = reader.read(relative, &entry, Some(&found))?;
        // The path is digested beside its contents, so that moving a file
        // without changing it is a change and swapping two names is one too.
        digest.field(display.as_bytes());
        contents.write(&mut digest);
    }

    Ok(ProjectFingerprint::content(digest.finish()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The domain tag is a promise about stored values, so it is pinned here
    /// rather than left to be changed by accident.
    ///
    /// **This test catches nothing behavioural, and that is worth saying.** A
    /// mutation that changed the tag to the Git kind's was applied, and every
    /// test in the suite still passed — because the two digests cannot collide
    /// even with one domain, the Git kind opening with `head` and this one with
    /// `manifest`. So the tag is belt and braces over the field structure rather
    /// than the thing that keeps the kinds apart, and no test can tell the
    /// difference. What this pins is the *decision*: the tag is part of the
    /// format of every fingerprint already stored, and changing it invalidates
    /// all of them.
    #[test]
    fn the_domain_tag_is_the_one_stored_fingerprints_were_written_under() {
        assert_eq!(
            DOMAIN, "sure.content-fingerprint.v1",
            "this tag is in every content fingerprint already stored; changing it \
             means every one of them stops matching"
        );
        assert_ne!(
            DOMAIN, "sure.git-fingerprint.v1",
            "one domain for both kinds would make a digest of one kind readable \
             as a digest of the other the first time the two ever coincided"
        );
    }
}
