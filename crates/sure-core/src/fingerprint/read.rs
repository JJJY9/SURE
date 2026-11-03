//! What is at a path, described in a way a digest can use.
//!
//! This is the part of fingerprinting that does not depend on how the paths were
//! found, and it is shared by both kinds for that reason. Git names the paths
//! that matter and the content manifest walks for them; everything after that —
//! opening the file, hashing it, deciding what a link means, what to do about a
//! pipe, spending the budget — is one implementation.
//!
//! # Why it is shared rather than written twice
//!
//! Two implementations of "what is at this path" would be two answers to a
//! question that has one, and the way they would diverge is not symmetric. A
//! link recorded by its target in one place and by nothing in the other would
//! make a project state that is one state into two — the harmless direction —
//! only until the reverse happens, and then a link retargeted to somewhere else
//! would leave the fingerprint where it was. That is a change nothing noticed,
//! which is the failure this product exists to prevent.
//!
//! The same argument already holds `crate::scan` and the nested-directory walk
//! together; this module is that decision applied one level further up.
//!
//! # The two rules that are decided here rather than by a caller
//!
//! **A link is recorded by its target and never read through.** Reading through
//! one would read whatever it names, including outside the project, and every
//! other part of SURE refuses to do that. The target as text is also the whole
//! of what a link is: a link retargeted to a different file is a different link
//! whatever is at the other end.
//!
//! **Something that is neither a file, a directory nor a link is described and
//! never opened.** `File::open` on a FIFO with no writer blocks until a writer
//! appears, and the working tree is written by whoever SURE is checking — a
//! project could otherwise hang a check with no output, and a check that never
//! returns cannot be told apart from one that is still working. What is recorded
//! is the kind, because a file replaced by a pipe is a change and a pipe
//! replaced by a socket is a change, and recording both as "nothing" would make
//! them one state.

use std::fs;
use std::path::Path;

use crate::scan::{ScanError, scan};

use super::FingerprintOptions;
use super::digest::{self, Digest, HashError};
use super::error::FingerprintError;

/// What is at one of the paths a fingerprint is over.
pub(super) enum Contents {
    /// A file, and the digest of its bytes.
    File(String),
    /// A directory, and the digest of everything the walk found inside it.
    Tree(String),
    /// A link, and the path it points at.
    ///
    /// The target as text rather than the file it names: reading through a link
    /// is the thing every other part of SURE refuses to do, and a link that
    /// points somewhere else is a different link whatever is at the other end.
    Link(String),
    /// Something that is neither a file nor a directory nor a link, named by its
    /// kind: a pipe, a socket, a device.
    ///
    /// The kind is recorded rather than any contents, because there are none to
    /// read and because opening it is what would not return. See the arm in
    /// [`Reader::read`] that produces this.
    Special(&'static str),
    /// Nothing. Git named a path that is not in the working tree — a deletion,
    /// or a staged change whose file has since gone.
    ///
    /// A content manifest never produces this: it only ever describes paths it
    /// found by walking. It is here because the type is shared, and the
    /// alternative — a second, nearly identical enum for the content kind —
    /// would be the divergence this module exists to prevent.
    Gone,
}

impl Contents {
    /// Write this into a digest, with a tag so that no two kinds can collide.
    pub(super) fn write(&self, digest: &mut Digest) {
        match self {
            Self::File(hex) => {
                digest.field("file").field(hex);
            }
            Self::Tree(hex) => {
                digest.field("tree").field(hex);
            }
            Self::Link(target) => {
                digest.field("link").field(target);
            }
            Self::Special(kind) => {
                digest.field("special").field(kind);
            }
            Self::Gone => {
                digest.field("gone");
            }
        }
    }
}

/// What kind of not-a-file something is, as a name that goes in a digest.
///
/// The names are this module's own and are never printed to anybody, so they are
/// stable across platforms on purpose: `fifo` means the same state on Linux and
/// on macOS, and a digest taken on one is the digest the other would take. On
/// Windows a pipe is not a filesystem entry and Git cannot report one as a
/// tracked path, so the fall-through is what Windows returns.
fn file_kind(file_type: &fs::FileType) -> &'static str {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt as _;
        if file_type.is_fifo() {
            return "fifo";
        }
        if file_type.is_socket() {
            return "socket";
        }
        if file_type.is_char_device() {
            return "char-device";
        }
        if file_type.is_block_device() {
            return "block-device";
        }
    }
    #[cfg(not(unix))]
    let _ = file_type;
    "other"
}

/// Reads what is at paths, within the budget it was given.
///
/// The budget is spent here rather than checked afterwards because the point of
/// a limit is not to notice a project that is too big — it is to not read it.
pub(super) struct Reader<'a> {
    options: &'a FingerprintOptions,
    /// The digest domain of the kind of fingerprint this reader is serving.
    ///
    /// Carried rather than fixed so that a nested tree's digest is namespaced by
    /// the kind that produced it. The two domains differ, so a tree digest taken
    /// during a content manifest cannot equal one taken during a Git
    /// fingerprint — belt and braces over the outer tag, and free.
    domain: &'static str,
    files: usize,
    bytes: u64,
}

impl<'a> Reader<'a> {
    pub(super) fn new(options: &'a FingerprintOptions, domain: &'static str) -> Self {
        Self {
            options,
            domain,
            files: 0,
            bytes: 0,
        }
    }

    /// What is at `relative`, which a fingerprint named and which lives at
    /// `entry`.
    pub(super) fn read(
        &mut self,
        relative: &Path,
        entry: &Path,
        found: Option<&fs::Metadata>,
    ) -> Result<Contents, FingerprintError> {
        let Some(metadata) = found else {
            return Ok(Contents::Gone);
        };
        // A link is answered before anything reads through it. `read_link`
        // returns what the link says, and does not follow it — which is the only
        // kind of reading a link gets anywhere in SURE.
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(entry).map_err(|error| FingerprintError::Unreadable {
                path: relative.to_path_buf(),
                message: error.to_string(),
            })?;
            return Ok(Contents::Link(display_path(&target)));
        }
        if metadata.is_dir() {
            return self.tree(relative, entry);
        }
        if !metadata.is_file() {
            // Neither a file, nor a directory, nor a link: a pipe, a socket, a
            // device. **This is answered without opening it, because opening it
            // is the thing that does not return.** `File::open` on a FIFO with
            // no writer blocks until one appears, and SURE reading a project
            // must not be stoppable by the project: a repository that tracks
            // `f` and whose working tree has a FIFO at `f` would otherwise hang
            // a check with no output and no way to tell it from a slow one.
            //
            // What is recorded is the kind, and not "no contents". A file
            // replaced by a pipe is a change, and a pipe replaced by a socket is
            // a change; recording both as `Gone` would make them one state. This
            // is the same decision as [`Contents::Link`] — describe what is
            // there, do not read through it — and it is why a special file named
            // by Git is *covered* while one met inside a walked directory is a
            // loss the walk refuses on. The walk cannot tell what else a
            // directory it could not fully read contains; Git has named exactly
            // one path, and its kind is knowable without opening it.
            self.take_file(relative)?;
            return Ok(Contents::Special(file_kind(&metadata.file_type())));
        }
        self.read_bytes(relative, entry)
    }

    /// A file's digest.
    pub(super) fn read_bytes(
        &mut self,
        relative: &Path,
        entry: &Path,
    ) -> Result<Contents, FingerprintError> {
        self.take_file(relative)?;
        let remaining = self.options.max_bytes.saturating_sub(self.bytes);
        match digest::hash_file(entry, remaining) {
            Ok(hashed) => {
                self.bytes += hashed.bytes;
                Ok(Contents::File(hashed.hex))
            }
            Err(HashError::TooLarge) => Err(FingerprintError::TooManyBytes {
                limit: self.options.max_bytes,
                path: relative.to_path_buf(),
            }),
            Err(HashError::Io(source)) => Err(FingerprintError::Unreadable {
                path: relative.to_path_buf(),
                message: source.to_string(),
            }),
        }
    }

    /// A directory's digest: everything the walk found inside it, with the
    /// walk's own ignore tables applied.
    ///
    /// This is the case a nested repository lands in — a checkout cloned into
    /// the project without being added, which Git reports as one untracked
    /// directory and does not descend into. Its files are files a check can
    /// read, so they are files the fingerprint covers; the alternative is a
    /// fingerprint that calls an old result current when somebody edits them.
    pub(super) fn tree(
        &mut self,
        relative: &Path,
        entry: &Path,
    ) -> Result<Contents, FingerprintError> {
        let walked = scan(entry, self.options.scan.clone()).map_err(|error| match error {
            ScanError::Unreadable { message, .. } => FingerprintError::Unreadable {
                path: relative.to_path_buf(),
                message,
            },
            other => FingerprintError::Unreadable {
                path: relative.to_path_buf(),
                message: other.to_string(),
            },
        })?;

        // A walk that lost something is not a walk whose result can be hashed.
        // The files it did not reach are files a check can still read, and
        // leaving them out is how this fingerprint would come to mean less than
        // it appears to.
        if let Some(lost) = walked.losses().next() {
            return Err(FingerprintError::IncompleteTree {
                path: relative.to_path_buf(),
                detail: lost.plain_description(),
            });
        }

        let mut files: Vec<_> = walked.files().collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));

        let mut digest = Digest::new(self.domain);
        digest.field("tree");
        for file in files {
            let contents = self.read_bytes(&file.path, &entry.join(&file.path))?;
            // The path is in the digest as well as the contents, so that moving
            // a file and changing nothing in it is a change. Two files swapping
            // names leaves every set of bytes exactly where it was.
            digest.field(display_path(&file.path).as_bytes());
            contents.write(&mut digest);
        }
        Ok(Contents::Tree(digest.finish()))
    }

    /// Spend one file from the budget.
    fn take_file(&mut self, relative: &Path) -> Result<(), FingerprintError> {
        if self.files >= self.options.max_files {
            return Err(FingerprintError::TooManyFiles {
                limit: self.options.max_files,
                path: relative.to_path_buf(),
            });
        }
        self.files += 1;
        Ok(())
    }
}

/// A path with `/` on every platform, for a digest.
///
/// The digest has to be the same value for the same project on Windows, macOS
/// and Linux, and `Display for Path` gives backslashes on Windows. This is the
/// same normalisation `crate::scan` applies to a path it reports, and it is
/// deliberately the same function rather than the same idea: a link target
/// recorded here and a path reported there are the same kind of thing.
pub(super) fn display_path(path: &Path) -> String {
    crate::scan::display_path(path)
}
