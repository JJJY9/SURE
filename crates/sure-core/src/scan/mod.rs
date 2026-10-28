//! Looking at a project's files, within limits it states.
//!
//! This is step 1 of `docs/architecture/CHECK_PIPELINE.md` — *discover* — and
//! everything after it reads what comes out of here. It is therefore the place
//! where a silent loss turns into a wrong answer much later, with nothing in
//! between able to notice.
//!
//! # The three guarantees
//!
//! **It stays inside the project it was given.** Children are built by joining
//! one directory-entry name onto a path that was already inside, and a name
//! from the operating system is a single component with no separator and no
//! `..`. Links are never followed ([`SkipReason::NotFollowed`]). Those two
//! rules are the whole containment argument, and it is an argument from
//! construction rather than a check that could be wrong: there is no reachable
//! state in which the walk holds a path outside the root, so there is no
//! `SkipReason::Outside` for one to be recorded as.
//!
//! A project reached through a link — `C:\work\current` junctioned to a
//! checkout somewhere else — is followed at the *root*, because the caller
//! named it. Everything below that is reported relative to it.
//!
//! **It is bounded.** [`ScanOptions::max_depth`] stops the walk going down, and
//! [`ScanOptions::max_entries`] stops it going wide. Both are limits on work
//! done, so neither can be exceeded by a project that is merely large, and both
//! are recorded in the result when they bite. A directory of two hundred
//! thousand files does not make SURE hang; it makes SURE say it stopped.
//!
//! **It says what it did not look at.** [`Scan::entries`] is what was found and
//! [`Scan::skipped`] is what was not, and the second is not a log. See
//! [`skip`] for why, and [`Scan::is_complete`] for the one question a caller
//! must answer before treating the first as the whole project.
//!
//! # What it does not do
//!
//! **It reads no file contents.** This is an enumeration: names, and whether
//! each is a file or a directory. Nothing here opens a file, so a scan of a
//! project whose files are enormous, encrypted, on a slow network share or
//! placeholders that would be fetched from a cloud provider costs the same as a
//! scan of any other. Deciding what to read, and reading it, is the
//! fingerprint's job (P2-T002, P2-T003) and the readers' jobs after that.
//!
//! **It does nothing about `.gitignore`.** A project's own ignore file is a
//! statement about what belongs in the repository, which is a different
//! question from what belongs in a check — a test fixture deliberately kept out
//! of a repository is still worth reading, and a file the project forgot to
//! ignore is not made uninteresting by being tracked. Reading those rules is a
//! decision for a task that needs it, with its own evidence.
//!
//! **A nested checkout is not this project's content.** A directory carrying a
//! `.git` entry is a repository or linked worktree of its own: a submodule, a
//! nested clone, or an agent's `.claude/worktrees/<name>`. The walk records it
//! as a [`SkipReason::VersionControl`] scope skip instead of scanning a second
//! copy of the same source under a second path, which is how a real project's
//! findings appeared twice on 2026-10-23. The root is never asked — the caller
//! named it, and its own `.git` is the repository the scan is of.
//!
//! **It does not decide what anything is.** Finding `package.json` here does
//! not mean the project is a Node project; that is P2-T004 onwards.
//!
//! # Determinism
//!
//! Entries come out in a fixed order: directories are listed in name order and
//! descended into as they are reached, so the result is the same on every run
//! on every filesystem. Names are compared as the operating system gives them
//! rather than through a lossy text conversion — two names that are distinct
//! bytes but the same replacement characters would compare equal as text, and a
//! comparison that ties leaves the order up to the sort. A fingerprint taken
//! over a list whose order moves is a fingerprint that changes when nothing
//! did.

pub mod error;
pub mod ignore;
pub mod skip;

pub use error::ScanError;
pub use ignore::{
    IGNORED_DIRECTORIES, IGNORED_FILES, IgnoreRule, left_out, matching_rule, table_for,
};
pub use skip::{SkipReason, Skipped};

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::{fs, io};

use sure_domain::variants::variants;

use crate::paths::CaseSensitivity;

/// How hard a scan is allowed to try.
///
/// Every field is a limit on work, and every limit that is reached is recorded
/// as a [`Skipped`] rather than applied quietly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    /// How many levels below the root SURE will list.
    ///
    /// A file directly inside the root is at level 1, so `0` lists nothing at
    /// all. The default is deep enough for any layout a person would recognise
    /// and shallow enough that a directory structure built by a mistake — or on
    /// purpose, to be a nuisance — cannot make the walk unbounded.
    ///
    /// Reaching this limit is a [`SkipReason::TooDeep`] loss: whatever is below
    /// is not in the scan and nobody has looked at it.
    pub max_depth: usize,
    /// How many directory entries SURE will examine in one scan.
    ///
    /// Counted over everything the walk meets, including the things it then
    /// decides not to look at, because the work of meeting them has already
    /// been done. Reaching this limit is a [`SkipReason::OutOfBudget`] loss.
    pub max_entries: usize,
    /// How the ignore table compares a name.
    ///
    /// Taken as an argument rather than read from the platform so that both
    /// rules can be tested on one machine, exactly as
    /// [`crate::paths::is_within_case`] does for locations.
    pub case: CaseSensitivity,
}

impl Default for ScanOptions {
    /// Written out rather than derived, because the case rule comes from the
    /// platform and a derived `Default` could only produce one fixed answer.
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_entries: 200_000,
            case: CaseSensitivity::platform(),
        }
    }
}

impl ScanOptions {
    /// The same options with a different depth limit.
    #[must_use]
    pub const fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// The same options with a different entry limit.
    #[must_use]
    pub const fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// The same options with the case rule stated rather than assumed.
    #[must_use]
    pub const fn with_case(mut self, case: CaseSensitivity) -> Self {
        self.case = case;
        self
    }
}

/// What kind of thing an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory that was looked inside.
    Directory,
}

variants!(
    /// Both kinds of entry a scan can list.
    EntryKind { File, Directory }
);

impl EntryKind {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }

    /// Whether this is a file.
    #[must_use]
    pub const fn is_file(self) -> bool {
        matches!(self, Self::File)
    }

    /// Whether this is a directory.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        matches!(self, Self::Directory)
    }
}

/// One thing that was found.
///
/// The path is relative to the scan root. Nothing here is absolute, so a scan
/// of the same project from two places describes the same project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Where it is, relative to the root.
    pub path: PathBuf,
    /// What it is.
    pub kind: EntryKind,
}

impl Entry {
    /// The path as text, with `/` on every platform.
    #[must_use]
    pub fn display_path(&self) -> String {
        display_path(&self.path)
    }
}

/// A path relative to a scan root, written with `/` on every platform.
///
/// A report has to name a file the same way wherever SURE runs, and a project
/// stored in a document has to compare equal for two people on two platforms.
/// `Display for Path` gives backslashes on Windows, so the components are
/// joined by hand instead.
///
/// A component that is not valid Unicode — possible on Unix, and for an unpaired
/// surrogate on Windows — becomes replacement characters. That is a *reporting*
/// loss and it is stated here rather than hidden: [`Entry::path`] is the real
/// path, and anything that has to tell two files apart uses it.
#[must_use]
pub fn display_path(path: &Path) -> String {
    let mut text = String::new();
    for component in path.components() {
        if !text.is_empty() {
            text.push('/');
        }
        text.push_str(&component.as_os_str().to_string_lossy());
    }
    text
}

/// What a scan found, and what it did not look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    root: PathBuf,
    entries: Vec<Entry>,
    skipped: Vec<Skipped>,
}

impl Scan {
    /// The directory this scan is of, as the caller named it.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Everything that was found, in a fixed order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Everything that was not looked at, in the order it was met.
    ///
    /// Both the declared scope (`.git`, `node_modules`) and the losses are
    /// here, because a caller that asked "what was skipped" should get the
    /// whole answer and use a predicate to narrow it.
    #[must_use]
    pub fn skipped(&self) -> &[Skipped] {
        &self.skipped
    }

    /// The files that were found.
    pub fn files(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|entry| entry.kind.is_file())
    }

    /// The directories that were found and looked inside.
    pub fn directories(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|entry| entry.kind.is_directory())
    }

    /// Whether the scan looked at everything it set out to look at.
    ///
    /// False when anything was lost — a directory that could not be read, a
    /// level the depth limit stopped, the point the entry limit was reached, a
    /// link that was not followed. The declared scope (`.git`, `node_modules`,
    /// build output, caches) does **not** make this false: leaving those out is
    /// what the scan said it would do, and the count of them is in
    /// [`Scan::scope`].
    ///
    /// A caller that reports on a scan without asking this is reporting on
    /// however much of the project it happened to reach, and `true` here is the
    /// only thing that makes "SURE looked at this project" a true sentence.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.skipped.iter().any(|s| s.reason.loses_coverage())
    }

    /// Everything that could have hidden project content.
    pub fn losses(&self) -> impl Iterator<Item = &Skipped> {
        self.skipped.iter().filter(|s| s.reason.loses_coverage())
    }

    /// Everything left out on purpose, by category.
    pub fn scope(&self) -> impl Iterator<Item = &Skipped> {
        self.skipped.iter().filter(|s| s.reason.is_by_design())
    }

    /// How many entries SURE declined to look at, by reason.
    ///
    /// A count per reason rather than the skips themselves: this is what a
    /// report says in one line ("SURE did not look inside 3 build directories
    /// or 1 vendor directory"), and the list underneath it is for a person who
    /// wants to check.
    ///
    /// Every reason is present with a count of zero when nothing was skipped
    /// for it, so that a caller building a table does not have to invent the
    /// missing rows.
    #[must_use]
    pub fn skip_counts(&self) -> Vec<(SkipReason, usize)> {
        SkipReason::ALL
            .iter()
            .map(|&reason| {
                let count = self.skipped.iter().filter(|s| s.reason == reason).count();
                (reason, count)
            })
            .collect()
    }
}

/// Look at a project, within [`ScanOptions`]' limits.
///
/// # Errors
///
/// Returns a [`ScanError`] when there is no scan to make at all — the root is
/// not absolute, does not exist, is not a directory, or cannot be listed. Every
/// other failure is a [`Skipped`] in the returned [`Scan`].
///
/// # Examples
///
/// ```no_run
/// use sure_core::scan::{scan, ScanOptions};
///
/// let scan = scan(std::path::Path::new(r"C:\work\project"), ScanOptions::default())?;
/// if !scan.is_complete() {
///     for loss in scan.losses() {
///         eprintln!("{}", loss.plain_description());
///     }
/// }
/// # Ok::<(), sure_core::scan::ScanError>(())
/// ```
pub fn scan(root: &Path, options: ScanOptions) -> Result<Scan, ScanError> {
    let root = open_root(root)?;
    let mut walk = Walk {
        options,
        entries: Vec::new(),
        skipped: Vec::new(),
        seen: 0,
        stopped: false,
    };
    walk.visit(&root, Path::new(""), 0);
    Ok(Scan {
        root,
        entries: walk.entries,
        skipped: walk.skipped,
    })
}

/// Accept a root only if there is a directory there to scan.
fn open_root(root: &Path) -> Result<PathBuf, ScanError> {
    if !root.is_absolute() || root.components().next().is_none() {
        return Err(ScanError::NotAbsolute {
            root: root.to_path_buf(),
        });
    }
    // `metadata` follows a link, which is what is wanted here and only here:
    // the caller named this path, so if it is a link to a directory, that
    // directory is the project. Every link *below* the root is a different
    // question and is refused.
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => Ok(root.to_path_buf()),
        Ok(_) => Err(ScanError::NotADirectory {
            root: root.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(ScanError::Missing {
            root: root.to_path_buf(),
        }),
        Err(error) => Err(ScanError::Unreadable {
            root: root.to_path_buf(),
            message: error.to_string(),
        }),
    }
}

/// Whether `dir` is a repository or linked worktree of its own.
///
/// A directory that carries a `.git` entry is a checkout, not content of the
/// project above it: a nested clone, a submodule, or an agent's linked
/// worktree (`.claude/worktrees/<name>` is the one that produced duplicate
/// findings in a real project on 2026-10-23). Walking into it would scan a
/// second copy of the same source as if it belonged here, and every finding
/// would appear twice under two paths.
///
/// The root itself is never asked: the caller named it, and its own `.git` is
/// the repository the scan is of.
fn nested_checkout(dir: &Path) -> Option<String> {
    match fs::symlink_metadata(dir.join(".git")) {
        Ok(_) => {
            Some("a nested repository or linked worktree is not this project's content".to_owned())
        }
        Err(_) => None,
    }
}

/// The walk's own state. Separate from [`Scan`] so that the result type has no
/// field a caller could reach mid-scan.
struct Walk {
    options: ScanOptions,
    entries: Vec<Entry>,
    skipped: Vec<Skipped>,
    seen: usize,
    stopped: bool,
}

impl Walk {
    /// Record an entry the ignore table declines, and say whether it was one.
    ///
    /// Returns `true` when a rule applied, having pushed the skip. Taking the
    /// path by value rather than by reference so that the two callers — which
    /// each need the path again afterwards, or do not — do not have to agree on
    /// a clone.
    fn ignored_by_name(&mut self, name: &OsStr, path: PathBuf, kind: EntryKind) -> bool {
        // `to_string_lossy` is safe for a lookup here: every name in both
        // tables is ASCII, and a name that is not cannot become one by being
        // replaced with U+FFFD.
        let Some(rule) = ignore::matching_rule(&name.to_string_lossy(), kind, self.options.case)
        else {
            return false;
        };
        self.skipped.push(Skipped {
            path,
            reason: rule.reason,
            detail: None,
        });
        true
    }

    /// List the contents of `dir`, if there is still budget to.
    ///
    /// `relative` is `dir`'s path relative to the root, which is empty for the
    /// root itself. `depth` is `dir`'s own depth: the root is 0, its contents
    /// are at 1.
    fn visit(&mut self, dir: &Path, relative: &Path, depth: usize) {
        if self.stopped || depth >= self.options.max_depth {
            return;
        }

        let listing = match fs::read_dir(dir) {
            Ok(listing) => listing,
            Err(error) => {
                // The caller checked the root before calling, so this is a
                // directory met during the walk. Recorded and stepped over: one
                // unreadable directory is not a reason to abandon the rest of
                // the project, and it is not a reason to say nothing either.
                self.skipped.push(Skipped {
                    path: relative.to_path_buf(),
                    reason: SkipReason::Unreadable,
                    detail: Some(error.to_string()),
                });
                return;
            }
        };

        let mut children: Vec<(OsString, Option<fs::FileType>)> = Vec::new();
        for entry in listing {
            match entry {
                Ok(entry) => {
                    let name = entry.file_name();
                    // `file_type` does not follow a link, so a link is seen as
                    // a link here and never as what it points at.
                    children.push((name, entry.file_type().ok()));
                }
                Err(error) => {
                    // A single entry the directory could not describe. Not the
                    // whole directory, and not nothing.
                    self.skipped.push(Skipped {
                        path: relative.to_path_buf(),
                        reason: SkipReason::Unreadable,
                        detail: Some(error.to_string()),
                    });
                }
            }
        }
        // Sorted by the name the operating system gave, not by its text: two
        // distinct names can render to the same replacement characters, and a
        // tie would leave the order to the sort.
        children.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, kind) in children {
            if self.stopped {
                return;
            }
            if self.seen >= self.options.max_entries {
                self.stopped = true;
                self.skipped.push(Skipped {
                    path: relative.to_path_buf(),
                    reason: SkipReason::OutOfBudget,
                    detail: None,
                });
                return;
            }
            self.seen += 1;

            let child_relative = relative.join(&name);

            match kind {
                None => self.skipped.push(Skipped {
                    path: child_relative,
                    reason: SkipReason::Unreadable,
                    detail: Some("the operating system did not say what it is".to_owned()),
                }),
                // A link is answered before the ignore tables are consulted.
                // What it points at is not in the scan whatever it is called,
                // and reporting it as "vendored" would describe a decision that
                // was not the one made.
                Some(kind) if kind.is_symlink() => self.skipped.push(Skipped {
                    path: child_relative,
                    reason: SkipReason::NotFollowed,
                    detail: None,
                }),
                Some(kind) if kind.is_dir() => {
                    if self.ignored_by_name(&name, child_relative.clone(), EntryKind::Directory) {
                        continue;
                    }
                    let child = dir.join(&name);
                    if let Some(detail) = nested_checkout(&child) {
                        self.skipped.push(Skipped {
                            path: child_relative,
                            reason: SkipReason::VersionControl,
                            detail: Some(detail),
                        });
                        continue;
                    }
                    self.entries.push(Entry {
                        path: child_relative.clone(),
                        kind: EntryKind::Directory,
                    });
                    if depth + 1 >= self.options.max_depth {
                        self.skipped.push(Skipped {
                            path: child_relative,
                            reason: SkipReason::TooDeep,
                            detail: None,
                        });
                    } else {
                        self.visit(&child, &child_relative, depth + 1);
                    }
                }
                Some(kind) if kind.is_file() => {
                    if self.ignored_by_name(&name, child_relative.clone(), EntryKind::File) {
                        continue;
                    }
                    self.entries.push(Entry {
                        path: child_relative,
                        kind: EntryKind::File,
                    });
                }
                Some(_) => self.skipped.push(Skipped {
                    path: child_relative,
                    reason: SkipReason::SpecialFile,
                    detail: None,
                }),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A walk with nowhere to put anything, for driving `visit` directly.
    fn empty_walk(options: ScanOptions) -> Walk {
        Walk {
            options,
            entries: Vec::new(),
            skipped: Vec::new(),
            seen: 0,
            stopped: false,
        }
    }

    /// Ask the real walker to list a path that is not there.
    ///
    /// `visit` is reached with a directory taken from a successful `read_dir`,
    /// so this input does not occur in a real scan. What it does exercise is the
    /// arm that handles `read_dir` failing — the same arm a directory the
    /// operating system refuses goes down — and that is what these tests are
    /// about. What they do **not** establish is that the operating system
    /// produces this error for a real unreadable directory; no test here can,
    /// because making a directory unreadable needs either a privileged user or
    /// an ACL change, and a test that silently passed as root would be worse
    /// than the gap.
    #[test]
    fn a_directory_that_cannot_be_listed_is_recorded_rather_than_dropped() {
        // A name that cannot exist, rather than one that probably does not.
        // `%TEMP%` is shared, and a test whose fixture it did not create can
        // fail because of something else on the machine.
        let missing = std::env::temp_dir().join(format!(
            "sure-scan-nothing-here-{}-{}",
            std::process::id(),
            "not-a-real-directory"
        ));
        assert!(
            !missing.exists(),
            "the fixture path exists: {}",
            missing.display()
        );

        let mut walk = empty_walk(ScanOptions::default());
        walk.visit(&missing, Path::new("sub"), 1);

        assert_eq!(walk.skipped.len(), 1, "{:?}", walk.skipped);
        let skip = &walk.skipped[0];
        assert_eq!(skip.reason, SkipReason::Unreadable);
        assert_eq!(skip.path, Path::new("sub"));
        assert!(
            skip.detail.is_some(),
            "the operating system's own words were dropped"
        );
        assert!(walk.entries.is_empty());
    }

    #[test]
    fn a_path_the_operating_system_will_not_accept_is_recorded_the_same_way() {
        // A second, independent way to make the real `fs::read_dir` return an
        // error: an interior NUL byte is refused before any system call, so
        // this reaches the same arm by a different route. Two routes into one
        // arm is the closest this suite can get to the real thing without a
        // permission the test runner may not have.
        let mut walk = empty_walk(ScanOptions::default());
        walk.visit(Path::new("bad\0name"), Path::new("weird"), 1);

        assert_eq!(walk.skipped.len(), 1, "{:?}", walk.skipped);
        assert_eq!(walk.skipped[0].reason, SkipReason::Unreadable);
        assert_eq!(walk.skipped[0].path, Path::new("weird"));
        assert!(walk.skipped[0].detail.is_some());
    }

    #[test]
    fn the_walk_stops_before_it_looks_at_a_level_past_the_limit() {
        // The guard at the top of `visit`. It is belt-and-braces — the caller
        // checks the same thing before recursing — and a limit that only holds
        // because the caller remembered to check is not a limit.
        let root = sure_testkit::repository_root();
        let mut walk = empty_walk(ScanOptions::default().with_max_depth(4));
        walk.visit(&root, Path::new(""), 4);
        assert!(walk.entries.is_empty());
        assert!(walk.skipped.is_empty());
    }

    #[test]
    fn a_walk_that_has_stopped_does_nothing_else() {
        let root = sure_testkit::repository_root();
        let mut walk = empty_walk(ScanOptions::default());
        walk.stopped = true;
        walk.visit(&root, Path::new(""), 0);
        assert!(walk.entries.is_empty());
        assert!(walk.skipped.is_empty());
    }

    #[test]
    fn a_relative_path_stays_relative_all_the_way_down() {
        // The containment argument depends on this: every entry's path is the
        // root's own relative path joined with one name from the operating
        // system, and the root's is empty. An absolute path appearing here
        // would mean something joined a location onto a location.
        let scan = scan(&sure_testkit::repository_root(), ScanOptions::default())
            .expect("the checkout is a directory");
        for entry in scan.entries() {
            assert!(
                entry.path.is_relative(),
                "{} is absolute",
                entry.path.display()
            );
            assert!(
                !entry
                    .path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "{} climbs out of the project",
                entry.path.display()
            );
        }
    }

    #[test]
    fn a_nested_checkout_is_skipped_as_version_control_and_not_scanned() {
        let root = sure_testkit::scratch::directory("scan nested checkout", "nested worktree");
        fs::create_dir_all(root.join("src")).expect("src");
        fs::write(root.join("src/main.rs"), b"").expect("main");
        // A linked worktree: `.git` is a file pointing at the real repository.
        fs::create_dir_all(root.join(".claude/worktrees/wt/src")).expect("worktree src");
        fs::write(
            root.join(".claude/worktrees/wt/.git"),
            b"gitdir: ../../.git/worktrees/wt",
        )
        .expect("worktree .git");
        fs::write(root.join(".claude/worktrees/wt/src/dup.rs"), b"").expect("dup");
        // A nested clone: `.git` is a directory.
        fs::create_dir_all(root.join("nested/.git")).expect("nested .git");
        fs::write(root.join("nested/file.rs"), b"").expect("nested file");

        let scan = scan(&root, ScanOptions::default()).expect("scan the fixture");
        let paths: Vec<String> = scan.entries().iter().map(Entry::display_path).collect();
        assert!(paths.iter().any(|path| path == "src/main.rs"), "{paths:?}");
        assert!(
            !paths
                .iter()
                .any(|path| path.starts_with(".claude/worktrees/wt")),
            "the linked worktree was scanned: {paths:?}"
        );
        assert!(
            !paths.iter().any(|path| path.starts_with("nested")),
            "the nested clone was scanned: {paths:?}"
        );

        for path in [".claude/worktrees/wt", "nested"] {
            let skip = scan
                .skipped()
                .iter()
                .find(|skip| skip.path == Path::new(path))
                .unwrap_or_else(|| panic!("{path} was not recorded: {:?}", scan.skipped()));
            assert_eq!(skip.reason, SkipReason::VersionControl, "{path}");
            assert!(skip.detail.is_some(), "{path}");
        }
        assert!(
            scan.is_complete(),
            "a declared scope skip is not a loss of coverage"
        );
    }
}
