//! Fingerprinting a project by reading it, and choosing between the two kinds.
//!
//! P2-T003 acceptance:
//!
//! > Scoped content manifest is deterministic.
//! > Generated/vendor churn is excluded by documented rules.
//!
//! # Why these tests touch a real filesystem
//!
//! Both criteria are about a value that has to come out the same for one project
//! state and different for another, and there is no way to check that without
//! project states. A test over a synthetic digest would be a test of the digest
//! function, which has its own unit tests; what is unverified after those is
//! whether this walk, on this filesystem, on this platform, puts the same things
//! into it twice.
//!
//! So every test below writes real files and drives
//! [`sure_core::fingerprint::content_fingerprint`] or
//! [`sure_core::fingerprint::project_fingerprint`].
//!
//! # The fixture is deliberately not the one `fingerprint_git.rs` uses
//!
//! That file's `Repo` carries what the Git kind needs and this one does not: two
//! ways to make a commit with fixed dates, `core.longpaths` for the long-path
//! test, and a 14-line panic explaining that a machine without Git cannot run it.
//! Copying it here would be copying the wrong half — and, more to the point,
//! would make the two files fail for each other's reasons. What is shared is
//! [`sure_testkit::repository_root`], which is what decides *where* a fixture
//! goes, and that is the part that has to agree.
//!
//! # What this file cannot test, and says so
//!
//! **A symbolic link, on Windows.** The [`Contents::Link`] machinery is covered
//! on Unix. It is not covered on Windows, and that is a fact about this machine
//! rather than an oversight: `CreateSymbolicLinkW` needs Developer Mode or
//! administrator rights, and this development machine has neither. The same gap
//! with the same cause is recorded for the Git kind in `fingerprint_git.rs`, so
//! it is one missing cover rather than two.
//!
//! **A pipe, on Windows.** Not a filesystem entry there, so the walk cannot meet
//! one. Covered on Unix, where meeting one could hang a check.
//!
//! **A directory that cannot be listed.** [`FingerprintError::Unreadable`] from
//! the walk is not produced anywhere here: forcing it needs an ACL or a mode
//! change that would be state outside the fixture.
//!
//! [`Contents::Link`]: sure_core::fingerprint::content

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use sure_core::fingerprint::{
    FingerprintError, FingerprintOptions, content_fingerprint, git_fingerprint, project_fingerprint,
};
use sure_core::scan::ScanOptions;
use sure_core::vocabulary::{FingerprintKind, ProjectFingerprint};

/// How many entries a fixture's walks are allowed before a test is wrong.
const FIXTURE_LIMIT: usize = 5_000;

/// A scratch directory that removes itself, with a project inside it.
///
/// Under the workspace's own `target/` rather than the system temp directory, so
/// the fixture is on the same volume as the checkout. The path contains a space
/// and a non-ASCII character, which is the cheapest way to make every path in
/// every test below a path two platforms disagree about.
///
/// There are two directories rather than one because one test needs a file
/// **outside** the project that the project links to, and a target inside the
/// project would be a file the manifest already covers — which would make the
/// test pass without testing anything.
struct Fixture {
    /// The directory everything is under. Not the project.
    scratch: PathBuf,
    /// The project: the directory a fingerprint is taken of.
    project: PathBuf,
}

impl Fixture {
    /// A fixture under the workspace's own `target/`, which is inside the SURE
    /// repository.
    fn new(test: &str) -> Self {
        Self::under(
            &sure_testkit::repository_root().join("target").join("tmp"),
            test,
        )
    }

    /// A fixture with no repository above it, wherever that is on this machine.
    ///
    /// **This exists because the first version of this file was wrong.** It put
    /// every fixture under `target/` — which is inside the SURE checkout, and
    /// therefore inside a Git working tree — and then had a test named
    /// `a_project_in_no_repository_at_all_is_fingerprinted_by_content`. That
    /// test passed, and it passed for the opposite reason: the directory *is*
    /// inside a repository, so it was exercising the "somebody else's
    /// repository" branch and never the "no repository" one at all. Nothing
    /// about the assertion was false; the fixture could not reach the case the
    /// test was named for, and nothing said so.
    ///
    /// The mutation that found it was "a directory in no repository is refused
    /// rather than read by content", which no test noticed. That is what a
    /// false green looks like from the inside, and it is why this constructor
    /// exists and why the test that uses it asserts its own premise.
    fn outside_any_repository(test: &str) -> Self {
        Self::under(&std::env::temp_dir(), test)
    }

    fn under(parent: &Path, test: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "{test}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let scratch = parent.join("sure 指纹 content").join(unique);
        std::fs::create_dir_all(&scratch)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", scratch.display()));
        let project = scratch.join("project");
        std::fs::create_dir_all(&project)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", project.display()));
        Self { scratch, project }
    }

    fn path(&self) -> &Path {
        &self.project
    }

    /// Write a file inside the project, creating its directory.
    fn write(&self, relative: &str, contents: &str) -> &Self {
        write_under(&self.project, relative, contents);
        self
    }

    /// Write a file outside the project, beside it.
    ///
    /// Gated rather than merely unused on Windows, because its only caller is
    /// the link test and that test is gated too. Left ungated it is a dead-code
    /// warning on Windows only, which is the shape of thing that gets "fixed"
    /// by deleting it and takes the Unix cover with it.
    #[cfg(unix)]
    fn write_outside(&self, relative: &str, contents: &str) -> &Self {
        write_under(&self.scratch, relative, contents);
        self
    }

    /// Run Git in the project, and fail loudly rather than carry on.
    fn git(&self, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.project)
            .args(arguments)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap_or_else(|error| panic!("these tests need Git on the path: {error}"));
        assert!(
            output.status.success(),
            "git {arguments:?} failed with {:?}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The fingerprint of the project under default options.
    fn fingerprint(&self) -> ProjectFingerprint {
        self.fingerprint_with(options())
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn fingerprint_with(
        &self,
        options: FingerprintOptions,
    ) -> Result<ProjectFingerprint, FingerprintError> {
        content_fingerprint(&self.project, &options)
    }

    /// How many files a walk of the project finds.
    ///
    /// For the tests about counts and limits: a fixture that quietly grew a file
    /// should fail at the assertion that says how many it has, rather than at
    /// the one about the limit, where the failure would read as a bug in the
    /// limit.
    fn count_files(&self) -> usize {
        sure_core::scan::scan(&self.project, ScanOptions::default())
            .unwrap_or_else(|error| panic!("{error}"))
            .files()
            .count()
    }

    /// Read a file inside the project.
    fn read(&self, relative: &str) -> String {
        let full = self.project.join(relative);
        std::fs::read_to_string(&full)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", full.display()))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Failing to clean up must not turn a passing test into a failing one.
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

fn write_under(root: &Path, relative: &str, contents: &str) {
    let full = root.join(relative);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
    }
    std::fs::write(&full, contents)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
}

/// The options every test here uses: the defaults, with a fixture-sized budget
/// so a fixture that escaped its root fails quickly.
fn options() -> FingerprintOptions {
    FingerprintOptions::default().with_scan(ScanOptions::default().with_max_entries(FIXTURE_LIMIT))
}

/// Two fingerprints, and whether they name the same project state.
///
/// [`ProjectFingerprint`] carries an id that is generated rather than derived, so
/// two fingerprints of one state are deliberately not `==`. This is the
/// comparison that answers the only question any of these tests asks.
fn same(a: &ProjectFingerprint, b: &ProjectFingerprint) -> bool {
    a.matches(b)
}

/// Where Git says this directory sits inside a repository, or `None` if it says
/// there is no repository.
///
/// Asked of `git` directly rather than through the product, because every use
/// below is a test asserting its own **premise** — that this fixture really is
/// in a repository, or really is not — and a premise checked with the code under
/// test is not a premise.
fn git_prefix(path: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--show-prefix"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap_or_else(|error| panic!("these tests need Git on the path: {error}"));
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// A project with two source files and a README.
fn small(test: &str) -> Fixture {
    let fixture = Fixture::new(test);
    fixture
        .write("src/main.rs", "fn main() {}\n")
        .write(
            "src/lib.rs",
            "pub fn add(a: u32, b: u32) -> u32 { a + b }\n",
        )
        .write("README.md", "# A project\n");
    fixture
}

/// The same, with the files committed to a repository at the project root.
fn committed(test: &str) -> Fixture {
    let fixture = small(test);
    fixture.git(&["init", "-b", "main"]);
    for (key, value) in [
        ("user.email", "sure@example.invalid"),
        ("user.name", "SURE test fixture"),
        ("commit.gpgsign", "false"),
        ("core.autocrlf", "false"),
        ("gc.auto", "0"),
    ] {
        fixture.git(&["config", key, value]);
    }
    fixture.git(&["add", "-A"]);
    fixture.git(&["commit", "-m", "first"]);
    fixture
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn the_same_project_read_twice_is_the_same_fingerprint() {
    let fixture = small("twice");
    let first = fixture.fingerprint();
    let second = fixture.fingerprint();
    assert!(
        same(&first, &second),
        "one project state produced two fingerprints: {} and {}",
        first.digest,
        second.digest
    );
    assert_eq!(first.kind, FingerprintKind::Content);
    assert!(
        first.git.is_none(),
        "a content fingerprint describes no Git state, and said it did"
    );
}

#[test]
fn two_copies_of_one_project_are_one_fingerprint() {
    // The same files in two different directories. If an absolute path reached
    // the digest, or the order the filesystem happened to hand names back in
    // did, these would differ — and the same project checked out on two machines
    // would never agree with itself.
    let here = small("copy-here");
    let there = small("copy-there");
    here.write("src/extra.rs", "// extra\n");
    there.write("src/extra.rs", "// extra\n");
    let one = here.fingerprint();
    let other = there.fingerprint();
    assert!(
        same(&one, &other),
        "two copies of one project are two fingerprints: {} and {}",
        one.digest,
        other.digest
    );
    assert_ne!(here.path(), there.path());
}

#[test]
fn a_change_to_a_covered_file_is_a_change_and_the_control_holds() {
    let fixture = small("changed");
    let before = fixture.fingerprint();
    fixture.write(
        "src/lib.rs",
        "pub fn add(a: u32, b: u32) -> u32 { a + b + 0 }\n",
    );
    let after = fixture.fingerprint();
    assert!(
        !same(&before, &after),
        "editing a source file left the fingerprint where it was"
    );
}

#[test]
fn moving_a_file_without_changing_a_byte_of_it_is_a_change() {
    // The path is in the digest beside the contents, so this is a change. The
    // other way round — contents only — would make a rename invisible, and a
    // rename moves what a check reads.
    let fixture = small("moved");
    let before = fixture.fingerprint();
    std::fs::rename(
        fixture.path().join("src/lib.rs"),
        fixture.path().join("src/library.rs"),
    )
    .unwrap();
    let after = fixture.fingerprint();
    assert!(
        !same(&before, &after),
        "renaming a file left the fingerprint where it was"
    );
}

#[test]
fn swapping_two_names_is_a_change_even_though_no_bytes_moved() {
    // Every byte in the project is exactly where it was; only which name is
    // over which set of bytes changed. A manifest that hashed the sorted set of
    // file contents without their names would call this the same project.
    let fixture = Fixture::new("swapped");
    fixture.write("a.txt", "one\n").write("b.txt", "two\n");
    let before = fixture.fingerprint();
    fixture.write("a.txt", "two\n").write("b.txt", "one\n");
    let after = fixture.fingerprint();
    assert!(
        !same(&before, &after),
        "two files swapping contents left the fingerprint where it was"
    );
}

#[test]
fn an_empty_project_is_fingerprinted_rather_than_refused() {
    let fixture = Fixture::new("empty");
    let fingerprint = fixture.fingerprint();
    assert_eq!(fingerprint.kind, FingerprintKind::Content);
    assert!(
        !fingerprint.digest.is_empty(),
        "an empty project produced an empty digest, which is what a failure to \
         compute one would also look like"
    );
}

#[test]
fn a_project_that_is_not_there_is_refused_rather_than_read_as_empty() {
    // The failure this prevents is the worst shape one can have: a fingerprint
    // over nothing looks exactly like a fingerprint over an empty project, so a
    // typo in a path would produce a value that matches every other typo.
    let fixture = Fixture::new("absent");
    let missing = fixture.path().join("no-such-directory");
    let error = content_fingerprint(&missing, &options())
        .expect_err("a directory that is not there has no contents to describe");
    assert!(
        matches!(error, FingerprintError::Unreadable { .. }),
        "expected Unreadable for a missing root, got {error}"
    );
}

#[test]
fn a_relative_root_is_refused() {
    let error = content_fingerprint(Path::new("some/relative/path"), &options())
        .expect_err("a relative root would make one stored value mean two things");
    assert!(
        matches!(error, FingerprintError::NotAbsolute { .. }),
        "expected NotAbsolute, got {error}"
    );
}

#[test]
fn the_two_kinds_cannot_produce_the_same_digest() {
    // Belt and braces over the domain tags: the same project, both ways. If
    // these could collide, a stored Git fingerprint would be reported as current
    // for a project that had been re-fingerprinted by content, or the reverse.
    let fixture = committed("kinds");
    let git = git_fingerprint(fixture.path(), &options()).unwrap_or_else(|error| panic!("{error}"));
    let content =
        content_fingerprint(fixture.path(), &options()).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(git.kind, FingerprintKind::Git);
    assert_eq!(content.kind, FingerprintKind::Content);
    assert_ne!(
        git.digest, content.digest,
        "the two kinds produced one digest, so neither identifies its own state"
    );
}

// ---------------------------------------------------------------------------
// What is out, and why the rule is the scan's rule
// ---------------------------------------------------------------------------

#[test]
fn churn_in_every_excluded_kind_of_directory_changes_nothing() {
    let fixture = small("excluded");
    // One directory per reason the scan has for leaving something out, so that
    // this is a test of the table rather than of one entry in it.
    let excluded = [
        ("target/debug/app.exe", "built\n"),
        ("node_modules/left-pad/index.js", "module.exports = 1\n"),
        ("vendor/tiny/lib.rs", "pub fn tiny() {}\n"),
        ("dist/bundle.js", "bundled\n"),
        ("build/out.o", "object\n"),
        ("__pycache__/mod.cpython-313.pyc", "bytecode\n"),
        (".pytest_cache/v/cache/lastfailed", "{}\n"),
        (".sure/evidence.json", "{\"results\": []}\n"),
        (".venv/lib/site.py", "installed\n"),
        // A harness's own runtime state inside a workspace root (measured on a
        // MiQi workspace, 2026-11-18): the bridge database is rewritten while
        // the harness runs, so covering it would make every check of a
        // workspace-as-project invalidate the one before it.
        (".forge-runtime/runtime.db", "{\"rows\": 1}\n"),
    ];
    for (path, contents) in excluded {
        fixture.write(path, contents);
    }
    let before = fixture.fingerprint();

    // Every one of them rewritten with different contents. Real churn: the bytes
    // on disk under these names all changed between the two fingerprints.
    for (path, _) in excluded {
        fixture.write(path, "different\n");
    }
    let after = fixture.fingerprint();
    assert!(
        same(&before, &after),
        "churn in excluded directories moved the fingerprint, so the second \
         acceptance criterion is not met: {} then {}",
        before.digest,
        after.digest
    );

    // The control, and it is the whole reason the assertion above means
    // anything: a fingerprint that never moved at all would pass it.
    fixture.write(
        "src/lib.rs",
        "pub fn add(a: u32, b: u32) -> u32 { a + b + 1 }\n",
    );
    let control = fixture.fingerprint();
    assert!(
        !same(&before, &control),
        "nothing moves this fingerprint, so its stillness says nothing about \
         what is excluded"
    );
}

#[test]
fn the_excluded_list_is_the_scans_and_not_a_second_copy_of_it() {
    // The claim being pinned is not "these names are excluded" — the test above
    // says that — but "the fingerprint files what a check could read, and it is
    // the scan that decides that". A path the scan reports as a file is in the
    // manifest; a path it reports as by-design-skipped is not. If the
    // fingerprint ever grew its own table, this is what would fail.
    let fixture = small("one-table");
    fixture.write("target/debug/app.exe", "built\n");
    fixture.write("node_modules/left-pad/index.js", "module.exports = 1\n");

    let walked = sure_core::scan::scan(fixture.path(), ScanOptions::default())
        .unwrap_or_else(|error| panic!("{error}"));
    let covered: Vec<String> = walked.files().map(|entry| entry.display_path()).collect();
    assert!(
        covered.contains(&"src/lib.rs".to_owned()),
        "the scan does not call a source file a file, so nothing below follows: {covered:?}"
    );
    for path in ["target/debug/app.exe", "node_modules/left-pad/index.js"] {
        assert!(
            !covered.contains(&path.to_owned()),
            "the scan covers {path}, so the fingerprint leaving it out would be a \
             second rule disagreeing with the first"
        );
    }

    // And the agreement itself: everything the scan covers is in the digest, so
    // changing any one of them is a change.
    let before = fixture.fingerprint();
    for path in ["src/main.rs", "src/lib.rs", "README.md"] {
        let original = fixture.read(path);
        fixture.write(path, &format!("{original}// touched\n"));
        let after = fixture.fingerprint();
        assert!(
            !same(&before, &after),
            "the scan reports {path} as covered and the fingerprint did not move \
             when it changed"
        );
        fixture.write(path, &original);
    }
}

#[test]
fn a_repositorys_own_storage_is_out_so_a_commit_does_not_move_the_manifest() {
    // The clearest case of the second acceptance criterion, because `.git` is
    // churn that happens *because of* the project rather than in it: a commit
    // rewrites the index, adds objects and moves a ref, and changes no file a
    // check would read. A manifest that covered it would move on every commit,
    // and every stored result for a busy repository would read as stale.
    let fixture = committed("git-churn");
    let before = fixture.fingerprint();

    let ref_before = fixture.read(".git/refs/heads/main");
    fixture.git(&["commit", "--allow-empty", "-m", "nothing changed"]);
    let ref_after = fixture.read(".git/refs/heads/main");
    assert_ne!(
        ref_before, ref_after,
        "the empty commit did not move the ref, so this fixture cannot show that \
         `.git` churn is what the fingerprint ignores"
    );

    let after = fixture.fingerprint();
    assert!(
        same(&before, &after),
        "a commit moved the content manifest: {} then {}",
        before.digest,
        after.digest
    );
}

// ---------------------------------------------------------------------------
// Limits: a manifest over part of a project is not a manifest over the project
// ---------------------------------------------------------------------------

#[test]
fn a_level_the_depth_limit_stopped_is_refused() {
    let fixture = small("deep");
    fixture.write("sub/deep/file.txt", "deep\n");
    let narrow = FingerprintOptions::default().with_scan(ScanOptions::default().with_max_depth(1));
    let error = fixture
        .fingerprint_with(narrow)
        .expect_err("the walk stopped above a file a check can still read");
    assert!(
        matches!(error, FingerprintError::IncompleteTree { .. }),
        "expected IncompleteTree, got {error}"
    );
}

#[test]
fn a_walk_that_ran_out_of_budget_is_refused() {
    let fixture = small("budget");
    let narrow =
        FingerprintOptions::default().with_scan(ScanOptions::default().with_max_entries(1));
    let error = fixture
        .fingerprint_with(narrow)
        .expect_err("the walk stopped with files left unlisted");
    assert!(
        matches!(error, FingerprintError::IncompleteTree { .. }),
        "expected IncompleteTree, got {error}"
    );
}

#[test]
fn more_files_than_the_limit_is_refused_rather_than_truncated() {
    // Both sides of the boundary, because one side alone does not say where it
    // is: a fingerprint that allowed one file past the limit would refuse a
    // project of three under a limit of one and look exactly like this.
    let fixture = small("files");
    assert_eq!(
        fixture.count_files(),
        3,
        "this fixture is written to hold exactly three files, and the two \
         assertions below are about a limit of three"
    );
    let at_the_limit = fixture
        .fingerprint_with(options().with_max_files(3))
        .unwrap_or_else(|error| panic!("three files under a limit of three: {error}"));
    assert_eq!(at_the_limit.kind, FingerprintKind::Content);

    let error = fixture
        .fingerprint_with(options().with_max_files(2))
        .expect_err("three files under a limit of two should have stopped this");
    assert!(
        matches!(error, FingerprintError::TooManyFiles { .. }),
        "expected TooManyFiles, got {error}"
    );
}

#[test]
fn more_bytes_than_the_limit_is_refused_rather_than_truncated() {
    let fixture = Fixture::new("bytes");
    fixture.write("big.txt", &"x".repeat(1_000));
    let error = fixture
        .fingerprint_with(options().with_max_bytes(16))
        .expect_err("a file past the byte limit should have stopped this");
    assert!(
        matches!(error, FingerprintError::TooManyBytes { .. }),
        "expected TooManyBytes, got {error}"
    );
}

#[test]
fn the_byte_budget_is_spent_by_the_whole_manifest_and_not_by_each_file() {
    // The limit is on how much SURE reads in one fingerprint, not on how large
    // any one file may be. A budget that reset for every file would read a
    // project of a million small files while reporting that it had respected a
    // limit of a few megabytes — which is the shape of a limit that is not one.
    let fixture = Fixture::new("cumulative-bytes");
    fixture
        .write("a.txt", &"a".repeat(10))
        .write("b.txt", &"b".repeat(10));
    assert_eq!(fixture.count_files(), 2);

    // Each file is under the limit on its own; the two together are over it.
    let error = fixture
        .fingerprint_with(options().with_max_bytes(15))
        .expect_err("twenty bytes were read under a budget of fifteen");
    assert!(
        matches!(error, FingerprintError::TooManyBytes { .. }),
        "expected TooManyBytes, got {error}"
    );

    // And the control: the same project under a budget that covers both.
    let fits = fixture
        .fingerprint_with(options().with_max_bytes(20))
        .unwrap_or_else(|error| panic!("twenty bytes under a budget of twenty: {error}"));
    assert_eq!(fits.kind, FingerprintKind::Content);
}

#[test]
fn a_directory_the_walk_did_not_descend_into_is_still_covered_by_what_it_holds() {
    // The counter-case to the depth test above: a directory the walk *does*
    // enter contributes its files, so changing one of them is a change. Without
    // this, a fingerprint that silently treated every directory as a single
    // opaque entry would pass most of this file.
    let fixture = Fixture::new("nested");
    fixture
        .write("a/b/c/one.txt", "one\n")
        .write("a/b/two.txt", "two\n");
    let before = fixture.fingerprint();
    fixture.write("a/b/c/one.txt", "one, changed\n");
    let after = fixture.fingerprint();
    assert!(
        !same(&before, &after),
        "a file three levels down was not in the manifest"
    );
}

// ---------------------------------------------------------------------------
// Links and pipes, where the platform allows the fixture to exist
// ---------------------------------------------------------------------------

/// Unix only, and this is what that means: it covers macOS and Linux CI and not
/// this development machine. Creating a symbolic link on Windows needs Developer
/// Mode or administrator rights, and a test that needs either is a test that is
/// skipped on the machine it was written on. The gap is recorded in
/// `docs/architecture/FINGERPRINTING.md` beside the Git kind's, which has the
/// same cause and the same platform.
#[cfg(unix)]
#[test]
fn a_link_is_recorded_by_where_it_points_and_never_read_through() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new("link");
    fixture.write(
        "src/lib.rs",
        "pub fn add(a: u32, b: u32) -> u32 { a + b }\n",
    );
    // The targets are outside the project on purpose. Inside it, the file the
    // link points at would be in the manifest in its own right, and neither of
    // the two assertions below could tell "the link was followed" from "the file
    // behind it was covered anyway".
    fixture.write_outside("outside/one.txt", "ONE\n");
    fixture.write_outside("outside/two.txt", "TWO\n");
    symlink("../outside/one.txt", fixture.path().join("link")).unwrap();

    let linked_to_one = fixture.fingerprint();

    // Reading through it would make this a change. It is not one: nothing SURE
    // reads has changed, and every other part of the product refuses to follow a
    // link for the same reason — what it names may be anywhere.
    fixture.write_outside("outside/one.txt", "ONE, CHANGED\n");
    let same_link_same_target = fixture.fingerprint();
    assert!(
        same(&linked_to_one, &same_link_same_target),
        "changing the file behind a link moved the fingerprint, so the link was \
         read through"
    );

    // Retargeting it is a change, and this is the dangerous direction the other
    // way: a manifest that ignored links would keep the same digest here, and
    // evidence about the old target would be reported as current for the new one.
    std::fs::remove_file(fixture.path().join("link")).unwrap();
    symlink("../outside/two.txt", fixture.path().join("link")).unwrap();
    let retargeted = fixture.fingerprint();
    assert!(
        !same(&linked_to_one, &retargeted),
        "a link pointing somewhere else left the fingerprint where it was"
    );
}

/// Unix only, for the same reason as above: a pipe is not a filesystem entry on
/// Windows, so there is nothing there for the walk to meet.
#[cfg(unix)]
#[test]
fn a_pipe_in_the_project_is_refused_rather_than_opened() {
    // This is the anti-hang property, and it is why the walk reports a pipe as a
    // loss rather than noting it. `File::open` on a FIFO with no writer blocks
    // until a writer appears, so a project holding one could stop a check with no
    // output — and a check that never returns cannot be told apart from one that
    // is still working. The Git kind describes a pipe rather than refusing,
    // because Git has named exactly one path and its kind is knowable without
    // opening it; a walk cannot know what else is in a directory it could not
    // fully read, so it refuses.
    let fixture = Fixture::new("pipe");
    fixture.write(
        "src/lib.rs",
        "pub fn add(a: u32, b: u32) -> u32 { a + b }\n",
    );
    let pipe = fixture.path().join("src/pipe");
    let output = Command::new("mkfifo")
        .arg(&pipe)
        .output()
        .unwrap_or_else(|error| panic!("cannot run mkfifo: {error}"));
    assert!(
        output.status.success(),
        "mkfifo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let error = fixture
        .fingerprint_with(options())
        .expect_err("a pipe is a thing the walk could not read, and this is a refusal");
    match error {
        FingerprintError::IncompleteTree { ref path, .. } => {
            assert_eq!(sure_core::scan::display_path(path), "src/pipe");
        }
        other => panic!("expected IncompleteTree for the pipe, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// Choosing between the two kinds
// ---------------------------------------------------------------------------

#[test]
fn a_project_at_the_root_of_its_own_repository_is_fingerprinted_by_git() {
    let fixture = committed("at-root");
    let chosen = project_fingerprint(fixture.path(), &options()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(chosen.kind, FingerprintKind::Git);
    let direct = git_fingerprint(fixture.path(), &options()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        same(&chosen, &direct),
        "the chooser and the Git kind disagree about the same project"
    );
}

#[test]
fn a_project_in_no_repository_at_all_is_fingerprinted_by_content() {
    let fixture = Fixture::outside_any_repository("no-repo");
    fixture.write("src/lib.rs", "pub fn add() {}\n");

    // The premise, asserted rather than assumed. This test is named for a case
    // that a fixture under `target/` cannot reach — see
    // [`Fixture::outside_any_repository`] — and a test that cannot reach its own
    // case passes for whatever reason it does reach.
    assert_eq!(
        git_prefix(fixture.path()),
        None,
        "this fixture is inside a repository after all, so it cannot show what \
         happens outside one: {}",
        fixture.path().display()
    );

    let chosen = project_fingerprint(fixture.path(), &options()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(chosen.kind, FingerprintKind::Content);
}

#[test]
fn a_project_inside_somebody_elses_repository_is_fingerprinted_by_content() {
    let fixture = committed("inside");
    let inner = fixture.path().join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    fixture.write("inner/thing.txt", "inner\n");
    fixture.write("elsewhere.txt", "not the inner project\n");
    fixture.git(&["add", "-A"]);
    fixture.git(&["commit", "-m", "both"]);

    // The premise. The chooser's whole decision is "is the prefix empty", so a
    // fixture where it came back empty would make this test the same as the one
    // above it, with a name that claims otherwise.
    assert_eq!(
        git_prefix(&inner).as_deref().map(str::trim_end),
        Some("inner/"),
        "Git does not place this directory inside the fixture's repository, so \
         nothing here is about being inside somebody else's"
    );

    let chosen = project_fingerprint(&inner, &options()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        chosen.kind,
        FingerprintKind::Content,
        "a directory one level inside somebody else's checkout was fingerprinted \
         by that repository"
    );
}

#[test]
fn the_git_kind_moves_for_a_commit_the_project_is_not_part_of_and_the_content_kind_does_not() {
    // This is not a test of desired behaviour; it is the measurement the chooser
    // exists because of, kept where the next person to consider simplifying the
    // chooser will find it. Both halves are asserted, so neither can quietly
    // stop being true and leave the reason looking like folklore.
    let fixture = committed("contrast");
    let inner = fixture.path().join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    fixture.write("inner/thing.txt", "inner\n");
    fixture.write("elsewhere.txt", "first\n");
    fixture.git(&["add", "-A"]);
    fixture.git(&["commit", "-m", "both"]);

    let content_before =
        project_fingerprint(&inner, &options()).unwrap_or_else(|error| panic!("{error}"));
    let git_before = git_fingerprint(&inner, &options()).unwrap_or_else(|error| panic!("{error}"));

    // A commit that touches a file nowhere near the inner directory, and nothing
    // inside it.
    fixture.write("elsewhere.txt", "second\n");
    fixture.git(&["add", "-A"]);
    fixture.git(&["commit", "-m", "elsewhere only"]);

    let content_after =
        project_fingerprint(&inner, &options()).unwrap_or_else(|error| panic!("{error}"));
    let git_after = git_fingerprint(&inner, &options()).unwrap_or_else(|error| panic!("{error}"));

    assert!(
        !same(&git_before, &git_after),
        "the Git kind no longer moves for a commit outside the project, so the \
         reason the chooser prefers the content kind here has changed"
    );
    assert!(
        same(&content_before, &content_after),
        "the content kind moved for a commit that touched nothing inside the \
         project: {} then {}",
        content_before.digest,
        content_after.digest
    );
}

#[test]
fn a_nested_checkout_within_a_project_is_covered_by_the_outer_manifest() {
    // A checkout cloned into the project without being added. Git reports it as
    // one untracked directory and does not descend, so the Git kind hashes a
    // tree digest for it; the content kind walks it, because its files are files
    // a check can read.
    let fixture = small("nested-checkout");
    let inner = fixture.path().join("cloned");
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::write(inner.join("dep.txt"), "dependency\n").unwrap();

    let before = fixture.fingerprint();
    std::fs::write(inner.join("dep.txt"), "dependency, edited\n").unwrap();
    let after = fixture.fingerprint();
    assert!(
        !same(&before, &after),
        "editing a file in a nested checkout left the manifest where it was, so \
         an old result would be reported as current for a changed project"
    );
}
