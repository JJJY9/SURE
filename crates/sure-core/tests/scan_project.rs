//! Looking at a real project on a real filesystem.
//!
//! P2-T001 acceptance:
//!
//! > Ignores VCS/vendor/build/cache appropriately.
//! > Handles spaces/Unicode/case-insensitive Windows semantics and long-path
//! > pressure.
//!
//! Both are about what happens on a filesystem, so every case here builds one.
//! The fixture directory's *name* contains a space and a non-ASCII character,
//! which is the cheapest way to make every path in every test a path Windows
//! and Unix disagree about.
//!
//! # What this file cannot test, and says so
//!
//! There is no test here for a directory the operating system refuses to list,
//! and none for a single directory entry the operating system fails to describe.
//! The first needs either a privileged user or an ACL change — `chmod 000` does
//! nothing when the tests run as root, and a test that passes because its premise
//! did not hold is worse than no test. The second needs an entry that cannot be
//! built at all. Both are covered as far as they can be inside
//! `src/scan/mod.rs`, and the gaps — with the mutation that corresponds to the
//! second — are recorded in `docs/architecture/PROJECT_DISCOVERY.md`.
//!
//! A file name that is not valid Unicode *is* tested, on Windows and on Unix
//! alike, by [`a_name_that_is_not_valid_unicode_is_ordered_by_the_name_and_not_by_its_text`].
//! macOS is left out of it, and the reason for that is a belief about APFS
//! recorded in the same document.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// Gated to exactly the platforms whose test uses it. The only caller is
// [`a_name_that_is_not_valid_unicode_is_ordered_by_the_name_and_not_by_its_text`],
// which excludes macOS; a bare `use` here is dead code on macOS and
// `cargo clippy --all-targets -D warnings` in CI says so.
#[cfg(not(target_os = "macos"))]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sure_core::paths::CaseSensitivity;
use sure_core::scan::{EntryKind, Scan, ScanError, ScanOptions, SkipReason, scan};

/// How many entries a fixture is allowed to have before a test is wrong.
///
/// The default is a fifth of a million, which is right for a real project and
/// useless for a test: a fixture that accidentally escaped its root would take
/// a while to fail. Every scan in this file goes through this.
const FIXTURE_LIMIT: usize = 5_000;

/// A scratch project directory that removes itself.
///
/// Under the workspace's own `target/` rather than the system temp directory,
/// so it is on the same volume as the checkout — which is where a path-handling
/// bug actually appears — and so that `target/` being in the ignore table is
/// exercised by the repository's own scan test.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "{test}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        // The space and the non-ASCII characters are the point of the fixture,
        // not decoration.
        let path = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("sure 扫描 scan")
            .join(unique);
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Create every path in the list, as a directory when it ends in `/`.
    fn build(&self, paths: &[&str]) -> &Self {
        for path in paths {
            let (text, directory) = match path.strip_suffix('/') {
                Some(text) => (text, true),
                None => (*path, false),
            };
            let full = self.path.join(text);
            if directory {
                std::fs::create_dir_all(&full)
                    .unwrap_or_else(|error| panic!("cannot create {}: {error}", full.display()));
            } else {
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent).unwrap_or_else(|error| {
                        panic!("cannot create {}: {error}", parent.display())
                    });
                }
                std::fs::write(&full, b"fixture")
                    .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
            }
        }
        self
    }

    /// Scan this fixture with the given options.
    fn scan_with(&self, options: ScanOptions) -> Scan {
        scan(self.path(), options).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Scan this fixture with a small entry budget.
    fn scan(&self) -> Scan {
        self.scan_with(ScanOptions::default().with_max_entries(FIXTURE_LIMIT))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Failing to clean up must not turn a passing test into a failing one.
        // Windows keeps directory handles open longer than Unix does, so a
        // reader may still hold one.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Every entry's path, as text, in the order the scan produced them.
fn paths(scan: &Scan) -> Vec<String> {
    scan.entries().iter().map(|e| e.display_path()).collect()
}

/// Every skip's path and reason, in the order the scan produced them.
fn skips(scan: &Scan) -> Vec<(String, SkipReason)> {
    scan.skipped()
        .iter()
        .map(|s| (s.display_path(), s.reason))
        .collect()
}

/// The reason recorded for one path, if the scan skipped it.
fn reason_at(scan: &Scan, path: &str) -> Option<SkipReason> {
    scan.skipped()
        .iter()
        .find(|s| s.display_path() == path)
        .map(|s| s.reason)
}

// ---------------------------------------------------------------------------
// The shape of a scan
// ---------------------------------------------------------------------------

#[test]
fn a_small_project_comes_back_as_files_and_directories_in_a_fixed_order() {
    let fixture = Scratch::new("shape");
    fixture.build(&[
        "README.md",
        "Cargo.toml",
        "src/",
        "src/main.rs",
        "src/lib.rs",
        "src/nested/",
        "src/nested/deep.rs",
        "tests/",
        "tests/it.rs",
    ]);

    let scan = fixture.scan();

    // Directories in name order, each descended into as it is reached. The
    // order is part of the contract: a fingerprint over a list whose order
    // moves is a fingerprint that changes when nothing did.
    assert_eq!(
        paths(&scan),
        [
            "Cargo.toml",
            "README.md",
            "src",
            "src/lib.rs",
            "src/main.rs",
            "src/nested",
            "src/nested/deep.rs",
            "tests",
            "tests/it.rs",
        ]
    );
    assert!(scan.is_complete(), "{:?}", skips(&scan));
    assert!(scan.skipped().is_empty(), "{:?}", skips(&scan));
    assert_eq!(scan.files().count(), 6);
    assert_eq!(scan.directories().count(), 3);
    assert_eq!(
        scan.entries()[0].kind,
        EntryKind::File,
        "a file and a directory with the same name must still be told apart"
    );
}

#[test]
fn the_order_does_not_depend_on_the_order_the_filesystem_returns() {
    // Created in a scrambled order on purpose. If the walk relied on what
    // `read_dir` gave it, this would differ from the sorted list — and the
    // difference would be invisible until a fingerprint disagreed with itself.
    let fixture = Scratch::new("order");
    for name in [
        "zebra.txt",
        "alpha.txt",
        "Middle.txt",
        "Beta.txt",
        "_under.txt",
    ] {
        fixture.build(&[name]);
    }

    let once = paths(&fixture.scan());
    let twice = paths(&fixture.scan());

    assert_eq!(once, twice);
    let mut sorted = once.clone();
    sorted.sort();
    assert_eq!(once, sorted, "the scan is not in name order");
}

#[test]
#[cfg(not(target_os = "macos"))]
fn a_name_that_is_not_valid_unicode_is_ordered_by_the_name_and_not_by_its_text() {
    // The one case where sorting by the operating system's name and sorting by
    // the rendered text give **different** orders, which is why the sort is on
    // `OsString` and not on `to_string_lossy`.
    //
    // The pair is a name that cannot be rendered — an unpaired surrogate on
    // Windows, an invalid byte sequence on Unix — and a valid name whose only
    // code point is above U+FFFD. The first renders as U+FFFD, so as text it
    // sorts *after* the second; as the operating system gives it, its bytes
    // come first. Nothing else distinguishes the two sorts: for two names that
    // both render faithfully, text order and name order are the same order.
    //
    // macOS is excluded because APFS validates a file name as UTF-8, so the
    // fixture may simply not be constructible there. That is recorded as an
    // open question in `docs/architecture/PROJECT_DISCOVERY.md` rather than
    // answered here, because answering it needs a Mac.
    let fixture = Scratch::new("invalid-name");
    let invalid = name_that_is_not_valid_unicode();
    let above = OsString::from("\u{e000}");

    std::fs::write(fixture.path().join(&invalid), b"fixture")
        .unwrap_or_else(|error| panic!("cannot write the invalid name: {error}"));
    std::fs::write(fixture.path().join(&above), b"fixture")
        .unwrap_or_else(|error| panic!("cannot write {above:?}: {error}"));

    let scan = fixture.scan();

    // Both are in the scan — this is about their order, not about either being
    // dropped. A name SURE cannot render is still a file the project has.
    assert_eq!(scan.entries().len(), 2, "{:?}", paths(&scan));
    assert_eq!(
        scan.entries()[0].path.as_os_str(),
        invalid.as_os_str(),
        "the unrenderable name sorted by its text, not by its name: {:?}",
        paths(&scan)
    );
    assert_eq!(
        scan.entries()[1].path.as_os_str(),
        above.as_os_str(),
        "{:?}",
        paths(&scan)
    );
    // And the rendered form is a loss, which is why the comparison above is not
    // made on it.
    //
    // How much of a loss is the platform's, and that is what this assertion used
    // not to allow for. Windows holds a name as WTF-8 and renders the single
    // unpaired surrogate as one U+FFFD; a Unix name is a byte string, the three
    // bytes of the same sequence are three maximal subparts of an invalid
    // sequence, and it renders as three. Pinning the count asserted one
    // platform's rendering onto the other and failed on Linux.
    //
    // The count is not the claim — `to_string_lossy` not being the identity here
    // is the claim — so what is asserted is that a replacement character
    // appeared, followed by the consequence the test exists for: sorting the
    // *rendered* names puts them in the opposite order to the names the
    // operating system gave. That is true of either rendering.
    let rendered = paths(&scan);
    assert!(
        rendered[0].contains('\u{fffd}'),
        "the unrenderable name rendered faithfully: {rendered:?}"
    );
    let mut by_text = rendered.clone();
    by_text.sort();
    assert_ne!(
        by_text, rendered,
        "the text order and the name order agree, so this fixture does not \
         demonstrate the difference it exists for"
    );
}

/// A file name the platform will accept and that is not valid Unicode.
#[cfg(windows)]
fn name_that_is_not_valid_unicode() -> std::ffi::OsString {
    // An unpaired high surrogate. Rust's `OsString` on Windows is WTF-8, so it
    // holds one; NTFS does not forbid one; `to_string_lossy` renders it U+FFFD.
    use std::os::windows::ffi::OsStringExt;
    std::ffi::OsString::from_wide(&[0xD800])
}

/// A file name the platform will accept and that is not valid Unicode.
///
/// `all(unix, not(target_os = "macos"))` and not a bare `unix`, because the
/// caller excludes macOS (APFS validates a name as UTF-8, so the fixture may not
/// be constructible there) while `unix` includes it. A helper gated *more
/// widely* than its only caller is dead code on the platforms in the gap, and
/// the Windows job cannot see it: the gap is macOS, and that is one of the two
/// jobs that were red.
#[cfg(all(unix, not(target_os = "macos")))]
fn name_that_is_not_valid_unicode() -> std::ffi::OsString {
    // The UTF-8 encoding of the same unpaired surrogate. A Unix file name is a
    // byte string, so this is a name the filesystem takes and UTF-8 rejects.
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(vec![0xED, 0xA0, 0x80])
}

#[test]
fn a_name_that_differs_only_in_case_is_a_different_name() {
    // Pinned on a case-sensitive platform by asking for the sensitive rule,
    // because on Windows the two files cannot both exist and the fixture would
    // fail to build. This also documents that the *listing* never folds case —
    // only the ignore table has a case rule at all.
    let fixture = Scratch::new("case-names");
    fixture.build(&["Notes.txt"]);

    let scan = fixture.scan_with(
        ScanOptions::default()
            .with_max_entries(FIXTURE_LIMIT)
            .with_case(CaseSensitivity::Sensitive),
    );
    assert_eq!(paths(&scan), ["Notes.txt"]);
}

// ---------------------------------------------------------------------------
// What is left out, and the report of it
// ---------------------------------------------------------------------------

#[test]
fn the_four_categories_the_task_names_are_left_out_and_each_one_is_reported() {
    let fixture = Scratch::new("categories");
    fixture.build(&[
        // Real project content, which must survive.
        "src/",
        "src/main.rs",
        "docs/",
        "docs/guide.md",
        // Version control.
        ".git/",
        ".git/objects/",
        ".git/objects/pack.idx",
        // Vendored.
        "node_modules/",
        "node_modules/left-pad/",
        "node_modules/left-pad/index.js",
        // Build output.
        "target/",
        "target/debug/",
        "target/debug/app.exe",
        "dist/",
        "dist/bundle.js",
        // Caches.
        "__pycache__/",
        "__pycache__/main.cpython-312.pyc",
        ".DS_Store",
    ]);

    let scan = fixture.scan();

    assert_eq!(
        paths(&scan),
        ["docs", "docs/guide.md", "src", "src/main.rs"]
    );

    assert_eq!(
        reason_at(&scan, ".git"),
        Some(SkipReason::VersionControl),
        "{:?}",
        skips(&scan)
    );
    assert_eq!(reason_at(&scan, "node_modules"), Some(SkipReason::Vendored));
    assert_eq!(reason_at(&scan, "target"), Some(SkipReason::BuildOutput));
    assert_eq!(reason_at(&scan, "dist"), Some(SkipReason::BuildOutput));
    assert_eq!(reason_at(&scan, "__pycache__"), Some(SkipReason::Cache));
    assert_eq!(reason_at(&scan, ".DS_Store"), Some(SkipReason::Cache));

    // Every one of these is a declared part of the scan, so none of them makes
    // the scan incomplete. That distinction is the whole point: a project with
    // a `.git` directory has not lost anything.
    assert!(scan.is_complete(), "{:?}", skips(&scan));
    assert_eq!(scan.losses().count(), 0);
    assert_eq!(scan.scope().count(), 6);
}

#[test]
fn a_left_out_directory_is_left_out_at_any_depth() {
    // Not only at the root. A repository inside a repository, a package with
    // its own `node_modules`, a workspace member with its own `target` — all
    // ordinary layouts, and all of them place the same names below the top
    // level.
    //
    // The rule is a statement about a *name*, and this is the test that makes
    // it a statement about every name the walk meets rather than about the
    // root's children. A version that compared the relative path against the
    // table would pass every test with a fixture that only had these names at
    // the top, and would then read a vendored tree in a real project.
    let fixture = Scratch::new("nested-ignored");
    fixture.build(&[
        "src/",
        "src/main.rs",
        // A package manager's own tree, below the top level.
        "packages/app/",
        "packages/app/package.json",
        "packages/app/node_modules/",
        "packages/app/node_modules/left-pad/index.js",
        // A nested checkout.
        "vendor/legacy/.git/",
        "vendor/legacy/.git/config",
        // A nested build directory.
        "packages/app/target/",
        "packages/app/target/debug/app.exe",
        // A nested cache.
        "packages/app/__pycache__/",
        "packages/app/__pycache__/mod.pyc",
    ]);

    let scan = fixture.scan();

    // `vendor` is itself a name the table leaves out, so the `.git` inside it
    // is never reached and never appears as a skip at all: the walk never
    // enters the directory, so nothing in it is met. That is worth having in
    // the fixture — it is what a real tree looks like — and it is why the
    // nested version-control case needs a fixture of its own below.
    assert_eq!(
        paths(&scan),
        [
            "packages",
            "packages/app",
            "packages/app/package.json",
            "src",
            "src/main.rs",
        ]
    );

    assert_eq!(
        reason_at(&scan, "packages/app/node_modules"),
        Some(SkipReason::Vendored),
        "{:?}",
        skips(&scan)
    );
    assert_eq!(
        reason_at(&scan, "packages/app/target"),
        Some(SkipReason::BuildOutput)
    );
    assert_eq!(
        reason_at(&scan, "packages/app/__pycache__"),
        Some(SkipReason::Cache)
    );
    assert!(scan.is_complete(), "{:?}", skips(&scan));
    assert_eq!(scan.losses().count(), 0);
}

#[test]
fn a_nested_checkout_is_left_out_whole() {
    // The same rule for the one category the fixture above cannot reach: a
    // checkout kept inside a directory that is itself read. A directory that
    // carries a `.git` entry is a checkout of its own, not this project's
    // content, so the walk does not enter it at all — the skip is the
    // directory, and everything below it is absent rather than filtered later.
    let fixture = Scratch::new("nested-git");
    fixture.build(&[
        "tools/",
        "tools/build.rs",
        "tools/third_party/.git/",
        "tools/third_party/.git/config",
        "tools/third_party/lib.rs",
    ]);

    let scan = fixture.scan();

    assert_eq!(paths(&scan), ["tools", "tools/build.rs"]);
    assert_eq!(
        reason_at(&scan, "tools/third_party"),
        Some(SkipReason::VersionControl),
        "{:?}",
        skips(&scan)
    );
    let skipped = scan
        .skipped()
        .iter()
        .find(|skipped| skipped.path == std::path::Path::new("tools/third_party"))
        .expect("the nested checkout is recorded as skipped");
    assert!(
        skipped
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("nested repository")),
        "{skipped:?}"
    );
    assert!(
        !scan
            .entries()
            .iter()
            .any(|entry| entry.path.starts_with("tools/third_party")),
        "nothing below a nested checkout is in the scan"
    );
}

#[test]
fn what_is_inside_a_left_out_directory_is_not_in_the_scan_at_all() {
    // Not merely filtered at the end. A file called `main.rs` inside
    // `node_modules/` is somebody else's `main.rs`, and a later stage that
    // matched on file name would find it and mean the wrong file.
    let fixture = Scratch::new("inside");
    fixture.build(&[
        "src/",
        "src/main.rs",
        "node_modules/",
        "node_modules/pkg/",
        "node_modules/pkg/Cargo.toml",
        "node_modules/pkg/src/",
        "node_modules/pkg/src/main.rs",
    ]);

    let scan = fixture.scan();

    assert_eq!(paths(&scan), ["src", "src/main.rs"]);
    assert!(
        !scan
            .entries()
            .iter()
            .any(|e| e.display_path().contains("node_modules")),
        "something under node_modules is in the scan"
    );
    assert_eq!(
        scan.entries()
            .iter()
            .filter(|e| e.path.file_name().is_some_and(|n| n == "Cargo.toml"))
            .count(),
        0,
        "the vendored manifest was found"
    );
}

#[test]
fn a_name_that_is_a_build_script_and_a_tool_output_is_only_left_out_as_a_directory() {
    // `build` at the root of a project is a directory of compiled output and
    // also a script somebody wrote. Leaving the script out would lose a file
    // that is part of the project, and nothing later in the pipeline could tell
    // that it had been there.
    //
    // Two fixtures rather than one, because a file and a directory cannot share
    // a name on Windows — or on any filesystem that folds case. The pair of
    // claims being tested is about the table, not about one directory holding
    // both.
    let as_a_script = Scratch::new("build-file");
    as_a_script.build(&["build", "target"]);
    let scan = as_a_script.scan();
    assert_eq!(
        paths(&scan),
        ["build", "target"],
        "a file a person named `build` was left out"
    );
    assert_eq!(scan.entries()[0].kind, EntryKind::File);
    assert!(scan.skipped().is_empty(), "{:?}", skips(&scan));

    let as_output = Scratch::new("build-directory");
    as_output.build(&["build/", "build/out.o"]);
    let scan = as_output.scan();
    assert!(paths(&scan).is_empty(), "{:?}", paths(&scan));
    assert_eq!(reason_at(&scan, "build"), Some(SkipReason::BuildOutput));
}

#[test]
fn sure_own_cache_inside_the_project_is_left_out() {
    // A fingerprint taken over a tree that contains SURE's own output changes
    // when SURE runs, so the second check would be of a different project state
    // than the first. The directory name comes from the constant that decides
    // where SURE writes, so the two cannot drift apart.
    let fixture = Scratch::new("own-cache");
    fixture.build(&[
        "src/",
        "src/main.rs",
        ".sure/",
        ".sure/last-run.json",
        ".sure/scratch.tmp",
    ]);

    let scan = fixture.scan();

    assert_eq!(paths(&scan), ["src", "src/main.rs"]);
    assert_eq!(
        reason_at(&scan, sure_core::paths::PROJECT_CACHE_DIR),
        Some(SkipReason::SureCache)
    );
    assert!(scan.is_complete());
}

#[test]
fn the_skip_counts_name_every_reason_including_the_ones_that_did_not_happen() {
    // A caller building a table should not have to invent the missing rows, and
    // a reason that silently vanished from the table would make one of them
    // disappear from the report.
    let fixture = Scratch::new("counts");
    fixture.build(&[".git/", "node_modules/", "src/", "src/main.rs"]);

    let scan = fixture.scan();
    let counts: Vec<(SkipReason, usize)> = scan.skip_counts();

    assert_eq!(counts.len(), SkipReason::ALL.len());
    for &reason in SkipReason::ALL {
        assert!(
            counts.iter().any(|(r, _)| *r == reason),
            "{reason:?} is missing from the table"
        );
    }
    let of = |reason: SkipReason| {
        counts
            .iter()
            .find(|(r, _)| *r == reason)
            .map(|(_, n)| *n)
            .unwrap()
    };
    assert_eq!(of(SkipReason::VersionControl), 1);
    assert_eq!(of(SkipReason::Vendored), 1);
    assert_eq!(of(SkipReason::Unreadable), 0);
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[test]
fn a_link_is_recorded_and_never_followed() {
    let fixture = Scratch::new("link-out");
    fixture.build(&["src/", "src/main.rs"]);
    // Somewhere else entirely, with a file that must not appear in the scan.
    let outside = Scratch::new("link-out-target");
    outside.build(&["secret.rs", "deep/", "deep/deeper.rs"]);

    link_to_directory(outside.path(), &fixture.path().join("shortcut"));

    let scan = fixture.scan();

    assert_eq!(
        reason_at(&scan, "shortcut"),
        Some(SkipReason::NotFollowed),
        "{:?}",
        skips(&scan)
    );
    assert!(
        !scan
            .entries()
            .iter()
            .any(|e| e.display_path().contains("secret") || e.display_path().contains("deep")),
        "the scan followed a link out of the project: {:?}",
        paths(&scan)
    );
    // And it is a loss, not a declared scope: what the link pointed at is not
    // in the scan, whatever it was.
    assert!(!scan.is_complete());
    assert_eq!(scan.losses().count(), 1);
}

#[test]
fn a_link_that_points_inside_the_project_is_still_not_followed() {
    // The rule is "no links", not "no links out of the project". Deciding
    // whether a link is safe means resolving it, and resolving it is the thing
    // being avoided: a link can be changed between the decision and the read.
    let fixture = Scratch::new("link-in");
    fixture.build(&["src/", "src/main.rs", "other/", "other/thing.rs"]);

    link_to_directory(&fixture.path().join("other"), &fixture.path().join("alias"));

    let scan = fixture.scan();

    assert_eq!(reason_at(&scan, "alias"), Some(SkipReason::NotFollowed));
    assert_eq!(
        paths(&scan),
        ["other", "other/thing.rs", "src", "src/main.rs"]
    );
}

#[test]
fn a_link_is_a_loss_whatever_it_is_called() {
    // The link arm is answered *before* the ignore tables are consulted, and
    // this is the test that makes the order matter. `node_modules` is a name
    // SURE leaves out on purpose; a *link* called `node_modules` — which is a
    // real setup, and the usual trick for sharing one installed tree between
    // checkouts — is something completely different: what it points at is not
    // in the scan.
    //
    // Switch the two and the skip comes back as `Vendored`, which
    // `is_by_design()` says is fine, `is_complete()` says is not a loss, and
    // the scan reports itself as having looked at the whole project while one
    // whole tree went unread. Reporting the wrong reason is enough on its own
    // to turn a loss into a green.
    let fixture = Scratch::new("link-ignored-name");
    fixture.build(&["src/", "src/main.rs"]);
    let outside = Scratch::new("link-ignored-name-target");
    outside.build(&["installed.js"]);

    link_to_directory(outside.path(), &fixture.path().join("node_modules"));

    let scan = fixture.scan();

    assert_eq!(
        reason_at(&scan, "node_modules"),
        Some(SkipReason::NotFollowed),
        "{:?}",
        skips(&scan)
    );
    assert!(!scan.is_complete(), "{:?}", skips(&scan));
    assert_eq!(scan.losses().count(), 1);
    assert_eq!(scan.scope().count(), 0);
}

#[test]
fn the_root_may_itself_be_reached_through_a_link() {
    // The caller named it. A project reached through a junction or a symlinked
    // path is an ordinary Windows and Unix setup, and refusing it would refuse
    // to check a project for no reason the user could act on.
    let real = Scratch::new("root-real");
    real.build(&["src/", "src/main.rs"]);

    let holder = Scratch::new("root-link");
    link_to_directory(real.path(), &holder.path().join("current"));

    let through = scan(
        &holder.path().join("current"),
        ScanOptions::default().with_max_entries(FIXTURE_LIMIT),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(paths(&through), ["src", "src/main.rs"]);
    assert!(through.is_complete());
}

#[test]
fn the_depth_limit_stops_the_walk_and_says_where() {
    let fixture = Scratch::new("depth");
    fixture.build(&[
        "level1/",
        "level1/at-one.rs",
        "level1/level2/",
        "level1/level2/at-two.rs",
        "level1/level2/level3/",
        "level1/level2/level3/at-three.rs",
    ]);

    let scan = fixture.scan_with(
        ScanOptions::default()
            .with_max_depth(2)
            .with_max_entries(FIXTURE_LIMIT),
    );

    // Level 2 is the deepest level listed: the directory at level 2 is in the
    // scan and its contents are not.
    assert_eq!(
        paths(&scan),
        ["level1", "level1/at-one.rs", "level1/level2"]
    );
    assert_eq!(reason_at(&scan, "level1/level2"), Some(SkipReason::TooDeep));
    assert!(!scan.is_complete());
    assert_eq!(scan.losses().count(), 1);
}

#[test]
fn a_depth_of_zero_lists_nothing_rather_than_everything() {
    // The boundary case of a limit. A depth limit that failed open would be the
    // worst possible version of it, and `0` is where a mistake in the
    // comparison shows up.
    let fixture = Scratch::new("depth-zero");
    fixture.build(&["src/", "src/main.rs"]);

    let scan = fixture.scan_with(
        ScanOptions::default()
            .with_max_depth(0)
            .with_max_entries(FIXTURE_LIMIT),
    );

    assert!(paths(&scan).is_empty());
    assert!(
        scan.is_complete(),
        "nothing was attempted, so nothing was lost"
    );
}

#[test]
fn the_entry_limit_stops_the_walk_and_is_recorded_once() {
    let fixture = Scratch::new("budget");
    let mut names = Vec::new();
    for index in 0..40 {
        names.push(format!("file{index:02}.txt"));
    }
    for name in &names {
        fixture.build(&[name]);
    }

    let scan = fixture.scan_with(ScanOptions::default().with_max_entries(10));

    assert_eq!(scan.entries().len(), 10, "{:?}", paths(&scan));
    let budget: Vec<&_> = scan
        .skipped()
        .iter()
        .filter(|s| s.reason == SkipReason::OutOfBudget)
        .collect();
    assert_eq!(budget.len(), 1, "the budget was reported more than once");
    assert_eq!(budget[0].path, Path::new(""));
    assert!(!scan.is_complete());
    assert_eq!(scan.losses().count(), 1);
    assert!(
        budget[0]
            .plain_description()
            .contains("as many files and folders"),
        "{}",
        budget[0].plain_description()
    );
}

#[test]
fn a_limit_that_is_never_reached_is_never_reported() {
    // The other half: a scan that stayed inside its bounds says nothing about
    // them. Otherwise every report would carry a warning about a limit that did
    // not bite, which is how a warning stops being read.
    let fixture = Scratch::new("no-budget");
    fixture.build(&["src/", "src/main.rs"]);

    let scan = fixture.scan_with(ScanOptions::default().with_max_entries(100));

    assert!(scan.is_complete());
    assert!(scan.skipped().is_empty());
}

// ---------------------------------------------------------------------------
// Paths: spaces, Unicode and long names
// ---------------------------------------------------------------------------

#[test]
fn spaces_and_non_ascii_names_survive_the_walk_unchanged() {
    // The fixture's own directory name already contains both, so this asserts
    // about names *below* the root as well — including a name that is only
    // non-ASCII, one with a space in the middle, and one with leading spaces.
    //
    // There is no name with a *trailing* space, and not because it was
    // overlooked: the Win32 layer strips one before the file is created, so a
    // fixture asking for `"padded "` on Windows produces `padded`.
    // `a_trailing_space_is_not_a_character_on_windows` is the test that pins
    // that, so the omission here is a fact with a test rather than a hole.
    let fixture = Scratch::new("names");
    fixture.build(&[
        "my project/",
        "my project/read me.txt",
        "配置/",
        "配置/説明.md",
        "  padded name",
        "emoji-🎯.txt",
    ]);

    let scan = fixture.scan();

    assert_eq!(
        paths(&scan),
        [
            "  padded name",
            "emoji-🎯.txt",
            "my project",
            "my project/read me.txt",
            "配置",
            "配置/説明.md",
        ]
    );
    assert!(scan.is_complete());
    // The text a report shows is spelled the same way on every platform, and it
    // names the same number of components as the real path. The second half is
    // the one that catches a display built by replacing separators in a string:
    // that version merges and splits names that contain the separator's
    // character, and the count is where it shows.
    for entry in scan.entries() {
        let shown = entry.display_path();
        assert!(!shown.contains('\\'), "{shown} is spelled for one platform");
        assert_eq!(
            Path::new(&shown).components().count(),
            entry.path.components().count(),
            "{shown} does not name the same shape of path as {}",
            entry.path.display()
        );
    }
}

#[test]
fn a_trailing_space_is_not_a_character_on_windows() {
    // Why the test above has no name with a trailing space, as a test rather
    // than as a comment. Win32 strips trailing spaces and dots from the last
    // component before the file is created, so asking Windows for `"padded "`
    // gets a file called `padded` and there is nothing else it could get. Unix
    // keeps the space, and there the name really is longer by one.
    //
    // The point either way is the same and it is the one a scanner has to get
    // right: SURE reports the name the filesystem holds, not the name the
    // caller asked for. A version that echoed the request back would disagree
    // with `read_dir` on Windows and be wrong about every file it reported.
    let fixture = Scratch::new("trailing-space");
    fixture.build(&["padded "]);

    let scan = fixture.scan();

    let expected: &[&str] = if cfg!(windows) {
        &["padded"]
    } else {
        &["padded "]
    };
    assert_eq!(paths(&scan), expected);
}

#[test]
fn a_path_longer_than_the_old_windows_limit_is_scanned() {
    // 260 characters was the Windows limit for a long time, and a scanner that
    // stopped there would report a project as smaller than it is. Three long
    // directory names give a path well past it without needing much depth, so
    // this is the length limit being tested and not the depth limit.
    let fixture = Scratch::new("long-path");
    let segment = "a".repeat(120);
    let deep = format!("{segment}/{segment}/{segment}/buried.rs");
    fixture.build(&[&deep]);

    let full = fixture
        .path()
        .join(segment.clone())
        .join(segment.clone())
        .join(segment.clone())
        .join("buried.rs");
    assert!(
        full.as_os_str().len() > 260,
        "the fixture is only {} characters long, so it tests nothing",
        full.as_os_str().len()
    );

    let scan = fixture.scan_with(ScanOptions::default().with_max_entries(FIXTURE_LIMIT));

    let found = paths(&scan);
    assert_eq!(found.len(), 4, "{found:?}");
    assert_eq!(
        found.last().map(String::as_str),
        Some(format!("{segment}/{segment}/{segment}/buried.rs").as_str())
    );
    assert!(scan.is_complete());
}

#[test]
fn the_root_is_not_itself_subject_to_the_ignore_table() {
    // A project directory called `build` is a project. The ignore tables are
    // about what is *inside* the project, and applying them to the root would
    // mean `sure check build` silently reported on nothing.
    let holder = Scratch::new("root-name");
    holder.build(&["build/", "build/src/", "build/src/main.rs"]);

    let scan = scan(
        &holder.path().join("build"),
        ScanOptions::default().with_max_entries(FIXTURE_LIMIT),
    )
    .expect("a directory named build is still a project");

    assert_eq!(paths(&scan), ["src", "src/main.rs"]);
    assert!(scan.is_complete());
}

// ---------------------------------------------------------------------------
// Roots that are not projects
// ---------------------------------------------------------------------------

#[test]
fn a_root_that_does_not_exist_is_a_refusal_and_not_an_empty_project() {
    // The shape of failure this whole module exists to prevent: an empty scan
    // and a project with nothing in it would be the same value, and every
    // later stage would read the first as the second.
    let fixture = Scratch::new("missing");
    let nowhere = fixture.path().join("there-is-no-such-directory");

    match scan(&nowhere, ScanOptions::default()) {
        Err(ScanError::Missing { root }) => assert_eq!(root, nowhere),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_file_given_as_the_root_is_refused() {
    let fixture = Scratch::new("file-root");
    fixture.build(&["Cargo.toml"]);

    match scan(&fixture.path().join("Cargo.toml"), ScanOptions::default()) {
        Err(ScanError::NotADirectory { .. }) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_relative_root_is_refused_rather_than_resolved_against_the_current_directory() {
    // Otherwise the same command reads a different project depending on where
    // it was run, and every path in the result is relative to a directory
    // nobody named.
    match scan(Path::new("target"), ScanOptions::default()) {
        Err(ScanError::NotAbsolute { root }) => assert_eq!(root, Path::new("target")),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_empty_root_is_refused_as_well_as_a_relative_one() {
    match scan(Path::new(""), ScanOptions::default()) {
        Err(ScanError::NotAbsolute { .. }) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn every_refusal_names_the_path_and_says_what_sure_did_instead() {
    let fixture = Scratch::new("messages");
    fixture.build(&["Cargo.toml"]);
    let cases = [
        fixture.path().join("nowhere"),
        fixture.path().join("Cargo.toml"),
    ];
    for root in cases {
        let error = scan(&root, ScanOptions::default()).unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains(&root.display().to_string()),
            "the message does not name the path: {text}"
        );
        assert!(
            text.contains("SURE stop"),
            "the message does not say what SURE did instead: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// The repository itself
// ---------------------------------------------------------------------------

#[test]
fn the_repository_scans_without_reading_its_own_build_directory() {
    // Dogfooding, and the one case where the fixture is large enough to be
    // real. `target/` is where this test suite's own scratch directories live,
    // and where every compiled artefact goes: if the ignore tables did not
    // work, this scan would meet the test fixtures of the tests running beside
    // it, and would be neither fast nor repeatable.
    let root = sure_testkit::repository_root();
    let scan = scan(&root, ScanOptions::default()).unwrap_or_else(|error| panic!("{error}"));

    let found = paths(&scan);
    let has = |text: &str| found.iter().any(|p| p == text);

    assert!(has("Cargo.toml"), "the workspace manifest is missing");
    assert!(has("crates"), "the crate directory is missing");
    assert!(
        has("crates/sure-core/src/scan/mod.rs"),
        "this module is not in the scan of its own repository"
    );

    // Compared by first path component, not by text prefix. `.gitattributes`
    // starts with the characters of `.git`, so the text version of this check
    // fails on a repository that is behaving perfectly — which is what it did
    // here before the component version replaced it. The same hazard is the
    // first entry in `paths::compare`'s list of reasons it exists.
    let under = |name: &str| {
        found.iter().any(|path| {
            Path::new(path)
                .components()
                .next()
                .is_some_and(|component| component.as_os_str() == name)
        })
    };
    assert!(!under("target"), "the build directory is in the scan");
    assert!(
        !under(".git"),
        "the repository's own version control storage is in the scan"
    );
    assert_eq!(
        reason_at(&scan, "target"),
        Some(SkipReason::BuildOutput),
        "{:?}",
        skips(&scan)
    );
    assert!(
        !scan.losses().any(|loss| loss.path == Path::new(".git")),
        "a link in the checkout is being reported as a loss: {:?}",
        skips(&scan)
    );
}

#[test]
fn scanning_the_repository_does_not_open_any_file() {
    // The scanner's second guarantee is that it reads no contents, and an
    // absence is not something a run can demonstrate: a scan of a project whose
    // files are all readable looks the same whether or not they were read. A
    // source scan is the only thing that can catch it, which is the same
    // technique P1-T009 used to keep `sure doctor` from reading the settings
    // file.
    let source = sure_testkit::repository_root().join("crates/sure-core/src/scan");
    let mut checked = 0;

    for file in ["mod.rs", "ignore.rs", "skip.rs", "error.rs"] {
        let path = source.join(file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        checked += 1;
        for forbidden in [
            "File::open",
            "fs::read(",
            "fs::read_to_string",
            "read_to_end",
            "BufReader",
            "read_link",
            "canonicalize",
        ] {
            assert!(
                !text.contains(forbidden),
                "{file} contains `{forbidden}`; the scanner must not read project content"
            );
        }
    }
    assert_eq!(checked, 4, "a scanner source file was not checked");
}

// ---------------------------------------------------------------------------
// Links, per platform
// ---------------------------------------------------------------------------

/// Create a directory link at `link` pointing at `target`.
///
/// Two platforms, two mechanisms, one rule.
#[cfg(windows)]
fn link_to_directory(target: &Path, link: &Path) {
    // A junction rather than a symbolic link. `mklink /J` needs no privilege on
    // Windows, which is the difference between a test that runs everywhere and
    // one that needs Developer Mode — and a junction is what a developer
    // actually creates to point a working directory at a checkout somewhere
    // else, so it is the case that matters. The arguments must be spelled with
    // backslashes: `mklink` reads `/` as the start of one of its own switches.
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap_or_else(|error| panic!("cannot run cmd: {error}"));
    assert!(
        output.status.success(),
        "mklink /J {} {} failed: {}{}",
        link.display(),
        target.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn link_to_directory(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap_or_else(|error| {
        panic!(
            "cannot link {} to {}: {error}",
            link.display(),
            target.display()
        )
    });
}
