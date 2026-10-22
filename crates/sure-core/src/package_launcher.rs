//! Starting the package managers Windows installs as batch files.
//!
//! A Node project's checks are planned as `npm run test` and the like
//! ([`crate::checks::node`]), and on Windows the `npm` a person has is
//! `npm.cmd` — a batch file. **SURE does not start batch files**:
//! [`crate::safety`] reads a `.cmd` name as unread text, and
//! [`crate::planned_work::Resolution`] says `InterpreterRequired` rather than a
//! program, so those checks could never run on the platform this product is
//! built for first.
//!
//! # What this module starts instead
//!
//! The shim itself runs one thing: the Node executable beside it, with the
//! package manager's own JavaScript entry (`node_modules/npm/bin/npm-cli.js`,
//! `node_modules/pnpm/bin/pnpm.cjs`, `node_modules/yarn/bin/yarn.js`). This
//! module resolves the planned name to exactly that pair — **a real executable
//! and the JavaScript file the installed manager ships**, found from the shim's
//! own directory and never from the project — and the runner starts it with the
//! plan's arguments unchanged (`run test`, …). When the shim is a corepack
//! wrapper (`node_modules/corepack/dist/corepack.js`) the dispatcher is used
//! with the command the plan named, which is what the shim itself calls. It
//! does not build a command line, does not read the batch file, and does not
//! start a command interpreter: `node` is a program [`crate::safety`]
//! classifies, and a project allowed to run its own scripts is allowed to run
//! the package manager's entry with them.
//!
//! # What it refuses
//!
//! Only a bare `npm`/`npx`/`pnpm`/`pnpx`/`yarn`/`yarnpkg` name whose resolved
//! file is a `.cmd` or `.bat` **and** whose directory carries both a startable
//! `node` (beside the shim or on `PATH`) and either the manager's shipped entry
//! or the corepack dispatcher is translated. Every other shape — a `.ps1`, a
//! name that resolves to nothing, an install without its JavaScript side —
//! returns `None`, and the original program is used: the check then fails with
//! the honest `InterpreterRequired`/not-found reason it already had. Nothing is
//! guessed.
//!
//! # Where it is bound
//!
//! [`PackageLaunchers`] is held by
//! [`ProcessRunner`](crate::planned_check_runner::ProcessRunner) and bound at
//! the composition root (`sure-cli/src/check.rs`), the same way the browser
//! driver is. A runner built without it starts what the plan names, which is
//! what the tests that measure the plan/result pairing do.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::planned_work::{ProgramPath, Resolution};

/// The launchers a run may use to start a package manager's JavaScript entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageLaunchers {
    path: ProgramPath,
}

/// What to start instead of a batch shim, and with which arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// The program the operating system starts: `node`.
    pub program: PathBuf,
    /// The plan's arguments, with the package manager's JavaScript entry in
    /// front. One element per argument; nothing is joined or split.
    pub arguments: Vec<OsString>,
}

impl PackageLaunchers {
    /// Launchers resolved against this machine's `PATH`.
    #[must_use]
    pub fn of_this_machine() -> Self {
        Self {
            path: ProgramPath::of_this_machine(),
        }
    }

    /// The same, against a search path a caller chose (for tests).
    #[must_use]
    pub fn from_search_path(search: impl Into<OsString>) -> Self {
        Self {
            path: ProgramPath::from_search_path(search),
        }
    }

    /// What to start for `program`, or `None` when the planned name is not a
    /// batch shim this module knows how to translate.
    ///
    /// `None` is not an error: the caller keeps the plan's own program, and a
    /// machine where npm is missing or is a real executable is untouched.
    #[must_use]
    pub fn resolve(&self, program: &OsStr, arguments: &[OsString]) -> Option<Launch> {
        // Only Windows completes a bare name with `.cmd`/`.bat`; on every other
        // platform npm is the file itself and is started as it stands. The
        // guard is a value rather than `#[cfg]` so the module compiles — and
        // its type is usable — everywhere.
        if !cfg!(windows) {
            return None;
        }
        let named = Path::new(program);
        // A path is the plan talking about a file, not a name on PATH.
        if named.components().count() != 1 {
            return None;
        }
        let name = named.file_stem()?.to_str()?.to_ascii_lowercase();
        // The package's own directory and the JavaScript entry its shim runs.
        // `yarnpkg` is Yarn's alternative name; `pnpx` is pnpm's npx.
        let (package, entry) = match name.as_str() {
            "npm" => ("npm", "npm-cli.js"),
            "npx" => ("npm", "npx-cli.js"),
            "pnpm" => ("pnpm", "pnpm.cjs"),
            "pnpx" => ("pnpm", "pnpx.cjs"),
            "yarn" | "yarnpkg" => ("yarn", "yarn.js"),
            _ => return None,
        };

        let Resolution::InterpreterRequired(shim) = self.path.resolve(program) else {
            // Executable (the platforms where the manager is a script) or
            // nothing at all: nothing to translate.
            return None;
        };
        let extension = shim.extension()?.to_str()?.to_ascii_lowercase();
        if extension != "cmd" && extension != "bat" {
            // `.ps1` is not a batch file and is not something this build
            // starts either; leave the plan's honest refusal in place.
            return None;
        }

        let directory = shim.parent()?;
        let node =
            node_beside(directory).or_else(|| match self.path.resolve(OsStr::new("node")) {
                Resolution::Executable(found) => Some(found),
                _ => None,
            })?;

        // The manager's own JavaScript entry, as an npm-global install ships
        // it; otherwise the corepack dispatcher the shim may be a wrapper for.
        let package_entry = directory
            .join("node_modules")
            .join(package)
            .join("bin")
            .join(entry);
        let mut launched: Vec<OsString> = Vec::with_capacity(arguments.len() + 2);
        if package_entry.is_file() {
            launched.push(package_entry.into_os_string());
        } else {
            let corepack = directory
                .join("node_modules")
                .join("corepack")
                .join("dist")
                .join("corepack.js");
            if !corepack.is_file() {
                return None;
            }
            // `corepack pnpm …` / `corepack yarn …` — the same dispatcher the
            // generated shim calls, with the command the plan named.
            launched.push(corepack.into_os_string());
            launched.push(OsString::from(name));
        }
        launched.extend(arguments.iter().cloned());
        Some(Launch {
            program: node,
            arguments: launched,
        })
    }
}

/// The `node.exe` that ships beside an npm shim, if one does.
///
/// On Windows the npm installer puts `node.exe` and `npm.cmd` in the same
/// directory, and the shim prefers that copy (`SET "NODE_EXE=%~dp0\node.exe"`).
/// Preferring it here keeps the version the shim would have used.
fn node_beside(directory: &Path) -> Option<PathBuf> {
    let candidate = directory.join("node.exe");
    candidate.is_file().then_some(candidate)
}

#[cfg(all(test, windows))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A scratch directory this test owns and removes.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("a clock after the epoch")
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "sure-launch-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&directory).expect("create the scratch directory");
            Self(directory)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn file(&self, relative: &str) -> PathBuf {
            // Join component by component so the path this returns uses the
            // platform's own separator, exactly like the resolver's joins.
            let mut path = self.0.clone();
            for component in Path::new(relative).components() {
                path.push(component);
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create the parent directory");
            }
            fs::write(&path, b"").expect("write the fixture file");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn launchers(directory: &Path) -> PackageLaunchers {
        PackageLaunchers::from_search_path(directory.as_os_str().to_os_string())
    }

    #[test]
    fn an_npm_shim_becomes_node_and_the_shipped_cli() {
        let scratch = Scratch::new("npm");
        let node = scratch.file("node.exe");
        scratch.file("npm.cmd");
        let cli = scratch.file("node_modules/npm/bin/npm-cli.js");

        let launch = launchers(scratch.path())
            .resolve(
                OsStr::new("npm"),
                &[OsString::from("run"), OsString::from("test")],
            )
            .expect("the shim is translatable");

        assert_eq!(launch.program, node);
        assert_eq!(
            launch.arguments,
            vec![
                cli.into_os_string(),
                OsString::from("run"),
                OsString::from("test")
            ]
        );
    }

    #[test]
    fn a_shim_without_its_javascript_is_not_translated() {
        let scratch = Scratch::new("no-js");
        scratch.file("node.exe");
        scratch.file("npm.cmd");

        assert_eq!(
            launchers(scratch.path()).resolve(OsStr::new("npm"), &[]),
            None
        );
    }

    #[test]
    fn a_shim_without_node_is_not_translated() {
        let scratch = Scratch::new("no-node");
        scratch.file("npm.cmd");
        scratch.file("node_modules/npm/bin/npm-cli.js");

        // Empty search path: node is neither beside the shim nor on PATH.
        assert_eq!(
            launchers(scratch.path()).resolve(OsStr::new("npm"), &[]),
            None
        );
    }

    #[test]
    fn other_programs_and_paths_are_left_alone() {
        let scratch = Scratch::new("others");
        scratch.file("node.exe");
        scratch.file("python.cmd");
        scratch.file("node_modules/npm/bin/npm-cli.js");

        assert_eq!(
            launchers(scratch.path()).resolve(OsStr::new("python"), &[]),
            None
        );
        assert_eq!(
            launchers(scratch.path()).resolve(OsStr::new("./npm"), &[]),
            None
        );
        assert_eq!(
            launchers(scratch.path()).resolve(OsStr::new("pnpm"), &[]),
            None
        );
    }

    #[test]
    fn a_pnpm_shim_becomes_node_and_its_entry() {
        let scratch = Scratch::new("pnpm");
        let node = scratch.file("node.exe");
        scratch.file("pnpm.cmd");
        let cli = scratch.file("node_modules/pnpm/bin/pnpm.cjs");

        let launch = launchers(scratch.path())
            .resolve(
                OsStr::new("pnpm"),
                &[OsString::from("run"), OsString::from("test")],
            )
            .expect("the pnpm shim is translatable");

        assert_eq!(launch.program, node);
        assert_eq!(
            launch.arguments,
            vec![
                cli.into_os_string(),
                OsString::from("run"),
                OsString::from("test")
            ]
        );
    }

    #[test]
    fn yarnpkg_uses_the_yarn_entry() {
        let scratch = Scratch::new("yarn");
        let node = scratch.file("node.exe");
        scratch.file("yarnpkg.cmd");
        let cli = scratch.file("node_modules/yarn/bin/yarn.js");

        let launch = launchers(scratch.path())
            .resolve(OsStr::new("yarnpkg"), &[OsString::from("test")])
            .expect("the yarn shim is translatable");

        assert_eq!(launch.program, node);
        assert_eq!(
            launch.arguments,
            vec![cli.into_os_string(), OsString::from("test")]
        );
    }

    #[test]
    fn a_corepack_shim_uses_the_dispatcher() {
        let scratch = Scratch::new("corepack");
        let node = scratch.file("node.exe");
        scratch.file("pnpm.cmd");
        let dispatcher = scratch.file("node_modules/corepack/dist/corepack.js");

        let launch = launchers(scratch.path())
            .resolve(
                OsStr::new("pnpm"),
                &[OsString::from("run"), OsString::from("test")],
            )
            .expect("the corepack shim is translatable");

        assert_eq!(launch.program, node);
        assert_eq!(
            launch.arguments,
            vec![
                dispatcher.into_os_string(),
                OsString::from("pnpm"),
                OsString::from("run"),
                OsString::from("test")
            ]
        );
    }

    #[test]
    fn npx_uses_its_own_entry() {
        let scratch = Scratch::new("npx");
        let node = scratch.file("node.exe");
        scratch.file("npx.cmd");
        let cli = scratch.file("node_modules/npm/bin/npx-cli.js");

        let launch = launchers(scratch.path())
            .resolve(OsStr::new("npx"), &[OsString::from("--no-install")])
            .expect("the npx shim is translatable");

        assert_eq!(launch.program, node);
        assert_eq!(
            launch.arguments,
            vec![cli.into_os_string(), OsString::from("--no-install")]
        );
    }
}
