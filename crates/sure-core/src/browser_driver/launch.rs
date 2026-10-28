//! Starting the browser, and finding the port it chose.
//!
//! This is the only file in the product that starts a browser, and it is the
//! fourth entry in `crates/sure-core/tests/spawn_sites.rs`'s census — which is
//! the check that exists so that a new way for SURE to run something cannot be
//! added without somebody reading the paragraph above the list.
//!
//! # Why the browser is started directly rather than through the runner
//!
//! [`crate::process`] is how SURE runs *a project's* commands, and the door into
//! it is `Enforcement::admitted`, which classifies a program by name and treats
//! one it does not recognise as capable of anything. A browser is not in that
//! table, so a browser cannot be started through it — correctly, because the
//! runner's contract is about the project's code and this is not the project's
//! code.
//!
//! **The browser is SURE's own tool, chosen by SURE from a table compiled into
//! this binary.** That is the same shape as
//! [`crate::fingerprint::git`](crate::fingerprint::git), which holds a program
//! name rather than calling for `git` where it is needed, and for the same
//! reason. What follows from that is the security property worth stating: the
//! address SURE opens comes from the project, and **nothing else does**.
//!
//! # Where the address is, and why not on the command line
//!
//! `--remote-debugging-port=0` asks the operating system for a free port, and
//! the browser writes the port it got into `DevToolsActivePort` inside its
//! profile directory. SURE reads it from there.
//!
//! **The page's address is never a command-line argument.** It is sent later, as
//! a `Page.navigate` command over the debugging connection, so there is no
//! argument vector for a project-supplied path to be injected into — no quoting
//! rule to get right, no `--` to place, and nothing that behaves differently
//! because a path began with a dash. `CLAUDE.md`'s rule about preferring typed
//! arguments to shell strings is satisfied here by there being no string.
//!
//! # The profile directory
//!
//! A browser started with remote debugging **refuses to use a profile that is
//! already the default one**, which is what stops a page from reaching the
//! debugging port of the browser a person is using. SURE creates a private
//! directory under the system temporary directory for each run, starts the
//! browser against that, and removes it afterwards. Nothing of the user's is
//! opened, read or written, and a run leaves no profile behind for the next one
//! to inherit.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::process::Cancellation;

/// How often the profile directory is looked at while the browser starts.
///
/// The file appears once and is then read; polling is what bounds the wait by
/// time rather than by a guess about how long a browser takes to start on a
/// machine this build has never run on.
const POLL: Duration = Duration::from_millis(25);

/// How much of what the browser said on its error stream is kept.
///
/// **Bounded, because the stream is not.** A browser that fails to start may say
/// a sentence or may say a great deal, and the report quotes this rather than
/// the whole of it. Four kibibytes is several times the longest Chrome startup
/// complaint anybody has needed to read.
const COMPLAINT_KEPT: usize = 4096;

/// A browser that is running, and where to talk to it.
///
/// Dropping this stops the browser. That is not a convenience: the value is held
/// across the whole look, and a path that returned early leaving a browser
/// running would leak a process — and a bound port — per checked project.
#[derive(Debug)]
pub struct Launched {
    child: Child,
    profile: PathBuf,
    port: u16,
    browser_path: String,
    /// Whether the child has already been reaped, so that `Drop` does not try to
    /// stop a process whose identifier the operating system may have handed to
    /// somebody else.
    reaped: bool,
}

/// What the wait ran out on, as far as the loop could see.
///
/// **Neither variant is a claim about how far the browser had got.** They are
/// the two things this file actually looked at, recorded so that the sentence a
/// person reads is made of observations instead of arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    /// `try_wait` answered that the program had not stopped.
    ///
    /// **Observed rather than assumed**: the loop asks on every pass, and a
    /// program that *had* stopped comes back as [`LaunchError::Exited`] with its
    /// exit status instead of reaching here. The observation is at most one
    /// [`POLL`] old — so "it was still running" means *as of up to twenty-five
    /// milliseconds before the deadline* — and it says nothing whatever about
    /// what the program was doing.
    Running,
    /// `try_wait` would not answer, so whether the program was still running is
    /// **not known**, and no sentence built from this says that it was.
    Unreported,
}

/// What the browser's private profile directory held when the wait ran out.
///
/// The directory itself is always there — [`start`] made it before it started
/// anything — so the question is about the one file inside it that the browser
/// writes when it has a debugging port: `DevToolsActivePort`.
///
/// **This is the only progress signal the loop has, and it is a coarse one.**
/// Measured on the development machine over six cold starts, polled every
/// millisecond, the file went from absent to complete in under a millisecond
/// every time and the half-written state was never observed at all — so at the
/// twenty-five millisecond [`POLL`] this loop uses, `HalfWritten` is a state it
/// will almost never see. What the two variants do say is still worth reading,
/// because they are different facts about the browser: it had, or had not, got
/// as far as writing the file SURE is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortFile {
    /// No `DevToolsActivePort` at all: the browser had not written one.
    Absent,
    /// There, but not holding both the port and the endpoint path — the state
    /// [`read_active_port`] reads as *a file being written*.
    HalfWritten,
}

/// Why a browser is not available to be driven.
///
/// Every variant ends as
/// [`AbsenceReason::DriverWouldNotStart`](crate::browser::AbsenceReason::DriverWouldNotStart),
/// so none of them says anything about the project. They are separate variants
/// because the sentence a person reads differs, and because a test can tell them
/// apart without matching on prose.
#[derive(Debug)]
pub enum LaunchError {
    /// The operating system would not start the program.
    WouldNotStart {
        program: PathBuf,
        error: std::io::Error,
    },
    /// The program started, and the wait ran out before it said which port it
    /// was listening on.
    ///
    /// # What `waited` is, and what it is not
    ///
    /// **It is how long SURE waited, and it is not a measurement of the
    /// browser.** The deadline is set before the loop, so `waited` is the
    /// caller's own `budget` plus at most one [`POLL`] of overshoot: it is
    /// bounded above by the budget by construction and would read the same for a
    /// browser one millisecond from writing its port and for one that was never
    /// going to write it.
    ///
    /// **It is printed as SURE's wait for exactly that reason**, and the
    /// sentence around it reports the two observations the loop did make
    /// ([`ChildState`] and [`PortFile`]) and states plainly that how close the
    /// browser was to reporting a port **is not known**. An earlier shape of
    /// this message read *"ran for N seconds without reporting a debugging
    /// port"*, which said the opposite by implication: that N measured the
    /// browser. Measured through this crate's own interface, two calls on one
    /// machine against one unchanging `chrome.exe` printed `0.050` and
    /// `0.150` — the two budgets they were given — and a third call with two
    /// seconds opened the same browser.
    NeverOpened {
        program: PathBuf,
        waited: Duration,
        child: ChildState,
        port_file: PortFile,
        complaint: String,
    },
    /// The program started and then stopped before it said.
    Exited {
        program: PathBuf,
        status: String,
        complaint: String,
    },
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WouldNotStart { program, error } => write!(
                formatter,
                "{} could not be started: {error}",
                program.display()
            ),
            Self::NeverOpened {
                program,
                waited,
                child,
                port_file,
                complaint,
            } => {
                write!(
                    formatter,
                    "{} had not reported a debugging port after {:.3} seconds of \
                     waiting, and {}, so how close it was to reporting one is not \
                     known",
                    program.display(),
                    waited.as_secs_f32(),
                    match child {
                        ChildState::Running => "the program was still running",
                        ChildState::Unreported => {
                            "whether the program was still running could not be \
                             read from the operating system"
                        }
                    },
                )?;
                formatter.write_str(match port_file {
                    PortFile::Absent => {
                        ", and its profile directory held no DevToolsActivePort file"
                    }
                    PortFile::HalfWritten => {
                        ", and its profile directory held a DevToolsActivePort file \
                         it had not finished writing"
                    }
                })?;
                formatter.write_str(&said(complaint))
            }
            Self::Exited {
                program,
                status,
                complaint,
            } => write!(
                formatter,
                "{} stopped before reporting a debugging port ({status}){}",
                program.display(),
                said(complaint)
            ),
        }
    }
}

/// What the profile directory holds now, in the two states this file can tell
/// apart.
///
/// The reading is [`read_active_port`]'s: a file that is there but does not hold
/// both lines is *being written*, which is the reading that function documents
/// and not a second one invented here.
fn port_file_state(profile: &Path) -> PortFile {
    if profile.join("DevToolsActivePort").exists() {
        PortFile::HalfWritten
    } else {
        PortFile::Absent
    }
}

/// The browser's own words, if it said any, as a clause a sentence can end with.
fn said(complaint: &str) -> String {
    let trimmed = complaint.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        // Quoted rather than folded into the sentence, because these are the
        // program's words and not SURE's reading of them.
        format!(", and said: {trimmed:?}")
    }
}

impl std::error::Error for LaunchError {}

/// Starts `program` and waits for it to report the port it is listening on.
///
/// `budget` bounds the wait, and it is spent entirely if the browser never
/// answers: a caller that has already used part of its own time passes what is
/// left rather than a fresh allowance, so that one look cannot take longer than
/// the limit its caller set.
///
/// # What the wait can and cannot tell apart
///
/// The loop watches a file the browser writes once it has a debugging port, and
/// asks the operating system whether the process has stopped. **Both answers are
/// about where the browser had got to, and neither is about how much longer it
/// needed.** A browser that had not written the file and was still running is
/// reported as [`LaunchError::NeverOpened`] whether it was one millisecond from
/// writing it or was never going to; a browser that stopped is reported as
/// [`LaunchError::Exited`] with its status; and a wait that runs out is a fact
/// about `budget` and not about the program, which is why the sentence built
/// from it says how long *SURE* waited. **The one thing raising `budget` cannot
/// do is make this distinction appear**, which is why the report carries the two
/// observations instead of a figure that implies closeness.
///
/// # Errors
///
/// [`LaunchError`], which the caller turns into
/// [`AbsenceReason::DriverWouldNotStart`](crate::browser::AbsenceReason::DriverWouldNotStart).
pub fn start(
    program: &Path,
    budget: Duration,
    cancellation: &Cancellation,
) -> Result<Launched, LaunchError> {
    let profile = private_profile();
    std::fs::create_dir_all(&profile).map_err(|error| LaunchError::WouldNotStart {
        program: program.to_path_buf(),
        error,
    })?;

    let mut child = match Command::new(program)
        .args(arguments(&profile))
        // The browser is run from its own private directory rather than from
        // wherever SURE was started. A process's working directory is a handle
        // on that directory, and on Windows a handle held by a program the
        // project did not write is still a handle that can stop the project's
        // directory being renamed or removed.
        .current_dir(&profile)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            // The directory was made before the program was tried, so a program
            // that cannot start would otherwise leave one behind on every call.
            // Nothing has run, so nothing holds it open and this succeeds.
            let _ = std::fs::remove_dir_all(&profile);
            return Err(LaunchError::WouldNotStart {
                program: program.to_path_buf(),
                error,
            });
        }
    };

    // The buffer the draining thread writes into. **Nothing reads it after a
    // successful start**, and it is kept for the whole life of the child on
    // purpose: the thread ends when the browser's error stream does, and until
    // then its only job is to be somewhere the pipe can empty into. A pipe
    // nobody reads fills, and a browser that blocks writing a warning it did not
    // ask anybody to read would stop answering on the debugging port.
    let complaint = Arc::new(Mutex::new(String::new()));
    if let Some(stream) = child.stderr.take() {
        drain_into(stream, Arc::clone(&complaint));
    }

    // The instant the wait is measured from, taken here rather than at each
    // reading so that what the error reports is how long SURE waited and not how
    // long the process had been alive. See `LaunchError::NeverOpened`.
    let waiting_since = Instant::now();
    let deadline = waiting_since + budget;

    // **Not assumed to be anything.** There is no initial value: the only path
    // that reaches the deadline check passes through the `try_wait` below and
    // writes what it answered here, and the compiler holds that in place. So a
    // deadline cannot be reported as a browser seen to be running without
    // something having actually looked.
    let mut child_state;

    // A browser that stopped with a *successful* status, kept so that the
    // deadline can report the exit rather than an absence. See the arm below
    // for why a clean exit is not treated as the end of the attempt.
    let mut exited_cleanly: Option<std::process::ExitStatus> = None;

    loop {
        if cancellation.is_cancelled() {
            let mut child = child;
            let _ = crate::process::terminate::stop(&mut child);
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&profile);
            return Err(LaunchError::WouldNotStart {
                program: program.to_path_buf(),
                error: std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"),
            });
        }
        match read_active_port(&profile) {
            Some((port, browser_path)) => {
                return Ok(Launched {
                    child,
                    profile,
                    port,
                    browser_path,
                    // A starter that already exited was reaped by `try_wait`;
                    // `Drop` must not signal a process identifier the operating
                    // system may have handed to somebody else. The browser that
                    // wrote the port is shut down over the debugging connection.
                    reaped: exited_cleanly.is_some(),
                });
            }
            None => {
                // A browser that stopped with a **failure** status will not
                // write the file, and waiting out the whole budget to say so
                // wastes the caller's time to learn something already known.
                // **This is also the observation the deadline arm reports**: the
                // three states are kept apart rather than collapsed, because
                // "it had stopped" and "it was still running" and "the
                // operating system would not say" are three different sentences
                // about three different machines.
                //
                // **A clean exit is different, and measured.** Edge (and Chrome)
                // on Windows can have the process SURE started hand the task to
                // another one and exit 0 before that one writes
                // `DevToolsActivePort`: measured on this fork's machine, the
                // starter was reaped at 0.066 s while the port file appeared a
                // moment later. Treating that exit as final is a launch failure
                // on a browser that is in fact starting, so the wait continues
                // until the port appears or the budget runs out; the status is
                // kept and reported at the deadline when the file never comes.
                // The debugging connection's own `Browser.close` is what shuts
                // the handed-off browser down, not this child handle.
                match child.try_wait() {
                    Ok(Some(status)) if status.success() => {
                        exited_cleanly = Some(status);
                        child_state = ChildState::Running;
                    }
                    Ok(Some(status)) => {
                        let complaint = complaint_text(&complaint);
                        let _ = std::fs::remove_dir_all(&profile);
                        return Err(LaunchError::Exited {
                            program: program.to_path_buf(),
                            status: status.to_string(),
                            complaint,
                        });
                    }
                    Ok(None) => child_state = ChildState::Running,
                    Err(_) => child_state = ChildState::Unreported,
                }
            }
        }
        if Instant::now() >= deadline {
            if let Some(status) = exited_cleanly {
                let complaint = complaint_text(&complaint);
                let _ = std::fs::remove_dir_all(&profile);
                return Err(LaunchError::Exited {
                    program: program.to_path_buf(),
                    status: status.to_string(),
                    complaint,
                });
            }
            // **Everything reported below is read here, at the deadline, and
            // before anything is tidied up.** That ordering is the whole point:
            // stopping a browser takes most of a second on Windows, and a figure
            // or a file state taken after that would be a measurement of this
            // function taking down a process rather than of the browser it was
            // waiting for. It was measured: an earlier shape of this arm read
            // the elapsed time after the teardown and a fifty-millisecond wait
            // was reported as `0.800`.
            let waited = waiting_since.elapsed();
            let port_file = port_file_state(&profile);
            let complaint = complaint_text(&complaint);
            let mut child = child;
            let _ = crate::process::terminate::stop(&mut child);
            let _ = std::fs::remove_dir_all(&profile);
            return Err(LaunchError::NeverOpened {
                program: program.to_path_buf(),
                waited,
                child: child_state,
                port_file,
                complaint,
            });
        }
        std::thread::sleep(POLL);
    }
}

/// The arguments the browser is started with, in full.
///
/// **This list is the configuration the mechanism was verified against**, and it
/// is written out rather than trimmed because a flag removed here is a
/// configuration that has not been tested. Each one earns its place:
///
/// - `--headless=new` — no window. A check that opened one would take over the
///   screen of the person running it, and `new` is the mode that renders with
///   the real engine rather than the old headless shell.
/// - `--remote-debugging-port=0` — the whole point; zero asks for a free port.
/// - `--user-data-dir` — the private profile the module documentation explains.
/// - `--no-first-run`, `--no-default-browser-check` — without these a fresh
///   profile starts a first-run flow that can block before the port is written.
///   They are not cosmetic: they are the difference between a browser that
///   answers and one that waits for a person who is not there.
/// - `--disable-gpu` — a machine running this may have no usable graphics
///   device, and a browser that stalls on one never writes the port file.
/// - `--disable-extensions` — the profile is new, so there is nothing to
///   disable; it is here because it is part of the verified configuration and
///   removing a flag from a verified configuration is a change that has not
///   been tested.
///
/// **`--no-sandbox` is deliberately absent.** It is the flag that makes a
/// Chromium start in containers and on CI images whose kernel restricts user
/// namespaces, and it is the flag that is reached for first when a browser will
/// not start on a build machine. It is not here because **the page this browser
/// opens is written by the project being checked** — it is the most untrusted
/// content in the whole of SURE — and the sandbox is what stops that page
/// reaching the rest of the machine. A browser that will not start without it is
/// reported as
/// [`DriverWouldNotStart`](crate::browser::AbsenceReason::DriverWouldNotStart)
/// and the check is skipped, which is a smaller loss than running a project's
/// JavaScript without the boundary that exists to contain it.
///
/// The address is not in this list. See the module documentation.
fn arguments(profile: &Path) -> Vec<std::ffi::OsString> {
    let mut arguments: Vec<std::ffi::OsString> = [
        "--headless=new",
        "--remote-debugging-port=0",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-gpu",
        "--disable-extensions",
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let mut data_dir = std::ffi::OsString::from("--user-data-dir=");
    data_dir.push(profile.as_os_str());
    arguments.push(data_dir);
    // The page this browser shows until SURE tells it where to go. Not a URL
    // from the project, so that the first thing the browser loads is nothing.
    arguments.push(std::ffi::OsString::from("about:blank"));
    arguments
}

/// A directory of this run's own, under the system temporary directory.
///
/// The process identifier and a counter, so that two runs in one process — and
/// two tests in one test binary, which is where the second one matters — never
/// share a profile. A shared profile is not a hypothetical: a browser refuses to
/// start against a profile another browser is using, so the failure would be a
/// check that could not run depending on what ran beside it.
fn private_profile() -> PathBuf {
    static RUNS: AtomicU32 = AtomicU32::new(0);
    let run = RUNS.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sure-browser-{}-{run}", std::process::id()))
}

/// The port and browser path the browser wrote, if it has written them.
///
/// The file's first line is the port and its second is the path of the
/// browser-wide debugging endpoint. **Both are read**, and the second is not
/// decoration: it is the only way to reach the endpoint that can list targets,
/// which is how a page is found.
///
/// A file that exists but does not yet hold two parseable lines returns `None`
/// rather than an error, because that is what a file **being written** looks
/// like — the browser creates it before it fills it in, and a reader that
/// treated the moment in between as a failure would fail on a fast machine and
/// pass on a slow one.
fn read_active_port(profile: &Path) -> Option<(u16, String)> {
    let text = std::fs::read_to_string(profile.join("DevToolsActivePort")).ok()?;
    let mut lines = text.lines();
    let port = lines.next()?.trim().parse::<u16>().ok()?;
    let path = lines.next()?.trim().to_owned();
    if !path.starts_with('/') {
        return None;
    }
    Some((port, path))
}

/// Reads a stream to its end into a shared, bounded buffer, on its own thread.
///
/// **A thread, because the alternative deadlocks.** A child's error stream is a
/// pipe with a fixed capacity: a program that writes more than that blocks until
/// somebody reads, and a parent that waits for the program to exit before
/// reading waits for a program that is waiting for it. The thread ends when the
/// stream does, which is when the browser exits.
///
/// The buffer stops growing at [`COMPLAINT_KEPT`], and says so — a report that
/// quoted the first four kibibytes of a very long complaint without saying it
/// had stopped would be a quote that looked complete.
fn drain_into(mut stream: impl std::io::Read + Send + 'static, into: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(read) => {
                    let Ok(mut kept) = into.lock() else {
                        return;
                    };
                    if kept.len() >= COMPLAINT_KEPT {
                        continue;
                    }
                    let room = COMPLAINT_KEPT - kept.len();
                    let take = room.min(read);
                    kept.push_str(&String::from_utf8_lossy(&buffer[..take]));
                    if take < read {
                        kept.push_str(" […]");
                    }
                }
            }
        }
    });
}

/// What the browser said, or an empty string.
fn complaint_text(complaint: &Arc<Mutex<String>>) -> String {
    complaint
        .lock()
        .map(|kept| kept.clone())
        .unwrap_or_default()
}

impl Launched {
    /// The path of the browser-wide debugging endpoint, beginning with a slash.
    #[must_use]
    pub fn browser_path(&self) -> &str {
        &self.browser_path
    }

    /// Where the debugging connection is made.
    #[must_use]
    pub fn address(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, self.port))
    }

    /// Waits up to `timeout` for the browser to exit on its own.
    ///
    /// Returns whether it did. This is the graceful half of stopping: a browser
    /// asked to close over the debugging connection shuts itself down and
    /// removes its own profile, and a caller that killed it instead would be
    /// killing something that was already leaving.
    pub fn wait_for_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped = true;
                    return true;
                }
                Ok(None) => {}
                Err(_) => return false,
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for Launched {
    fn drop(&mut self) {
        if !self.reaped {
            // As much of it as this platform reaches, and not "the tree" by
            // default: a browser has children, and `terminate::stop` reaches them
            // whole on Windows — what `taskkill /T /F` reporting success means —
            // while everywhere else it is `Child::kill` on the launcher alone, so
            // a browser's own children may still be running when this returns.
            // Which of the two happened is the `Stop` that call returns rather
            // than an assumption made here; `crate::process::terminate` is where
            // that value and its two cases are written out. The call's result is
            // deliberately not unwrapped — a drop cannot report — and the
            // fallback below runs whether or not it worked.
            let _ = crate::process::terminate::stop(&mut self.child);
            let _ = self.child.wait();
            self.reaped = true;
        }
        // Best effort, and after the browser has gone: on Windows a directory a
        // running program has open cannot be removed, so a failure here means
        // the browser is still holding it and not that the removal was wrong.
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **`--no-sandbox` is not in the argument vector**, which is a security
    /// decision this test holds in place rather than a formatting one.
    ///
    /// The page this browser opens is written by the project being checked, so
    /// the sandbox is the boundary between that page and the machine. The
    /// pressure to add the flag is real — it is what makes a Chromium start on
    /// CI images and in containers — and it is the pressure this test is for.
    #[test]
    fn the_sandbox_is_never_disabled() {
        let arguments = arguments(Path::new("/tmp/a-profile"));
        let flattened: Vec<String> = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        for forbidden in [
            "--no-sandbox",
            "--disable-web-security",
            "--allow-running-insecure-content",
        ] {
            assert!(
                !flattened.iter().any(|argument| argument == forbidden),
                "{forbidden} was passed, and the page this browser opens is the project's"
            );
        }
        assert!(
            flattened
                .iter()
                .any(|argument| argument == "--headless=new"),
            "the browser would open a window"
        );
        assert!(
            flattened
                .iter()
                .any(|argument| argument.starts_with("--user-data-dir=")),
            "the browser would use the profile of the person running SURE"
        );
    }

    /// **The page's address is not among the arguments**, because it is sent
    /// later as a protocol command.
    ///
    /// What that buys is stated in the module documentation: there is no
    /// argument vector for a project-supplied path to be injected into. The
    /// assertion is that the only thing in the vector that could be a URL is the
    /// constant this file wrote.
    #[test]
    fn the_only_address_on_the_command_line_is_the_one_this_file_wrote() {
        let arguments = arguments(Path::new("/tmp/a-profile"));
        let last = arguments.last().expect("there is a last argument");
        assert_eq!(last.to_string_lossy(), "about:blank");
        for argument in &arguments {
            let text = argument.to_string_lossy();
            assert!(
                !text.starts_with("http://") && !text.starts_with("https://"),
                "{text} is an address from somewhere other than this file"
            );
        }
    }

    /// **Two runs never share a profile**, which is what makes it safe for the
    /// tests in one binary to run at the same time.
    #[test]
    fn a_profile_is_this_run_s_own() {
        let first = private_profile();
        let second = private_profile();
        assert_ne!(first, second, "two runs were given one profile");
        assert!(first.is_absolute(), "{} is not absolute", first.display());
    }

    /// The file the browser writes, read from a directory this test wrote —
    /// including the two states that are not a port.
    ///
    /// **A half-written file is `None` and not an error**, because that is what
    /// the file looks like between being created and being filled in, and a
    /// reader that called that a failure would fail on whichever machine won the
    /// race.
    #[test]
    fn the_port_file_is_read_only_when_it_holds_both_lines() {
        let directory = std::env::temp_dir().join(format!("sure-port-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let file = directory.join("DevToolsActivePort");

        std::fs::write(&file, "12345\n/devtools/browser/abc\n").expect("written");
        assert_eq!(
            read_active_port(&directory),
            Some((12345, String::from("/devtools/browser/abc")))
        );

        std::fs::write(&file, "12345\n").expect("written");
        assert_eq!(read_active_port(&directory), None, "a half-written file");

        std::fs::write(&file, "not a port\n/devtools/browser/abc\n").expect("written");
        assert_eq!(
            read_active_port(&directory),
            None,
            "a first line that is not a port"
        );

        std::fs::write(&file, "12345\nnot-a-path\n").expect("written");
        assert_eq!(
            read_active_port(&directory),
            None,
            "a second line that is not a path"
        );

        std::fs::remove_file(&file).expect("removed");
        assert_eq!(read_active_port(&directory), None, "no file at all");

        std::fs::remove_dir_all(&directory).expect("removed");
    }

    /// **A program that starts and then stops is `Exited`, and never the
    /// deadline** — which is the observation that makes `NeverOpened` mean
    /// something.
    ///
    /// The program is this test binary, started with the browser's argument
    /// vector. `--headless=new` is not an option the test harness has, so it
    /// stops immediately and says why; the launch loop's `try_wait` sees that
    /// within one poll and reports the exit status. **If the loop did not ask,
    /// this would be a `NeverOpened` after ten seconds** — the same sentence a
    /// browser that was still starting gets — and that is the whole difference
    /// this test holds in place.
    ///
    /// The budget is ten seconds against a program that stops in tens of
    /// milliseconds, so what is being measured is the question being asked and
    /// not the speed of the machine. It is deliberately not tuned tighter: a
    /// test that failed because a loaded runner took a second to load a process
    /// would be a test about the runner.
    #[test]
    fn a_program_that_stops_is_reported_as_stopped_and_not_as_a_deadline() {
        let itself = std::env::current_exe().expect("this test binary has a path");
        let error = start(&itself, Duration::from_secs(10), &Cancellation::default())
            .expect_err("a program that stops without writing a port is an error");

        let LaunchError::Exited { status, .. } = &error else {
            panic!(
                "a program that had stopped was reported as something else: {error:?} \
                 — which is the difference between a sentence about a program that \
                 gave up and one about a wait that ran out"
            );
        };
        assert!(
            !status.trim().is_empty(),
            "the report does not say how the program ended"
        );
        // Reaching here means the branch was taken, which is the assertion that
        // matters; the sentence below is checked so that a reader of a failure
        // sees which program it was.
        assert!(
            error.to_string().contains("stopped before reporting"),
            "{error}"
        );
    }

    /// **A clean exit is not the end of the attempt.** A browser on Windows can
    /// hand the work to another process and exit 0 before that process writes
    /// `DevToolsActivePort`; treating the exit as final fails a launch that is
    /// still in progress. The program here exits 0 immediately and never writes
    /// the file, so the launcher must spend the rest of its budget before
    /// reporting the exit — the timing is the assertion.
    #[test]
    fn a_program_that_exits_cleanly_gets_the_rest_of_the_budget_for_a_handed_off_port() {
        #[cfg(windows)]
        let program = {
            let directory =
                std::env::temp_dir().join(format!("sure-exit-zero-{}", std::process::id()));
            std::fs::create_dir_all(&directory).expect("a temporary directory");
            let path = directory.join("exit-zero.cmd");
            std::fs::write(&path, "@exit /b 0\r\n").expect("written");
            path
        };
        #[cfg(not(windows))]
        let program = std::path::PathBuf::from("/bin/true");

        let budget = Duration::from_millis(600);
        let started = std::time::Instant::now();
        let error = start(&program, budget, &Cancellation::default())
            .expect_err("a program that never writes a port is an error");
        let waited = started.elapsed();

        assert!(
            matches!(error, LaunchError::Exited { .. }),
            "a clean exit was reported as something else: {error:?}"
        );
        assert!(
            waited >= Duration::from_millis(450),
            "a clean exit was treated as final after {waited:?}; the process it handed \
             the work to never got the rest of the budget"
        );

        #[cfg(windows)]
        {
            let _ =
                std::fs::remove_dir_all(program.parent().expect("the program is in a directory"));
        }
    }

    /// **The sentence for a wait that ran out reports what was observed and
    /// never implies the figure measured the browser.**
    ///
    /// This is the shape the message was changed to, pinned without a browser so
    /// that it fails on the wording rather than on a machine: every combination
    /// of what the loop can have seen is rendered, and two things are required
    /// of all of them — that the duration is attributed to SURE's waiting rather
    /// than to the program, and that the closeness that is not known is said not
    /// to be known.
    ///
    /// The old sentence is asserted *against*, not merely left out: *"ran for N
    /// seconds without reporting a debugging port"* is the phrasing that made
    /// four recorded CI failures read as a measurement of Chrome when the figure
    /// was the caller's budget minus a sub-millisecond search. A future edit that
    /// went back to it would have to delete this test.
    #[test]
    fn the_sentence_for_a_wait_that_ran_out_does_not_claim_the_browser_took_that_long() {
        for child in [ChildState::Running, ChildState::Unreported] {
            for port_file in [PortFile::Absent, PortFile::HalfWritten] {
                let error = LaunchError::NeverOpened {
                    program: PathBuf::from("/usr/bin/chromium"),
                    waited: Duration::from_secs(30),
                    child,
                    port_file,
                    complaint: String::new(),
                };
                let text = error.to_string();

                assert!(
                    text.contains("30.000 seconds of waiting"),
                    "the wait is not reported as SURE's, in seconds, rounded to the                      millisecond this machine can actually measure: {text}"
                );
                assert!(
                    text.contains("/usr/bin/chromium"),
                    "the program is not named: {text}"
                );
                assert!(
                    !text.contains("ran for"),
                    "the sentence claims the program ran for the figure, which is \
                     what the figure does not measure: {text}"
                );
                assert!(
                    text.contains("how close it was to reporting one is not known"),
                    "the sentence does not say what it does not know: {text}"
                );
                match child {
                    ChildState::Running => assert!(
                        text.contains("and the program was still running,"),
                        "an observed-live child is not reported as running: {text}"
                    ),
                    // The overclaim this arm exists to stop: `try_wait` refused,
                    // so nothing may say the program was running. The assertion
                    // is on the *asserting* phrase and not on the words, because
                    // the honest sentence for this arm has to say what it could
                    // not find out and those words are part of that too.
                    ChildState::Unreported => {
                        assert!(
                            !text.contains("and the program was still running,"),
                            "a child whose state the operating system would not \
                             report is claimed to have been running: {text}"
                        );
                        assert!(
                            text.contains(
                                "whether the program was still running could not be read \
                                 from the operating system"
                            ),
                            "an unreadable child state is not said to be unreadable: {text}"
                        );
                    }
                }
            }
        }

        for port_file in [PortFile::Absent, PortFile::HalfWritten] {
            let error = LaunchError::NeverOpened {
                program: PathBuf::from("/usr/bin/chromium"),
                waited: Duration::from_secs(30),
                child: ChildState::Running,
                port_file,
                complaint: "Failed to connect to the bus".to_owned(),
            };
            let text = error.to_string();
            assert!(
                text.contains("Failed to connect to the bus"),
                "the browser's own words are dropped: {text}"
            );
            match port_file {
                PortFile::Absent => assert!(
                    text.contains("held no DevToolsActivePort file"),
                    "the profile directory's state is not reported: {text}"
                ),
                PortFile::HalfWritten => assert!(
                    text.contains("had not finished writing"),
                    "a half-written port file is not reported: {text}"
                ),
            }
        }
    }

    /// **A program that cannot be started is reported, not panicked on**, and
    /// the report names the program.
    #[test]
    fn a_program_that_does_not_exist_is_an_error_a_caller_can_read() {
        let missing = std::env::temp_dir().join("sure-there-is-no-such-browser-anywhere");
        let error = start(
            &missing,
            Duration::from_millis(500),
            &Cancellation::default(),
        )
        .expect_err("a program that does not exist cannot be started");
        assert!(
            matches!(error, LaunchError::WouldNotStart { .. }),
            "{error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("sure-there-is-no-such-browser-anywhere"),
            "the report does not name the program: {error}"
        );
    }
}
