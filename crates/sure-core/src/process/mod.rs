//! The one place SURE runs a program.
//!
//! `docs/architecture/RUST_DESIGN.md` §Process execution lists what has to be
//! centralized: *executable + argument vector; cwd; environment allow/deny
//! behavior; timeout/cancellation; stdout/stderr capture and bounds;
//! exit/termination information; execution-trust classification; timing/evidence
//! metadata.* This module is all of that except classification — which is
//! `P3-T004`'s question, and belongs to a caller that has decided *whether* to
//! run something, not to the machinery that runs it.
//!
//! # The rule
//!
//! **Nothing about a run is inherited or assumed.** Not the working directory,
//! not the environment, not the time it has, not how much it may say. Every one
//! of them is a named field on a [`ProcessRequest`], stated by the caller, and
//! readable back before the run happens. Where a value could have had a
//! `Default`, it has a constructor argument instead.
//!
//! **There is no shell, and no door that takes one.** [`ProcessRequest`] holds
//! a program and a list of arguments, one element per argument, and nothing in
//! this module splits a string. A caller holding `npm install && npm test` has
//! a `String` and nowhere to put it. That is a statement about what **SURE**
//! assembles, and it is not the same as a fence around what runs: hand this
//! runner the path of a `.cmd` or a `.bat` and Windows starts a command
//! interpreter to run it, without having been asked. See "What is not here"
//! below for the measurement and for the two rules that bound how far it
//! reaches.
//!
//! # What is not here
//!
//! **This module is a mechanism with a shipped caller, and since `P18-T007` a
//! shipped *path* to it.** It has two callers.
//! [`crate::planned_check_runner`] runs the command behind each check the
//! enforcement admitted, and `sure check` reaches it through
//! [`crate::pipeline`] — so a product path reaches [`run`], which is the fact
//! this section used to deny. The boundary in front of it is not this module's:
//! a command arrives as an [`crate::enforce::AdmittedCommand`] or it does not
//! arrive, and under `inspect_only` — the mode a run starts in — none is
//! admitted, which is measured in `pipeline.rs`'s
//! `a_run_a_user_did_not_grant_starts_nothing`. [`crate::service`] is the other
//! caller: it starts a service by running a [`ProcessRequest`] on a thread and
//! stopping it through [`ProcessRequest::cancellation`], and **that** half is
//! still unreached by the product, because nothing builds a `Supervisor` yet.
//! `tests/spawn_sites.rs` holds the census of files that may name a
//! `Supervisor`, a `StartSmoke` or a `ProcessRequest`. The distinction it would
//! be easy to lose: a route reaches this runner now, and it is the one the
//! checks take, not the one a service would take.
//!
//! **Windows brings a command interpreter to a batch file.** Measured on
//! Windows 11 with Rust 1.98, and held by tests in `tests/process_runner.rs`:
//! naming `C:\path\to\thing.cmd` runs it, and the process that runs is
//! `C:\Windows\System32\cmd.exe`. A `.bat` is the same, and so is a `npm.cmd`
//! found on `PATH` — so a caller that names a batch file gets a shell, not one
//! SURE built and not one anything here can take back. Two rules bound how far
//! that reaches, and both are the operating system's, not this module's:
//!
//! - A name with **no** extension is completed with `.exe` and nothing else, so
//!   a bare `npm` is not found on a machine where `npm.cmd` is on `PATH`, and a
//!   bare `build` does not reach the `build.cmd` sitting beside it. This is the
//!   rule that keeps a project directory full of shims from being run by a name
//!   that merely looks like one of them.
//! - A `.ps1` is refused outright — `CreateProcess` starts images, and a script
//!   is not one. That failure is `not a valid Win32 application`, which is a
//!   different fact from the "cannot find the file" above and is worth keeping
//!   distinct: one is a script that is not there, the other a script the
//!   operating system will not start without being told how.
//!
//! **Whether a batch file may be named is not decided here.** Running one is
//! running project-controlled shell text, which is `P3-T004`'s classification
//! and `P3-T005`'s permission question, and `P3-T007` is the one that enforces
//! the answer in `inspect_only` mode. This module records what happens rather
//! than settling it: a mechanism that quietly refused `.cmd` would be making
//! policy inside the machinery, and one that quietly allowed it while the
//! documentation said "no shell" would be the false green this repository treats
//! as the worst outcome there is.
//!
//! **A caller may avoid naming the batch file.** Since 2026-10-22 the product
//! runner translates a known package-manager shim into `node` and the
//! JavaScript entry the shim itself runs (`crate::package_launcher`), so a Node
//! check can run without this module ever naming a `.cmd`. The rules above are
//! unchanged for every other name.
//!
//! **Nothing here confines a process.** A deadline and an output bound are
//! bounds on SURE's *patience and memory*, not a boundary around the program.
//! A child started with [`Environment::Only`] and an empty list can still read
//! every file the user can read and reach the network. Sandboxing is `P3-T008`'s
//! question and its answer is a container, described in its own acceptance as
//! limited isolation rather than a perfect sandbox.
//!
//! **Only Windows reaches a whole process tree.** [`Stop`] carries which of the
//! two happened, so this is never inferred from the fact that a stop was asked
//! for. The `terminate` module's own documentation has the reason and what it
//! would take to change it.
//!
//! # What a run is held to
//!
//! | Part | Where it is stated | What happens without it |
//! | --- | --- | --- |
//! | Program | [`ProcessRequest::new`] | cannot be built |
//! | Arguments | [`ProcessRequest::with_arguments`] | none, which is a run with no arguments |
//! | Working directory | [`ProcessRequest::new`] | cannot be built |
//! | Environment | [`ProcessRequest::with_environment`] | SURE's own is passed on |
//! | Deadline | [`Limits::new`] | cannot be built; there is no "no deadline" |
//! | Cancellation | [`ProcessRequest::new`] | cannot be built; see [`Cancellation`] |
//! | Output bound | [`Limits::new`] | cannot be built; see [`Limits`] |
//! | Stdin, pipes | this module, not a field | null in, piped out, always |
//!
//! The two rows that say "SURE's own is passed on" and "none" are the choices
//! that change nothing, and they are what [`Environment::inherited`] and an
//! empty argument list mean. They are still choices: the point of the rule is
//! that a caller who wanted something else had to say so, not that every
//! call site is verbose.

pub mod error;
pub mod outcome;
pub mod request;
pub(crate) mod terminate;

use std::fs;
use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

pub use error::ProcessError;
pub use outcome::{CapturedOutput, Outcome, Stop, Termination};
pub use request::{Cancellation, Environment, Limits, ProcessRequest};

/// How often the runner asks the operating system whether the process is done.
///
/// A poll rather than a blocking wait, because the deadline and the
/// cancellation have to be noticed while the process is still running, and
/// there is no `wait` that also takes a duration. A millisecond is short enough
/// that a deadline is honoured to within a millisecond of when it was asked
/// for, and long enough that a process running for a minute costs sixty
/// thousand system calls rather than sixty million.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// How long SURE waits for a stopped process's output streams to close.
///
/// They usually close at once: the process is gone, so the write ends are gone,
/// so the reader gets end-of-file. The case this exists for is a process that
/// started *another* process which inherited the same pipe — on a platform
/// where [`Stop::ProcessOnly`] is all SURE can reach, that one is still
/// running, still holds the pipe open, and would leave the reader blocked with
/// no end. A runner whose stop leads to a wait with no end is a check that
/// hangs, which is the failure this product treats as worse than an error.
///
/// So the wait is bounded, and running out of it is *reported* — in
/// [`CapturedOutput::unfinished`] — rather than being allowed to look like a
/// stream that ended.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Run `request` and report what came of it.
///
/// # Errors
///
/// [`ProcessError`] when the process did not run — a working directory that is
/// not a full path or is not there, a program the operating system would not
/// start, or a process that started and could not be followed. A process that
/// ran and was stopped is **not** an error: it is an [`Outcome`] whose
/// [`Termination`] says which stop it was, because the output of a stopped
/// process is the evidence for why it was stopped.
///
/// # What is checked before the process is started
///
/// The working directory, and whether a stop has already been asked for. Both
/// are checked here rather than left to the operating system, for a reason
/// each: a missing directory and a missing program produce the *same* error
/// from the operating system, so a directory that had moved would be reported
/// as a program that was not installed; and a run that was cancelled before it
/// began must not start and then be killed, because "it never started" and "it
/// started and was stopped" are different answers for a caller starting
/// something with an effect.
pub fn run(request: &ProcessRequest) -> Result<Outcome, ProcessError> {
    run_when_started(request, || {})
}

/// [`run`], with a callback for the moment the process is under way.
///
/// `started` is called **once**, on the run's own thread, after the operating
/// system has accepted the spawn *and* SURE has begun reading both streams —
/// which is the first instant at which this module can honestly say the process
/// is running. It is never called on any of the paths that return before a
/// spawn: a working directory that is not a full path, one that is not there or
/// is not a directory, and a stop already asked for. So a caller that hears
/// nothing back knows the run never began, and a caller that hears back knows
/// something is running that it must stop or outlive.
///
/// # What "started" does not mean
///
/// **Not that the program is ready for anything.** Nothing here knows whether
/// the process has reached its first line of work, has bound a port, or has
/// already exited. Readiness is a question about the program, and the answer to
/// it is a probe rather than a moment in this module.
///
/// **Not that the callback cannot be slow, or that it cannot block the run.**
/// It runs on the thread that drives the process, before the wait loop below
/// starts, so a callback that blocks delays the deadline being noticed and
/// delays both streams being drained — a `stdout` that fills its pipe during a
/// blocking callback stops the child. The caller's obligation is therefore that
/// this returns promptly; [`crate::service`]'s callback stores a flag and sends
/// on a channel, and does neither blocking nor allocating work beyond that.
pub fn run_when_started(
    request: &ProcessRequest,
    started: impl FnOnce(),
) -> Result<Outcome, ProcessError> {
    let working_directory = request.working_directory();
    if !working_directory.is_absolute() {
        return Err(ProcessError::WorkingDirectoryNotAbsolute {
            working_directory: working_directory.to_path_buf(),
        });
    }
    match fs::metadata(working_directory) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(ProcessError::WorkingDirectoryUnusable {
                working_directory: working_directory.to_path_buf(),
                message: String::from("it is there, and it is not a directory"),
            });
        }
        Err(error) => {
            return Err(ProcessError::WorkingDirectoryUnusable {
                working_directory: working_directory.to_path_buf(),
                message: error.to_string(),
            });
        }
    }

    if request.cancellation().is_cancelled() {
        return Ok(Outcome::never_started(request.program().to_os_string()));
    }

    let started_at = SystemTime::now();
    let clock = Instant::now();
    let stdout_bytes = request.limits().stdout_bytes();
    let stderr_bytes = request.limits().stderr_bytes();

    let mut child = request
        .command()
        .spawn()
        .map_err(|error| ProcessError::NotStarted {
            program: request.program().to_os_string(),
            working_directory: working_directory.to_path_buf(),
            message: error.to_string(),
        })?;

    // The readers start before anything waits on the process. A pipe holds
    // about 64 KiB, and a process that fills one while nobody is reading stops
    // there: reading and waiting have to happen at the same time or the run
    // deadlocks against itself.
    let stdout = reader_for(child.stdout.take(), stdout_bytes, "standard output");
    let stderr = reader_for(child.stderr.take(), stderr_bytes, "standard error");

    // Everything that can fail has been done, and both streams are being read.
    // This is the last point before the wait loop, and the only call: every
    // `return` above it is a run that never began.
    started();

    let deadline = clock + request.limits().timeout();
    let termination = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                break Termination::Exited {
                    code: status.code(),
                };
            }
            Ok(None) => {}
            Err(error) => {
                return Err(ProcessError::CouldNotBeWatched {
                    program: request.program().to_os_string(),
                    message: error.to_string(),
                });
            }
        }
        // The deadline is checked before the cancellation, and the order is a
        // choice worth naming: both are one poll interval wide, and when they
        // land in the same interval this reports the deadline. The deadline is
        // a number the caller wrote into the request before the run; a
        // cancellation is an event that may arrive at any moment. Reporting the
        // deadline keeps the outcome a function of the request rather than of
        // when somebody pressed something.
        if Instant::now() >= deadline {
            let stopped = stop(&mut child, request)?;
            break Termination::TimedOut { stopped };
        }
        if request.cancellation().is_cancelled() {
            let stopped = stop(&mut child, request)?;
            break Termination::Cancelled { stopped };
        }
        thread::sleep(POLL_INTERVAL);
    };

    let took = clock.elapsed();
    let draining = Instant::now() + DRAIN_GRACE;
    let stdout = collect(stdout, draining, "standard output");
    let stderr = collect(stderr, draining, "standard error");

    Ok(Outcome::new(
        request.program().to_os_string(),
        termination,
        stdout,
        stderr,
        started_at,
        took,
    ))
}

/// Stop the process, turning a failure to reap it into the one error that says
/// SURE does not know what happened.
fn stop(child: &mut std::process::Child, request: &ProcessRequest) -> Result<Stop, ProcessError> {
    terminate::stop(child).map_err(|error| ProcessError::CouldNotBeWatched {
        program: request.program().to_os_string(),
        message: error.to_string(),
    })
}

/// Start reading one of the process's streams, and hand back where its contents
/// will arrive.
///
/// A thread per stream, because both have to be read at once and a thread is
/// the only way to do that without a runtime this workspace does not carry.
/// `None` is a stream that was not piped, which the request cannot ask for and
/// which would still be a fact SURE must not paper over with an empty answer:
/// an unread stream is not an empty one.
fn reader_for<R: Read + Send + 'static>(
    pipe: Option<R>,
    limit: usize,
    name: &'static str,
) -> Receiver<CapturedOutput> {
    let (sender, receiver) = mpsc::channel();
    match pipe {
        Some(pipe) => {
            thread::spawn(move || {
                // A send that fails means the runner has already given up on
                // this stream and dropped its end, which happens only on the
                // path that reports the stream as unfinished. There is nothing
                // left to tell, and nobody to tell.
                let _ = sender.send(drain(pipe, limit));
            });
        }
        None => {
            let _ = sender.send(CapturedOutput::never_finished(format!(
                "SURE was not given {name} to read"
            )));
        }
    }
    receiver
}

/// Read a stream to its end, keeping the first `limit` bytes and counting the
/// rest.
///
/// **The reading goes on past the limit on purpose.** Stopping at the limit
/// would close the pipe, and a process writing to a closed pipe is killed by
/// the operating system for a reason that has nothing to do with what it was
/// doing — which would be reported as the program failing. So the bytes past
/// the limit are read and discarded, and how many there were is kept, so that a
/// truncated stream says so.
fn drain<R: Read>(mut source: R, limit: usize) -> CapturedOutput {
    let mut kept: Vec<u8> = Vec::new();
    let mut discarded: u64 = 0;
    let mut buffer = [0u8; 8192];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => return CapturedOutput::new(kept, discarded, None),
            Ok(read) => {
                let room = limit.saturating_sub(kept.len());
                let keep = room.min(read);
                kept.extend_from_slice(&buffer[..keep]);
                // `read` is at most 8192 and `keep` at most `read`, so the
                // subtraction cannot go negative.
                discarded += (read - keep) as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // A stream SURE could not finish reading is not an empty stream,
            // and this is where that is said. Returning what was read so far
            // without the error would be a partial answer wearing the shape of
            // a whole one.
            Err(error) => {
                return CapturedOutput::new(kept, discarded, Some(error.to_string()));
            }
        }
    }
}

/// Wait for a reader to finish, but not past `deadline`.
///
/// The two ways this can fail are different facts and they are reported
/// differently: a reader that is still going when the grace runs out means the
/// stream is still open somewhere, and a reader that went away means the thread
/// itself did not finish. Neither is allowed to become an empty string.
fn collect(
    receiver: Receiver<CapturedOutput>,
    deadline: Instant,
    name: &'static str,
) -> CapturedOutput {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(captured) => captured,
        Err(RecvTimeoutError::Timeout) => CapturedOutput::never_finished(format!(
            "SURE stopped reading {name}: it was still open after the process was stopped, \
             which means something the process started is still holding it. Whatever was \
             written is not all of what was written."
        )),
        Err(RecvTimeoutError::Disconnected) => CapturedOutput::never_finished(format!(
            "SURE stopped reading {name}: the reader did not finish"
        )),
    }
}

// The workspace forbids `unwrap`, `expect` and `panic` in shipped code, because
// a panic is a message nobody chose. A test is the one place they are the point:
// the panic *is* the report, and it names the value that was wrong.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A reader that hands over some bytes and then fails, the way a pipe does
    /// when the process at the other end is killed mid-write.
    struct Breaks {
        remaining: &'static [u8],
    }

    impl Read for Breaks {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.remaining.is_empty() {
                return Err(io::Error::other("the pipe broke"));
            }
            let take = buffer.len().min(self.remaining.len());
            buffer[..take].copy_from_slice(&self.remaining[..take]);
            self.remaining = &self.remaining[take..];
            Ok(take)
        }
    }

    /// A reader that is interrupted once, the way a read is when a signal
    /// arrives — and which must be retried rather than reported.
    struct InterruptedOnce {
        interrupted: bool,
        remaining: &'static [u8],
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let take = buffer.len().min(self.remaining.len());
            buffer[..take].copy_from_slice(&self.remaining[..take]);
            self.remaining = &self.remaining[take..];
            Ok(take)
        }
    }

    #[test]
    fn a_stream_shorter_than_the_bound_is_kept_whole_and_not_called_truncated() {
        let captured = drain(io::Cursor::new(b"a short thing".to_vec()), 1024);
        assert_eq!(captured.bytes(), b"a short thing");
        assert_eq!(captured.discarded_bytes(), 0);
        assert!(!captured.was_truncated());
        assert_eq!(captured.unfinished(), None);
        assert_eq!(captured.text_lossy(), "a short thing");
    }

    #[test]
    fn a_stream_longer_than_the_bound_keeps_the_beginning_and_counts_the_rest() {
        // Longer than one read, so the discarding happens across several
        // buffers rather than in a single call.
        let source: Vec<u8> = (0..40_000_u32).map(|n| (n % 251) as u8).collect();
        let captured = drain(io::Cursor::new(source.clone()), 1000);

        assert_eq!(
            captured.bytes(),
            &source[..1000],
            "the bound keeps the beginning, in the order the process wrote it"
        );
        assert_eq!(captured.discarded_bytes(), 39_000);
        assert!(captured.was_truncated());
        assert_eq!(
            captured.unfinished(),
            None,
            "the stream was read to its end; being cut short by the bound is a different fact"
        );
    }

    #[test]
    fn a_stream_that_is_exactly_the_bound_is_not_called_truncated() {
        // The boundary the flag turns on. Off by one here and every run that
        // said exactly as much as it was allowed would be reported as cut short,
        // which is the direction that makes a reader distrust a correct answer.
        let captured = drain(io::Cursor::new(vec![b'z'; 64]), 64);
        assert_eq!(captured.bytes().len(), 64);
        assert_eq!(captured.discarded_bytes(), 0);
        assert!(!captured.was_truncated());
    }

    #[test]
    fn one_byte_past_the_bound_is_already_a_stream_that_was_cut_short() {
        // The other side of the boundary above, and the reason it is a separate
        // test: "more than the bound" and "at least the bound" are one byte
        // apart, and a check written as `>= limit` would report every run that
        // said exactly as much as it was allowed as having been cut short. Both
        // directions of the same off-by-one are worth holding, because they fail
        // a reader in opposite ways — one hides a truncation, the other invents
        // one.
        let captured = drain(io::Cursor::new(vec![b'z'; 65]), 64);
        assert_eq!(captured.bytes().len(), 64);
        assert_eq!(captured.discarded_bytes(), 1);
        assert!(
            captured.was_truncated(),
            "one byte was discarded, so the stream is a beginning rather than a whole"
        );
    }

    #[test]
    fn a_read_that_fails_keeps_what_was_read_and_says_the_stream_did_not_end() {
        let captured = drain(
            Breaks {
                remaining: b"what got through",
            },
            1024,
        );
        assert_eq!(
            captured.bytes(),
            b"what got through",
            "bytes that arrived are still evidence, even though the stream broke"
        );
        assert!(
            captured.unfinished().is_some(),
            "a stream SURE could not finish reading is not an empty one, and must not read as one"
        );
        assert!(
            !captured.was_truncated(),
            "nothing was discarded by the bound; the stream failed, which is the other thing"
        );
    }

    #[test]
    fn a_read_that_is_interrupted_is_tried_again_rather_than_reported() {
        let captured = drain(
            InterruptedOnce {
                interrupted: false,
                remaining: b"all of it",
            },
            1024,
        );
        assert_eq!(
            captured.bytes(),
            b"all of it",
            "an interrupted read is not a failed one, and retrying is what makes the difference"
        );
        assert_eq!(captured.unfinished(), None);
    }
}
