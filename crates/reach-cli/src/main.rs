#![forbid(unsafe_code)]

use std::{
    io::{self, IsTerminal, Write},
    process::ExitCode,
};

use clap::{CommandFactory, Parser, error::ErrorKind};
use reach_core::{Cancelled, DiagnosticResult, ExitStatus, parse_request, run_diagnostic};
use reach_platform::PlatformDiagnosticIo;
use tokio_util::sync::CancellationToken;

mod presentation;

#[derive(Debug, Parser)]
#[command(
    name = "reach",
    version,
    about = "Diagnose network connectivity to an address and optional TCP port"
)]
struct Cli {
    /// Hostname, IPv4 literal, or IPv6 literal (optionally with a scope).
    #[arg(allow_hyphen_values = true)]
    address: String,
    /// TCP port in the range 1..=65535.
    #[arg(allow_hyphen_values = true)]
    port: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let mut stdout = io::stdout().lock();
            let rendered = if error.kind() == ErrorKind::DisplayHelp {
                Cli::command().render_long_help().to_string()
            } else {
                format!("reach {}\n", env!("CARGO_PKG_VERSION"))
            };
            return exit_after_write(stdout.write_all(rendered.as_bytes()), ExitStatus::Success);
        }
        Err(_) => {
            let _ = writeln!(
                io::stderr().lock(),
                "reach: invalid command line; expected reach <address> [port]"
            );
            return ExitCode::from(ExitStatus::ExecutionError.code());
        }
    };

    let parsed = match parse_request(&cli.address, cli.port.as_deref()) {
        Ok(parsed) => parsed,
        Err(error) => {
            // Core input errors are closed enums whose Display text never
            // interpolates the untrusted argument.
            let _ = writeln!(io::stderr().lock(), "reach: {error}");
            return ExitCode::from(ExitStatus::ExecutionError.code());
        }
    };

    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_cancellation.cancel()) {
        let _ = writeln!(
            io::stderr().lock(),
            "reach: unable to install cancellation handler: {}",
            presentation::terminal_escape(&error.to_string())
        );
        return ExitCode::from(ExitStatus::ExecutionError.code());
    }
    let progress = Progress::start();
    let result = run_diagnostic(parsed, &PlatformDiagnosticIo::new(), &cancellation).await;
    progress.finish();
    let result = apply_cancellation_priority(result, cancellation.is_cancelled());

    let status = result.exit_status();
    let write_result = match &result {
        DiagnosticResult::Completed(_) => {
            let mut stdout = io::stdout().lock();
            presentation::write_result(&result, &mut stdout)
        }
        DiagnosticResult::ExecutionError(_) | DiagnosticResult::Cancelled(_) => {
            let mut stderr = io::stderr().lock();
            presentation::write_result(&result, &mut stderr)
        }
    };
    exit_after_write(write_result, status)
}

fn apply_cancellation_priority(result: DiagnosticResult, cancelled: bool) -> DiagnosticResult {
    if cancelled {
        DiagnosticResult::Cancelled(Cancelled {
            safe_message: "interrupted".into(),
        })
    } else {
        result
    }
}

fn exit_after_write(result: io::Result<()>, status: ExitStatus) -> ExitCode {
    if let Err(error) = result {
        let _ = writeln!(
            io::stderr().lock(),
            "reach: unable to write diagnostic output: {}",
            presentation::terminal_escape(&error.to_string())
        );
        return ExitCode::from(status_after_write_failure(status).code());
    }
    ExitCode::from(status.code())
}

const fn status_after_write_failure(status: ExitStatus) -> ExitStatus {
    if matches!(status, ExitStatus::Cancelled) {
        ExitStatus::Cancelled
    } else {
        ExitStatus::ExecutionError
    }
}

struct Progress {
    visible: bool,
}

impl Progress {
    fn start() -> Self {
        let visible = io::stderr().is_terminal();
        let _ = write_progress_start(visible, &mut io::stderr());
        Self { visible }
    }

    fn finish(self) {
        let _ = write_progress_finish(self.visible, &mut io::stderr());
    }
}

fn write_progress_start(visible: bool, writer: &mut impl Write) -> io::Result<()> {
    if visible {
        writer.write_all(b"reach: diagnosing...\r")?;
        writer.flush()?;
    }
    Ok(())
}

fn write_progress_finish(visible: bool, writer: &mut impl Write) -> io::Result<()> {
    if visible {
        writer.write_all(b"                       \r")?;
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use reach_core::{DiagnosticResult, ExitStatus};

    use super::{
        Cli, apply_cancellation_priority, status_after_write_failure, write_progress_finish,
        write_progress_start,
    };

    #[test]
    fn cli_shape_has_exactly_two_positional_arguments() {
        let parsed =
            Cli::try_parse_from(["reach", "example.com", "443"]).expect("valid command shape");
        assert_eq!(parsed.address, "example.com");
        assert_eq!(parsed.port.as_deref(), Some("443"));
        let parsed = Cli::try_parse_from(["reach", "example.com", "-1"])
            .expect("port value semantics belong to Core");
        assert_eq!(parsed.port.as_deref(), Some("-1"));
        assert!(Cli::try_parse_from(["reach", "a", "1", "extra"]).is_err());
    }

    #[test]
    fn progress_is_stderr_text_only_for_a_tty() {
        let mut redirected = Vec::new();
        write_progress_start(false, &mut redirected).expect("in-memory writer");
        write_progress_finish(false, &mut redirected).expect("in-memory writer");
        assert!(redirected.is_empty());

        let mut terminal = Vec::new();
        write_progress_start(true, &mut terminal).expect("in-memory writer");
        write_progress_finish(true, &mut terminal).expect("in-memory writer");
        assert_eq!(terminal, b"reach: diagnosing...\r                       \r");
        assert!(!terminal.contains(&0x1b));
    }

    #[test]
    fn cancellation_priority_survives_a_failure_to_write_its_explanation() {
        assert_eq!(
            status_after_write_failure(ExitStatus::Cancelled),
            ExitStatus::Cancelled
        );
        assert_eq!(
            status_after_write_failure(ExitStatus::Success),
            ExitStatus::ExecutionError
        );
    }

    #[test]
    fn cancellation_observed_after_core_completion_still_has_top_priority() {
        let result = DiagnosticResult::ExecutionError(reach_core::ExecutionError {
            kind: reach_core::ExecutionErrorKind::InternalFailure,
            safe_message: "synthetic".into(),
            partial_evidence: Vec::new(),
        });
        assert!(matches!(
            apply_cancellation_priority(result, true),
            DiagnosticResult::Cancelled(_)
        ));
    }
}
