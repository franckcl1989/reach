#![forbid(unsafe_code)]

use std::{
    io::{self, IsTerminal},
    process::ExitCode,
    time::Duration,
};

use clap::{Parser, error::ErrorKind};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use reach_core::{Cancelled, DiagnosticResult, ExitStatus, parse_request, run_diagnostic};
use reach_platform::PlatformDiagnosticIo;
use tokio_util::sync::CancellationToken;

mod presentation;

#[derive(Debug, Parser)]
#[command(
    name = "reach",
    bin_name = "reach",
    version,
    about = "Check whether an address or TCP port is reachable",
    long_about = "Check whether a hostname or IP address responds. Add a TCP port to test whether a TCP connection to that exact port can be established.",
    after_help = "Examples:\n  reach example.com\n  reach example.com 443\n  reach 192.0.2.10 22\n  reach fe80::1%12\n\nWithout PORT, Reach uses ICMP Echo and does not test a website or application.\nWith PORT, Reach tests only the TCP connection and sends no application data."
)]
struct Cli {
    /// Hostname, IPv4 address, or IPv6 address (optionally with a %scope).
    #[arg(allow_hyphen_values = true)]
    address: String,
    /// Optional TCP port from 1 through 65535.
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
            return exit_after_write(error.print(), ExitStatus::Success);
        }
        Err(error) => {
            let missing_address = error.kind() == ErrorKind::MissingRequiredArgument;
            let mut stderr = anstream::stderr();
            let write = presentation::write_command_error(
                missing_address,
                &mut stderr,
                presentation::Theme::terminal(),
            );
            return exit_after_write(write, ExitStatus::ExecutionError);
        }
    };

    let parsed = match parse_request(&cli.address, cli.port.as_deref()) {
        Ok(parsed) => parsed,
        Err(error) => {
            let mut stderr = anstream::stderr();
            let write = presentation::write_input_error(
                &error,
                &cli.address,
                cli.port.as_deref(),
                &mut stderr,
                presentation::Theme::terminal(),
            );
            return exit_after_write(write, ExitStatus::ExecutionError);
        }
    };

    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_cancellation.cancel()) {
        let mut stderr = anstream::stderr();
        let write = presentation::write_startup_error(
            &error.to_string(),
            &mut stderr,
            presentation::Theme::terminal(),
        );
        return exit_after_write(write, ExitStatus::ExecutionError);
    }
    let progress = Progress::start();
    let result = run_diagnostic(parsed, &PlatformDiagnosticIo::new(), &cancellation).await;
    progress.finish();
    let result = apply_cancellation_priority(result, cancellation.is_cancelled());

    let status = result.exit_status();
    let write_result = match &result {
        DiagnosticResult::Completed(_) => {
            let mut stdout = anstream::stdout();
            presentation::write_result(&result, &mut stdout, presentation::Theme::terminal())
        }
        DiagnosticResult::ExecutionError(_) | DiagnosticResult::Cancelled(_) => {
            let mut stderr = anstream::stderr();
            presentation::write_result(&result, &mut stderr, presentation::Theme::terminal())
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
        let mut stderr = anstream::stderr();
        let _ = presentation::write_output_error(
            &error.to_string(),
            &mut stderr,
            presentation::Theme::terminal(),
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

struct Progress(ProgressBar);

impl Progress {
    fn start() -> Self {
        let visible = io::stderr().is_terminal();
        let progress = if visible {
            let progress =
                ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(12));
            if let Ok(style) = ProgressStyle::with_template(
                "{spinner:.cyan} Checking network connectivity… {elapsed_precise}",
            ) {
                progress.set_style(style.tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "));
            }
            progress.enable_steady_tick(Duration::from_millis(80));
            progress
        } else {
            ProgressBar::hidden()
        };
        Self(progress)
    }

    fn finish(self) {
        self.0.finish_and_clear();
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use reach_core::{DiagnosticResult, ExitStatus};

    use super::{Cli, apply_cancellation_priority, status_after_write_failure};

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
