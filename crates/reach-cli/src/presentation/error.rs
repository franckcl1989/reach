use std::fmt::Write as _;

use reach_core::{
    Cancelled, CapabilityReason, DnsExchangeEvidence, EvidenceFact, ExecutionError,
    ExecutionErrorKind, InputError, NameResolutionEvidenceOutcome, NeighborObservation,
    NeighborState,
};

use super::{Theme, bullets, field, headline, paragraph, section, terminal_escape};

pub(super) fn render_execution(error: &ExecutionError, theme: Theme) -> String {
    let mut output = String::new();
    headline(
        &mut output,
        theme,
        "× CHECK COULD NOT FINISH",
        Theme::failure,
    );
    let _ = writeln!(output);
    paragraph(&mut output, theme, execution_explanation(error.kind));
    let _ = writeln!(output);

    section(&mut output, theme, "WHAT TO DO");
    bullets(
        &mut output,
        theme,
        execution_actions(error.kind)
            .iter()
            .map(|value| (*value).to_owned()),
    );
    let _ = writeln!(output);

    section(&mut output, theme, "TECHNICAL DETAILS");
    field(&mut output, theme, "Error type", execution_type(error.kind));
    field(
        &mut output,
        theme,
        "Reason",
        terminal_escape(&error.safe_message),
    );
    for evidence in &error.partial_evidence {
        let detail = match &evidence.fact {
            EvidenceFact::Attempt(id) => format!("Attempt A{} completed before the error", id.0),
            EvidenceFact::InitialPath(value) => {
                format!("Snapshot path inference: {}", terminal_escape(value))
            }
            EvidenceFact::CurrentPath(value) => {
                format!("Targeted OS path query: {}", terminal_escape(value))
            }
            EvidenceFact::NeighborTransition { before, after } => {
                format!(
                    "Neighbor: {} -> {}",
                    neighbor_observation(*before),
                    neighbor_state(*after)
                )
            }
            EvidenceFact::NameResolution(evidence) => format!(
                "System name resolution: {}",
                name_resolution_outcome(evidence.outcome)
            ),
            EvidenceFact::DnsExchange(DnsExchangeEvidence::Formal(exchange)) => {
                format!(
                    "Formal DNS {} exchange with {}: {}",
                    dns_query_type(exchange.query_type),
                    exchange.endpoint.address,
                    terminal_escape(&exchange.query_name)
                )
            }
            EvidenceFact::DnsExchange(DnsExchangeEvidence::Diagnostic(id)) => {
                format!(
                    "Direct DNS diagnostic attempt A{} completed before the error",
                    id.0
                )
            }
            EvidenceFact::CapabilityUnavailable { capability, reason } => {
                format!(
                    "{} unavailable: {}",
                    terminal_escape(capability),
                    capability_reason(reason)
                )
            }
            EvidenceFact::SnapshotInconsistency(value) => {
                format!(
                    "Snapshot cross-check inconsistency: {}",
                    terminal_escape(value)
                )
            }
            EvidenceFact::SocketPathComparison(value) => {
                format!("Socket/path comparison: {}", terminal_escape(value))
            }
        };
        field(&mut output, theme, "Partial fact", detail);
    }
    field(&mut output, theme, "Exit code", "2");
    output
}

fn neighbor_observation(value: NeighborObservation) -> &'static str {
    match value {
        NeighborObservation::NotSampled => "not sampled",
        NeighborObservation::Observed(state) => neighbor_state(state),
        NeighborObservation::Unknown => "unknown",
        NeighborObservation::Unavailable => "unavailable",
    }
}

fn name_resolution_outcome(value: NameResolutionEvidenceOutcome) -> &'static str {
    match value {
        NameResolutionEvidenceOutcome::Succeeded { .. } => "completed with usable addresses",
        NameResolutionEvidenceOutcome::SucceededWithoutUsableAddress => {
            "completed without a usable IP address"
        }
        NameResolutionEvidenceOutcome::NegativeWithoutUsableAddress => {
            "returned no usable IPv4 or IPv6 address"
        }
        NameResolutionEvidenceOutcome::NonDefinitiveFailure => "failed without a definitive answer",
    }
}

const fn dns_query_type(value: reach_core::DnsQueryType) -> &'static str {
    match value {
        reach_core::DnsQueryType::A => "A",
        reach_core::DnsQueryType::Aaaa => "AAAA",
    }
}

fn neighbor_state(value: NeighborState) -> &'static str {
    match value {
        NeighborState::Absent => "absent (no matching entry)",
        NeighborState::Resolving => "resolving",
        NeighborState::Usable => "usable",
        NeighborState::TerminalFailure => "terminal failure",
        NeighborState::Unknown => "unknown",
    }
}

fn capability_reason(value: &CapabilityReason) -> String {
    match value {
        CapabilityReason::NotExposedByOperatingSystem => {
            "not exposed by the operating system".to_owned()
        }
        CapabilityReason::OrdinaryUserPermissionDenied => {
            "ordinary-user permission was denied".to_owned()
        }
        CapabilityReason::SnapshotInconsistent => {
            "a captured-fact cross-reference inconsistency was found".to_owned()
        }
        CapabilityReason::QuerySemanticsUnavailable => {
            "the required read-only query is unavailable".to_owned()
        }
        CapabilityReason::AttemptCorrelationUnavailable => {
            "responses cannot be correlated reliably to their attempt".to_owned()
        }
        CapabilityReason::UnsupportedEnvironment => {
            "the current environment is unsupported".to_owned()
        }
        CapabilityReason::Other(value) => terminal_escape(value),
    }
}

pub(super) fn render_cancelled(cancelled: &Cancelled, theme: Theme) -> String {
    let mut output = String::new();
    headline(&mut output, theme, "! CHECK CANCELLED", Theme::warning);
    let _ = writeln!(output);
    paragraph(
        &mut output,
        theme,
        "Reach stopped because the check was interrupted. No final network result was produced.",
    );
    let _ = writeln!(output);
    section(&mut output, theme, "TECHNICAL DETAILS");
    field(
        &mut output,
        theme,
        "Reason",
        terminal_escape(&cancelled.safe_message),
    );
    field(&mut output, theme, "Exit code", "130");
    output
}

pub(super) fn render_input(
    error: &InputError,
    address: &str,
    port: Option<&str>,
    theme: Theme,
) -> String {
    let (title, explanation, action) = match error {
        InputError::EmptyAddress => (
            "ADDRESS IS MISSING",
            "Reach needs a hostname or IP address before it can start a check.",
            "Enter a hostname, IPv4 address, or IPv6 address.",
        ),
        InputError::InvalidAddress => (
            "ADDRESS IS NOT VALID",
            "Reach could not read the address as a hostname, IPv4 address, or IPv6 address.",
            "Remove prefixes such as http://, paths such as /login, and embedded ports such as :443.",
        ),
        InputError::InvalidIpv6Scope => (
            "IPV6 SCOPE IS NOT VALID",
            "A link-local IPv6 scope must identify one local network interface.",
            "Use an interface index or name after %, for example fe80::1%12.",
        ),
        InputError::InvalidPortSyntax => (
            "TCP PORT IS NOT VALID",
            "The TCP port must contain digits only.",
            "Use a number from 1 through 65535, for example 443.",
        ),
        InputError::PortOutOfRange => (
            "TCP PORT IS OUT OF RANGE",
            "A TCP port must be a number from 1 through 65535.",
            "Correct the port number and run the check again.",
        ),
    };

    let mut output = String::new();
    headline(&mut output, theme, &format!("× {title}"), Theme::failure);
    let _ = writeln!(output);
    paragraph(&mut output, theme, explanation);
    let _ = writeln!(output);
    section(&mut output, theme, "WHAT TO DO");
    bullets(&mut output, theme, [action.to_owned()]);
    let _ = writeln!(output);
    write_usage(&mut output, theme);
    let _ = writeln!(output);
    section(&mut output, theme, "TECHNICAL DETAILS");
    field(&mut output, theme, "Address", terminal_escape(address));
    if let Some(port) = port {
        field(&mut output, theme, "Port", terminal_escape(port));
    }
    field(&mut output, theme, "Exit code", "2");
    output
}

pub(super) fn render_command(missing_address: bool, theme: Theme) -> String {
    let mut output = String::new();
    let title = if missing_address {
        "× ADDRESS IS MISSING"
    } else {
        "× COMMAND IS NOT VALID"
    };
    headline(&mut output, theme, title, Theme::failure);
    let _ = writeln!(output);
    if missing_address {
        paragraph(
            &mut output,
            theme,
            "Reach needs a hostname or IP address before it can start a check.",
        );
    } else {
        paragraph(
            &mut output,
            theme,
            "Reach accepts one address and, optionally, one TCP port.",
        );
    }
    let _ = writeln!(output);
    write_usage(&mut output, theme);
    let _ = writeln!(output);
    section(&mut output, theme, "TECHNICAL DETAILS");
    field(&mut output, theme, "Exit code", "2");
    output
}

pub(super) fn render_startup(reason: &str, theme: Theme) -> String {
    let mut output = String::new();
    headline(
        &mut output,
        theme,
        "× CHECK COULD NOT START",
        Theme::failure,
    );
    let _ = writeln!(output);
    paragraph(
        &mut output,
        theme,
        "Reach could not install the operating-system handler used to stop a running check safely.",
    );
    let _ = writeln!(output);
    section(&mut output, theme, "WHAT TO DO");
    bullets(
        &mut output,
        theme,
        ["Close other copies of Reach, then run the command again.".to_owned()],
    );
    let _ = writeln!(output);
    section(&mut output, theme, "TECHNICAL DETAILS");
    field(&mut output, theme, "Reason", terminal_escape(reason));
    field(&mut output, theme, "Exit code", "2");
    output
}

pub(super) fn render_output_failure(reason: &str, theme: Theme) -> String {
    let mut output = String::new();
    headline(
        &mut output,
        theme,
        "× REPORT COULD NOT BE WRITTEN",
        Theme::failure,
    );
    let _ = writeln!(output);
    paragraph(
        &mut output,
        theme,
        "The network check finished, but Reach could not write the complete report to its output destination.",
    );
    let _ = writeln!(output);
    section(&mut output, theme, "TECHNICAL DETAILS");
    field(&mut output, theme, "Reason", terminal_escape(reason));
    field(&mut output, theme, "Exit code", "2");
    output
}

fn write_usage(output: &mut String, theme: Theme) {
    section(output, theme, "USAGE");
    paragraph(output, theme, "reach <ADDRESS> [PORT]");
    let _ = writeln!(output);
    paragraph(output, theme, "Examples:");
    bullets(
        output,
        theme,
        [
            "reach example.com".to_owned(),
            "reach example.com 443".to_owned(),
            "reach 192.0.2.10 22".to_owned(),
            "reach fe80::1%12".to_owned(),
        ],
    );
}

const fn execution_explanation(kind: ExecutionErrorKind) -> &'static str {
    match kind {
        ExecutionErrorKind::InvalidInput => {
            "Reach could not understand the requested address or TCP port."
        }
        ExecutionErrorKind::ScopedIpv6BindingFailed => {
            "Reach could not match the IPv6 scope to a local network interface."
        }
        ExecutionErrorKind::RequiredCapabilityUnavailable => {
            "This system cannot perform a check that is required for a reliable answer."
        }
        ExecutionErrorKind::ResourceExhausted => {
            "This computer ran out of local networking resources before Reach could finish."
        }
        ExecutionErrorKind::InternalFailure => {
            "Reach encountered an internal or operating-system error before it could produce a reliable answer."
        }
    }
}

const fn execution_type(kind: ExecutionErrorKind) -> &'static str {
    match kind {
        ExecutionErrorKind::InvalidInput => "Invalid input",
        ExecutionErrorKind::ScopedIpv6BindingFailed => "IPv6 scope binding failed",
        ExecutionErrorKind::RequiredCapabilityUnavailable => "Required capability unavailable",
        ExecutionErrorKind::ResourceExhausted => "Local resources exhausted",
        ExecutionErrorKind::InternalFailure => "Internal execution failure",
    }
}

const fn execution_actions(kind: ExecutionErrorKind) -> &'static [&'static str] {
    match kind {
        ExecutionErrorKind::InvalidInput => &[
            "Check the address and optional TCP port, then run the command again.",
            "Run reach --help to see accepted input examples.",
        ],
        ExecutionErrorKind::ScopedIpv6BindingFailed => &[
            "Check that the interface name or index after % still exists on this computer.",
            "Run the command again with the correct scope, for example fe80::1%12.",
        ],
        ExecutionErrorKind::RequiredCapabilityUnavailable => &[
            "Read the technical reason below; this check cannot be replaced with a different protocol without changing its meaning.",
            "Send this report to your support team if the required capability should be available on this computer.",
        ],
        ExecutionErrorKind::ResourceExhausted => &[
            "Close applications that are using many network connections, then run the check again.",
            "If the problem continues, send this report to your support team.",
        ],
        ExecutionErrorKind::InternalFailure => &[
            "Run the same command once more.",
            "If it fails again, send this result and the command you used to the Reach maintainer or your support team.",
        ],
    }
}
