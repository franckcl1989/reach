use std::{fmt::Write as _, io};

use reach_core::{
    AggregateOutcome, Attempt, AttemptOutcome, AttemptSubject, CapabilityReason,
    CompletedDiagnostic, Conclusion, DiagnosticResult, DnsAttemptResult, Evidence, EvidenceFact,
    IcmpAttemptResult, IcmpMessageKind, PrimaryOutcome, TargetIp, TcpAttemptResult,
};

pub fn write_result(result: &DiagnosticResult, output: &mut impl io::Write) -> io::Result<()> {
    match result {
        DiagnosticResult::Completed(completed) => {
            output.write_all(render_completed(completed).as_bytes())
        }
        DiagnosticResult::ExecutionError(error) => writeln!(
            output,
            "reach: execution error: {}",
            terminal_escape(&error.safe_message)
        ),
        DiagnosticResult::Cancelled(cancelled) => writeln!(
            output,
            "reach: cancelled: {}",
            terminal_escape(&cancelled.safe_message)
        ),
    }
}

fn render_completed(completed: &CompletedDiagnostic) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "result: {}",
        aggregate_label(completed.aggregate_outcome)
    );
    let _ = writeln!(
        output,
        "conclusion: {}",
        conclusion_label(&completed.conclusion)
    );

    if completed.targets.is_empty() {
        let _ = writeln!(
            output,
            "address: {}",
            terminal_escape(&completed.request.original_address)
        );
    } else {
        for target in &completed.targets {
            let _ = writeln!(
                output,
                "target {}: {} ({})",
                target_label(
                    &target.target,
                    completed.request.port.map(|port| port.get())
                ),
                outcome_label(target.primary_outcome),
                conclusion_label(&target.conclusion)
            );
            for diagnostic in &target.diagnostic_conclusions {
                let _ = writeln!(output, "  diagnostic: {}", conclusion_label(diagnostic));
            }
        }
    }

    if !completed.key_evidence.is_empty() {
        let _ = writeln!(output, "key evidence:");
        for evidence in &completed.key_evidence {
            let _ = writeln!(output, "- {}", evidence_label(evidence, completed));
        }
    }
    output
}

fn aggregate_label(outcome: AggregateOutcome) -> &'static str {
    match outcome {
        AggregateOutcome::AllSatisfied => "all targets satisfied",
        AggregateOutcome::SatisfiedWithAnomaly => "satisfied with anomaly",
        AggregateOutcome::Mixed => "mixed target results",
        AggregateOutcome::NoneCleanlySatisfied => "network check not satisfied",
        AggregateOutcome::NoFormalTargets => "no formal target was formed",
    }
}

fn outcome_label(outcome: PrimaryOutcome) -> &'static str {
    match outcome {
        PrimaryOutcome::Satisfied => "satisfied",
        PrimaryOutcome::SatisfiedWithAnomaly => "satisfied with anomaly",
        PrimaryOutcome::NotSatisfied => "not satisfied",
        PrimaryOutcome::Indeterminate => "indeterminate",
    }
}

fn conclusion_label(conclusion: &Conclusion) -> &'static str {
    match conclusion {
        Conclusion::TcpConnectSucceeded => "TCP connection succeeded",
        Conclusion::TcpConnectSucceededAfterTimeout => {
            "TCP connection succeeded after an earlier timeout"
        }
        Conclusion::TcpConnectionRefused => "TCP connection was refused",
        Conclusion::TcpExplicitFailure => "TCP connection failed explicitly",
        Conclusion::TcpConnectTimedOut => "TCP connection timed out twice",
        Conclusion::TcpTimedOutButTargetIcmpResponded => {
            "TCP timed out, but the target responded to ICMP"
        }
        Conclusion::TcpTimedOutWithExplicitIcmpResult => {
            "TCP timed out and target ICMP returned an explicit result"
        }
        Conclusion::IcmpEchoReplied => "target replied to ICMP Echo",
        Conclusion::IcmpEchoRepliedAfterTimeout => {
            "target replied to ICMP Echo after an earlier timeout"
        }
        Conclusion::IcmpExplicitFailure => "ICMP check returned an explicit failure",
        Conclusion::IcmpEchoTimedOut => "ICMP Echo timed out twice",
        Conclusion::IcmpResponseIndeterminate => "ICMP response was indeterminate",
        Conclusion::DefinitiveNoPath => "the initial network snapshot proves no usable path",
        Conclusion::NeighborResolutionFailed => "required local Neighbor resolution failed",
        Conclusion::NeighborResolutionIndeterminate => {
            "required local Neighbor resolution was indeterminate"
        }
        Conclusion::FirstHopResponded => "the current first hop responded",
        Conclusion::MultiplePathRespondersObserved => {
            "multiple responder addresses were observed at one path hop"
        }
        Conclusion::PathEndpointResponded => {
            "later path diagnosis observed a correlated endpoint response"
        }
        Conclusion::PathExplicitlyTerminated => {
            "path diagnosis ended with a correlated explicit error"
        }
        Conclusion::PathResponseIndeterminate => {
            "path diagnosis received a correlated but indeterminate response"
        }
        Conclusion::PathLimitReachedWithoutEndpointEvidence => {
            "path limit reached without endpoint evidence"
        }
        Conclusion::HostnameResolved => "system resolver formed target addresses",
        Conclusion::HostnameNoFormalTargets => "system resolver formed no usable target address",
        Conclusion::HostnameResolutionDefinitiveNegative => {
            "system resolver returned a definitive negative result"
        }
        Conclusion::HostnameResolutionIndeterminate => {
            "system resolver failure remained indeterminate"
        }
        Conclusion::AllTargetsSatisfied => "all formal targets were cleanly satisfied",
        Conclusion::TargetsSatisfiedWithAnomaly => {
            "all formal targets eventually responded, with retained anomalies"
        }
        Conclusion::TargetResultsMixed => "formal targets produced different outcomes",
        Conclusion::NoTargetCleanlySatisfied => "no formal target was cleanly satisfied",
        Conclusion::CapabilityLimited => "diagnostic depth was capability-limited",
    }
}

fn evidence_label(evidence: &Evidence, completed: &CompletedDiagnostic) -> String {
    match &evidence.fact {
        EvidenceFact::Attempt(id) => completed
            .targets
            .iter()
            .flat_map(|target| target.attempts.iter())
            .chain(
                completed
                    .resolver_diagnostics
                    .iter()
                    .flat_map(|diagnostic| diagnostic.attempts.iter()),
            )
            .find(|attempt| attempt.id == *id)
            .map_or_else(|| format!("attempt {} was retained", id.0), attempt_label),
        EvidenceFact::InitialPath(value) => {
            format!("initial path: {}", terminal_escape(value))
        }
        EvidenceFact::CurrentPath(value) => {
            format!("current path: {}", terminal_escape(value))
        }
        EvidenceFact::NeighborTransition { before, after } => format!(
            "Neighbor state: {} -> {}",
            before.map_or("unknown", neighbor_state_label),
            neighbor_state_label(*after)
        ),
        EvidenceFact::SystemResolverResult(value) => {
            format!("system resolver: {}", terminal_escape(value))
        }
        EvidenceFact::DirectDnsResult(value) => {
            format!("direct DNS diagnostic: {}", terminal_escape(value))
        }
        EvidenceFact::CapabilityUnavailable { capability, reason } => format!(
            "{} unavailable: {}",
            terminal_escape(capability),
            capability_reason_label(reason)
        ),
        EvidenceFact::SnapshotInconsistency(value) => {
            format!("snapshot inconsistency: {}", terminal_escape(value))
        }
        EvidenceFact::SocketPathComparison(value) => {
            format!("socket/path comparison: {}", terminal_escape(value))
        }
    }
}

fn attempt_label(attempt: &Attempt) -> String {
    let subject = match &attempt.subject {
        AttemptSubject::Target(target) => target_label(target, None),
        AttemptSubject::NextHop(neighbor) => neighbor.address.to_string(),
        AttemptSubject::Resolver {
            endpoint,
            query_name,
        } => format!("{} for {}", endpoint, terminal_escape(query_name)),
    };
    let result = match &attempt.outcome {
        AttemptOutcome::Tcp(result) => tcp_result_label(result),
        AttemptOutcome::Icmp(result) => icmp_result_label(result),
        AttemptOutcome::Dns(result) => dns_result_label(result),
    };
    format!("{}: {}", subject, result)
}

fn tcp_result_label(result: &TcpAttemptResult) -> String {
    match result {
        TcpAttemptResult::Connected { .. } => "TCP connected".into(),
        TcpAttemptResult::ConnectionRefused => "TCP connection refused".into(),
        TcpAttemptResult::NoRoute => "TCP failed: no route".into(),
        TcpAttemptResult::NetworkUnreachable => "TCP failed: network unreachable".into(),
        TcpAttemptResult::HostUnreachable => "TCP failed: host unreachable".into(),
        TcpAttemptResult::PermissionDenied => "TCP failed: permission denied".into(),
        TcpAttemptResult::ResourceExhausted => "TCP failed: local resources exhausted".into(),
        TcpAttemptResult::OtherExplicitError { os_code } => {
            format!("TCP failed explicitly (OS code {os_code:?})")
        }
        TcpAttemptResult::Timeout => "TCP timed out".into(),
    }
}

fn icmp_result_label(result: &IcmpAttemptResult) -> String {
    match result {
        IcmpAttemptResult::Message {
            kind, responder, ..
        } => format!("ICMP {} from {}", icmp_kind_label(*kind), responder),
        IcmpAttemptResult::Messages(messages) => {
            let responders = messages
                .iter()
                .map(|message| message.responder.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{} correlated ICMP messages from [{}]",
                messages.len(),
                responders
            )
        }
        IcmpAttemptResult::ExplicitNetworkError { os_code } => {
            format!("ICMP failed explicitly (OS code {os_code:?})")
        }
        IcmpAttemptResult::Timeout => "ICMP timed out".into(),
    }
}

fn icmp_kind_label(kind: IcmpMessageKind) -> &'static str {
    match kind {
        IcmpMessageKind::EchoReply => "Echo Reply",
        IcmpMessageKind::DestinationUnreachable => "Destination Unreachable",
        IcmpMessageKind::TimeExceeded => "Time Exceeded",
        IcmpMessageKind::PacketTooBig => "Packet Too Big",
        IcmpMessageKind::ParameterProblem => "Parameter Problem",
        IcmpMessageKind::Other => "message",
    }
}

fn neighbor_state_label(state: reach_core::NeighborState) -> &'static str {
    match state {
        reach_core::NeighborState::Resolving => "resolving",
        reach_core::NeighborState::Usable => "usable",
        reach_core::NeighborState::TerminalFailure => "terminal failure",
        reach_core::NeighborState::Unknown => "unknown",
    }
}

fn dns_result_label(result: &DnsAttemptResult) -> String {
    match result {
        DnsAttemptResult::Response {
            response_code,
            addresses,
            aliases,
            truncated,
        } => format!(
            "DNS response code {response_code}, {} address(es), {} alias(es), truncated={truncated}",
            addresses.len(),
            aliases.len()
        ),
        DnsAttemptResult::TransportError { os_code } => {
            format!("DNS transport failed (OS code {os_code:?})")
        }
        DnsAttemptResult::ProtocolError => "DNS protocol error".into(),
        DnsAttemptResult::Timeout => "DNS timed out".into(),
    }
}

fn target_label(target: &TargetIp, port: Option<u16>) -> String {
    let mut label = target.address.to_string();
    if let Some(scope) = &target.scope {
        let _ = write!(label, "%{}", scope.index);
    }
    if let Some(port) = port {
        if target.address.is_ipv6() {
            label = format!("[{label}]:{port}");
        } else {
            let _ = write!(label, ":{port}");
        }
    }
    label
}

fn capability_reason_label(reason: &CapabilityReason) -> String {
    match reason {
        CapabilityReason::NotExposedByOperatingSystem => {
            "not exposed by the operating system".into()
        }
        CapabilityReason::OrdinaryUserPermissionDenied => "ordinary-user permission denied".into(),
        CapabilityReason::SnapshotInconsistent => "snapshot was inconsistent".into(),
        CapabilityReason::QuerySemanticsUnavailable => {
            "required query semantics unavailable".into()
        }
        CapabilityReason::AttemptCorrelationUnavailable => "attempt correlation unavailable".into(),
        CapabilityReason::UnsupportedEnvironment => "unsupported environment".into(),
        CapabilityReason::Other(value) => terminal_escape(value),
    }
}

/// Encodes every non-ASCII or control character with Rust's standard,
/// deterministic character escaping. This preserves Core facts while
/// preventing newlines, ANSI ESC, bidi controls, and terminal state changes.
pub fn terminal_escape(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, time::Duration};

    use reach_core::{
        Cancelled, CapabilityReason, CapabilityValue, CompletedDiagnostic, Conclusion,
        DiagnosticResult, Evidence, ExecutionError, ExecutionErrorKind, HostnameResolutionOutcome,
        InitialNetworkSnapshot, InterfaceFact, PrimaryOutcome, Provenance, ProvenanceSource,
        ResolverAddressSet, ResolverConfiguration, RouteFact, TargetDiagnostic, TargetIp,
        TargetNetworkFacts, analyze_initial_path, parse_request,
    };

    use super::*;

    #[test]
    fn terminal_text_cannot_inject_lines_ansi_or_bidi_controls() {
        assert_eq!(
            terminal_escape("safe\n\x1b[31m\u{202e}tail"),
            "safe\\n\\u{1b}[31m\\u{202e}tail"
        );
    }

    #[test]
    fn execution_error_is_encoded_for_its_selected_writer() {
        let result = DiagnosticResult::ExecutionError(ExecutionError {
            kind: ExecutionErrorKind::InternalFailure,
            safe_message: "bad\n\x1b[2J".into(),
            partial_evidence: Vec::new(),
        });
        let mut output = Vec::new();
        write_result(&result, &mut output).expect("render succeeds");
        assert_eq!(
            String::from_utf8(output).expect("UTF-8 output"),
            "reach: execution error: bad\\n\\u{1b}[2J\n"
        );
    }

    #[test]
    fn cancellation_has_a_plain_text_terminal() {
        let result = DiagnosticResult::Cancelled(Cancelled {
            safe_message: "interrupted".into(),
        });
        let mut output = io::Cursor::new(Vec::new());
        write_result(&result, &mut output).expect("render succeeds");
        assert_eq!(
            String::from_utf8(output.into_inner()).expect("UTF-8 output"),
            "reach: cancelled: interrupted\n"
        );
    }

    #[test]
    fn mixed_output_keeps_each_formal_target_result_visible() {
        let snapshot = synthetic_snapshot();
        let first = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 1));
        let second = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 2));
        let completed = CompletedDiagnostic::new(
            parse_request("example.com", Some("443")).expect("valid request"),
            snapshot.clone(),
            None,
            HostnameResolutionOutcome::Succeeded(ResolverAddressSet::from_raw(vec![
                first.clone(),
                second.clone(),
            ])),
            vec![
                synthetic_target(
                    &snapshot,
                    first,
                    0,
                    PrimaryOutcome::Satisfied,
                    Conclusion::TcpConnectSucceeded,
                ),
                synthetic_target(
                    &snapshot,
                    second,
                    1,
                    PrimaryOutcome::NotSatisfied,
                    Conclusion::TcpConnectionRefused,
                ),
            ],
            Vec::new(),
            Vec::new(),
        );
        let mut output = Vec::new();
        write_result(
            &DiagnosticResult::Completed(Box::new(completed)),
            &mut output,
        )
        .expect("render succeeds");
        let output = String::from_utf8(output).expect("UTF-8 output");

        assert!(output.contains("result: mixed target results"));
        assert!(output.contains("target 192.0.2.1:443: satisfied"));
        assert!(output.contains("target 192.0.2.2:443: not satisfied"));
    }

    #[test]
    fn zero_target_output_is_an_explicit_non_success_not_an_empty_success() {
        let completed = CompletedDiagnostic::new(
            parse_request("example.com", None).expect("valid request"),
            synthetic_snapshot(),
            None,
            HostnameResolutionOutcome::SucceededWithoutUsableAddress,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut output = Vec::new();
        write_result(
            &DiagnosticResult::Completed(Box::new(completed)),
            &mut output,
        )
        .expect("render succeeds");
        let output = String::from_utf8(output).expect("UTF-8 output");

        assert!(output.contains("result: no formal target was formed"));
        assert!(output.contains("address: example.com"));
        assert!(!output.contains("all targets satisfied"));
    }

    fn synthetic_target(
        snapshot: &InitialNetworkSnapshot,
        target: TargetIp,
        ordinal: usize,
        outcome: PrimaryOutcome,
        conclusion: Conclusion,
    ) -> TargetDiagnostic {
        TargetDiagnostic::new(
            target.clone(),
            Some(ordinal),
            outcome,
            conclusion,
            TargetNetworkFacts {
                initial_path: analyze_initial_path(snapshot, &target),
                current_path: CapabilityValue::unavailable(
                    CapabilityReason::QuerySemanticsUnavailable,
                    synthetic_provenance(),
                ),
                neighbor_pre_state: None,
                neighbor_post_state: None,
            },
            Vec::new(),
            Vec::<Evidence>::new(),
        )
    }

    fn synthetic_snapshot() -> InitialNetworkSnapshot {
        let provenance = synthetic_provenance();
        InitialNetworkSnapshot {
            capture_started_at: Duration::ZERO,
            capture_completed_at: Duration::ZERO,
            interfaces: CapabilityValue::<Vec<InterfaceFact>>::unavailable(
                CapabilityReason::UnsupportedEnvironment,
                provenance.clone(),
            ),
            routes_v4: CapabilityValue::<Vec<RouteFact>>::unavailable(
                CapabilityReason::UnsupportedEnvironment,
                provenance.clone(),
            ),
            routes_v6: CapabilityValue::<Vec<RouteFact>>::unavailable(
                CapabilityReason::UnsupportedEnvironment,
                provenance.clone(),
            ),
            routing_policy_facts: CapabilityValue::<reach_core::RoutingPolicyFacts>::unavailable(
                CapabilityReason::UnsupportedEnvironment,
                provenance.clone(),
            ),
            resolver_configuration: CapabilityValue::<ResolverConfiguration>::unavailable(
                CapabilityReason::UnsupportedEnvironment,
                provenance,
            ),
            inconsistencies: Vec::new(),
        }
    }

    fn synthetic_provenance() -> Provenance {
        Provenance::new(ProvenanceSource::SyntheticTest).at(Duration::ZERO)
    }
}
