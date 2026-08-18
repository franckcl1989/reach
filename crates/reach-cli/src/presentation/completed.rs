use std::fmt::Write as _;

use comfy_table::{
    ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_BORDERS_ONLY,
};
use reach_core::{
    AggregateOutcome, Attempt, AttemptId, AttemptKind, AttemptOutcome, CapabilityReason,
    CompletedDiagnostic, Conclusion, DnsAttemptResult, DnsExchangeEvidence, DnsQueryType, Evidence,
    EvidenceFact, EvidenceSubject, HostnameResolutionOutcome, IcmpAttemptResult, IcmpMessageKind,
    NameResolutionSource, NeighborObservation, NeighborState, PrimaryOutcome, TargetDiagnostic,
    TargetIp, TcpAttemptResult,
};

use super::{
    Theme, bullets, field, headline, human_duration, name_resolution, paragraph, section,
    terminal_escape,
};

pub(super) fn render(completed: &CompletedDiagnostic, theme: Theme) -> String {
    let mut output = String::new();
    render_verdict(&mut output, completed, theme);
    render_check(&mut output, completed, theme);
    name_resolution::render_name_resolution_sections(&mut output, completed, theme);
    if !completed.targets.is_empty() {
        render_targets(&mut output, completed, theme);
    }
    render_meaning(&mut output, completed, theme);
    render_actions(&mut output, completed, theme);
    render_key_evidence(&mut output, completed, theme);
    output
}

fn render_verdict(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    let title = verdict_title(completed);
    let (marker, paint): (&str, fn(Theme, &str) -> String) = match completed.aggregate_outcome {
        AggregateOutcome::AllSatisfied => ("✓", Theme::success),
        AggregateOutcome::SatisfiedWithAnomaly | AggregateOutcome::Mixed => ("!", Theme::warning),
        AggregateOutcome::NoneCleanlySatisfied | AggregateOutcome::NoFormalTargets => {
            ("×", Theme::failure)
        }
    };
    let title_line = format!("{marker} {title}");
    headline(output, theme, &title_line, paint);
    let _ = writeln!(output);
    for line in verdict_summary(completed) {
        paragraph(output, theme, &line);
    }
    let _ = writeln!(output);
}

fn render_check(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    section(output, theme, "CHECK");
    field(
        output,
        theme,
        "Address",
        terminal_escape(&completed.request.original_address),
    );
    if completed.aggregate_outcome == AggregateOutcome::NoFormalTargets {
        if let Some(port) = completed.request.port {
            field(
                output,
                theme,
                "Requested test",
                format!("TCP connection to port {}", port.get()),
            );
        } else {
            field(output, theme, "Requested test", "ICMP Echo");
        }
        field(output, theme, "Result", result_summary(completed));
        let _ = writeln!(output);
        return;
    }
    if let Some(port) = completed.request.port {
        field(
            output,
            theme,
            "Test",
            format!("TCP connection to port {}", port.get()),
        );
    } else {
        field(output, theme, "Test", "ICMP Echo");
    }
    if let Some((label, summary)) = resolver_check_summary(completed) {
        field(output, theme, label, summary);
    }
    if let Some(servers) = formal_dns_servers(completed) {
        if servers.len() == 1 {
            field(output, theme, "DNS server", &servers[0]);
        } else {
            field(output, theme, "DNS servers", servers.join(", "));
        }
    }
    field(output, theme, "Result", result_summary(completed));
    let _ = writeln!(output);
}

fn formal_dns_servers(completed: &CompletedDiagnostic) -> Option<Vec<String>> {
    let exchanges = name_resolution::formal_exchanges(completed);
    if exchanges.is_empty() {
        return None;
    }
    Some(name_resolution::distinct_endpoints(exchanges.iter()))
}

fn render_targets(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    section(output, theme, "TARGETS");
    if theme.content_width() < 60 {
        for (index, target) in completed.targets.iter().enumerate() {
            field(
                output,
                theme,
                &format!("Target {}", index + 1),
                target_label(
                    &target.target,
                    completed.request.port.map(|port| port.get()),
                ),
            );
            field(
                output,
                theme,
                "Status",
                target_status(target.primary_outcome),
            );
            field(output, theme, "Observed result", target_observation(target));
        }
    } else {
        let mut table = report_table(theme);
        if theme.content_width() < 80 {
            table.set_header(["Target", "Result"]);
            for target in &completed.targets {
                table.add_row([
                    target_label(
                        &target.target,
                        completed.request.port.map(|port| port.get()),
                    ),
                    format!(
                        "{} — {}",
                        target_status(target.primary_outcome),
                        target_observation(target)
                    ),
                ]);
            }
        } else {
            table.set_header(["Status", "Target", "Observed result"]);
            for target in &completed.targets {
                table.add_row([
                    target_status(target.primary_outcome).to_owned(),
                    target_label(
                        &target.target,
                        completed.request.port.map(|port| port.get()),
                    ),
                    target_observation(target),
                ]);
            }
        }
        for line in table.to_string().lines() {
            let _ = writeln!(output, "  {line}");
        }
    }
    let _ = writeln!(output);
}

fn render_meaning(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    section(output, theme, "WHAT THIS MEANS");
    bullets(output, theme, meaning(completed));
    let _ = writeln!(output);
}

fn render_actions(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    let values = actions(completed);
    if values.is_empty() {
        return;
    }
    section(output, theme, "WHAT TO DO");
    bullets(output, theme, values);
    let _ = writeln!(output);
}

fn render_key_evidence(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    if completed.key_evidence.is_empty()
        || matches!(completed.aggregate_outcome, AggregateOutcome::AllSatisfied)
    {
        return;
    }
    let values = completed
        .key_evidence
        .iter()
        .filter(|evidence| name_resolution::evidence_is_distinct(completed, &evidence.fact))
        .map(|evidence| evidence_summary(completed, evidence))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return;
    }
    section(output, theme, "EVIDENCE");
    bullets(output, theme, values);
    let _ = writeln!(output);
}

fn report_table(theme: Theme) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_BORDERS_ONLY)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    let available = theme.content_width().saturating_sub(2).max(1);
    table.set_width(u16::try_from(available).unwrap_or(u16::MAX));
    table
}

fn verdict_title(completed: &CompletedDiagnostic) -> &'static str {
    match completed.aggregate_outcome {
        AggregateOutcome::AllSatisfied => {
            if completed.request.port.is_some() {
                "TCP CONNECTION SUCCEEDED"
            } else {
                "ADDRESS RESPONDED"
            }
        }
        AggregateOutcome::SatisfiedWithAnomaly => "REACHABLE, BUT A RETRY WAS NEEDED",
        AggregateOutcome::Mixed => "RESULTS DIFFER BETWEEN IP ADDRESSES",
        AggregateOutcome::NoneCleanlySatisfied => {
            if all_targets_are(completed, Conclusion::TcpTimedOutButTargetIcmpResponded) {
                "TCP PORT DID NOT RESPOND"
            } else if all_targets_are(completed, Conclusion::TcpConnectionRefused) {
                "TCP CONNECTION WAS REFUSED"
            } else if completed.request.port.is_some() {
                "TCP CONNECTION DID NOT SUCCEED"
            } else {
                "NO ICMP REPLY WAS CONFIRMED"
            }
        }
        AggregateOutcome::NoFormalTargets => match completed.hostname_resolution {
            HostnameResolutionOutcome::NegativeWithoutUsableAddress { .. } => {
                "NO USABLE IP ADDRESS"
            }
            HostnameResolutionOutcome::NonDefinitiveFailure { .. } => {
                "NAME COULD NOT BE RESOLVED RELIABLY"
            }
            HostnameResolutionOutcome::SucceededWithoutUsableAddress
            | HostnameResolutionOutcome::NotRequested
            | HostnameResolutionOutcome::Succeeded(_) => "NO USABLE IP ADDRESS",
        },
    }
}

fn verdict_summary(completed: &CompletedDiagnostic) -> Vec<String> {
    let count = completed.targets.len();
    let address = terminal_escape(&completed.request.original_address);
    match completed.aggregate_outcome {
        AggregateOutcome::AllSatisfied => {
            if let Some(port) = completed.request.port {
                vec![if count == 1 {
                    format!(
                        "A TCP connection to {} succeeded.",
                        target_label(&completed.targets[0].target, Some(port.get()))
                    )
                } else {
                    format!(
                        "TCP connections to port {} succeeded for all {count} IP addresses returned for {address}.",
                        port.get()
                    )
                }]
            } else {
                vec![if count == 1 {
                    format!(
                        "{} replied to ICMP Echo.",
                        target_label(&completed.targets[0].target, None)
                    )
                } else {
                    format!("All {count} IP addresses returned for {address} replied to ICMP Echo.")
                }]
            }
        }
        AggregateOutcome::SatisfiedWithAnomaly => vec![if count == 1 {
            "The destination eventually responded, but its first attempt timed out and a retry was needed."
                .to_owned()
        } else {
            format!(
                "All {count} IP addresses eventually responded, but at least one first timed out and required a retry."
            )
        }],
        AggregateOutcome::Mixed => {
            let clean = completed
                .targets
                .iter()
                .filter(|target| target.primary_outcome == PrimaryOutcome::Satisfied)
                .count();
            let eventual = completed
                .targets
                .iter()
                .filter(|target| target.primary_outcome.is_eventually_satisfied())
                .count();
            vec![format!(
                "The same check produced different results across {count} IP addresses: {clean} passed cleanly and {eventual} responded successfully in total."
            )]
        }
        AggregateOutcome::NoneCleanlySatisfied => {
            if let Some(port) = completed.request.port {
                if all_targets_are(completed, Conclusion::TcpTimedOutButTargetIcmpResponded) {
                    if count == 1 {
                        vec![
                            format!(
                                "Two TCP connection attempts to {} timed out.",
                                target_label(&completed.targets[0].target, Some(port.get()))
                            ),
                            "That IP address replied to ICMP Echo.".to_owned(),
                        ]
                    } else {
                        vec![
                            format!(
                                "TCP connection attempts to port {} timed out twice for all {count} IP addresses.",
                                port.get()
                            ),
                            "Those IP addresses replied to ICMP Echo.".to_owned(),
                        ]
                    }
                } else if all_targets_are(completed, Conclusion::TcpConnectionRefused) {
                    vec![if count == 1 {
                        format!(
                            "The TCP connection to {} was explicitly refused.",
                            target_label(&completed.targets[0].target, Some(port.get()))
                        )
                    } else {
                        format!(
                            "All {count} IP addresses explicitly refused the TCP connection to port {}.",
                            port.get()
                        )
                    }]
                } else {
                    vec![if count == 1 {
                        format!(
                            "The TCP connection to {} did not succeed.",
                            target_label(&completed.targets[0].target, Some(port.get()))
                        )
                    } else {
                        format!(
                            "No TCP connection to port {} succeeded for the {count} IP addresses checked.",
                            port.get()
                        )
                    }]
                }
            } else {
                vec![if count == 1 {
                    "The IP address did not produce a confirmed ICMP Echo Reply.".to_owned()
                } else {
                    format!(
                        "None of the {count} IP addresses produced a confirmed ICMP Echo Reply."
                    )
                }]
            }
        }
        AggregateOutcome::NoFormalTargets => match &completed.hostname_resolution {
            HostnameResolutionOutcome::NegativeWithoutUsableAddress { .. } => vec![format!(
                "System name resolution returned no usable IPv4 or IPv6 address for {address}."
            )],
            HostnameResolutionOutcome::NonDefinitiveFailure { .. } => vec![format!(
                "System name resolution could not produce a reliable IP address for {address}."
            )],
            HostnameResolutionOutcome::SucceededWithoutUsableAddress => vec![format!(
                "System name resolution completed but returned no usable IPv4 or IPv6 address for {address}."
            )],
            HostnameResolutionOutcome::NotRequested | HostnameResolutionOutcome::Succeeded(_) => {
                vec![
                    "Reach could not form an IP address that could be checked reliably.".to_owned(),
                ]
            }
        },
    }
}

fn meaning(completed: &CompletedDiagnostic) -> Vec<String> {
    match completed.aggregate_outcome {
        AggregateOutcome::AllSatisfied => {
            if completed.request.port.is_some() {
                vec![
                    "The TCP handshake completed, confirming TCP connectivity to the requested port at the time of the check."
                        .to_owned(),
                    "Reach sent no application data, so this does not prove that HTTP, HTTPS, SSH, or another application protocol is working."
                        .to_owned(),
                ]
            } else {
                vec![
                    "The destination returned an ICMP Echo Reply, confirming an address-level response at the time of the check."
                        .to_owned(),
                    "This does not test a TCP port, website, or application service.".to_owned(),
                ]
            }
        }
        AggregateOutcome::SatisfiedWithAnomaly => vec![
            "Connectivity was eventually observed, but the earlier timeout remains evidence of an intermittent result."
                .to_owned(),
            "The later success does not erase the first timeout, so Reach does not report a clean pass."
                .to_owned(),
        ],
        AggregateOutcome::Mixed => vec![
            "A hostname can lead to several IP addresses, and those destinations can respond differently."
                .to_owned(),
            "A successful address does not erase a failure or uncertainty on another address."
                .to_owned(),
        ],
        AggregateOutcome::NoneCleanlySatisfied => {
            if all_targets_are(
                completed,
                Conclusion::TcpTimedOutButTargetIcmpResponded,
            ) {
                let subject = if completed.targets.len() == 1 {
                    "The destination IP responded to ICMP"
                } else {
                    "The destination IP addresses responded to ICMP"
                };
                vec![
                    format!(
                        "{subject}, but no TCP connection to the requested port completed."
                    ),
                    "This does not prove that the port is closed. Reach cannot determine from these observations alone whether filtering, the network path, or the destination service caused the missing TCP response."
                        .to_owned(),
                ]
            } else if all_targets_are(completed, Conclusion::TcpConnectionRefused) {
                vec![
                    "An explicit refusal proves that the TCP attempt received a response, but the requested connection was not established."
                        .to_owned(),
                    "The refusal may come from the destination or an intermediate device; it does not by itself prove that no application is listening."
                        .to_owned(),
                ]
            } else if completed.request.port.is_some() {
                vec![
                    "The requested TCP connection did not succeed; the destination results and evidence below show the boundary Reach actually observed."
                        .to_owned(),
                    "Reach does not guess an unobserved root cause from a timeout or an operating-system error name."
                        .to_owned(),
                ]
            } else {
                vec![
                    "Reach did not obtain a confirmed ICMP Echo Reply. This alone does not prove that the destination is down because ICMP may be blocked or limited."
                        .to_owned(),
                ]
            }
        }
        AggregateOutcome::NoFormalTargets => {
            let mut values = vec![
                "The hostname did not resolve to an IP address.".to_owned(),
                "No ICMP or TCP check was started.".to_owned(),
            ];
            if name_resolution::diagnostic_dns_ran(completed) {
                values.push(
                    "Any direct DNS evidence above is failure diagnosis only and was not used as a destination address."
                        .to_owned(),
                );
            }
            values
        }
    }
}

fn actions(completed: &CompletedDiagnostic) -> Vec<String> {
    match completed.aggregate_outcome {
        AggregateOutcome::AllSatisfied => Vec::new(),
        AggregateOutcome::SatisfiedWithAnomaly => vec![
            "Run the same check again and note whether the timeout repeats.".to_owned(),
            "If users notice intermittent failures, send this result to the service owner or network team."
                .to_owned(),
        ],
        AggregateOutcome::Mixed => vec![
            "Send this result to the service owner or network team; the per-address difference is important."
                .to_owned(),
            "Keep every address and result when sharing it.".to_owned(),
        ],
        AggregateOutcome::NoneCleanlySatisfied => {
            if let Some(port) = completed.request.port {
                vec![
                    format!(
                        "Verify that TCP port {} is correct and that the service is expected to accept connections on it.",
                        port.get()
                    ),
                    "If the port should be reachable, send this result to the service owner or network team."
                        .to_owned(),
                ]
            } else {
                vec![
                    "If the destination is expected to answer ping, run the check again to rule out short packet loss."
                        .to_owned(),
                    "If you need help, send this result to the network team; ICMP silence alone is not proof that the destination is down."
                        .to_owned(),
                ]
            }
        }
        AggregateOutcome::NoFormalTargets => vec![
            "Check that the hostname is correct.".to_owned(),
            "Check this computer's name-resolution/DNS configuration.".to_owned(),
        ],
    }
}

fn resolver_check_summary(completed: &CompletedDiagnostic) -> Option<(&'static str, String)> {
    match &completed.hostname_resolution {
        HostnameResolutionOutcome::NotRequested => None,
        HostnameResolutionOutcome::Succeeded(addresses) => {
            if let Some(observation) = &completed.system_resolver
                && observation
                    .name_resolution
                    .steps
                    .last()
                    .is_some_and(|step| step.source == NameResolutionSource::Hosts)
            {
                return Some(("Name source", "hosts".to_owned()));
            }
            Some((
                "Name resolution",
                format!(
                    "{}, {} checked",
                    counted(
                        addresses.raw_addresses.len(),
                        "address returned",
                        "addresses returned"
                    ),
                    counted(
                        addresses.formal_targets.len(),
                        "unique address",
                        "unique addresses"
                    )
                ),
            ))
        }
        HostnameResolutionOutcome::SucceededWithoutUsableAddress => Some((
            "Name resolution",
            "completed, but returned no usable IP address".to_owned(),
        )),
        HostnameResolutionOutcome::NegativeWithoutUsableAddress { .. } => Some((
            "Name resolution",
            "returned no usable IPv4 or IPv6 address".to_owned(),
        )),
        HostnameResolutionOutcome::NonDefinitiveFailure { .. } => Some((
            "Name resolution",
            "failed without a definitive answer".to_owned(),
        )),
    }
}

fn result_summary(completed: &CompletedDiagnostic) -> String {
    match completed.aggregate_outcome {
        AggregateOutcome::AllSatisfied => "Passed".to_owned(),
        AggregateOutcome::SatisfiedWithAnomaly => {
            "Passed after retry; earlier timeout retained".to_owned()
        }
        AggregateOutcome::Mixed => count_summary(completed),
        AggregateOutcome::NoneCleanlySatisfied => {
            let failed = completed
                .targets
                .iter()
                .filter(|target| target.primary_outcome == PrimaryOutcome::NotSatisfied)
                .count();
            let inconclusive = completed
                .targets
                .iter()
                .filter(|target| target.primary_outcome == PrimaryOutcome::Indeterminate)
                .count();
            match (failed, inconclusive) {
                (0, _) => "Inconclusive".to_owned(),
                (_, 0) => "Failed".to_owned(),
                _ => format!("{failed} failed, {inconclusive} inconclusive"),
            }
        }
        AggregateOutcome::NoFormalTargets => "Not started".to_owned(),
    }
}

fn count_summary(completed: &CompletedDiagnostic) -> String {
    let clean = completed
        .targets
        .iter()
        .filter(|target| target.primary_outcome == PrimaryOutcome::Satisfied)
        .count();
    let retry = completed
        .targets
        .iter()
        .filter(|target| target.primary_outcome == PrimaryOutcome::SatisfiedWithAnomaly)
        .count();
    let failed = completed
        .targets
        .iter()
        .filter(|target| target.primary_outcome == PrimaryOutcome::NotSatisfied)
        .count();
    let inconclusive = completed
        .targets
        .iter()
        .filter(|target| target.primary_outcome == PrimaryOutcome::Indeterminate)
        .count();
    format!(
        "{clean} passed, {retry} passed after retry, {failed} failed, {inconclusive} inconclusive"
    )
}

fn target_status(outcome: PrimaryOutcome) -> &'static str {
    match outcome {
        PrimaryOutcome::Satisfied => "✓ PASS",
        PrimaryOutcome::SatisfiedWithAnomaly => "! RETRIED",
        PrimaryOutcome::NotSatisfied => "× FAILED",
        PrimaryOutcome::Indeterminate => "? INCONCLUSIVE",
    }
}

fn target_observation(target: &TargetDiagnostic) -> String {
    match target.conclusion {
        Conclusion::TcpConnectSucceeded => "TCP connection succeeded".to_owned(),
        Conclusion::TcpConnectSucceededAfterTimeout => {
            "TCP connection succeeded on retry after an earlier timeout".to_owned()
        }
        Conclusion::TcpConnectionRefused => "TCP connection was explicitly refused".to_owned(),
        Conclusion::TcpExplicitFailure => {
            "TCP connection failed with an explicit network result".to_owned()
        }
        Conclusion::TcpConnectTimedOut => "TCP connection timed out twice".to_owned(),
        Conclusion::TcpTimedOutButTargetIcmpResponded => {
            "TCP timed out twice; ICMP Echo replied".to_owned()
        }
        Conclusion::TcpTimedOutWithExplicitIcmpResult => {
            "TCP timed out twice; ICMP returned an explicit network result".to_owned()
        }
        Conclusion::IcmpEchoReplied => "ICMP Echo Reply received".to_owned(),
        Conclusion::IcmpEchoRepliedAfterTimeout => {
            "ICMP Echo Reply received on retry after an earlier timeout".to_owned()
        }
        Conclusion::IcmpExplicitFailure => "ICMP returned an explicit network result".to_owned(),
        Conclusion::IcmpEchoTimedOut => "No ICMP Echo Reply after two attempts".to_owned(),
        Conclusion::IcmpResponseIndeterminate => {
            "ICMP response did not prove success or a definite failure".to_owned()
        }
        Conclusion::DefinitiveNoPath => {
            "Local network facts prove there is no usable path".to_owned()
        }
        Conclusion::NeighborResolutionFailed => {
            "Required local Neighbor resolution failed".to_owned()
        }
        Conclusion::NeighborResolutionIndeterminate => {
            "Required local Neighbor resolution was inconclusive".to_owned()
        }
        Conclusion::FirstHopResponded
        | Conclusion::MultiplePathRespondersObserved
        | Conclusion::PathEndpointResponded
        | Conclusion::PathExplicitlyTerminated
        | Conclusion::PathResponseIndeterminate
        | Conclusion::PathLimitReachedWithoutEndpointEvidence
        | Conclusion::HostnameResolved
        | Conclusion::HostnameNoFormalTargets
        | Conclusion::HostnameResolutionNoUsableAddress
        | Conclusion::HostnameResolutionIndeterminate
        | Conclusion::AllTargetsSatisfied
        | Conclusion::TargetsSatisfiedWithAnomaly
        | Conclusion::TargetResultsMixed
        | Conclusion::NoTargetCleanlySatisfied
        | Conclusion::CapabilityLimited => diagnostic_note(&target.conclusion).to_owned(),
    }
}

fn diagnostic_note(conclusion: &Conclusion) -> &'static str {
    match conclusion {
        Conclusion::TcpConnectSucceeded => "TCP connection succeeded",
        Conclusion::TcpConnectSucceededAfterTimeout => {
            "TCP connection succeeded only after an earlier timeout"
        }
        Conclusion::TcpConnectionRefused => "TCP connection was explicitly refused",
        Conclusion::TcpExplicitFailure => "TCP connection failed with an explicit result",
        Conclusion::TcpConnectTimedOut => "TCP connection timed out twice",
        Conclusion::TcpTimedOutButTargetIcmpResponded => {
            "TCP timed out, but the target IP replied to ICMP Echo"
        }
        Conclusion::TcpTimedOutWithExplicitIcmpResult => {
            "TCP timed out and ICMP returned an explicit result"
        }
        Conclusion::IcmpEchoReplied => "ICMP Echo Reply received",
        Conclusion::IcmpEchoRepliedAfterTimeout => {
            "ICMP Echo Reply received only after an earlier timeout"
        }
        Conclusion::IcmpExplicitFailure => "ICMP returned an explicit failure result",
        Conclusion::IcmpEchoTimedOut => "ICMP Echo timed out twice",
        Conclusion::IcmpResponseIndeterminate => "ICMP response remained inconclusive",
        Conclusion::DefinitiveNoPath => "Snapshot path inference proved no usable path",
        Conclusion::NeighborResolutionFailed => "Required local Neighbor resolution failed",
        Conclusion::NeighborResolutionIndeterminate => {
            "Required local Neighbor resolution remained inconclusive"
        }
        Conclusion::FirstHopResponded => "The targeted first hop replied directly",
        Conclusion::MultiplePathRespondersObserved => {
            "More than one responder was observed at the same path hop"
        }
        Conclusion::PathEndpointResponded => {
            "Later path diagnosis observed a correlated endpoint response; it does not erase the primary failure"
        }
        Conclusion::PathExplicitlyTerminated => {
            "Path diagnosis ended with a correlated explicit network error"
        }
        Conclusion::PathResponseIndeterminate => {
            "Path diagnosis received a correlated but inconclusive response"
        }
        Conclusion::PathLimitReachedWithoutEndpointEvidence => {
            "Path diagnosis reached its hop limit without endpoint evidence"
        }
        Conclusion::HostnameResolved => "System name resolution produced destination addresses",
        Conclusion::HostnameNoFormalTargets => {
            "System name resolution produced no usable destination address"
        }
        Conclusion::HostnameResolutionNoUsableAddress => {
            "System name resolution returned no usable IPv4 or IPv6 address"
        }
        Conclusion::HostnameResolutionIndeterminate => {
            "System name resolution failed without a definitive answer"
        }
        Conclusion::AllTargetsSatisfied => "Every address passed cleanly",
        Conclusion::TargetsSatisfiedWithAnomaly => {
            "Every address eventually responded, with an earlier anomaly retained"
        }
        Conclusion::TargetResultsMixed => "Different addresses produced different results",
        Conclusion::NoTargetCleanlySatisfied => "No address passed cleanly",
        Conclusion::CapabilityLimited => {
            "The primary result is retained, but this system could not safely perform a deeper diagnostic step"
        }
    }
}

fn evidence_summary(completed: &CompletedDiagnostic, evidence: &Evidence) -> String {
    match &evidence.fact {
        EvidenceFact::Attempt(id) => find_attempt(completed, *id).map_or_else(
            || "A decision attempt was retained, but its detail is unavailable.".to_owned(),
            |(attempt, ordinal)| attempt_evidence_summary(attempt, ordinal),
        ),
        EvidenceFact::InitialPath(value) => {
            format!("Snapshot path inference: {}.", terminal_escape(value))
        }
        EvidenceFact::CurrentPath(value) => {
            format!("Targeted OS path query: {}.", terminal_escape(value))
        }
        EvidenceFact::NeighborTransition { before, after } => format!(
            "Neighbor before: {}; after: {}.",
            neighbor_observation_label(*before),
            neighbor_state_label(*after)
        ),
        EvidenceFact::NameResolution(value) => {
            format!(
                "Name resolution: {}.",
                name_resolution::name_resolution_outcome_label(value.outcome)
            )
        }
        EvidenceFact::DnsExchange(DnsExchangeEvidence::Formal(exchange)) => {
            format!(
                "Formal DNS {} exchange with {} for {}: {}.",
                name_resolution::dns_query_type_label(exchange.query_type),
                exchange.endpoint.address,
                terminal_escape(&exchange.query_name),
                name_resolution::formal_exchange_summary(exchange),
            )
        }
        EvidenceFact::DnsExchange(DnsExchangeEvidence::Diagnostic(id)) => {
            find_attempt(completed, *id).map_or_else(
                || {
                    "A direct DNS diagnostic attempt was retained, but its detail is unavailable."
                        .to_owned()
                },
                |(attempt, ordinal)| attempt_evidence_summary(attempt, ordinal),
            )
        }
        EvidenceFact::CapabilityUnavailable { capability, reason } => {
            let subject = match &evidence.subject {
                EvidenceSubject::Resolver(label) => {
                    format!("Resolver {}: ", terminal_escape(label))
                }
                _ => String::new(),
            };
            format!(
                "{subject}{} unavailable: {}.",
                terminal_escape(capability),
                capability_reason(reason)
            )
        }
        EvidenceFact::SnapshotInconsistency(value) => format!(
            "Snapshot cross-check found an inconsistency: {}.",
            terminal_escape(value)
        ),
        EvidenceFact::SocketPathComparison(value) => {
            format!("Targeted OS path comparison: {}.", terminal_escape(value))
        }
    }
}

fn attempt_evidence_summary(attempt: &Attempt, ordinal: Option<usize>) -> String {
    let check = attempt_display_label(attempt.kind, ordinal);
    let budget = attempt
        .timing
        .deadline_at
        .saturating_sub(attempt.timing.started_at);
    if attempt_timed_out(&attempt.outcome) {
        return format!(
            "{check}: No result before the {} deadline.",
            human_duration(budget)
        );
    }
    let timing = if attempt.timing.duration().is_zero() {
        " at the same observable clock reading".to_owned()
    } else {
        format!(" in {}", human_duration(attempt.timing.duration()))
    };
    format!("{check}: {}{timing}.", friendly_attempt_outcome(attempt))
}

fn find_attempt(
    completed: &CompletedDiagnostic,
    id: AttemptId,
) -> Option<(&Attempt, Option<usize>)> {
    for target in &completed.targets {
        if let Some((index, attempt)) = target
            .attempts
            .iter()
            .enumerate()
            .find(|(_, attempt)| attempt.id == id)
        {
            return Some((attempt, local_attempt_ordinal(&target.attempts, index)));
        }
    }
    for resolver in &completed.resolver_diagnostics {
        if let Some((index, attempt)) = resolver
            .attempts
            .iter()
            .enumerate()
            .find(|(_, attempt)| attempt.id == id)
        {
            return Some((attempt, local_attempt_ordinal(&resolver.attempts, index)));
        }
    }
    None
}

fn local_attempt_ordinal(attempts: &[Attempt], index: usize) -> Option<usize> {
    let kind = attempts[index].kind;
    let count = attempts
        .iter()
        .filter(|attempt| attempt.kind == kind)
        .count();
    (count > 1).then(|| {
        attempts[..=index]
            .iter()
            .filter(|attempt| attempt.kind == kind)
            .count()
    })
}

fn attempt_display_label(kind: AttemptKind, ordinal: Option<usize>) -> String {
    match (kind, ordinal) {
        (AttemptKind::TcpPath { hop_limit }, Some(ordinal)) => {
            format!("TCP path at hop {hop_limit}, attempt #{ordinal}")
        }
        (AttemptKind::IcmpPath { hop_limit }, Some(ordinal)) => {
            format!("ICMP path at hop {hop_limit}, attempt #{ordinal}")
        }
        (_, Some(ordinal)) => format!("{} #{ordinal}", attempt_kind_label(kind)),
        _ => attempt_kind_label(kind),
    }
}

fn attempt_kind_label(kind: AttemptKind) -> String {
    match kind {
        AttemptKind::TcpConnect => "TCP connect".to_owned(),
        AttemptKind::TargetIcmpEcho => "ICMP Echo".to_owned(),
        AttemptKind::NextHopIcmpEcho => "Next-hop ICMP Echo".to_owned(),
        AttemptKind::TcpPath { hop_limit } => format!("TCP path at hop {hop_limit}"),
        AttemptKind::IcmpPath { hop_limit } => format!("ICMP path at hop {hop_limit}"),
        AttemptKind::DnsUdp { query_type } => {
            format!(
                "Direct DNS {} over UDP",
                name_resolution::dns_query_type_label(query_type)
            )
        }
        AttemptKind::DnsTcp { query_type } => {
            format!(
                "Direct DNS {} over TCP",
                name_resolution::dns_query_type_label(query_type)
            )
        }
    }
}

fn attempt_timed_out(outcome: &AttemptOutcome) -> bool {
    matches!(
        outcome,
        AttemptOutcome::Tcp(TcpAttemptResult::Timeout)
            | AttemptOutcome::Icmp(IcmpAttemptResult::Timeout)
            | AttemptOutcome::Dns(DnsAttemptResult::Timeout)
    )
}

fn friendly_attempt_outcome(attempt: &Attempt) -> String {
    match &attempt.outcome {
        AttemptOutcome::Tcp(result) => tcp_outcome_label(result),
        AttemptOutcome::Icmp(IcmpAttemptResult::Message {
            kind, responder, ..
        }) => format!("{} from {responder}", icmp_kind_label(*kind)),
        AttemptOutcome::Icmp(IcmpAttemptResult::Messages(messages)) => messages
            .iter()
            .map(|message| {
                format!(
                    "{} from {}",
                    icmp_kind_label(message.kind),
                    message.responder
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
        AttemptOutcome::Icmp(IcmpAttemptResult::ExplicitNetworkError { os_code }) => format!(
            "explicit operating-system network error{}",
            os_code.map_or_else(String::new, |code| format!(" (code {code})"))
        ),
        AttemptOutcome::Icmp(IcmpAttemptResult::Timeout) => {
            "no ICMP response before the deadline".to_owned()
        }
        AttemptOutcome::Dns(result) => dns_outcome_label(result, attempt),
    }
}

fn tcp_outcome_label(result: &TcpAttemptResult) -> String {
    match result {
        TcpAttemptResult::Connected { .. } => "TCP connection succeeded".to_owned(),
        TcpAttemptResult::ConnectionRefused => "TCP connection was refused".to_owned(),
        TcpAttemptResult::NoRoute => "the operating system reported no route".to_owned(),
        TcpAttemptResult::NetworkUnreachable => {
            "the operating system reported the network unreachable".to_owned()
        }
        TcpAttemptResult::HostUnreachable => {
            "the operating system reported the host unreachable".to_owned()
        }
        TcpAttemptResult::PermissionDenied => {
            "the operating system denied the connection attempt".to_owned()
        }
        TcpAttemptResult::ResourceExhausted => {
            "local networking resources were exhausted".to_owned()
        }
        TcpAttemptResult::OtherExplicitError { os_code } => format!(
            "explicit operating-system error{}",
            os_code.map_or_else(String::new, |code| format!(" (code {code})"))
        ),
        TcpAttemptResult::Timeout => "no TCP result before the deadline".to_owned(),
    }
}

fn dns_outcome_label(result: &DnsAttemptResult, attempt: &Attempt) -> String {
    let query_type = match attempt.kind {
        AttemptKind::DnsUdp { query_type } | AttemptKind::DnsTcp { query_type } => query_type,
        _ => DnsQueryType::A,
    };
    match result {
        DnsAttemptResult::Response {
            response_code,
            addresses,
            aliases,
            truncated,
        } => name_resolution::dns_attempt_response_label(
            reach_core::DnsResponseCode::from(*response_code),
            addresses,
            aliases,
            *truncated,
            query_type,
        ),
        DnsAttemptResult::TransportError { os_code } => format!(
            "Transport error{}",
            os_code.map_or_else(String::new, |code| format!(" (OS code {code})"))
        ),
        DnsAttemptResult::ProtocolError => "Protocol error".to_owned(),
        DnsAttemptResult::Timeout => "Timed out".to_owned(),
    }
}

fn capability_reason(reason: &CapabilityReason) -> String {
    match reason {
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
            "the required read-only query is not available".to_owned()
        }
        CapabilityReason::AttemptCorrelationUnavailable => {
            "responses cannot be correlated reliably to the originating attempt".to_owned()
        }
        CapabilityReason::UnsupportedEnvironment => {
            "the current environment is not supported".to_owned()
        }
        CapabilityReason::Other(value) => terminal_escape(value),
    }
}

fn neighbor_observation_label(value: NeighborObservation) -> &'static str {
    match value {
        NeighborObservation::NotSampled => "not sampled",
        NeighborObservation::Observed(state) => neighbor_state_label(state),
        NeighborObservation::Unknown => "unknown",
        NeighborObservation::Unavailable => "unavailable",
    }
}

const fn neighbor_state_label(value: NeighborState) -> &'static str {
    match value {
        NeighborState::Absent => "absent (no matching entry)",
        NeighborState::Resolving => "resolving",
        NeighborState::Usable => "usable",
        NeighborState::TerminalFailure => "terminal failure",
        NeighborState::Unknown => "unknown state",
    }
}

fn all_targets_are(completed: &CompletedDiagnostic, conclusion: Conclusion) -> bool {
    !completed.targets.is_empty()
        && completed
            .targets
            .iter()
            .all(|target| target.conclusion == conclusion)
}

fn target_label(target: &TargetIp, port: Option<u16>) -> String {
    let mut address = target.address.to_string();
    if let Some(scope) = &target.scope {
        let _ = write!(address, "%{}", scope.index);
    }
    match port {
        Some(port) if target.address.is_ipv6() => format!("[{address}]:{port}"),
        Some(port) => format!("{address}:{port}"),
        None => address,
    }
}

fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

const fn icmp_kind_label(value: IcmpMessageKind) -> &'static str {
    match value {
        IcmpMessageKind::EchoReply => "Reply",
        IcmpMessageKind::DestinationUnreachable => "ICMP Destination Unreachable",
        IcmpMessageKind::TimeExceeded => "ICMP Time Exceeded",
        IcmpMessageKind::PacketTooBig => "ICMP Packet Too Big",
        IcmpMessageKind::ParameterProblem => "ICMP Parameter Problem",
        IcmpMessageKind::Other => "other ICMP message",
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use super::*;
    use reach_core::{
        CapabilityValue, CompletedDiagnostic, EvidenceId, EvidenceRole, EvidenceSubject,
        HostnameResolutionOutcome, IcmpNativeStatus, InitialNetworkSnapshot, InterfaceFact,
        NameResolutionEvidenceOutcome, NameResolutionSource, PrimaryOutcome, Provenance,
        ProvenanceSource, ResolverConfiguration, RouteFact, TargetNetworkFacts,
        analyze_initial_path, parse_request,
    };
    use unicode_width::UnicodeWidthStr as _;

    #[test]
    fn timeout_and_icmp_reply_uses_only_numbered_key_evidence() {
        let completed = timeout_then_icmp_result();
        let output = render(&completed, Theme::plain());

        assert!(output.contains("Two TCP connection attempts to 192.0.2.20:8443 timed out"));
        assert!(output.contains("That IP address replied to ICMP Echo"));
        assert!(output.contains("TCP connect #1: No result before the 5 s deadline"));
        assert!(output.contains("TCP connect #2: No result before the 5 s deadline"));
        assert!(output.contains("ICMP Echo: Reply from 192.0.2.20"));
        assert!(output.contains("This does not prove that the port is closed"));
        for forbidden in [
            "TECHNICAL DETAILS",
            "NETWORK ATTEMPTS",
            "PATH AND NEIGHBOR FACTS",
            "raw-state=",
            "Interface identity",
            "System DNS",
            "send this entire report",
        ] {
            assert!(
                !output.contains(forbidden),
                "unexpected {forbidden:?}\n{output}"
            );
        }
    }

    #[test]
    fn attempt_numbers_are_local_to_one_logical_operation() {
        let mut attempts = vec![
            attempt(
                1,
                AttemptKind::TcpConnect,
                AttemptOutcome::Tcp(TcpAttemptResult::Timeout),
                Duration::from_secs(5),
                Duration::from_secs(5),
            ),
            attempt(
                2,
                AttemptKind::TcpConnect,
                AttemptOutcome::Tcp(TcpAttemptResult::Timeout),
                Duration::from_secs(5),
                Duration::from_secs(5),
            ),
            attempt(
                3,
                AttemptKind::TargetIcmpEcho,
                AttemptOutcome::Icmp(IcmpAttemptResult::Timeout),
                Duration::from_secs(3),
                Duration::from_secs(3),
            ),
        ];
        assert_eq!(local_attempt_ordinal(&attempts, 0), Some(1));
        assert_eq!(local_attempt_ordinal(&attempts, 1), Some(2));
        assert_eq!(local_attempt_ordinal(&attempts, 2), None);

        attempts.push(attempt(
            4,
            AttemptKind::TargetIcmpEcho,
            AttemptOutcome::Icmp(IcmpAttemptResult::Timeout),
            Duration::from_secs(3),
            Duration::from_secs(3),
        ));
        assert_eq!(local_attempt_ordinal(&attempts, 2), Some(1));
        assert_eq!(local_attempt_ordinal(&attempts, 3), Some(2));
    }

    #[test]
    fn clean_success_stops_after_the_minimum_explanation() {
        let completed = clean_icmp_success();
        let output = render(&completed, Theme::plain());

        assert!(output.starts_with("✓ ADDRESS RESPONDED\n"));
        assert!(output.contains("This does not test a TCP port, website"));
        assert!(!output.contains("EVIDENCE"));
        assert!(!output.contains("TECHNICAL DETAILS"));
        assert!(!output.contains("0 ms"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn name_resolution_section_explains_a_no_formal_target_failure() {
        let snapshot = synthetic_snapshot();
        let exchanges = vec![
            formal_exchange(
                DnsQueryType::A,
                reach_core::DnsResponseCode::NxDomain,
                "missing.example.",
                Duration::from_millis(12),
            ),
            formal_exchange(
                DnsQueryType::Aaaa,
                reach_core::DnsResponseCode::NxDomain,
                "missing.example.",
                Duration::from_millis(11),
            ),
        ];
        let completed = CompletedDiagnostic::new(
            parse_request("missing.example", None).expect("valid request"),
            snapshot.clone(),
            Some(resolver_observation(
                "missing.example",
                vec![reach_core::NameResolutionStep {
                    source: NameResolutionSource::Dns,
                    query_names: vec!["missing.example".into()],
                    dns_exchanges: exchanges,
                    outcome: reach_core::NameResolutionStepOutcome::NotFound,
                    provenance: provenance(),
                }],
                Vec::new(),
                reach_core::SystemResolverResult::Failed(reach_core::SystemResolverFailure {
                    kind: reach_core::SystemResolverFailureKind::NoUsableAddress,
                    platform_code: None,
                    platform_message: "no usable address".into(),
                }),
            )),
            HostnameResolutionOutcome::NegativeWithoutUsableAddress {
                platform_code: None,
            },
            Vec::new(),
            Vec::new(),
            vec![
                Evidence {
                    id: EvidenceId(1),
                    subject: EvidenceSubject::Hostname,
                    role: EvidenceRole::PrimaryDecision,
                    fact: EvidenceFact::NameResolution(reach_core::NameResolutionEvidence {
                        outcome: NameResolutionEvidenceOutcome::NegativeWithoutUsableAddress,
                    }),
                },
                Evidence {
                    id: EvidenceId(2),
                    subject: EvidenceSubject::Hostname,
                    role: EvidenceRole::CapabilityLimitation,
                    fact: EvidenceFact::CapabilityUnavailable {
                        capability: "resolver transport diagnosis".into(),
                        reason: CapabilityReason::QuerySemanticsUnavailable,
                    },
                },
            ],
        );
        let output = render(&completed, Theme::plain());

        assert!(output.starts_with("× NO USABLE IP ADDRESS\n"));
        assert!(output.contains("Requested test     ICMP Echo"));
        assert!(output.contains("Result             Not started"));
        assert!(output.contains("NAME RESOLUTION"));
        assert!(output.contains("Source             DNS"));
        assert!(output.contains("DNS server         192.0.2.53:53"));
        assert!(output.contains("Query              missing.example"));
        assert!(output.contains("A                  NXDOMAIN, 12 ms"));
        assert!(output.contains("AAAA               NXDOMAIN, 11 ms"));
        assert!(output.contains("The hostname did not resolve to an IP address"));
        assert!(output.contains("No ICMP or TCP check was started"));
        assert!(output.contains("Check that the hostname is correct"));
        assert!(output.contains("Check this computer's name-resolution/DNS configuration"));
        assert!(!output.contains("Any direct DNS evidence"));
        assert!(!output.contains("DNS DIAGNOSTIC"));
        assert!(output.contains("EVIDENCE"));
        assert!(!output.contains("Name resolution: returned no usable IPv4 or IPv6 address"));
        assert!(output.contains("resolver transport diagnosis unavailable"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn diagnostic_dns_section_is_labeled_and_conditional() {
        let snapshot = synthetic_snapshot();
        let completed = CompletedDiagnostic::new(
            parse_request("missing.example", None).expect("valid request"),
            snapshot.clone(),
            Some(resolver_observation(
                "missing.example",
                vec![reach_core::NameResolutionStep {
                    source: NameResolutionSource::SystemResolverOpaque,
                    query_names: Vec::new(),
                    dns_exchanges: Vec::new(),
                    outcome: reach_core::NameResolutionStepOutcome::NotFound,
                    provenance: provenance(),
                }],
                vec!["the exact formal DNS server identity selected by the platform system resolver is not exposed by the selected ordinary-user API".into()],
                reach_core::SystemResolverResult::Failed(reach_core::SystemResolverFailure {
                    kind: reach_core::SystemResolverFailureKind::NoUsableAddress,
                    platform_code: None,
                    platform_message: "no usable address".into(),
                }),
            )),
            HostnameResolutionOutcome::NegativeWithoutUsableAddress { platform_code: None },
            Vec::new(),
            resolver_diagnostics(snapshot),
            vec![Evidence {
                id: EvidenceId(1),
                subject: EvidenceSubject::Hostname,
                role: EvidenceRole::PrimaryDecision,
                fact: EvidenceFact::NameResolution(reach_core::NameResolutionEvidence {
                    outcome: NameResolutionEvidenceOutcome::NegativeWithoutUsableAddress,
                }),
            }],
        );
        let output = render(&completed, Theme::plain());

        assert!(output.contains("Formal DNS server  Not exposed by this platform"));
        assert!(output.contains("DNS DIAGNOSTIC"));
        assert!(output.contains("Server             192.0.2.53:53"));
        assert!(output.contains("Query              missing.example"));
        assert!(output.contains("A                  NXDOMAIN"));
        assert!(output.contains("AAAA               SERVFAIL"));
        let flattened = output.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flattened.contains(
            "Any direct DNS evidence above is failure diagnosis only and was not used as a destination address"
        ));
        assert!(!output.contains("EVIDENCE"));
    }

    #[test]
    fn search_expansion_is_displayed_only_when_the_query_name_differs() {
        let snapshot = synthetic_snapshot();
        let exchanges = vec![
            formal_exchange(
                DnsQueryType::A,
                reach_core::DnsResponseCode::NxDomain,
                "admin.corp.example.",
                Duration::ZERO,
            ),
            formal_exchange(
                DnsQueryType::A,
                reach_core::DnsResponseCode::NxDomain,
                "admin.",
                Duration::ZERO,
            ),
            formal_exchange(
                DnsQueryType::Aaaa,
                reach_core::DnsResponseCode::NxDomain,
                "admin.corp.example.",
                Duration::ZERO,
            ),
            formal_exchange(
                DnsQueryType::Aaaa,
                reach_core::DnsResponseCode::NxDomain,
                "admin.",
                Duration::ZERO,
            ),
        ];
        let completed = CompletedDiagnostic::new(
            parse_request("admin", None).expect("valid request"),
            snapshot.clone(),
            Some(resolver_observation(
                "admin",
                vec![reach_core::NameResolutionStep {
                    source: NameResolutionSource::Dns,
                    query_names: vec!["admin.corp.example".into(), "admin".into()],
                    dns_exchanges: exchanges,
                    outcome: reach_core::NameResolutionStepOutcome::NotFound,
                    provenance: provenance(),
                }],
                Vec::new(),
                reach_core::SystemResolverResult::Failed(reach_core::SystemResolverFailure {
                    kind: reach_core::SystemResolverFailureKind::NoUsableAddress,
                    platform_code: None,
                    platform_message: "no usable address".into(),
                }),
            )),
            HostnameResolutionOutcome::NegativeWithoutUsableAddress {
                platform_code: None,
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let output = render(&completed, Theme::plain());

        assert!(output.contains("Input              admin"));
        assert!(output.contains("Query              admin.corp.example, admin"));
    }

    #[test]
    fn hostname_dns_success_shows_the_actual_dns_server_compactly() {
        let snapshot = synthetic_snapshot();
        let target_ip = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 20));
        let completed = CompletedDiagnostic::new(
            parse_request("example.com", None).expect("valid request"),
            snapshot.clone(),
            Some(resolver_observation(
                "example.com",
                vec![reach_core::NameResolutionStep {
                    source: NameResolutionSource::Dns,
                    query_names: vec!["example.com".into()],
                    dns_exchanges: vec![formal_exchange(
                        DnsQueryType::A,
                        reach_core::DnsResponseCode::NoError,
                        "example.com.",
                        Duration::from_millis(8),
                    )],
                    outcome: reach_core::NameResolutionStepOutcome::Found,
                    provenance: provenance(),
                }],
                Vec::new(),
                reach_core::SystemResolverResult::Succeeded(
                    reach_core::ResolverAddressSet::from_raw(vec![target_ip.clone()]),
                ),
            )),
            HostnameResolutionOutcome::Succeeded(reach_core::ResolverAddressSet::from_raw(vec![
                target_ip.clone(),
            ])),
            vec![result_only_target(
                &snapshot,
                target_ip,
                0,
                PrimaryOutcome::Satisfied,
                Conclusion::IcmpEchoReplied,
            )],
            Vec::new(),
            Vec::new(),
        );
        let output = render(&completed, Theme::plain());

        assert!(output.contains("Name resolution    1 address returned, 1 unique address checked"));
        assert!(output.contains("DNS server         192.0.2.53:53"));
        assert!(!output.contains("NAME RESOLUTION"));
        assert!(!output.contains("EVIDENCE"));
    }

    #[test]
    fn hosts_success_uses_name_source_without_a_dns_server_claim() {
        let snapshot = synthetic_snapshot();
        let target_ip = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 20));
        let completed = CompletedDiagnostic::new(
            parse_request("app.internal", None).expect("valid request"),
            snapshot.clone(),
            Some(resolver_observation(
                "app.internal",
                vec![reach_core::NameResolutionStep {
                    source: NameResolutionSource::Hosts,
                    query_names: Vec::new(),
                    dns_exchanges: Vec::new(),
                    outcome: reach_core::NameResolutionStepOutcome::Found,
                    provenance: provenance(),
                }],
                Vec::new(),
                reach_core::SystemResolverResult::Succeeded(
                    reach_core::ResolverAddressSet::from_raw(vec![target_ip.clone()]),
                ),
            )),
            HostnameResolutionOutcome::Succeeded(reach_core::ResolverAddressSet::from_raw(vec![
                target_ip.clone(),
            ])),
            vec![result_only_target(
                &snapshot,
                target_ip,
                0,
                PrimaryOutcome::Satisfied,
                Conclusion::IcmpEchoReplied,
            )],
            Vec::new(),
            Vec::new(),
        );
        let output = render(&completed, Theme::plain());

        assert!(output.contains("Name source        hosts"));
        assert!(!output.contains("DNS server"));
    }

    #[test]
    fn dns_response_codes_render_symbolically_and_unknown_codes_stay_numbered() {
        use reach_core::DnsResponseCode;
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::NxDomain,
                &[],
                &[],
                false,
                DnsQueryType::A
            ),
            "NXDOMAIN"
        );
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::ServFail,
                &[],
                &[],
                false,
                DnsQueryType::Aaaa
            ),
            "SERVFAIL"
        );
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::Refused,
                &[],
                &[],
                false,
                DnsQueryType::A
            ),
            "REFUSED"
        );
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::NoError,
                &[],
                &[],
                false,
                DnsQueryType::A
            ),
            "No A address returned"
        );
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::NoError,
                &[],
                &[],
                false,
                DnsQueryType::Aaaa
            ),
            "No AAAA address returned"
        );
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::NoError,
                &[],
                &[],
                true,
                DnsQueryType::A
            ),
            "Response truncated"
        );
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::Other(12),
                &[],
                &[],
                false,
                DnsQueryType::A
            ),
            "DNS response code 12"
        );
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::NoError,
                &[Ipv4Addr::new(192, 0, 2, 1).into()],
                &[],
                false,
                DnsQueryType::A
            ),
            "192.0.2.1"
        );
        assert_eq!(
            name_resolution::dns_attempt_response_label(
                DnsResponseCode::NoError,
                &[Ipv4Addr::new(192, 0, 2, 1).into()],
                &["cdn.example".to_owned()],
                false,
                DnsQueryType::A
            ),
            "192.0.2.1 (alias: cdn.example)"
        );
    }

    fn resolver_observation(
        input_name: &str,
        steps: Vec<reach_core::NameResolutionStep>,
        limitations: Vec<String>,
        result: reach_core::SystemResolverResult,
    ) -> reach_core::SystemResolverObservation {
        reach_core::SystemResolverObservation {
            started_at: Duration::ZERO,
            completed_at: Duration::from_millis(1),
            name_resolution: reach_core::NameResolutionObservation {
                input_name: input_name.into(),
                steps,
                limitations,
                result,
            },
            provenance: provenance(),
        }
    }

    fn formal_exchange(
        query_type: DnsQueryType,
        response_code: reach_core::DnsResponseCode,
        query_name: &str,
        duration: Duration,
    ) -> reach_core::DnsExchangeObservation {
        let started_at = Duration::ZERO;
        reach_core::DnsExchangeObservation {
            purpose: reach_core::DnsExchangePurpose::FormalResolution,
            endpoint: reach_core::IpEndpoint {
                address: Ipv4Addr::new(192, 0, 2, 53).into(),
                port: 53,
                scope_id: None,
            },
            transport: reach_core::DnsExchangeTransport::Udp,
            query_name: query_name.into(),
            query_type,
            outcome: reach_core::DnsExchangeOutcome::Response {
                response_code,
                addresses: Vec::new(),
                aliases: Vec::new(),
                truncated: false,
            },
            timing: reach_core::AttemptTiming {
                started_at,
                deadline_at: Duration::from_secs(1),
                completed_at: started_at + duration,
            },
            provenance: provenance(),
        }
    }

    fn resolver_diagnostics(
        snapshot: InitialNetworkSnapshot,
    ) -> Vec<reach_core::ResolverDependencyDiagnostic> {
        let endpoint = reach_core::ResolverEndpoint {
            address: Ipv4Addr::new(192, 0, 2, 53).into(),
            port: 53,
            transport: reach_core::ResolverTransport::Udp,
            interface: None,
            domains: Vec::new(),
            priority: Some(0),
            provenance: provenance(),
        };
        let target = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 53));
        let attempts = vec![
            dns_attempt(
                1,
                DnsQueryType::A,
                DnsAttemptResult::Response {
                    response_code: 3,
                    addresses: Vec::new(),
                    aliases: Vec::new(),
                    truncated: false,
                },
            ),
            dns_attempt(
                2,
                DnsQueryType::Aaaa,
                DnsAttemptResult::Response {
                    response_code: 2,
                    addresses: Vec::new(),
                    aliases: Vec::new(),
                    truncated: false,
                },
            ),
        ];
        vec![reach_core::ResolverDependencyDiagnostic::new(
            endpoint,
            TargetNetworkFacts {
                initial_path: analyze_initial_path(&snapshot, &target),
                current_path: CapabilityValue::unavailable(
                    CapabilityReason::QuerySemanticsUnavailable,
                    provenance(),
                ),
                neighbor_pre_state: None,
                neighbor_post_state: None,
            },
            attempts,
            Vec::new(),
        )]
    }

    fn dns_attempt(id: u64, query_type: DnsQueryType, outcome: DnsAttemptResult) -> Attempt {
        Attempt {
            id: AttemptId(id),
            subject: reach_core::AttemptSubject::Resolver {
                endpoint: std::net::SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 53),
                query_name: "missing.example".into(),
            },
            kind: AttemptKind::DnsUdp { query_type },
            timing: reach_core::AttemptTiming {
                started_at: Duration::ZERO,
                deadline_at: Duration::from_secs(2),
                completed_at: Duration::from_millis(12),
            },
            outcome: AttemptOutcome::Dns(outcome),
            provenance: provenance(),
        }
    }

    #[test]
    fn name_resolution_is_never_called_system_dns() {
        let completed = timeout_then_icmp_result();
        let output = render(&completed, Theme::plain());
        assert!(output.contains("Name resolution"));
        assert!(!output.to_ascii_lowercase().contains("system dns"));

        let negative = CompletedDiagnostic::new(
            parse_request("missing.invalid", None).expect("valid request"),
            synthetic_snapshot(),
            Some(reach_core::SystemResolverObservation {
                started_at: Duration::ZERO,
                completed_at: Duration::from_millis(1),
                name_resolution: reach_core::NameResolutionObservation {
                    input_name: "missing.invalid".into(),
                    steps: vec![reach_core::NameResolutionStep {
                        source: NameResolutionSource::SystemResolverOpaque,
                        query_names: Vec::new(),
                        dns_exchanges: Vec::new(),
                        outcome: reach_core::NameResolutionStepOutcome::NotFound,
                        provenance: provenance(),
                    }],
                    limitations: vec![
                        "the exact formal DNS server identity selected by the platform system resolver is not exposed by the selected ordinary-user API"
                            .into(),
                    ],
                    result: reach_core::SystemResolverResult::Failed(reach_core::SystemResolverFailure {
                        kind: reach_core::SystemResolverFailureKind::NoUsableAddress,
                        platform_code: Some(11_001),
                        platform_message: "synthetic negative".into(),
                    }),
                },
                provenance: provenance(),
            }),
            HostnameResolutionOutcome::NegativeWithoutUsableAddress {
                platform_code: Some(11_001),
            },
            Vec::new(),
            Vec::new(),
            vec![Evidence {
                id: EvidenceId(1),
                subject: EvidenceSubject::Hostname,
                role: EvidenceRole::PrimaryDecision,
                fact: EvidenceFact::NameResolution(reach_core::NameResolutionEvidence {
                    outcome: NameResolutionEvidenceOutcome::NegativeWithoutUsableAddress,
                }),
            }],
        );
        let output = render(&negative, Theme::plain());
        assert!(output.starts_with("× NO USABLE IP ADDRESS\n"));
        assert!(output.contains("System name resolution"));
        assert!(output.contains("NAME RESOLUTION"));
        assert!(output.contains("Requested test"));
        assert!(output.contains("Not started"));
        assert!(output.contains("Not exposed by this platform"));
        assert!(output.contains("The hostname did not resolve to an IP address"));
        assert!(output.contains("No ICMP or TCP check was started"));
        assert!(!output.contains("does not exist"));
        assert!(!output.contains("Any direct DNS evidence"));
        assert!(!output.to_ascii_lowercase().contains("system dns"));
    }

    #[test]
    fn extra_context_attempts_never_leak_into_default_output() {
        let mut completed = timeout_then_icmp_result();
        let target = &mut completed.targets[0];
        target.attempts.push(attempt(
            99,
            AttemptKind::NextHopIcmpEcho,
            AttemptOutcome::Icmp(IcmpAttemptResult::ExplicitNetworkError {
                os_code: Some(9_999),
            }),
            Duration::from_secs(1),
            Duration::from_millis(2),
        ));
        target.evidence.push(Evidence {
            id: EvidenceId(99),
            subject: EvidenceSubject::Target(target.target.clone()),
            role: EvidenceRole::Context,
            fact: EvidenceFact::Attempt(AttemptId(99)),
        });

        let output = render(&completed, Theme::plain());
        assert!(!output.contains("9999"));
        assert!(!output.contains("Next-hop"));
    }

    #[test]
    fn windows_native_status_cannot_appear_as_an_icmp_wire_code() {
        let outcome = AttemptOutcome::Icmp(IcmpAttemptResult::Message {
            kind: IcmpMessageKind::EchoReply,
            responder: Ipv4Addr::LOCALHOST.into(),
            raw_type: None,
            raw_code: None,
            native_status: Some(IcmpNativeStatus::WindowsIpHelper(0)),
        });
        let test_attempt = Attempt {
            id: AttemptId(1),
            subject: reach_core::AttemptSubject::Target(TargetIp::v4(Ipv4Addr::LOCALHOST)),
            kind: AttemptKind::TargetIcmpEcho,
            timing: reach_core::AttemptTiming {
                started_at: Duration::ZERO,
                deadline_at: Duration::from_secs(2),
                completed_at: Duration::ZERO,
            },
            outcome,
            provenance: provenance(),
        };
        let rendered = friendly_attempt_outcome(&test_attempt);
        assert_eq!(rendered, "Reply from 127.0.0.1");
        assert!(!rendered.contains("raw"));
        assert!(!rendered.contains("status"));
    }

    #[test]
    fn zero_duration_is_described_as_clock_resolution_not_a_latency_claim() {
        let attempt = attempt(
            1,
            AttemptKind::TargetIcmpEcho,
            AttemptOutcome::Icmp(IcmpAttemptResult::ExplicitNetworkError { os_code: None }),
            Duration::from_secs(2),
            Duration::ZERO,
        );
        let rendered = attempt_evidence_summary(&attempt, Some(1));
        assert!(rendered.contains("same observable clock reading"));
        assert!(!rendered.contains("0 ms"));
        assert!(!rendered.contains("<1"));
    }

    #[test]
    fn deadline_wording_does_not_report_scheduler_tail_as_budget() {
        let attempt = attempt(
            1,
            AttemptKind::TcpConnect,
            AttemptOutcome::Tcp(TcpAttemptResult::Timeout),
            Duration::from_secs(5),
            Duration::from_millis(5_016),
        );
        let rendered = attempt_evidence_summary(&attempt, Some(1));
        assert_eq!(
            rendered,
            "TCP connect #1: No result before the 5 s deadline."
        );
        assert!(!rendered.contains("5s 16ms"));
        assert!(!rendered.contains("/ 5s"));
    }

    #[test]
    fn neighbor_observation_states_are_not_conflated() {
        assert_eq!(
            neighbor_observation_label(NeighborObservation::NotSampled),
            "not sampled"
        );
        assert_eq!(
            neighbor_observation_label(NeighborObservation::Observed(NeighborState::Absent)),
            "absent (no matching entry)"
        );
        assert_eq!(
            neighbor_observation_label(NeighborObservation::Unknown),
            "unknown"
        );
        assert_eq!(
            neighbor_observation_label(NeighborObservation::Unavailable),
            "unavailable"
        );
    }

    #[test]
    fn snapshot_inconsistency_never_claims_temporal_change() {
        let evidence = Evidence {
            id: EvidenceId(1),
            subject: EvidenceSubject::Run,
            role: EvidenceRole::CapabilityLimitation,
            fact: EvidenceFact::SnapshotInconsistency("route refers to missing interface".into()),
        };
        let rendered = evidence_summary(&timeout_then_icmp_result(), &evidence);
        assert!(rendered.starts_with("Snapshot cross-check found an inconsistency"));
        assert!(!rendered.contains("changed"));
        assert!(!rendered.contains("stable"));
    }

    #[test]
    fn one_address_uses_singular_pronouns() {
        let output = render(&timeout_then_icmp_result(), Theme::plain());
        assert!(output.contains("That IP address"));
        assert!(!output.contains("all 1 IP address"));
        assert!(!output.contains("The same IP addresses"));
    }

    #[test]
    fn layouts_from_twenty_to_three_hundred_columns_do_not_overflow() {
        let completed = timeout_then_icmp_result();
        for width in [20_u16, 40, 59, 60, 80, 120, 140, 300] {
            let output = render(&completed, Theme::plain_with_width(width));
            for line in output.lines() {
                assert!(
                    line.width() <= usize::from(width),
                    "width {width}, rendered {} columns: {line:?}\n{output}",
                    line.width()
                );
            }
            assert!(output.contains("192.0.2.20:8443"));
            assert!(output.contains("EVIDENCE"));
        }
    }

    #[test]
    fn mixed_addresses_remain_separate() {
        let snapshot = synthetic_snapshot();
        let first = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 1));
        let second = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 2));
        let completed = CompletedDiagnostic::new(
            parse_request("example.com", Some("443")).expect("valid request"),
            snapshot.clone(),
            None,
            HostnameResolutionOutcome::Succeeded(reach_core::ResolverAddressSet::from_raw(vec![
                first.clone(),
                second.clone(),
            ])),
            vec![
                result_only_target(
                    &snapshot,
                    first,
                    0,
                    PrimaryOutcome::Satisfied,
                    Conclusion::TcpConnectSucceeded,
                ),
                result_only_target(
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
        let output = render(&completed, Theme::plain());
        assert!(output.starts_with("! RESULTS DIFFER BETWEEN IP ADDRESSES\n"));
        assert!(output.contains("192.0.2.1:443"));
        assert!(output.contains("192.0.2.2:443"));
        assert!(output.contains("Keep every address and result"));
    }

    #[test]
    fn retry_success_remains_a_warning_not_a_clean_pass() {
        let snapshot = synthetic_snapshot();
        let target_ip = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 3));
        let completed = CompletedDiagnostic::new(
            parse_request("192.0.2.3", Some("443")).expect("valid request"),
            snapshot.clone(),
            None,
            HostnameResolutionOutcome::NotRequested,
            vec![result_only_target(
                &snapshot,
                target_ip,
                0,
                PrimaryOutcome::SatisfiedWithAnomaly,
                Conclusion::TcpConnectSucceededAfterTimeout,
            )],
            Vec::new(),
            Vec::new(),
        );
        let output = render(&completed, Theme::plain());
        assert!(output.starts_with("! REACHABLE, BUT A RETRY WAS NEEDED\n"));
        assert!(output.contains("later success does not erase the first timeout"));
    }

    #[test]
    fn icmp_silence_does_not_claim_that_the_destination_is_down() {
        let snapshot = synthetic_snapshot();
        let target_ip = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 4));
        let completed = CompletedDiagnostic::new(
            parse_request("192.0.2.4", None).expect("valid request"),
            snapshot.clone(),
            None,
            HostnameResolutionOutcome::NotRequested,
            vec![result_only_target(
                &snapshot,
                target_ip,
                0,
                PrimaryOutcome::Indeterminate,
                Conclusion::IcmpEchoTimedOut,
            )],
            Vec::new(),
            Vec::new(),
        );
        let output = render(&completed, Theme::plain());
        let flattened = output.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(output.starts_with("× NO ICMP REPLY WAS CONFIRMED\n"));
        assert!(flattened.contains("does not prove that the destination is down"));
        assert!(output.contains("? INCONCLUSIVE"));
    }

    #[test]
    fn every_conclusion_has_a_plain_language_label() {
        let conclusions = [
            Conclusion::TcpConnectSucceeded,
            Conclusion::TcpConnectSucceededAfterTimeout,
            Conclusion::TcpConnectionRefused,
            Conclusion::TcpExplicitFailure,
            Conclusion::TcpConnectTimedOut,
            Conclusion::TcpTimedOutButTargetIcmpResponded,
            Conclusion::TcpTimedOutWithExplicitIcmpResult,
            Conclusion::IcmpEchoReplied,
            Conclusion::IcmpEchoRepliedAfterTimeout,
            Conclusion::IcmpExplicitFailure,
            Conclusion::IcmpEchoTimedOut,
            Conclusion::IcmpResponseIndeterminate,
            Conclusion::DefinitiveNoPath,
            Conclusion::NeighborResolutionFailed,
            Conclusion::NeighborResolutionIndeterminate,
            Conclusion::FirstHopResponded,
            Conclusion::MultiplePathRespondersObserved,
            Conclusion::PathEndpointResponded,
            Conclusion::PathExplicitlyTerminated,
            Conclusion::PathResponseIndeterminate,
            Conclusion::PathLimitReachedWithoutEndpointEvidence,
            Conclusion::HostnameResolved,
            Conclusion::HostnameNoFormalTargets,
            Conclusion::HostnameResolutionNoUsableAddress,
            Conclusion::HostnameResolutionIndeterminate,
            Conclusion::AllTargetsSatisfied,
            Conclusion::TargetsSatisfiedWithAnomaly,
            Conclusion::TargetResultsMixed,
            Conclusion::NoTargetCleanlySatisfied,
            Conclusion::CapabilityLimited,
        ];
        for conclusion in conclusions {
            let label = diagnostic_note(&conclusion);
            assert!(!label.is_empty());
            assert!(!label.contains("formal"));
            assert!(!label.contains("CapabilityValue"));
            assert!(!label.contains("System DNS"));
        }
    }

    fn timeout_then_icmp_result() -> CompletedDiagnostic {
        let snapshot = synthetic_snapshot();
        let target_ip = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 20));
        let target = TargetDiagnostic::new(
            target_ip.clone(),
            Some(0),
            PrimaryOutcome::NotSatisfied,
            Conclusion::TcpTimedOutButTargetIcmpResponded,
            TargetNetworkFacts {
                initial_path: analyze_initial_path(&snapshot, &target_ip),
                current_path: CapabilityValue::unavailable(
                    CapabilityReason::QuerySemanticsUnavailable,
                    provenance(),
                ),
                neighbor_pre_state: None,
                neighbor_post_state: None,
            },
            vec![
                attempt(
                    1,
                    AttemptKind::TcpConnect,
                    AttemptOutcome::Tcp(TcpAttemptResult::Timeout),
                    Duration::from_secs(5),
                    Duration::from_millis(5_016),
                ),
                attempt(
                    2,
                    AttemptKind::TcpConnect,
                    AttemptOutcome::Tcp(TcpAttemptResult::Timeout),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                ),
                attempt(
                    3,
                    AttemptKind::TargetIcmpEcho,
                    AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                        kind: IcmpMessageKind::EchoReply,
                        responder: target_ip.address,
                        raw_type: None,
                        raw_code: None,
                        native_status: Some(IcmpNativeStatus::WindowsIpHelper(0)),
                    }),
                    Duration::from_secs(2),
                    Duration::from_millis(15),
                ),
            ],
            vec![
                attempt_evidence(1, &target_ip, EvidenceRole::AnomalyHistory),
                attempt_evidence(2, &target_ip, EvidenceRole::PrimaryDecision),
                attempt_evidence(3, &target_ip, EvidenceRole::BoundaryNarrowing),
            ],
        );
        CompletedDiagnostic::new(
            parse_request("example.com", Some("8443")).expect("valid request"),
            snapshot,
            None,
            HostnameResolutionOutcome::Succeeded(reach_core::ResolverAddressSet::from_raw(vec![
                target_ip,
            ])),
            vec![target],
            Vec::new(),
            Vec::new(),
        )
    }

    fn clean_icmp_success() -> CompletedDiagnostic {
        let snapshot = synthetic_snapshot();
        let target_ip = TargetIp::v4(Ipv4Addr::LOCALHOST);
        let target = TargetDiagnostic::new(
            target_ip.clone(),
            Some(0),
            PrimaryOutcome::Satisfied,
            Conclusion::IcmpEchoReplied,
            TargetNetworkFacts {
                initial_path: analyze_initial_path(&snapshot, &target_ip),
                current_path: CapabilityValue::unavailable(
                    CapabilityReason::QuerySemanticsUnavailable,
                    provenance(),
                ),
                neighbor_pre_state: None,
                neighbor_post_state: None,
            },
            vec![attempt(
                1,
                AttemptKind::TargetIcmpEcho,
                AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                    kind: IcmpMessageKind::EchoReply,
                    responder: target_ip.address,
                    raw_type: Some(0),
                    raw_code: Some(0),
                    native_status: None,
                }),
                Duration::from_secs(2),
                Duration::ZERO,
            )],
            vec![attempt_evidence(
                1,
                &target_ip,
                EvidenceRole::PrimaryDecision,
            )],
        );
        CompletedDiagnostic::new(
            parse_request("127.0.0.1", None).expect("valid request"),
            snapshot,
            None,
            HostnameResolutionOutcome::NotRequested,
            vec![target],
            Vec::new(),
            Vec::new(),
        )
    }

    fn attempt(
        id: u64,
        kind: AttemptKind,
        outcome: AttemptOutcome,
        budget: Duration,
        recorded_duration: Duration,
    ) -> Attempt {
        let started_at = Duration::from_secs(id);
        Attempt {
            id: AttemptId(id),
            subject: reach_core::AttemptSubject::Target(TargetIp::v4(Ipv4Addr::new(192, 0, 2, 20))),
            kind,
            timing: reach_core::AttemptTiming {
                started_at,
                deadline_at: started_at + budget,
                completed_at: started_at + recorded_duration,
            },
            outcome,
            provenance: provenance(),
        }
    }

    fn attempt_evidence(id: u64, target: &TargetIp, role: EvidenceRole) -> Evidence {
        Evidence {
            id: EvidenceId(id),
            subject: EvidenceSubject::Target(target.clone()),
            role,
            fact: EvidenceFact::Attempt(AttemptId(id)),
        }
    }

    fn result_only_target(
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
                    provenance(),
                ),
                neighbor_pre_state: None,
                neighbor_post_state: None,
            },
            Vec::new(),
            Vec::new(),
        )
    }

    fn provenance() -> Provenance {
        Provenance::new(ProvenanceSource::SyntheticTest).at(Duration::ZERO)
    }

    fn synthetic_snapshot() -> InitialNetworkSnapshot {
        let provenance = provenance();
        InitialNetworkSnapshot {
            capture_started_at: Duration::ZERO,
            capture_completed_at: Duration::from_millis(2),
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
            routing_policy_facts: CapabilityValue::unavailable(
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
}
