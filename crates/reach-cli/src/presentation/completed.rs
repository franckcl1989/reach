use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    net::IpAddr,
    time::Duration,
};

use comfy_table::{
    ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_BORDERS_ONLY,
};
use humantime::format_duration;
use reach_core::{
    AggregateOutcome, Attempt, AttemptId, AttemptKind, AttemptOutcome, CapabilityReason,
    CapabilityValue, CompletedDiagnostic, Conclusion, DnsAttemptResult, DnsQueryType, Evidence,
    EvidenceFact, EvidenceRole, HostnameResolutionOutcome, IcmpAttemptResult, IcmpMessageKind,
    InitialPathAnalysis, InitialPathStatus, NeighborFact, NeighborState, OperationPathContext,
    PathRelation, PrimaryOutcome, ResolverDependencyDiagnostic, ResolverTransport, RouteBehavior,
    RouteFact, SystemResolverFailureKind, SystemResolverResult, TargetDiagnostic, TargetIp,
    TargetNetworkFacts, TcpAttemptResult,
};

use super::{Theme, bullets, field, indented_block, paragraph, section, terminal_escape};

pub(super) fn render(completed: &CompletedDiagnostic, theme: Theme) -> String {
    let mut output = String::new();
    render_verdict(&mut output, completed, theme);
    render_check(&mut output, completed, theme);
    if !completed.targets.is_empty() {
        render_targets(&mut output, completed, theme);
    }
    render_meaning(&mut output, completed, theme);
    render_actions(&mut output, completed, theme);
    render_key_evidence(&mut output, completed, theme);
    render_technical_details(&mut output, completed, theme);
    output
}

fn render_verdict(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    let title = verdict_title(completed);
    let decorated = match completed.aggregate_outcome {
        AggregateOutcome::AllSatisfied => theme.success(&format!("✓ {title}")),
        AggregateOutcome::SatisfiedWithAnomaly | AggregateOutcome::Mixed => {
            theme.warning(&format!("! {title}"))
        }
        AggregateOutcome::NoneCleanlySatisfied | AggregateOutcome::NoFormalTargets => {
            theme.failure(&format!("× {title}"))
        }
    };
    let _ = writeln!(output, "{decorated}");
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
        "Address",
        terminal_escape(&completed.request.original_address),
    );
    if let Some(port) = completed.request.port {
        field(
            output,
            "Test",
            format!("TCP connection to port {}", port.get()),
        );
    } else {
        field(output, "Test", "ICMP Echo (address-level response)");
    }
    if let Some(summary) = resolver_check_summary(completed) {
        field(output, "System DNS", summary);
    }
    field(output, "Result", count_summary(completed));
    let _ = writeln!(output);
}

fn render_targets(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    section(output, theme, "TARGETS");
    let mut table = report_table(theme);
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
    indented_block(output, &table.to_string());
    let _ = writeln!(output);
}

fn render_meaning(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    section(output, theme, "WHAT THIS MEANS");
    bullets(output, theme, meaning(completed));
    let _ = writeln!(output);
}

fn render_actions(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    let actions = actions(completed);
    if actions.is_empty() {
        return;
    }
    section(output, theme, "WHAT TO DO");
    bullets(output, theme, actions);
    let _ = writeln!(output);
}

fn render_key_evidence(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    if completed.key_evidence.is_empty()
        || matches!(completed.aggregate_outcome, AggregateOutcome::AllSatisfied)
    {
        return;
    }
    section(output, theme, "WHY REACH GAVE THIS RESULT");
    bullets(
        output,
        theme,
        completed
            .key_evidence
            .iter()
            .map(|evidence| evidence_summary(completed, evidence)),
    );
    let _ = writeln!(output);
}

fn render_technical_details(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    section(output, theme, "TECHNICAL DETAILS");
    field(output, "Reach version", env!("CARGO_PKG_VERSION"));
    field(
        output,
        "Platform",
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
    );
    field(
        output,
        "Input",
        request_label(
            &completed.request.original_address,
            completed.request.port.map(|port| port.get()),
        ),
    );
    field(
        output,
        "Exit code",
        completed.exit_status().code().to_string(),
    );
    let _ = writeln!(output);

    render_system_resolver(output, completed, theme);
    if !matches!(completed.aggregate_outcome, AggregateOutcome::AllSatisfied) {
        render_snapshot(output, completed, theme);
        render_path_details(output, completed, theme);
        render_diagnostic_notes(output, completed, theme);
    }
    render_target_attempts(output, completed, theme);
    render_additional_evidence(output, completed, theme);
    for (index, resolver) in completed.resolver_diagnostics.iter().enumerate() {
        render_resolver_details(output, resolver, index + 1, theme);
    }
}

fn render_system_resolver(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    let Some(resolver) = &completed.system_resolver else {
        return;
    };
    let _ = writeln!(output, "  {}", theme.strong("SYSTEM DNS"));
    field(
        output,
        "Duration",
        human_duration(resolver.completed_at.saturating_sub(resolver.started_at)),
    );
    match &resolver.result {
        SystemResolverResult::Succeeded(addresses) => {
            field(output, "Outcome", "Succeeded");
            field(
                output,
                "Returned",
                counted(
                    addresses.raw_addresses.len(),
                    "address record",
                    "address records",
                ),
            );
            field(
                output,
                "Checked",
                counted(
                    addresses.formal_targets.len(),
                    "unique address",
                    "unique addresses",
                ),
            );
            let values = addresses
                .raw_addresses
                .iter()
                .enumerate()
                .map(|(index, target)| format!("{}: {}", index + 1, target_label(target, None)))
                .collect::<Vec<_>>();
            field(
                output,
                "In order",
                if values.is_empty() {
                    "none".to_owned()
                } else {
                    values.join(", ")
                },
            );
        }
        SystemResolverResult::Failed(failure) => {
            field(output, "Outcome", resolver_failure_label(failure.kind));
            field(
                output,
                "OS code",
                failure
                    .platform_code
                    .map_or_else(|| "not provided".to_owned(), |code| code.to_string()),
            );
            field(
                output,
                "OS message",
                terminal_escape(&failure.platform_message),
            );
        }
    }
    let _ = writeln!(output);
}

fn render_snapshot(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    let snapshot = &completed.initial_snapshot;
    let _ = writeln!(output, "  {}", theme.strong("LOCAL NETWORK SNAPSHOT"));
    field(
        output,
        "Capture duration",
        human_duration(
            snapshot
                .capture_completed_at
                .saturating_sub(snapshot.capture_started_at),
        ),
    );
    field(
        output,
        "Interfaces",
        capability_count(&snapshot.interfaces, "interface", "interfaces"),
    );
    field(
        output,
        "IPv4 routes",
        capability_count(&snapshot.routes_v4, "route", "routes"),
    );
    field(
        output,
        "IPv6 routes",
        capability_count(&snapshot.routes_v6, "route", "routes"),
    );
    field(
        output,
        "Route policy",
        match &snapshot.routing_policy_facts {
            CapabilityValue::Available { value, .. } => format!(
                "available ({}; static selection complete={})",
                counted(value.facts.len(), "fact", "facts"),
                value.static_selection_complete
            ),
            CapabilityValue::Unknown { reason, .. } => {
                format!("unknown ({})", capability_reason(reason))
            }
            CapabilityValue::Unavailable { reason, .. } => {
                format!("unavailable ({})", capability_reason(reason))
            }
        },
    );
    field(
        output,
        "Resolver config",
        match &snapshot.resolver_configuration {
            CapabilityValue::Available { value, .. } => {
                format!(
                    "available ({})",
                    counted(value.endpoints.len(), "endpoint", "endpoints")
                )
            }
            CapabilityValue::Unknown { reason, .. } => {
                format!("unknown ({})", capability_reason(reason))
            }
            CapabilityValue::Unavailable { reason, .. } => {
                format!("unavailable ({})", capability_reason(reason))
            }
        },
    );
    if snapshot.inconsistencies.is_empty() {
        field(output, "Consistency", "No snapshot change was detected");
    } else {
        for inconsistency in &snapshot.inconsistencies {
            field(
                output,
                "Inconsistency",
                format!(
                    "{:?}: {}",
                    inconsistency.scope,
                    terminal_escape(&inconsistency.detail)
                ),
            );
        }
    }
    let _ = writeln!(output);
}

fn render_path_details(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    if completed.targets.is_empty() {
        return;
    }
    let _ = writeln!(output, "  {}", theme.strong("PATH AND NEIGHBOR FACTS"));
    let mut table = report_table(theme);
    table.set_header(["Target", "Initial path", "Current path", "Neighbor"]);
    for target in &completed.targets {
        table.add_row([
            target_label(
                &target.target,
                completed.request.port.map(|port| port.get()),
            ),
            initial_path_summary(&target.network_facts.initial_path),
            current_path_summary(&target.network_facts.current_path),
            neighbor_pair_summary(&target.network_facts),
        ]);
    }
    indented_block(output, &table.to_string());
    let mut limitations = BTreeMap::<String, Vec<String>>::new();
    let mut comparisons = BTreeMap::<String, Vec<String>>::new();
    let mut interface_identities = BTreeMap::<u32, BTreeSet<String>>::new();
    for target in &completed.targets {
        let label = target_label(
            &target.target,
            completed.request.port.map(|port| port.get()),
        );
        for route in &target.network_facts.initial_path.matching_routes {
            field(
                output,
                "Matching route",
                format!("{label}: {}", route_summary(route)),
            );
        }
        for limitation in &target.network_facts.initial_path.limitations {
            limitations
                .entry(readable_detail(limitation))
                .or_default()
                .push(label.clone());
        }
        if let CapabilityValue::Available { value, .. } = &target.network_facts.current_path {
            if let Some(comparison) = &value.relation_to_initial_snapshot {
                comparisons
                    .entry(terminal_escape(comparison))
                    .or_default()
                    .push(label.clone());
            }
            record_interface_identity(&mut interface_identities, value.egress_interface.as_ref());
        }
        for neighbor in [
            target.network_facts.neighbor_pre_state.as_ref(),
            target.network_facts.neighbor_post_state.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if let CapabilityValue::Available { value, .. } = neighbor {
                record_interface_identity(
                    &mut interface_identities,
                    Some(&value.identity.interface),
                );
            }
        }
    }
    for (limitation, targets) in limitations {
        field(
            output,
            "Path limitation",
            format!(
                "{}: {limitation}",
                grouped_targets(&targets, completed.targets.len())
            ),
        );
    }
    for (comparison, targets) in comparisons {
        field(
            output,
            "Path comparison",
            format!(
                "{}: {comparison}",
                grouped_targets(&targets, completed.targets.len())
            ),
        );
    }
    for (index, stable_ids) in interface_identities {
        if !stable_ids.is_empty() {
            field(
                output,
                "Interface identity",
                format!(
                    "index {index}: {}",
                    stable_ids.into_iter().collect::<Vec<_>>().join(", ")
                ),
            );
        }
    }
    let _ = writeln!(output);
}

fn render_diagnostic_notes(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    if completed
        .targets
        .iter()
        .all(|target| target.diagnostic_conclusions.is_empty())
    {
        return;
    }
    let _ = writeln!(output, "  {}", theme.strong("DIAGNOSTIC NOTES"));
    for target in &completed.targets {
        let label = target_label(
            &target.target,
            completed.request.port.map(|port| port.get()),
        );
        for conclusion in &target.diagnostic_conclusions {
            field(
                output,
                "Target note",
                format!("{label}: {}", diagnostic_note(conclusion)),
            );
        }
    }
    let _ = writeln!(output);
}

fn render_target_attempts(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    let count = completed
        .targets
        .iter()
        .map(|target| target.attempts.len())
        .sum::<usize>();
    if count == 0 {
        return;
    }
    let _ = writeln!(output, "  {}", theme.strong("NETWORK ATTEMPTS"));
    field(output, "Total", counted(count, "attempt", "attempts"));
    let mut table = report_table(theme);
    table.set_header([
        "Target",
        "# / ID",
        "Check",
        "Observed result",
        "Elapsed / limit",
    ]);
    for target in &completed.targets {
        let label = target_label(
            &target.target,
            completed.request.port.map(|port| port.get()),
        );
        for (index, attempt) in target.attempts.iter().enumerate() {
            table.add_row([
                label.clone(),
                format!("{} / A{}", index + 1, attempt.id.0),
                attempt_kind_label(attempt.kind),
                attempt_outcome_label(&attempt.outcome),
                format!(
                    "{} / {}",
                    human_duration(attempt.timing.duration()),
                    human_duration(
                        attempt
                            .timing
                            .deadline_at
                            .saturating_sub(attempt.timing.started_at)
                    )
                ),
            ]);
        }
    }
    indented_block(output, &table.to_string());
    let _ = writeln!(output);
}

fn render_additional_evidence(output: &mut String, completed: &CompletedDiagnostic, theme: Theme) {
    let values = completed
        .targets
        .iter()
        .flat_map(|target| {
            let label = target_label(
                &target.target,
                completed.request.port.map(|port| port.get()),
            );
            target.evidence.iter().filter_map(move |evidence| {
                additional_evidence(&evidence.fact)
                    .map(|fact| format!("{label}: {}: {fact}", evidence_role_label(evidence.role)))
            })
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        return;
    }
    let _ = writeln!(output, "  {}", theme.strong("ADDITIONAL EVIDENCE"));
    for value in values {
        field(output, "Evidence", value);
    }
    let _ = writeln!(output);
}

fn render_resolver_details(
    output: &mut String,
    resolver: &ResolverDependencyDiagnostic,
    ordinal: usize,
    theme: Theme,
) {
    let endpoint = format!(
        "{}:{} via {}",
        resolver.endpoint.address,
        resolver.endpoint.port,
        resolver_transport_label(resolver.endpoint.transport)
    );
    let _ = writeln!(
        output,
        "  {}",
        theme.strong(&format!("DNS DIAGNOSTIC {ordinal} — {endpoint}"))
    );
    render_network_facts(output, &resolver.network_facts);
    render_attempts(output, &resolver.attempts, theme);
    render_non_attempt_evidence(output, &resolver.evidence);
    let _ = writeln!(output);
}

fn render_network_facts(output: &mut String, facts: &TargetNetworkFacts) {
    field(
        output,
        "Initial path",
        initial_path_summary(&facts.initial_path),
    );
    for route in &facts.initial_path.matching_routes {
        field(output, "Matching route", route_summary(route));
    }
    for limitation in &facts.initial_path.limitations {
        field(output, "Path limit", readable_detail(limitation));
    }
    field(
        output,
        "Current path",
        current_path_summary(&facts.current_path),
    );
    if let Some(before) = &facts.neighbor_pre_state {
        field(output, "Neighbor before", neighbor_summary(before));
    }
    if let Some(after) = &facts.neighbor_post_state {
        field(output, "Neighbor after", neighbor_summary(after));
    }
}

fn render_attempts(output: &mut String, attempts: &[Attempt], theme: Theme) {
    if attempts.is_empty() {
        field(output, "Attempts", "No active network attempt was needed");
        return;
    }
    let mut table = report_table(theme);
    table.set_header(["#", "Check", "Observed result", "Timing"]);
    for (index, attempt) in attempts.iter().enumerate() {
        table.add_row([
            format!("{} (A{})", index + 1, attempt.id.0),
            attempt_kind_label(attempt.kind),
            attempt_outcome_label(&attempt.outcome),
            format!(
                "{} / {}",
                human_duration(attempt.timing.duration()),
                human_duration(
                    attempt
                        .timing
                        .deadline_at
                        .saturating_sub(attempt.timing.started_at)
                )
            ),
        ]);
    }
    field(output, "Attempts", format!("{} total", attempts.len()));
    indented_block(output, &table.to_string());
}

fn render_non_attempt_evidence(output: &mut String, evidence: &[Evidence]) {
    for item in evidence {
        if matches!(item.fact, EvidenceFact::Attempt(_)) {
            continue;
        }
        field(
            output,
            "Evidence",
            format!(
                "{}: {}",
                evidence_role_label(item.role),
                evidence_fact_label(&item.fact)
            ),
        );
    }
}

fn report_table(theme: Theme) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_BORDERS_ONLY)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    if let Some(width) = theme.table_width() {
        table.set_width(width);
    }
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
            HostnameResolutionOutcome::DefinitiveNegative { .. } => "NAME WAS NOT FOUND",
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
        AggregateOutcome::SatisfiedWithAnomaly => vec![format!(
            "All {} eventually responded, but at least one first timed out and succeeded only on retry.",
            counted(count, "IP address", "IP addresses")
        )],
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
                    vec![
                        format!(
                            "TCP connections to port {} timed out for all {}.",
                            port.get(),
                            counted(count, "IP address", "IP addresses")
                        ),
                        "The same IP addresses replied to ICMP Echo even though the TCP connections did not complete."
                            .to_owned(),
                    ]
                } else if all_targets_are(completed, Conclusion::TcpConnectionRefused) {
                    vec![format!(
                        "Every IP address explicitly refused the TCP connection to port {}.",
                        port.get()
                    )]
                } else {
                    vec![format!(
                        "No TCP connection to port {} completed successfully for the {} checked.",
                        port.get(),
                        counted(count, "IP address", "IP addresses")
                    )]
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
            HostnameResolutionOutcome::DefinitiveNegative { .. } => vec![format!(
                "The system DNS resolver reported that {address} does not exist."
            )],
            HostnameResolutionOutcome::NonDefinitiveFailure { .. } => vec![format!(
                "The system DNS resolver could not produce a reliable IP address for {address}."
            )],
            HostnameResolutionOutcome::SucceededWithoutUsableAddress => vec![format!(
                "The system DNS resolver completed but returned no usable IPv4 or IPv6 address for {address}."
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
                    "The TCP handshake completed. This confirms TCP connectivity to the requested port at the time of the check."
                        .to_owned(),
                    "Reach did not send application data, so this does not prove that HTTP, HTTPS, SSH, or another application protocol is working."
                        .to_owned(),
                ]
            } else {
                vec![
                    "The destination returned an ICMP Echo Reply, confirming an address-level response at the time of the check."
                        .to_owned(),
                    "This does not test a TCP port, website, or other application service."
                        .to_owned(),
                ]
            }
        }
        AggregateOutcome::SatisfiedWithAnomaly => vec![
            "Connectivity was eventually observed, but the earlier timeout is real evidence of a transient or intermittent problem."
                .to_owned(),
            "The later success does not erase the first timeout, so Reach does not report a clean pass."
                .to_owned(),
        ],
        AggregateOutcome::Mixed => vec![
            "A hostname can lead to several IP addresses. Some paths or destination instances responded differently from others."
                .to_owned(),
            "A successful address does not erase a failure or uncertainty on another address."
                .to_owned(),
        ],
        AggregateOutcome::NoneCleanlySatisfied => {
            if all_targets_are(
                completed,
                Conclusion::TcpTimedOutButTargetIcmpResponded,
            ) {
                vec![
                    "The IP addresses exchanged ICMP traffic with this computer, but no TCP connection to the requested port completed."
                        .to_owned(),
                    "A timeout does not prove that the port is closed and does not identify whether filtering, the network path, or the destination service caused the missing TCP response."
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
                    "The requested TCP connection did not complete. The per-target observations and technical details show the exact failure boundary Reach observed."
                        .to_owned(),
                    "Reach does not guess an unobserved root cause from a timeout or operating-system error name."
                        .to_owned(),
                ]
            } else {
                vec![
                    "Reach did not obtain a confirmed ICMP Echo response. This alone does not prove that the destination is down because ICMP may be blocked or limited."
                        .to_owned(),
                    "The technical details retain any route, Neighbor, first-hop, and capability evidence that could narrow the boundary safely."
                        .to_owned(),
                ]
            }
        }
        AggregateOutcome::NoFormalTargets => vec![
            "No destination connection or ICMP check was started because Reach did not have a usable IP address from the system resolver."
                .to_owned(),
            "Any direct DNS checks shown below are diagnostic evidence only and were not promoted into destination addresses."
                .to_owned(),
        ],
    }
}

fn actions(completed: &CompletedDiagnostic) -> Vec<String> {
    match completed.aggregate_outcome {
        AggregateOutcome::AllSatisfied => Vec::new(),
        AggregateOutcome::SatisfiedWithAnomaly => vec![
            "Run the same check again and note whether the timeout repeats.".to_owned(),
            "If users notice intermittent failures, send this entire report to the service owner or network team."
                .to_owned(),
        ],
        AggregateOutcome::Mixed => vec![
            "Send this entire report to the service owner or network team; the per-address difference is important."
                .to_owned(),
            "Do not remove the addresses that failed when sharing the result.".to_owned(),
        ],
        AggregateOutcome::NoneCleanlySatisfied => {
            if let Some(port) = completed.request.port {
                vec![
                    format!(
                        "Verify that TCP port {} is correct and that the service is expected to accept connections on it.",
                        port.get()
                    ),
                    "If the port should be reachable, send this entire report to the service owner or network team."
                        .to_owned(),
                ]
            } else {
                vec![
                    "If the destination is expected to answer ping, run the check again to rule out a short transient loss."
                        .to_owned(),
                    "If you need help, send this entire report to the network team; ICMP silence alone is not proof that the destination is down."
                        .to_owned(),
                ]
            }
        }
        AggregateOutcome::NoFormalTargets => vec![
            "Check the spelling of the hostname and try again.".to_owned(),
            "If the name is correct, send this entire report to the support or network team so they can inspect the DNS details."
                .to_owned(),
        ],
    }
}

fn resolver_check_summary(completed: &CompletedDiagnostic) -> Option<String> {
    match &completed.hostname_resolution {
        HostnameResolutionOutcome::NotRequested => None,
        HostnameResolutionOutcome::Succeeded(addresses) => Some(format!(
            "{}, {} checked",
            counted(addresses.raw_addresses.len(), "record", "records"),
            counted(
                addresses.formal_targets.len(),
                "unique address",
                "unique addresses"
            )
        )),
        HostnameResolutionOutcome::SucceededWithoutUsableAddress => {
            Some("completed, but returned no usable IP address".to_owned())
        }
        HostnameResolutionOutcome::DefinitiveNegative { .. } => {
            Some("name does not exist".to_owned())
        }
        HostnameResolutionOutcome::NonDefinitiveFailure { .. } => {
            Some("failed without a definitive answer".to_owned())
        }
    }
}

fn count_summary(completed: &CompletedDiagnostic) -> String {
    if completed.targets.is_empty() {
        return "No IP address was checked".to_owned();
    }
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
        Conclusion::TcpExplicitFailure => target
            .attempts
            .iter()
            .find_map(|attempt| match &attempt.outcome {
                AttemptOutcome::Tcp(result) if !matches!(result, TcpAttemptResult::Timeout) => {
                    Some(attempt_outcome_label(&attempt.outcome))
                }
                _ => None,
            })
            .unwrap_or_else(|| "TCP connection failed with an explicit error".to_owned()),
        Conclusion::TcpConnectTimedOut => "TCP connection timed out twice".to_owned(),
        Conclusion::TcpTimedOutButTargetIcmpResponded => {
            "TCP timed out twice; the IP address replied to ICMP Echo".to_owned()
        }
        Conclusion::TcpTimedOutWithExplicitIcmpResult => {
            "TCP timed out twice; ICMP returned an explicit network result".to_owned()
        }
        Conclusion::IcmpEchoReplied => "ICMP Echo Reply received".to_owned(),
        Conclusion::IcmpEchoRepliedAfterTimeout => {
            "ICMP Echo Reply received on retry after an earlier timeout".to_owned()
        }
        Conclusion::IcmpExplicitFailure => target
            .attempts
            .iter()
            .find_map(|attempt| match &attempt.outcome {
                AttemptOutcome::Icmp(result) if !matches!(result, IcmpAttemptResult::Timeout) => {
                    Some(attempt_outcome_label(&attempt.outcome))
                }
                _ => None,
            })
            .unwrap_or_else(|| "ICMP returned an explicit network result".to_owned()),
        Conclusion::IcmpEchoTimedOut => "No ICMP Echo Reply after two attempts".to_owned(),
        Conclusion::IcmpResponseIndeterminate => {
            "ICMP response did not prove success or a definite failure".to_owned()
        }
        Conclusion::DefinitiveNoPath => {
            "Local network information proves there is no usable path".to_owned()
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
        | Conclusion::HostnameResolutionDefinitiveNegative
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
        Conclusion::TcpExplicitFailure => "TCP connection failed with an explicit error",
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
        Conclusion::DefinitiveNoPath => "Initial local facts prove no usable path",
        Conclusion::NeighborResolutionFailed => "Required local Neighbor resolution failed",
        Conclusion::NeighborResolutionIndeterminate => {
            "Required local Neighbor resolution remained inconclusive"
        }
        Conclusion::FirstHopResponded => "The current first hop replied directly",
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
        Conclusion::HostnameResolved => "System DNS produced destination addresses",
        Conclusion::HostnameNoFormalTargets => "System DNS produced no usable destination address",
        Conclusion::HostnameResolutionDefinitiveNegative => {
            "System DNS reported that the hostname does not exist"
        }
        Conclusion::HostnameResolutionIndeterminate => {
            "System DNS failed without a definitive answer"
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
            || format!("Attempt A{} was retained as decision evidence.", id.0),
            |(attempt, ordinal)| {
                format!(
                    "{} attempt {ordinal} (A{}): {} in {}.",
                    attempt_kind_label(attempt.kind),
                    attempt.id.0,
                    friendly_attempt_outcome(&attempt.outcome),
                    human_duration(attempt.timing.duration())
                )
            },
        ),
        EvidenceFact::SystemResolverResult(_) => resolver_check_summary(completed).map_or_else(
            || "System DNS completed.".to_owned(),
            |summary| format!("System DNS: {summary}."),
        ),
        fact => as_sentence(evidence_fact_label(fact)),
    }
}

fn additional_evidence(fact: &EvidenceFact) -> Option<String> {
    match fact {
        EvidenceFact::Attempt(_)
        | EvidenceFact::InitialPath(_)
        | EvidenceFact::CurrentPath(_)
        | EvidenceFact::NeighborTransition { .. }
        | EvidenceFact::SystemResolverResult(_) => None,
        EvidenceFact::DirectDnsResult(_)
        | EvidenceFact::CapabilityUnavailable { .. }
        | EvidenceFact::SnapshotInconsistency(_)
        | EvidenceFact::SocketPathComparison(_) => Some(evidence_fact_label(fact)),
    }
}

fn as_sentence(mut value: String) -> String {
    if !value.ends_with(['.', '!', '?']) {
        value.push('.');
    }
    value
}

fn evidence_fact_label(fact: &EvidenceFact) -> String {
    match fact {
        EvidenceFact::Attempt(id) => format!("Attempt A{}", id.0),
        EvidenceFact::InitialPath(value) => {
            format!("Initial path: {}", terminal_escape(value))
        }
        EvidenceFact::CurrentPath(value) => {
            format!("Current path: {}", terminal_escape(value))
        }
        EvidenceFact::NeighborTransition { before, after } => format!(
            "Neighbor state changed from {} to {}",
            before.map_or("not observed", neighbor_state_label),
            neighbor_state_label(*after)
        ),
        EvidenceFact::SystemResolverResult(value) => {
            format!("System DNS: {}", terminal_escape(value))
        }
        EvidenceFact::DirectDnsResult(value) => {
            format!("Direct DNS diagnostic: {}", terminal_escape(value))
        }
        EvidenceFact::CapabilityUnavailable { capability, reason } => format!(
            "{} unavailable: {}",
            terminal_escape(capability),
            capability_reason(reason)
        ),
        EvidenceFact::SnapshotInconsistency(value) => {
            format!("Network snapshot changed: {}", terminal_escape(value))
        }
        EvidenceFact::SocketPathComparison(value) => {
            format!("Socket/path comparison: {}", terminal_escape(value))
        }
    }
}

fn find_attempt(completed: &CompletedDiagnostic, id: AttemptId) -> Option<(&Attempt, usize)> {
    for target in &completed.targets {
        if let Some((index, attempt)) = target
            .attempts
            .iter()
            .enumerate()
            .find(|(_, attempt)| attempt.id == id)
        {
            return Some((attempt, index + 1));
        }
    }
    for resolver in &completed.resolver_diagnostics {
        if let Some((index, attempt)) = resolver
            .attempts
            .iter()
            .enumerate()
            .find(|(_, attempt)| attempt.id == id)
        {
            return Some((attempt, index + 1));
        }
    }
    None
}

fn attempt_kind_label(kind: AttemptKind) -> String {
    match kind {
        AttemptKind::TcpConnect => "TCP Connect".to_owned(),
        AttemptKind::TargetIcmpEcho => "Target ICMP Echo".to_owned(),
        AttemptKind::NextHopIcmpEcho => "Next-hop ICMP Echo".to_owned(),
        AttemptKind::TcpPath { hop_limit } => {
            format!("TCP path probe (hop limit {hop_limit})")
        }
        AttemptKind::IcmpPath { hop_limit } => {
            format!("ICMP path probe (hop limit {hop_limit})")
        }
        AttemptKind::DnsUdp { query_type } => {
            format!("DNS {} over UDP", dns_query_type_label(query_type))
        }
        AttemptKind::DnsTcp { query_type } => {
            format!("DNS {} over TCP", dns_query_type_label(query_type))
        }
    }
}

fn attempt_outcome_label(outcome: &AttemptOutcome) -> String {
    match outcome {
        AttemptOutcome::Tcp(result) => tcp_outcome_label(result),
        AttemptOutcome::Icmp(result) => icmp_outcome_label(result),
        AttemptOutcome::Dns(result) => dns_outcome_label(result),
    }
}

fn friendly_attempt_outcome(outcome: &AttemptOutcome) -> String {
    match outcome {
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
            "explicit operating-system network error (code {})",
            os_code.map_or_else(|| "not provided".to_owned(), |code| code.to_string())
        ),
        AttemptOutcome::Icmp(IcmpAttemptResult::Timeout) => {
            "timed out with no ICMP response".to_owned()
        }
        AttemptOutcome::Dns(result) => dns_outcome_label(result),
    }
}

fn tcp_outcome_label(result: &TcpAttemptResult) -> String {
    match result {
        TcpAttemptResult::Connected { local, remote } => format!(
            "Connected (local {}; remote {})",
            endpoint_capability(local),
            endpoint_capability(remote)
        ),
        TcpAttemptResult::ConnectionRefused => "Connection refused".to_owned(),
        TcpAttemptResult::NoRoute => "No route".to_owned(),
        TcpAttemptResult::NetworkUnreachable => "Network unreachable".to_owned(),
        TcpAttemptResult::HostUnreachable => "Host unreachable".to_owned(),
        TcpAttemptResult::PermissionDenied => "Permission denied".to_owned(),
        TcpAttemptResult::ResourceExhausted => "Local resources exhausted".to_owned(),
        TcpAttemptResult::OtherExplicitError { os_code } => format!(
            "Explicit operating-system error (code {})",
            os_code.map_or_else(|| "not provided".to_owned(), |code| code.to_string())
        ),
        TcpAttemptResult::Timeout => "Timed out with no explicit result".to_owned(),
    }
}

fn endpoint_capability(value: &CapabilityValue<reach_core::IpEndpoint>) -> String {
    match value {
        CapabilityValue::Available { value, .. } => {
            if value.address.is_ipv6() {
                format!("[{}]:{}", value.address, value.port)
            } else {
                format!("{}:{}", value.address, value.port)
            }
        }
        CapabilityValue::Unknown { reason, .. } => {
            format!("unknown: {}", capability_reason(reason))
        }
        CapabilityValue::Unavailable { reason, .. } => {
            format!("unavailable: {}", capability_reason(reason))
        }
    }
}

fn icmp_outcome_label(result: &IcmpAttemptResult) -> String {
    match result {
        IcmpAttemptResult::Message {
            kind,
            responder,
            raw_type,
            raw_code,
        } => format!(
            "{} from {} (raw type {}, raw code {})",
            icmp_kind_label(*kind),
            responder,
            raw_icmp_value(*raw_type),
            optional_number(*raw_code)
        ),
        IcmpAttemptResult::Messages(messages) => messages
            .iter()
            .map(|message| {
                format!(
                    "{} from {} (raw type {}, raw code {})",
                    icmp_kind_label(message.kind),
                    message.responder,
                    raw_icmp_value(message.raw_type),
                    optional_number(message.raw_code)
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
        IcmpAttemptResult::ExplicitNetworkError { os_code } => format!(
            "Explicit operating-system network error (code {})",
            os_code.map_or_else(|| "not provided".to_owned(), |code| code.to_string())
        ),
        IcmpAttemptResult::Timeout => "Timed out with no ICMP response".to_owned(),
    }
}

fn dns_outcome_label(result: &DnsAttemptResult) -> String {
    match result {
        DnsAttemptResult::Response {
            response_code,
            addresses,
            aliases,
            truncated,
        } => format!(
            "Response code {response_code}; addresses [{}]; aliases [{}]; truncated={truncated}",
            addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            aliases
                .iter()
                .map(|alias| terminal_escape(alias))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        DnsAttemptResult::TransportError { os_code } => format!(
            "DNS transport error (OS code {})",
            os_code.map_or_else(|| "not provided".to_owned(), |code| code.to_string())
        ),
        DnsAttemptResult::ProtocolError => "DNS protocol error".to_owned(),
        DnsAttemptResult::Timeout => "DNS request timed out".to_owned(),
    }
}

fn initial_path_summary(path: &InitialPathAnalysis) -> String {
    let status = match path.status {
        InitialPathStatus::UsablePath => "usable",
        InitialPathStatus::DefinitiveNoPath => "definitively unavailable",
        InitialPathStatus::UnknownPath => "unknown",
    };
    let mut facts = vec![status.to_owned()];
    if path.relation != PathRelation::Unknown {
        facts.push(path_relation_label(path.relation).to_owned());
    }
    if let Some(interface) = &path.egress_interface {
        facts.push(interface_short_label(interface));
    }
    if let Some(next_hop) = path.next_hop {
        facts.push(format!("via {next_hop}"));
    }
    if let Some(source) = path.preferred_source {
        facts.push(format!("source {source}"));
    }
    facts.join("; ")
}

fn current_path_summary(path: &CapabilityValue<OperationPathContext>) -> String {
    match path {
        CapabilityValue::Available { value, .. } => format!(
            "{}; {}; next-hop={}; source={}",
            path_relation_label(value.relation),
            value.egress_interface.as_ref().map_or_else(
                || "interface not identified".to_owned(),
                interface_short_label
            ),
            optional_ip(value.next_hop),
            optional_ip(value.preferred_source)
        ),
        CapabilityValue::Unknown { reason, .. } => {
            format!("unknown ({})", capability_reason(reason))
        }
        CapabilityValue::Unavailable { reason, .. } => {
            format!("unavailable ({})", capability_reason(reason))
        }
    }
}

fn neighbor_summary(value: &CapabilityValue<NeighborFact>) -> String {
    match value {
        CapabilityValue::Available { value, .. } => format!(
            "{} for {}; {}; raw-state={}",
            neighbor_state_label(value.state),
            value.identity.address,
            interface_short_label(&value.identity.interface),
            value
                .raw_state
                .as_ref()
                .map_or_else(|| "not provided".to_owned(), |state| terminal_escape(state))
        ),
        CapabilityValue::Unknown { reason, .. } => {
            format!("unknown ({})", capability_reason(reason))
        }
        CapabilityValue::Unavailable { reason, .. } => {
            format!("unavailable ({})", capability_reason(reason))
        }
    }
}

fn neighbor_pair_summary(facts: &TargetNetworkFacts) -> String {
    match (&facts.neighbor_pre_state, &facts.neighbor_post_state) {
        (None, None) => "not required or not observed".to_owned(),
        (Some(before), None) => {
            format!("before: {}; after: not observed", neighbor_summary(before))
        }
        (None, Some(after)) => format!("before: not observed; after: {}", neighbor_summary(after)),
        (Some(before), Some(after)) => format!(
            "before: {}; after: {}",
            neighbor_summary(before),
            neighbor_summary(after)
        ),
    }
}

fn route_summary(route: &RouteFact) -> String {
    format!(
        "{}; behavior={}; next-hop={}; interface={}; metric={}; table/compartment={}; source={}; ECMP-weight={}",
        route.destination,
        route_behavior_label(route.behavior),
        optional_ip(route.next_hop),
        route
            .egress_interface
            .as_ref()
            .map_or_else(|| "not identified".to_owned(), interface_label),
        optional_number(route.metric),
        optional_number(route.table_or_compartment),
        optional_ip(route.preferred_source),
        optional_number(route.multipath_weight)
    )
}

fn capability_count<T>(value: &CapabilityValue<Vec<T>>, singular: &str, plural: &str) -> String {
    match value {
        CapabilityValue::Available { value, .. } => {
            format!("available ({})", counted(value.len(), singular, plural))
        }
        CapabilityValue::Unknown { reason, .. } => {
            format!("unknown ({})", capability_reason(reason))
        }
        CapabilityValue::Unavailable { reason, .. } => {
            format!("unavailable ({})", capability_reason(reason))
        }
    }
}

fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

fn readable_detail(value: &str) -> String {
    let mut value = terminal_escape(value);
    for (internal, readable) in [
        (
            "NotExposedByOperatingSystem",
            "not exposed by the operating system",
        ),
        (
            "OrdinaryUserPermissionDenied",
            "ordinary-user permission was denied",
        ),
        (
            "SnapshotInconsistent",
            "the local network snapshot was inconsistent",
        ),
        (
            "QuerySemanticsUnavailable",
            "the required read-only query semantics are unavailable",
        ),
        (
            "AttemptCorrelationUnavailable",
            "attempt correlation is unavailable",
        ),
        ("UnsupportedEnvironment", "the environment is unsupported"),
    ] {
        value = value.replace(internal, readable);
    }
    value
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
            "the local network snapshot changed during capture".to_owned()
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

fn all_targets_are(completed: &CompletedDiagnostic, conclusion: Conclusion) -> bool {
    !completed.targets.is_empty()
        && completed
            .targets
            .iter()
            .all(|target| target.conclusion == conclusion)
}

fn request_label(address: &str, port: Option<u16>) -> String {
    port.map_or_else(
        || terminal_escape(address),
        |port| format!("{} {port}", terminal_escape(address)),
    )
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

fn interface_label(interface: &reach_core::InterfaceId) -> String {
    interface.stable_id.as_ref().map_or_else(
        || format!("index {}", interface.index),
        |stable| format!("index {} ({})", interface.index, terminal_escape(stable)),
    )
}

fn interface_short_label(interface: &reach_core::InterfaceId) -> String {
    format!("interface #{}", interface.index)
}

fn record_interface_identity(
    identities: &mut BTreeMap<u32, BTreeSet<String>>,
    interface: Option<&reach_core::InterfaceId>,
) {
    let Some(interface) = interface else {
        return;
    };
    if let Some(stable_id) = &interface.stable_id {
        identities
            .entry(interface.index)
            .or_default()
            .insert(terminal_escape(stable_id));
    }
}

fn grouped_targets(targets: &[String], total: usize) -> String {
    if targets.len() == total && total > 1 {
        format!("all {total} targets")
    } else {
        targets.join(", ")
    }
}

fn optional_ip(value: Option<IpAddr>) -> String {
    value.map_or_else(|| "not provided".to_owned(), |value| value.to_string())
}

fn optional_number<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "not provided".to_owned(), |value| value.to_string())
}

fn raw_icmp_value(value: Option<u16>) -> String {
    value.map_or_else(|| "not exposed".to_owned(), |value| value.to_string())
}

fn human_duration(value: Duration) -> String {
    if value.is_zero() {
        "0 ms".to_owned()
    } else {
        format_duration(value).to_string()
    }
}

const fn path_relation_label(value: PathRelation) -> &'static str {
    match value {
        PathRelation::Local => "local",
        PathRelation::OnLink => "on-link",
        PathRelation::Remote => "remote",
        PathRelation::Unknown => "unknown",
    }
}

const fn neighbor_state_label(value: NeighborState) -> &'static str {
    match value {
        NeighborState::Resolving => "resolving",
        NeighborState::Usable => "usable",
        NeighborState::TerminalFailure => "terminal failure",
        NeighborState::Unknown => "unknown",
    }
}

const fn route_behavior_label(value: RouteBehavior) -> &'static str {
    match value {
        RouteBehavior::Unicast => "unicast",
        RouteBehavior::Local => "local",
        RouteBehavior::Broadcast => "broadcast",
        RouteBehavior::Multicast => "multicast",
        RouteBehavior::Reject => "reject",
        RouteBehavior::Blackhole => "blackhole",
        RouteBehavior::Unreachable => "unreachable",
        RouteBehavior::Prohibit => "prohibit",
        RouteBehavior::Throw => "throw",
        RouteBehavior::Unknown => "unknown",
    }
}

const fn resolver_transport_label(value: ResolverTransport) -> &'static str {
    match value {
        ResolverTransport::Udp => "UDP",
        ResolverTransport::Tcp => "TCP",
        ResolverTransport::Tls => "TLS",
        ResolverTransport::Https => "HTTPS",
        ResolverTransport::SystemPrivate => "system-private transport",
        ResolverTransport::Unknown => "unknown transport",
    }
}

const fn resolver_failure_label(value: SystemResolverFailureKind) -> &'static str {
    match value {
        SystemResolverFailureKind::DefinitiveNoName => "Definitive name-not-found result",
        SystemResolverFailureKind::Temporary => "Temporary resolver failure",
        SystemResolverFailureKind::Timeout => "Resolver timeout",
        SystemResolverFailureKind::ResolverFailure => "Resolver failure",
        SystemResolverFailureKind::OtherPlatformFailure => "Other operating-system failure",
        SystemResolverFailureKind::Unknown => "Unknown resolver failure",
    }
}

const fn dns_query_type_label(value: DnsQueryType) -> &'static str {
    match value {
        DnsQueryType::A => "A",
        DnsQueryType::Aaaa => "AAAA",
    }
}

const fn icmp_kind_label(value: IcmpMessageKind) -> &'static str {
    match value {
        IcmpMessageKind::EchoReply => "Echo Reply",
        IcmpMessageKind::DestinationUnreachable => "Destination Unreachable",
        IcmpMessageKind::TimeExceeded => "Time Exceeded",
        IcmpMessageKind::PacketTooBig => "Packet Too Big",
        IcmpMessageKind::ParameterProblem => "Parameter Problem",
        IcmpMessageKind::Other => "Other ICMP message",
    }
}

const fn evidence_role_label(value: EvidenceRole) -> &'static str {
    match value {
        EvidenceRole::PrimaryDecision => "primary decision",
        EvidenceRole::AnomalyHistory => "anomaly history",
        EvidenceRole::BoundaryNarrowing => "failure-boundary detail",
        EvidenceRole::CapabilityLimitation => "capability limitation",
        EvidenceRole::Context => "context",
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use super::*;
    use reach_core::{
        CapabilityReason, CapabilityValue, CompletedDiagnostic, Conclusion, Evidence, EvidenceFact,
        EvidenceId, EvidenceRole, EvidenceSubject, HostnameResolutionOutcome,
        InitialNetworkSnapshot, InterfaceFact, PrimaryOutcome, Provenance, ProvenanceSource,
        ResolverConfiguration, RouteFact, TargetDiagnostic, TargetNetworkFacts,
        analyze_initial_path, parse_request,
    };

    #[test]
    fn tcp_timeout_and_icmp_reply_is_friendly_and_attempts_are_numbered() {
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
                    5,
                ),
                attempt(
                    2,
                    AttemptKind::TcpConnect,
                    AttemptOutcome::Tcp(TcpAttemptResult::Timeout),
                    5,
                ),
                attempt(
                    3,
                    AttemptKind::TargetIcmpEcho,
                    AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                        kind: IcmpMessageKind::EchoReply,
                        responder: target_ip.address,
                        raw_type: Some(0),
                        raw_code: Some(0),
                    }),
                    1,
                ),
            ],
            vec![
                attempt_evidence(1, &target_ip, EvidenceRole::AnomalyHistory),
                attempt_evidence(2, &target_ip, EvidenceRole::PrimaryDecision),
                attempt_evidence(3, &target_ip, EvidenceRole::BoundaryNarrowing),
            ],
        );
        let completed = CompletedDiagnostic::new(
            parse_request("example.com", Some("8443")).expect("valid request"),
            snapshot,
            None,
            HostnameResolutionOutcome::Succeeded(reach_core::ResolverAddressSet::from_raw(vec![
                target_ip,
            ])),
            vec![target],
            Vec::new(),
            Vec::new(),
        );

        let output = render(&completed, Theme::plain());
        assert!(output.contains("TCP timed out twice; the IP address replied to ICMP Echo"));
        assert!(output.contains("1 (A1)"));
        assert!(output.contains("2 (A2)"));
        assert!(output.contains("3 (A3)"));
        assert!(output.contains("A timeout does not prove that the port is closed"));
        assert!(!output.contains("formal target"));
        assert!(!output.contains("TCP timed out\n  - 192.0.2.20: TCP timed out"));
    }

    #[test]
    fn redirected_success_report_has_no_ansi_and_explains_scope() {
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
                }),
                1,
            )],
            vec![attempt_evidence(
                1,
                &target_ip,
                EvidenceRole::PrimaryDecision,
            )],
        );
        let completed = CompletedDiagnostic::new(
            parse_request("127.0.0.1", None).expect("valid request"),
            snapshot,
            None,
            HostnameResolutionOutcome::NotRequested,
            vec![target],
            Vec::new(),
            Vec::new(),
        );
        let output = render(&completed, Theme::plain());
        assert!(output.starts_with("✓ ADDRESS RESPONDED\n"));
        assert!(output.contains("This does not test a TCP port, website"));
        assert!(output.contains("Exit code          0"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn definitive_dns_negative_is_explained_without_internal_vocabulary() {
        let completed = CompletedDiagnostic::new(
            parse_request("missing.invalid", None).expect("valid request"),
            synthetic_snapshot(),
            None,
            HostnameResolutionOutcome::DefinitiveNegative {
                platform_code: Some(11_001),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let output = render(&completed, Theme::plain());
        assert!(output.starts_with("× NAME WAS NOT FOUND\n"));
        assert!(output.contains("No destination connection or ICMP check was started"));
        assert!(output.contains("Exit code          1"));
        assert!(!output.contains("formal target"));
        assert!(!output.contains("aggregate"));
    }

    #[test]
    fn mixed_addresses_are_kept_separate_and_shared_together() {
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
        assert!(output.contains("Do not remove the addresses that failed"));
        assert!(output.contains("Exit code          1"));
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
        assert!(output.contains("Exit code          1"));
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
        assert!(output.contains("Exit code          1"));
    }

    #[test]
    fn every_conclusion_has_a_plain_language_diagnostic_label() {
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
            Conclusion::HostnameResolutionDefinitiveNegative,
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
            assert!(!label.contains("Indeterminate"));
        }
    }

    fn attempt(id: u64, kind: AttemptKind, outcome: AttemptOutcome, seconds: u64) -> Attempt {
        Attempt {
            id: AttemptId(id),
            subject: reach_core::AttemptSubject::Target(TargetIp::v4(Ipv4Addr::new(192, 0, 2, 20))),
            kind,
            timing: reach_core::AttemptTiming {
                started_at: Duration::from_secs(id),
                deadline_at: Duration::from_secs(id + seconds),
                completed_at: Duration::from_secs(id + seconds),
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
