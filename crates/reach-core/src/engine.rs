use std::{collections::HashMap, num::NonZeroU16};

use futures_util::{StreamExt, stream};
use tokio_util::sync::CancellationToken;

use crate::{
    Attempt, AttemptId, AttemptOutcome, AttemptSubject, BoundAddressInput, Cancelled,
    CapabilityReason, CapabilityValue, CompletedDiagnostic, Conclusion, DNS_TCP_BUDGET,
    DNS_UDP_BUDGET, DiagnosticIo, DiagnosticIoError, DiagnosticIoErrorKind, DiagnosticResult,
    DirectDnsOperation, DirectDnsTransportReason, DnsAttemptResult, DnsQueryType, Evidence,
    EvidenceFact, EvidenceId, EvidenceRole, EvidenceSubject, ExecutionError, ExecutionErrorKind,
    FormalTarget, Hostname, HostnameResolutionOutcome, IcmpAttemptResult, IcmpEchoSubject,
    IcmpMessageKind, IcmpOperation, InitialNetworkSnapshot, InitialPathAnalysis, InitialPathStatus,
    MAX_ACTIVE_RESOLVERS, MAX_ACTIVE_TARGETS, MAX_PATH_HOP_LIMIT, NEXT_HOP_ICMP_BUDGET,
    NeighborDependency, NeighborFact, NeighborIdentity, NeighborState, OperationPathContext,
    PATH_ATTEMPT_BUDGET, ParsedRequest, PathOperation, PathRelation, PrimaryOutcome, Provenance,
    ProvenanceSource, ResolverDependencyDiagnostic, ResolverEndpoint, ResolverTransport,
    SnapshotInconsistencyScope, SystemResolverFailureKind, SystemResolverObservation,
    SystemResolverResult, TARGET_ICMP_BUDGET, TCP_CONNECT_BUDGET, TargetDiagnostic, TargetIp,
    TargetNetworkFacts, TcpAttemptResult, TcpOperation, analyze_initial_path,
    bind_diagnostic_request, neighbor_dependency_for_path, reconcile_current_operation_path,
};

pub async fn run_diagnostic(
    parsed: ParsedRequest,
    io: &impl DiagnosticIo,
    cancellation: &CancellationToken,
) -> DiagnosticResult {
    if cancellation.is_cancelled() {
        return cancelled();
    }
    let snapshot = match io.capture_initial_snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => return terminal_io_error(error, cancellation),
    };
    let request = match bind_diagnostic_request(&parsed, &snapshot.interfaces) {
        Ok(request) => request,
        Err(error) => {
            if cancellation.is_cancelled() {
                return cancelled();
            }
            return DiagnosticResult::ExecutionError(ExecutionError {
                kind: ExecutionErrorKind::ScopedIpv6BindingFailed,
                safe_message: error.to_string(),
                partial_evidence: Vec::new(),
            });
        }
    };

    let (system_resolver, mut hostname_resolution, formal_targets, mut run_evidence) =
        match &request.address {
            BoundAddressInput::Ipv4Literal(target) | BoundAddressInput::Ipv6Literal(target) => (
                None,
                HostnameResolutionOutcome::NotRequested,
                vec![FormalTarget {
                    target: target.clone(),
                    resolver_ordinal: None,
                }],
                Vec::new(),
            ),
            BoundAddressInput::Hostname(hostname) => {
                let observation = match io.system_resolve(hostname, cancellation).await {
                    Ok(observation) => observation,
                    Err(error) => return terminal_io_error(error, cancellation),
                };
                let evidence = vec![system_resolver_evidence(&observation)];
                match &observation.result {
                    SystemResolverResult::Succeeded(addresses)
                        if addresses.formal_targets.is_empty() =>
                    {
                        (
                            Some(observation.clone()),
                            HostnameResolutionOutcome::SucceededWithoutUsableAddress,
                            Vec::new(),
                            evidence,
                        )
                    }
                    SystemResolverResult::Succeeded(addresses) => (
                        Some(observation.clone()),
                        HostnameResolutionOutcome::Succeeded(addresses.clone()),
                        addresses.formal_targets.clone(),
                        evidence,
                    ),
                    SystemResolverResult::Failed(failure)
                        if failure.kind == SystemResolverFailureKind::DefinitiveNoName =>
                    {
                        (
                            Some(observation.clone()),
                            HostnameResolutionOutcome::DefinitiveNegative {
                                platform_code: failure.platform_code,
                            },
                            Vec::new(),
                            evidence,
                        )
                    }
                    SystemResolverResult::Failed(failure) => (
                        Some(observation.clone()),
                        HostnameResolutionOutcome::NonDefinitiveFailure {
                            platform_code: failure.platform_code,
                            direct_dns_was_diagnostic_only: false,
                        },
                        Vec::new(),
                        evidence,
                    ),
                }
            }
        };

    let mut resolver_diagnostics = Vec::new();
    if formal_targets.is_empty()
        && matches!(
            hostname_resolution,
            HostnameResolutionOutcome::NonDefinitiveFailure { .. }
        )
        && let BoundAddressInput::Hostname(hostname) = &request.address
    {
        let diagnostic =
            match diagnose_resolver_failure(hostname, &snapshot, io, cancellation).await {
                Ok(diagnostic) => diagnostic,
                Err(error) => return terminal_io_error(error, cancellation),
            };
        resolver_diagnostics = diagnostic.dependencies;
        run_evidence.extend(diagnostic.evidence);
        if let HostnameResolutionOutcome::NonDefinitiveFailure {
            direct_dns_was_diagnostic_only,
            ..
        } = &mut hostname_resolution
        {
            *direct_dns_was_diagnostic_only = resolver_diagnostics
                .iter()
                .any(|diagnostic| !diagnostic.attempts.is_empty());
        }
    }

    if formal_targets.is_empty() {
        if cancellation.is_cancelled() {
            return cancelled();
        }
        return DiagnosticResult::Completed(Box::new(CompletedDiagnostic::new(
            parsed,
            snapshot,
            system_resolver,
            hostname_resolution,
            Vec::new(),
            resolver_diagnostics,
            run_evidence,
        )));
    }

    let prepared = match prepare_targets(&snapshot, &formal_targets, io, cancellation).await {
        Ok(prepared) => prepared,
        Err(error) => return terminal_io_error(error, cancellation),
    };
    if cancellation.is_cancelled() {
        return cancelled();
    }

    let diagnostics = stream::iter(prepared.into_iter().enumerate())
        .map(|(ordinal, prepared)| {
            diagnose_target(io, prepared, request.port, ordinal, cancellation)
        })
        .buffered(MAX_ACTIVE_TARGETS);
    let mut diagnostics = Box::pin(diagnostics);
    let mut targets = Vec::with_capacity(formal_targets.len());
    while let Some(result) = diagnostics.next().await {
        match result {
            Ok(target) => targets.push(target),
            Err(error) => return terminal_io_error(error, cancellation),
        }
    }
    if cancellation.is_cancelled() {
        return cancelled();
    }

    DiagnosticResult::Completed(Box::new(CompletedDiagnostic::new(
        parsed,
        snapshot,
        system_resolver,
        hostname_resolution,
        targets,
        resolver_diagnostics,
        run_evidence,
    )))
}

struct ResolverFailureDiagnosis {
    dependencies: Vec<ResolverDependencyDiagnostic>,
    evidence: Vec<Evidence>,
}

async fn diagnose_resolver_failure(
    hostname: &Hostname,
    snapshot: &InitialNetworkSnapshot,
    io: &impl DiagnosticIo,
    cancellation: &CancellationToken,
) -> Result<ResolverFailureDiagnosis, DiagnosticIoError> {
    let resolver_inconsistencies = snapshot
        .inconsistencies
        .iter()
        .filter(|item| item.scope == SnapshotInconsistencyScope::ResolverSelection)
        .collect::<Vec<_>>();
    if !resolver_inconsistencies.is_empty() {
        return Ok(ResolverFailureDiagnosis {
            dependencies: Vec::new(),
            evidence: resolver_inconsistencies
                .into_iter()
                .enumerate()
                .map(|(ordinal, inconsistency)| Evidence {
                    id: EvidenceId(100 + ordinal as u64),
                    subject: EvidenceSubject::Hostname,
                    role: EvidenceRole::CapabilityLimitation,
                    fact: EvidenceFact::SnapshotInconsistency(inconsistency.detail.clone()),
                })
                .collect(),
        });
    }
    let configuration = match &snapshot.resolver_configuration {
        CapabilityValue::Available { value, .. } => value,
        CapabilityValue::Unknown { reason, .. } | CapabilityValue::Unavailable { reason, .. } => {
            return Ok(ResolverFailureDiagnosis {
                dependencies: Vec::new(),
                evidence: vec![Evidence {
                    id: EvidenceId(100),
                    subject: EvidenceSubject::Hostname,
                    role: EvidenceRole::CapabilityLimitation,
                    fact: EvidenceFact::CapabilityUnavailable {
                        capability: "applicable resolver configuration".into(),
                        reason: reason.clone(),
                    },
                }],
            });
        }
    };

    match &configuration.dns_protocol_candidates_applicable {
        CapabilityValue::Available { value: true, .. } => {}
        CapabilityValue::Available { value: false, .. } => {
            return Ok(ResolverFailureDiagnosis {
                dependencies: Vec::new(),
                evidence: vec![Evidence {
                    id: EvidenceId(100),
                    subject: EvidenceSubject::Hostname,
                    role: EvidenceRole::CapabilityLimitation,
                    fact: EvidenceFact::CapabilityUnavailable {
                        capability: "applicable DNS protocol source".into(),
                        reason: CapabilityReason::Other(
                            "captured resolver-source policy does not include classic DNS".into(),
                        ),
                    },
                }],
            });
        }
        CapabilityValue::Unknown { reason, .. } | CapabilityValue::Unavailable { reason, .. } => {
            return Ok(ResolverFailureDiagnosis {
                dependencies: Vec::new(),
                evidence: vec![Evidence {
                    id: EvidenceId(100),
                    subject: EvidenceSubject::Hostname,
                    role: EvidenceRole::CapabilityLimitation,
                    fact: EvidenceFact::CapabilityUnavailable {
                        capability: "applicable DNS protocol source".into(),
                        reason: reason.clone(),
                    },
                }],
            });
        }
    }

    let (mut candidates, mut unsupported) = select_resolver_candidates(hostname, configuration);
    if !configuration.ordering_is_semantic {
        candidates.sort_by_key(resolver_sort_key);
        unsupported.sort_by_key(resolver_sort_key);
    }
    let mut evidence = Vec::new();
    for (ordinal, endpoint) in unsupported.into_iter().enumerate() {
        evidence.push(Evidence {
            id: EvidenceId(110 + ordinal as u64),
            subject: EvidenceSubject::Resolver(resolver_label(&endpoint)),
            role: EvidenceRole::CapabilityLimitation,
            fact: EvidenceFact::CapabilityUnavailable {
                capability: "resolver transport diagnosis".into(),
                reason: CapabilityReason::QuerySemanticsUnavailable,
            },
        });
    }
    if candidates.is_empty() {
        if evidence.is_empty() {
            evidence.push(Evidence {
                id: EvidenceId(100),
                subject: EvidenceSubject::Hostname,
                role: EvidenceRole::CapabilityLimitation,
                fact: EvidenceFact::CapabilityUnavailable {
                    capability: "applicable DNS resolver candidate".into(),
                    reason: CapabilityReason::QuerySemanticsUnavailable,
                },
            });
        }
        return Ok(ResolverFailureDiagnosis {
            dependencies: Vec::new(),
            evidence,
        });
    }
    if !hostname.ascii().ends_with('.') && !configuration.search_domains.is_empty() {
        evidence.push(Evidence {
            id: EvidenceId(101),
            subject: EvidenceSubject::Hostname,
            role: EvidenceRole::CapabilityLimitation,
            fact: EvidenceFact::CapabilityUnavailable {
                capability: "system resolver actual query-name equivalence".into(),
                reason: CapabilityReason::QuerySemanticsUnavailable,
            },
        });
    }

    let prepared = prepare_resolver_candidates(snapshot, candidates, io, cancellation).await?;
    let diagnostics = stream::iter(prepared.into_iter().enumerate())
        .map(|(ordinal, prepared)| {
            diagnose_resolver_candidate(hostname, prepared, ordinal, io, cancellation)
        })
        .buffered(MAX_ACTIVE_RESOLVERS);
    let mut diagnostics = Box::pin(diagnostics);
    let mut dependencies = Vec::new();
    while let Some(result) = diagnostics.next().await {
        let result = result?;
        evidence.extend(result.evidence.iter().cloned());
        dependencies.push(result);
    }
    Ok(ResolverFailureDiagnosis {
        dependencies,
        evidence,
    })
}

fn select_resolver_candidates(
    hostname: &Hostname,
    configuration: &crate::ResolverConfiguration,
) -> (Vec<ResolverEndpoint>, Vec<ResolverEndpoint>) {
    let scored: Vec<_> = configuration
        .endpoints
        .iter()
        .filter_map(|endpoint| {
            resolver_match_score(endpoint, hostname).map(|score| (score, endpoint))
        })
        .collect();
    let best_scoped_score = scored.iter().map(|(score, _)| *score).max().unwrap_or(0);
    let selected = scored
        .into_iter()
        .filter(|(score, _)| {
            (best_scoped_score == 0 && *score == 0)
                || (best_scoped_score > 0 && *score == best_scoped_score)
        })
        .map(|(_, endpoint)| endpoint.clone());
    selected.partition(|endpoint| {
        matches!(
            endpoint.transport,
            ResolverTransport::Udp | ResolverTransport::Tcp
        )
    })
}

fn resolver_match_score(endpoint: &ResolverEndpoint, hostname: &Hostname) -> Option<usize> {
    if endpoint.domains.is_empty() {
        return Some(0);
    }
    let hostname = hostname.ascii().trim_end_matches('.').to_ascii_lowercase();
    endpoint
        .domains
        .iter()
        .filter_map(|domain| {
            let domain = domain
                .trim_start_matches('~')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if domain.is_empty() {
                Some(1)
            } else {
                (hostname == domain || hostname.strip_suffix(&format!(".{domain}")).is_some())
                    .then_some(domain.len() + 1)
            }
        })
        .max()
}

fn resolver_sort_key(
    endpoint: &ResolverEndpoint,
) -> (
    Option<String>,
    Option<u32>,
    u64,
    std::net::IpAddr,
    u16,
    u8,
    String,
) {
    (
        endpoint
            .interface
            .as_ref()
            .and_then(|interface| interface.stable_id.clone()),
        endpoint.interface.as_ref().map(|interface| interface.index),
        endpoint.priority.unwrap_or(u64::MAX),
        endpoint.address,
        endpoint.port,
        resolver_transport_order(endpoint.transport),
        resolver_domains_sort_key(endpoint),
    )
}

fn resolver_domains_sort_key(endpoint: &ResolverEndpoint) -> String {
    let mut domains = endpoint
        .domains
        .iter()
        .map(|domain| domain.to_ascii_lowercase())
        .collect::<Vec<_>>();
    domains.sort();
    domains.join("\u{0}")
}

const fn resolver_transport_order(transport: ResolverTransport) -> u8 {
    match transport {
        ResolverTransport::Udp => 0,
        ResolverTransport::Tcp => 1,
        ResolverTransport::Tls => 2,
        ResolverTransport::Https => 3,
        ResolverTransport::SystemPrivate => 4,
        ResolverTransport::Unknown => 5,
    }
}

#[derive(Clone)]
struct PreparedResolverCandidate {
    endpoint: ResolverEndpoint,
    initial_path: InitialPathAnalysis,
    current_path: CapabilityValue<OperationPathContext>,
    neighbor_dependency: NeighborDependency,
    neighbor_pre_state: Option<CapabilityValue<NeighborFact>>,
}

async fn prepare_resolver_candidates(
    snapshot: &InitialNetworkSnapshot,
    candidates: Vec<ResolverEndpoint>,
    io: &impl DiagnosticIo,
    cancellation: &CancellationToken,
) -> Result<Vec<PreparedResolverCandidate>, DiagnosticIoError> {
    let mut prepared = Vec::with_capacity(candidates.len());
    for endpoint in candidates {
        if cancellation.is_cancelled() {
            return Err(DiagnosticIoError::new(
                DiagnosticIoErrorKind::Cancelled,
                "interrupted",
            ));
        }
        let target = TargetIp {
            address: endpoint.address,
            scope: endpoint.interface.clone(),
        };
        let initial_path = analyze_initial_path(snapshot, &target);
        if initial_path.status == InitialPathStatus::DefinitiveNoPath {
            prepared.push(PreparedResolverCandidate {
                endpoint,
                initial_path,
                current_path: skipped_current_path(snapshot),
                neighbor_dependency: NeighborDependency::NotApplicable,
                neighbor_pre_state: None,
            });
            continue;
        }
        let current_path = io.current_operation_path(&target).await?;
        let current_path = match current_path {
            CapabilityValue::Available { value, provenance } => CapabilityValue::available(
                reconcile_current_operation_path(value, &initial_path, &snapshot.interfaces),
                provenance,
            ),
            other => other,
        };
        let neighbor_dependency = dependency_from_current_path(&current_path);
        prepared.push(PreparedResolverCandidate {
            endpoint,
            initial_path,
            current_path,
            neighbor_dependency,
            neighbor_pre_state: None,
        });
    }

    let mut pre_states = HashMap::<NeighborIdentity, CapabilityValue<NeighborFact>>::new();
    for item in &prepared {
        let NeighborDependency::Known(identity) = &item.neighbor_dependency else {
            continue;
        };
        if !pre_states.contains_key(identity) {
            pre_states.insert(identity.clone(), io.neighbor(identity).await?);
        }
    }
    for item in &mut prepared {
        if let NeighborDependency::Known(identity) = &item.neighbor_dependency {
            item.neighbor_pre_state = pre_states.get(identity).cloned();
        }
    }
    Ok(prepared)
}

async fn diagnose_resolver_candidate(
    hostname: &Hostname,
    prepared: PreparedResolverCandidate,
    ordinal: usize,
    io: &impl DiagnosticIo,
    cancellation: &CancellationToken,
) -> Result<ResolverDependencyDiagnostic, DiagnosticIoError> {
    let base = 1_000_000 + ordinal as u64 * 1_000;
    let mut network_facts = TargetNetworkFacts {
        initial_path: prepared.initial_path.clone(),
        current_path: prepared.current_path.clone(),
        neighbor_pre_state: prepared.neighbor_pre_state.clone(),
        neighbor_post_state: None,
    };
    let mut evidence = vec![Evidence {
        id: EvidenceId(base),
        subject: EvidenceSubject::Resolver(resolver_label(&prepared.endpoint)),
        role: EvidenceRole::Context,
        fact: EvidenceFact::InitialPath(format!("{:?}", prepared.initial_path.status)),
    }];
    match &prepared.current_path {
        CapabilityValue::Available { value, .. } => evidence.push(Evidence {
            id: EvidenceId(base + 1),
            subject: EvidenceSubject::Resolver(resolver_label(&prepared.endpoint)),
            role: EvidenceRole::Context,
            fact: EvidenceFact::CurrentPath(format!("{:?}", value.relation)),
        }),
        CapabilityValue::Unknown { reason, .. } | CapabilityValue::Unavailable { reason, .. } => {
            evidence.push(Evidence {
                id: EvidenceId(base + 1),
                subject: EvidenceSubject::Resolver(resolver_label(&prepared.endpoint)),
                role: EvidenceRole::Context,
                fact: EvidenceFact::CapabilityUnavailable {
                    capability: "resolver current targeted path lookup".into(),
                    reason: reason.clone(),
                },
            });
        }
    }
    if prepared.initial_path.status == InitialPathStatus::DefinitiveNoPath {
        evidence[0].role = EvidenceRole::BoundaryNarrowing;
        return Ok(ResolverDependencyDiagnostic::new(
            prepared.endpoint,
            network_facts,
            Vec::new(),
            evidence,
        ));
    }

    let resolver = resolver_socket_address(&prepared.endpoint);
    let transport = prepared.endpoint.transport;
    let a = dns_query_series(
        hostname.ascii(),
        resolver,
        transport,
        DnsQueryType::A,
        base + 10,
        io,
        cancellation,
    );
    let aaaa = dns_query_series(
        hostname.ascii(),
        resolver,
        transport,
        DnsQueryType::Aaaa,
        base + 110,
        io,
        cancellation,
    );
    let (a, aaaa) = futures_util::future::join(a, aaaa).await;
    let mut attempts = a?;
    attempts.extend(aaaa?);
    for attempt in &attempts {
        let summary = direct_dns_evidence_summary(attempt)?;
        evidence.push(Evidence {
            id: EvidenceId(attempt.id.0),
            subject: EvidenceSubject::Resolver(resolver_label(&prepared.endpoint)),
            role: EvidenceRole::BoundaryNarrowing,
            fact: EvidenceFact::DirectDnsResult(summary),
        });
    }
    if !attempts.iter().any(is_dns_response) {
        let post_state = refresh_neighbor_after_failure(
            io,
            &prepared.neighbor_dependency,
            &mut network_facts,
            cancellation,
        )
        .await?;
        if post_state.is_some() {
            add_neighbor_evidence(
                &network_facts,
                &mut evidence,
                EvidenceRole::BoundaryNarrowing,
                AttemptId(base + 900),
            );
        } else {
            add_resolver_neighbor_observation_limitation(
                &prepared.neighbor_dependency,
                &network_facts,
                &prepared.endpoint,
                &mut evidence,
                EvidenceId(base + 900),
            );
            add_resolver_dependency_limitation(
                &prepared.neighbor_dependency,
                &prepared.endpoint,
                &mut evidence,
                EvidenceId(base + 901),
            );
        }
    }
    Ok(ResolverDependencyDiagnostic::new(
        prepared.endpoint,
        network_facts,
        attempts,
        evidence,
    ))
}

async fn dns_query_series(
    query_name: &str,
    resolver: std::net::SocketAddr,
    transport: ResolverTransport,
    query_type: DnsQueryType,
    base_id: u64,
    io: &impl DiagnosticIo,
    cancellation: &CancellationToken,
) -> Result<Vec<Attempt>, DiagnosticIoError> {
    if transport == ResolverTransport::Tcp {
        return dns_tcp_series(
            query_name,
            resolver,
            query_type,
            base_id,
            DirectDnsTransportReason::ConfiguredTransport,
            io,
            cancellation,
        )
        .await;
    }
    let first = io
        .direct_dns_udp(
            dns_operation(
                query_name,
                resolver,
                query_type,
                AttemptId(base_id),
                DNS_UDP_BUDGET,
                DirectDnsTransportReason::ConfiguredTransport,
            ),
            cancellation,
        )
        .await?;
    validate_dns_attempt(&first)?;
    let first_timeout = is_attempt_timeout(&first);
    let first_truncated = is_dns_truncated(&first);
    let mut attempts = vec![first];
    if first_truncated {
        attempts.extend(
            dns_tcp_series(
                query_name,
                resolver,
                query_type,
                base_id + 10,
                DirectDnsTransportReason::UdpTruncationCompletion,
                io,
                cancellation,
            )
            .await?,
        );
        return Ok(attempts);
    }
    if !first_timeout {
        return Ok(attempts);
    }
    let second = io
        .direct_dns_udp(
            dns_operation(
                query_name,
                resolver,
                query_type,
                AttemptId(base_id + 1),
                DNS_UDP_BUDGET,
                DirectDnsTransportReason::ConfiguredTransport,
            ),
            cancellation,
        )
        .await?;
    validate_dns_attempt(&second)?;
    let repeated_timeout = is_attempt_timeout(&second);
    let truncated = is_dns_truncated(&second);
    attempts.push(second);
    if repeated_timeout || truncated {
        let reason = if truncated {
            DirectDnsTransportReason::UdpTruncationCompletion
        } else {
            DirectDnsTransportReason::UdpTimeoutComparison
        };
        attempts.extend(
            dns_tcp_series(
                query_name,
                resolver,
                query_type,
                base_id + 10,
                reason,
                io,
                cancellation,
            )
            .await?,
        );
    }
    Ok(attempts)
}

async fn dns_tcp_series(
    query_name: &str,
    resolver: std::net::SocketAddr,
    query_type: DnsQueryType,
    base_id: u64,
    reason: DirectDnsTransportReason,
    io: &impl DiagnosticIo,
    cancellation: &CancellationToken,
) -> Result<Vec<Attempt>, DiagnosticIoError> {
    let first = io
        .direct_dns_tcp(
            dns_operation(
                query_name,
                resolver,
                query_type,
                AttemptId(base_id),
                DNS_TCP_BUDGET,
                reason,
            ),
            cancellation,
        )
        .await?;
    validate_dns_attempt(&first)?;
    let retry = is_attempt_timeout(&first);
    let mut attempts = vec![first];
    if retry {
        let second = io
            .direct_dns_tcp(
                dns_operation(
                    query_name,
                    resolver,
                    query_type,
                    AttemptId(base_id + 1),
                    DNS_TCP_BUDGET,
                    reason,
                ),
                cancellation,
            )
            .await?;
        validate_dns_attempt(&second)?;
        attempts.push(second);
    }
    Ok(attempts)
}

fn dns_operation(
    query_name: &str,
    resolver: std::net::SocketAddr,
    query_type: DnsQueryType,
    attempt_id: AttemptId,
    budget: std::time::Duration,
    reason: DirectDnsTransportReason,
) -> DirectDnsOperation {
    DirectDnsOperation {
        attempt_id,
        message_id: attempt_id.0 as u16,
        resolver,
        query_name: query_name.to_owned(),
        query_type,
        budget,
        reason,
    }
}

fn resolver_socket_address(endpoint: &ResolverEndpoint) -> std::net::SocketAddr {
    match endpoint.address {
        std::net::IpAddr::V4(address) => std::net::SocketAddr::new(address.into(), endpoint.port),
        std::net::IpAddr::V6(address) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            address,
            endpoint.port,
            0,
            endpoint
                .interface
                .as_ref()
                .map_or(0, |interface| interface.index),
        )),
    }
}

fn resolver_label(endpoint: &ResolverEndpoint) -> String {
    resolver_socket_address(endpoint).to_string()
}

fn is_dns_truncated(attempt: &Attempt) -> bool {
    matches!(
        attempt.outcome,
        AttemptOutcome::Dns(DnsAttemptResult::Response {
            truncated: true,
            ..
        })
    )
}

fn is_dns_response(attempt: &Attempt) -> bool {
    matches!(
        attempt.outcome,
        AttemptOutcome::Dns(DnsAttemptResult::Response { .. })
    )
}

fn direct_dns_evidence_summary(attempt: &Attempt) -> Result<String, DiagnosticIoError> {
    let AttemptOutcome::Dns(outcome) = &attempt.outcome else {
        return Err(DiagnosticIoError::new(
            DiagnosticIoErrorKind::Internal,
            "platform adapter returned a non-DNS outcome for a direct-DNS Attempt",
        ));
    };
    let outcome = match outcome {
        DnsAttemptResult::Response {
            response_code,
            addresses,
            aliases,
            truncated,
        } => format!(
            "response code {response_code}, {} address(es), {} alias(es), truncated={truncated}",
            addresses.len(),
            aliases.len()
        ),
        DnsAttemptResult::TransportError { os_code } => {
            format!("transport error (OS code {os_code:?})")
        }
        DnsAttemptResult::ProtocolError => "protocol error".into(),
        DnsAttemptResult::Timeout => "timeout".into(),
    };
    Ok(format!("{:?}: {outcome}", attempt.kind))
}

#[derive(Clone)]
struct PreparedTarget {
    formal: FormalTarget,
    initial_path: InitialPathAnalysis,
    current_path: CapabilityValue<OperationPathContext>,
    neighbor_dependency: NeighborDependency,
    neighbor_pre_state: Option<CapabilityValue<NeighborFact>>,
}

async fn prepare_targets(
    snapshot: &InitialNetworkSnapshot,
    targets: &[FormalTarget],
    io: &impl DiagnosticIo,
    cancellation: &CancellationToken,
) -> Result<Vec<PreparedTarget>, DiagnosticIoError> {
    let mut prepared = Vec::with_capacity(targets.len());
    for target in targets {
        if cancellation.is_cancelled() {
            return Err(DiagnosticIoError::new(
                DiagnosticIoErrorKind::Cancelled,
                "interrupted",
            ));
        }
        let initial_path = analyze_initial_path(snapshot, &target.target);
        if initial_path.status == InitialPathStatus::DefinitiveNoPath {
            prepared.push(PreparedTarget {
                formal: target.clone(),
                initial_path,
                current_path: skipped_current_path(snapshot),
                neighbor_dependency: NeighborDependency::NotApplicable,
                neighbor_pre_state: None,
            });
            continue;
        }
        let current_path = io.current_operation_path(&target.target).await?;
        let current_path = match current_path {
            CapabilityValue::Available { value, provenance } => CapabilityValue::available(
                reconcile_current_operation_path(value, &initial_path, &snapshot.interfaces),
                provenance,
            ),
            other => other,
        };
        let neighbor_dependency = dependency_from_current_path(&current_path);
        prepared.push(PreparedTarget {
            formal: target.clone(),
            initial_path,
            current_path,
            neighbor_dependency,
            neighbor_pre_state: None,
        });
    }

    // This phase is a barrier before any product-controlled target traffic.
    // It guarantees one immutable pre-state for every shared dependency even
    // when its target diagnostics later run concurrently.
    let mut pre_states = HashMap::<NeighborIdentity, CapabilityValue<NeighborFact>>::new();
    for item in &prepared {
        let NeighborDependency::Known(identity) = &item.neighbor_dependency else {
            continue;
        };
        if !pre_states.contains_key(identity) {
            pre_states.insert(identity.clone(), io.neighbor(identity).await?);
        }
    }
    for item in &mut prepared {
        if let NeighborDependency::Known(identity) = &item.neighbor_dependency {
            item.neighbor_pre_state = pre_states.get(identity).cloned();
        }
    }
    Ok(prepared)
}

fn dependency_from_current_path(
    current_path: &CapabilityValue<OperationPathContext>,
) -> NeighborDependency {
    match current_path {
        CapabilityValue::Available { value, .. } => neighbor_dependency_for_path(value),
        CapabilityValue::Unknown { reason, .. } => NeighborDependency::Unknown {
            reason: format!("current path is unknown: {reason:?}"),
        },
        CapabilityValue::Unavailable { reason, .. } => NeighborDependency::Unknown {
            reason: format!("current path is unavailable: {reason:?}"),
        },
    }
}

async fn diagnose_target(
    io: &impl DiagnosticIo,
    prepared: PreparedTarget,
    port: Option<NonZeroU16>,
    semantic_ordinal: usize,
    cancellation: &CancellationToken,
) -> Result<TargetDiagnostic, DiagnosticIoError> {
    let base_id = (semantic_ordinal as u64 + 1) * 10_000;
    let mut ids = IdSequence::new(base_id + 10);
    let mut evidence = initial_evidence(&prepared, base_id);
    let mut facts = TargetNetworkFacts {
        initial_path: prepared.initial_path.clone(),
        current_path: prepared.current_path.clone(),
        neighbor_pre_state: prepared.neighbor_pre_state.clone(),
        neighbor_post_state: None,
    };

    if prepared.initial_path.status == InitialPathStatus::DefinitiveNoPath {
        return Ok(TargetDiagnostic::new(
            prepared.formal.target,
            prepared.formal.resolver_ordinal,
            PrimaryOutcome::NotSatisfied,
            Conclusion::DefinitiveNoPath,
            facts,
            Vec::new(),
            evidence,
        ));
    }

    match port {
        Some(port) => {
            diagnose_port_target(
                io,
                prepared,
                port.get(),
                &mut ids,
                &mut facts,
                &mut evidence,
                cancellation,
            )
            .await
        }
        None => {
            diagnose_address_target(
                io,
                prepared,
                &mut ids,
                &mut facts,
                &mut evidence,
                cancellation,
            )
            .await
        }
    }
}

async fn diagnose_port_target(
    io: &impl DiagnosticIo,
    prepared: PreparedTarget,
    port: u16,
    ids: &mut IdSequence,
    facts: &mut TargetNetworkFacts,
    evidence: &mut Vec<Evidence>,
    cancellation: &CancellationToken,
) -> Result<TargetDiagnostic, DiagnosticIoError> {
    let target = prepared.formal.target.clone();
    let first = io
        .tcp_connect(
            TcpOperation {
                attempt_id: ids.next(),
                target: target.clone(),
                port,
                budget: TCP_CONNECT_BUDGET,
            },
            cancellation,
        )
        .await?;
    evidence.push(attempt_evidence(&first, EvidenceRole::PrimaryDecision));
    let mut attempts = vec![first];
    match tcp_result(&attempts[0])? {
        TcpAttemptResult::Connected { .. } => {
            return Ok(finish_target(
                prepared,
                PrimaryOutcome::Satisfied,
                Conclusion::TcpConnectSucceeded,
                facts.clone(),
                attempts,
                evidence.clone(),
            ));
        }
        TcpAttemptResult::ConnectionRefused => {
            return Ok(finish_target(
                prepared,
                PrimaryOutcome::NotSatisfied,
                Conclusion::TcpConnectionRefused,
                facts.clone(),
                attempts,
                evidence.clone(),
            ));
        }
        TcpAttemptResult::ResourceExhausted => return Err(resource_exhausted_error()),
        result @ (TcpAttemptResult::NoRoute
        | TcpAttemptResult::NetworkUnreachable
        | TcpAttemptResult::HostUnreachable
        | TcpAttemptResult::PermissionDenied
        | TcpAttemptResult::OtherExplicitError { .. }) => {
            add_tcp_path_comparison(result, &prepared.initial_path, evidence, ids.next());
            return Ok(finish_target(
                prepared,
                PrimaryOutcome::NotSatisfied,
                Conclusion::TcpExplicitFailure,
                facts.clone(),
                attempts,
                evidence.clone(),
            ));
        }
        TcpAttemptResult::Timeout => {}
    }

    let second = io
        .tcp_connect(
            TcpOperation {
                attempt_id: ids.next(),
                target: target.clone(),
                port,
                budget: TCP_CONNECT_BUDGET,
            },
            cancellation,
        )
        .await?;
    evidence.push(attempt_evidence(&second, EvidenceRole::AnomalyHistory));
    attempts.push(second);
    match tcp_result(&attempts[1])? {
        TcpAttemptResult::Connected { .. } => {
            return Ok(finish_target(
                prepared,
                PrimaryOutcome::SatisfiedWithAnomaly,
                Conclusion::TcpConnectSucceededAfterTimeout,
                facts.clone(),
                attempts,
                evidence.clone(),
            ));
        }
        TcpAttemptResult::ResourceExhausted => return Err(resource_exhausted_error()),
        result @ (TcpAttemptResult::ConnectionRefused
        | TcpAttemptResult::NoRoute
        | TcpAttemptResult::NetworkUnreachable
        | TcpAttemptResult::HostUnreachable
        | TcpAttemptResult::PermissionDenied
        | TcpAttemptResult::OtherExplicitError { .. }) => {
            add_tcp_path_comparison(result, &prepared.initial_path, evidence, ids.next());
            return Ok(finish_target(
                prepared,
                PrimaryOutcome::NotSatisfied,
                if matches!(result, TcpAttemptResult::ConnectionRefused) {
                    Conclusion::TcpConnectionRefused
                } else {
                    Conclusion::TcpExplicitFailure
                },
                facts.clone(),
                attempts,
                evidence.clone(),
            ));
        }
        TcpAttemptResult::Timeout => {}
    }

    let mut icmp = match run_icmp_series(
        io,
        IcmpEchoSubject::Target(target.clone()),
        TARGET_ICMP_BUDGET,
        ids,
        cancellation,
    )
    .await
    {
        Ok(attempts) => attempts,
        Err(error) if error.kind == DiagnosticIoErrorKind::RequiredCapabilityUnavailable => {
            evidence.push(optional_io_limitation(
                "target ICMP failure diagnosis",
                error,
                &target,
                ids.next(),
            ));
            return Ok(finish_target(
                prepared,
                PrimaryOutcome::NotSatisfied,
                Conclusion::TcpConnectTimedOut,
                facts.clone(),
                attempts,
                evidence.clone(),
            )
            .with_diagnostic_conclusions(vec![Conclusion::CapabilityLimited]));
        }
        Err(error) => return Err(error),
    };
    for attempt in &icmp {
        evidence.push(attempt_evidence(attempt, EvidenceRole::BoundaryNarrowing));
    }
    let target_icmp_replied = icmp.iter().any(is_icmp_echo_reply);
    attempts.append(&mut icmp);
    if target_icmp_replied {
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::NotSatisfied,
            Conclusion::TcpTimedOutButTargetIcmpResponded,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }
    if attempts.iter().any(is_non_timeout_icmp_result) {
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::NotSatisfied,
            Conclusion::TcpTimedOutWithExplicitIcmpResult,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }

    let post_state =
        refresh_neighbor_after_failure(io, &prepared.neighbor_dependency, facts, cancellation)
            .await?;
    if post_state == Some(NeighborState::TerminalFailure) {
        add_neighbor_evidence(facts, evidence, EvidenceRole::BoundaryNarrowing, ids.next());
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::NotSatisfied,
            Conclusion::NeighborResolutionFailed,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }

    if post_state == Some(NeighborState::Resolving) {
        add_neighbor_evidence(facts, evidence, EvidenceRole::BoundaryNarrowing, ids.next());
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::NotSatisfied,
            Conclusion::NeighborResolutionIndeterminate,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }

    let mut diagnostic_conclusions = Vec::new();
    if post_state == Some(NeighborState::Unknown) {
        add_neighbor_evidence(facts, evidence, EvidenceRole::BoundaryNarrowing, ids.next());
        diagnostic_conclusions.push(Conclusion::NeighborResolutionIndeterminate);
    }
    if add_target_neighbor_observation_limitation(
        &prepared.neighbor_dependency,
        facts,
        &target,
        evidence,
        ids.next(),
    ) {
        diagnostic_conclusions.push(Conclusion::CapabilityLimited);
    }
    if add_target_dependency_limitation(
        &prepared.neighbor_dependency,
        &target,
        evidence,
        ids.next(),
    ) {
        diagnostic_conclusions.push(Conclusion::CapabilityLimited);
    }
    if post_state == Some(NeighborState::Usable)
        && current_relation(&facts.current_path) == Some(PathRelation::Remote)
        && let NeighborDependency::Known(next_hop) = &prepared.neighbor_dependency
    {
        let next_hop_attempts = run_icmp_series(
            io,
            IcmpEchoSubject::NextHop(next_hop.clone()),
            NEXT_HOP_ICMP_BUDGET,
            ids,
            cancellation,
        )
        .await;
        let mut next_hop_attempts = match next_hop_attempts {
            Ok(attempts) => attempts,
            Err(error) if error.kind == DiagnosticIoErrorKind::RequiredCapabilityUnavailable => {
                evidence.push(optional_io_limitation(
                    "next-hop ICMP diagnosis",
                    error,
                    &target,
                    ids.next(),
                ));
                diagnostic_conclusions.push(Conclusion::CapabilityLimited);
                Vec::new()
            }
            Err(error) => return Err(error),
        };
        let first_hop_responded = next_hop_attempts.iter().any(is_matching_icmp_message);
        for attempt in &next_hop_attempts {
            evidence.push(attempt_evidence(attempt, EvidenceRole::BoundaryNarrowing));
        }
        attempts.append(&mut next_hop_attempts);
        if first_hop_responded {
            diagnostic_conclusions.push(Conclusion::FirstHopResponded);
            diagnostic_conclusions.extend(
                run_path_diagnosis(
                    io,
                    PathDiagnosisContext {
                        target: &target,
                        port: Some(port),
                        tcp: true,
                        ids,
                        attempts: &mut attempts,
                        evidence,
                    },
                    cancellation,
                )
                .await?,
            );
        }
    }

    Ok(finish_target(
        prepared,
        PrimaryOutcome::NotSatisfied,
        Conclusion::TcpConnectTimedOut,
        facts.clone(),
        attempts,
        evidence.clone(),
    )
    .with_diagnostic_conclusions(diagnostic_conclusions))
}

async fn diagnose_address_target(
    io: &impl DiagnosticIo,
    prepared: PreparedTarget,
    ids: &mut IdSequence,
    facts: &mut TargetNetworkFacts,
    evidence: &mut Vec<Evidence>,
    cancellation: &CancellationToken,
) -> Result<TargetDiagnostic, DiagnosticIoError> {
    let target = prepared.formal.target.clone();
    let attempts = run_icmp_series(
        io,
        IcmpEchoSubject::Target(target.clone()),
        TARGET_ICMP_BUDGET,
        ids,
        cancellation,
    )
    .await?;
    for (index, attempt) in attempts.iter().enumerate() {
        evidence.push(attempt_evidence(
            attempt,
            if index == 0 {
                EvidenceRole::PrimaryDecision
            } else {
                EvidenceRole::AnomalyHistory
            },
        ));
    }
    if attempts.first().is_some_and(is_icmp_echo_reply) {
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::Satisfied,
            Conclusion::IcmpEchoReplied,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }
    if attempts.get(1).is_some_and(is_icmp_echo_reply) {
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::SatisfiedWithAnomaly,
            Conclusion::IcmpEchoRepliedAfterTimeout,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }
    if attempts.iter().any(is_indeterminate_icmp_message) {
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::Indeterminate,
            Conclusion::IcmpResponseIndeterminate,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }
    if attempts.iter().any(is_non_timeout_icmp_result) {
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::NotSatisfied,
            Conclusion::IcmpExplicitFailure,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }

    let mut attempts = attempts;
    let post_state =
        refresh_neighbor_after_failure(io, &prepared.neighbor_dependency, facts, cancellation)
            .await?;
    if post_state == Some(NeighborState::TerminalFailure) {
        add_neighbor_evidence(facts, evidence, EvidenceRole::BoundaryNarrowing, ids.next());
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::NotSatisfied,
            Conclusion::NeighborResolutionFailed,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }

    if post_state == Some(NeighborState::Resolving) {
        add_neighbor_evidence(facts, evidence, EvidenceRole::BoundaryNarrowing, ids.next());
        return Ok(finish_target(
            prepared,
            PrimaryOutcome::Indeterminate,
            Conclusion::NeighborResolutionIndeterminate,
            facts.clone(),
            attempts,
            evidence.clone(),
        ));
    }

    let mut diagnostic_conclusions = Vec::new();
    if post_state == Some(NeighborState::Unknown) {
        add_neighbor_evidence(facts, evidence, EvidenceRole::BoundaryNarrowing, ids.next());
        diagnostic_conclusions.push(Conclusion::NeighborResolutionIndeterminate);
    }
    if add_target_neighbor_observation_limitation(
        &prepared.neighbor_dependency,
        facts,
        &target,
        evidence,
        ids.next(),
    ) {
        diagnostic_conclusions.push(Conclusion::CapabilityLimited);
    }
    if add_target_dependency_limitation(
        &prepared.neighbor_dependency,
        &target,
        evidence,
        ids.next(),
    ) {
        diagnostic_conclusions.push(Conclusion::CapabilityLimited);
    }
    if post_state == Some(NeighborState::Usable)
        && current_relation(&facts.current_path) == Some(PathRelation::Remote)
        && let NeighborDependency::Known(next_hop) = &prepared.neighbor_dependency
    {
        let next_hop_attempts = run_icmp_series(
            io,
            IcmpEchoSubject::NextHop(next_hop.clone()),
            NEXT_HOP_ICMP_BUDGET,
            ids,
            cancellation,
        )
        .await;
        let mut next_hop_attempts = match next_hop_attempts {
            Ok(attempts) => attempts,
            Err(error) if error.kind == DiagnosticIoErrorKind::RequiredCapabilityUnavailable => {
                evidence.push(optional_io_limitation(
                    "next-hop ICMP diagnosis",
                    error,
                    &target,
                    ids.next(),
                ));
                diagnostic_conclusions.push(Conclusion::CapabilityLimited);
                Vec::new()
            }
            Err(error) => return Err(error),
        };
        let first_hop_responded = next_hop_attempts.iter().any(is_matching_icmp_message);
        for attempt in &next_hop_attempts {
            evidence.push(attempt_evidence(attempt, EvidenceRole::BoundaryNarrowing));
        }
        attempts.append(&mut next_hop_attempts);
        if first_hop_responded {
            diagnostic_conclusions.push(Conclusion::FirstHopResponded);
            diagnostic_conclusions.extend(
                run_path_diagnosis(
                    io,
                    PathDiagnosisContext {
                        target: &target,
                        port: None,
                        tcp: false,
                        ids,
                        attempts: &mut attempts,
                        evidence,
                    },
                    cancellation,
                )
                .await?,
            );
        }
    }

    Ok(finish_target(
        prepared,
        PrimaryOutcome::Indeterminate,
        Conclusion::IcmpEchoTimedOut,
        facts.clone(),
        attempts,
        evidence.clone(),
    )
    .with_diagnostic_conclusions(diagnostic_conclusions))
}

async fn run_icmp_series(
    io: &impl DiagnosticIo,
    subject: IcmpEchoSubject,
    budget: std::time::Duration,
    ids: &mut IdSequence,
    cancellation: &CancellationToken,
) -> Result<Vec<Attempt>, DiagnosticIoError> {
    let first = io
        .icmp_echo(
            IcmpOperation {
                attempt_id: ids.next(),
                subject: subject.clone(),
                budget,
            },
            cancellation,
        )
        .await?;
    validate_icmp_attempt(&first)?;
    let retry = is_attempt_timeout(&first);
    let mut attempts = vec![first];
    if retry {
        let second = io
            .icmp_echo(
                IcmpOperation {
                    attempt_id: ids.next(),
                    subject,
                    budget,
                },
                cancellation,
            )
            .await?;
        validate_icmp_attempt(&second)?;
        attempts.push(second);
    }
    Ok(attempts)
}

async fn refresh_neighbor_after_failure(
    io: &impl DiagnosticIo,
    dependency: &NeighborDependency,
    facts: &mut TargetNetworkFacts,
    cancellation: &CancellationToken,
) -> Result<Option<NeighborState>, DiagnosticIoError> {
    let NeighborDependency::Known(identity) = dependency else {
        return Ok(None);
    };
    let mut observation = io.neighbor(identity).await?;
    if capability_neighbor_state(&observation) == Some(NeighborState::Resolving) {
        observation = io
            .observe_neighbor_convergence(identity, cancellation)
            .await?;
    }
    let state = capability_neighbor_state(&observation);
    facts.neighbor_post_state = Some(observation);
    Ok(state)
}

struct PathDiagnosisContext<'a> {
    target: &'a crate::TargetIp,
    port: Option<u16>,
    tcp: bool,
    ids: &'a mut IdSequence,
    attempts: &'a mut Vec<Attempt>,
    evidence: &'a mut Vec<Evidence>,
}

async fn run_path_diagnosis(
    io: &impl DiagnosticIo,
    context: PathDiagnosisContext<'_>,
    cancellation: &CancellationToken,
) -> Result<Vec<Conclusion>, DiagnosticIoError> {
    let PathDiagnosisContext {
        target,
        port,
        tcp,
        ids,
        attempts,
        evidence,
    } = context;
    let mut last_path_evidence = None;
    let mut saw_multiple_responders = false;
    for hop_limit in 1..=MAX_PATH_HOP_LIMIT {
        let operation = PathOperation {
            attempt_id: ids.next(),
            target: target.clone(),
            port,
            hop_limit,
            budget: PATH_ATTEMPT_BUDGET,
        };
        let first = if tcp {
            io.tcp_path_attempt(operation.clone(), cancellation).await?
        } else {
            io.icmp_path_attempt(operation.clone(), cancellation)
                .await?
        };
        let Some(first) = available_path_attempt(first, evidence, operation.attempt_id, tcp)?
        else {
            return Ok(path_conclusions(
                saw_multiple_responders,
                Conclusion::CapabilityLimited,
            ));
        };
        let disposition = path_attempt_disposition(&first, target);
        let multiple_responders = has_multiple_path_responders(&first);
        let first_evidence = evidence.len();
        evidence.push(attempt_evidence(
            &first,
            if multiple_responders && !saw_multiple_responders {
                EvidenceRole::BoundaryNarrowing
            } else {
                EvidenceRole::Context
            },
        ));
        saw_multiple_responders |= multiple_responders;
        last_path_evidence = Some(first_evidence);
        attempts.push(first);
        match disposition {
            PathAttemptDisposition::Endpoint => {
                evidence[first_evidence].role = EvidenceRole::BoundaryNarrowing;
                return Ok(path_conclusions(
                    saw_multiple_responders,
                    Conclusion::PathEndpointResponded,
                ));
            }
            PathAttemptDisposition::ExplicitTermination => {
                evidence[first_evidence].role = EvidenceRole::BoundaryNarrowing;
                return Ok(path_conclusions(
                    saw_multiple_responders,
                    Conclusion::PathExplicitlyTerminated,
                ));
            }
            PathAttemptDisposition::Indeterminate => {
                evidence[first_evidence].role = EvidenceRole::BoundaryNarrowing;
                return Ok(path_conclusions(
                    saw_multiple_responders,
                    Conclusion::PathResponseIndeterminate,
                ));
            }
            PathAttemptDisposition::Timeout => {
                let operation = PathOperation {
                    attempt_id: ids.next(),
                    ..operation
                };
                let second = if tcp {
                    io.tcp_path_attempt(operation.clone(), cancellation).await?
                } else {
                    io.icmp_path_attempt(operation.clone(), cancellation)
                        .await?
                };
                let Some(second) =
                    available_path_attempt(second, evidence, operation.attempt_id, tcp)?
                else {
                    return Ok(path_conclusions(
                        saw_multiple_responders,
                        Conclusion::CapabilityLimited,
                    ));
                };
                let disposition = path_attempt_disposition(&second, target);
                let multiple_responders = has_multiple_path_responders(&second);
                let second_evidence = evidence.len();
                evidence.push(attempt_evidence(
                    &second,
                    if multiple_responders && !saw_multiple_responders {
                        EvidenceRole::BoundaryNarrowing
                    } else {
                        EvidenceRole::Context
                    },
                ));
                saw_multiple_responders |= multiple_responders;
                last_path_evidence = Some(second_evidence);
                attempts.push(second);
                match disposition {
                    PathAttemptDisposition::Endpoint => {
                        evidence[second_evidence].role = EvidenceRole::BoundaryNarrowing;
                        return Ok(path_conclusions(
                            saw_multiple_responders,
                            Conclusion::PathEndpointResponded,
                        ));
                    }
                    PathAttemptDisposition::ExplicitTermination => {
                        evidence[second_evidence].role = EvidenceRole::BoundaryNarrowing;
                        return Ok(path_conclusions(
                            saw_multiple_responders,
                            Conclusion::PathExplicitlyTerminated,
                        ));
                    }
                    PathAttemptDisposition::Indeterminate => {
                        evidence[second_evidence].role = EvidenceRole::BoundaryNarrowing;
                        return Ok(path_conclusions(
                            saw_multiple_responders,
                            Conclusion::PathResponseIndeterminate,
                        ));
                    }
                    PathAttemptDisposition::Timeout | PathAttemptDisposition::Advance => {}
                }
            }
            PathAttemptDisposition::Advance => {}
        }
    }
    if let Some(index) = last_path_evidence {
        evidence[index].role = EvidenceRole::BoundaryNarrowing;
    }
    Ok(path_conclusions(
        saw_multiple_responders,
        Conclusion::PathLimitReachedWithoutEndpointEvidence,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathAttemptDisposition {
    Timeout,
    Advance,
    Endpoint,
    ExplicitTermination,
    Indeterminate,
}

fn path_attempt_disposition(attempt: &Attempt, target: &TargetIp) -> PathAttemptDisposition {
    match &attempt.outcome {
        AttemptOutcome::Tcp(
            TcpAttemptResult::Connected { .. } | TcpAttemptResult::ConnectionRefused,
        ) => PathAttemptDisposition::Endpoint,
        AttemptOutcome::Tcp(TcpAttemptResult::Timeout)
        | AttemptOutcome::Icmp(IcmpAttemptResult::Timeout) => PathAttemptDisposition::Timeout,
        AttemptOutcome::Tcp(
            TcpAttemptResult::NoRoute
            | TcpAttemptResult::NetworkUnreachable
            | TcpAttemptResult::HostUnreachable,
        ) => PathAttemptDisposition::ExplicitTermination,
        AttemptOutcome::Tcp(
            TcpAttemptResult::PermissionDenied
            | TcpAttemptResult::OtherExplicitError { .. }
            | TcpAttemptResult::ResourceExhausted,
        )
        | AttemptOutcome::Icmp(IcmpAttemptResult::ExplicitNetworkError { .. })
        | AttemptOutcome::Dns(_) => PathAttemptDisposition::Indeterminate,
        AttemptOutcome::Icmp(IcmpAttemptResult::Message {
            kind, responder, ..
        }) => path_message_disposition(*kind, *responder, target),
        AttemptOutcome::Icmp(IcmpAttemptResult::Messages(messages)) => {
            let dispositions = messages
                .iter()
                .map(|message| path_message_disposition(message.kind, message.responder, target))
                .collect::<Vec<_>>();
            if dispositions.contains(&PathAttemptDisposition::Endpoint) {
                PathAttemptDisposition::Endpoint
            } else if !dispositions.is_empty()
                && dispositions
                    .iter()
                    .all(|item| *item == PathAttemptDisposition::Advance)
            {
                PathAttemptDisposition::Advance
            } else if !dispositions.is_empty()
                && dispositions
                    .iter()
                    .all(|item| *item == PathAttemptDisposition::ExplicitTermination)
            {
                PathAttemptDisposition::ExplicitTermination
            } else {
                PathAttemptDisposition::Indeterminate
            }
        }
    }
}

fn path_message_disposition(
    kind: IcmpMessageKind,
    responder: std::net::IpAddr,
    target: &TargetIp,
) -> PathAttemptDisposition {
    match kind {
        IcmpMessageKind::EchoReply if responder == target.address => {
            PathAttemptDisposition::Endpoint
        }
        IcmpMessageKind::TimeExceeded => PathAttemptDisposition::Advance,
        IcmpMessageKind::DestinationUnreachable
        | IcmpMessageKind::PacketTooBig
        | IcmpMessageKind::ParameterProblem => PathAttemptDisposition::ExplicitTermination,
        IcmpMessageKind::EchoReply | IcmpMessageKind::Other => {
            PathAttemptDisposition::Indeterminate
        }
    }
}

fn has_multiple_path_responders(attempt: &Attempt) -> bool {
    let AttemptOutcome::Icmp(IcmpAttemptResult::Messages(messages)) = &attempt.outcome else {
        return false;
    };
    let mut responders = messages
        .iter()
        .map(|message| message.responder)
        .collect::<Vec<_>>();
    responders.sort_unstable();
    responders.dedup();
    responders.len() > 1
}

fn path_conclusions(multiple_responders: bool, terminal: Conclusion) -> Vec<Conclusion> {
    let mut conclusions = Vec::with_capacity(usize::from(multiple_responders) + 1);
    if multiple_responders {
        conclusions.push(Conclusion::MultiplePathRespondersObserved);
    }
    conclusions.push(terminal);
    conclusions
}

fn available_path_attempt(
    capability: CapabilityValue<Attempt>,
    evidence: &mut Vec<Evidence>,
    id: AttemptId,
    expected_tcp: bool,
) -> Result<Option<Attempt>, DiagnosticIoError> {
    match capability {
        CapabilityValue::Available { value, .. }
            if matches!(
                value.outcome,
                AttemptOutcome::Tcp(TcpAttemptResult::ResourceExhausted)
            ) =>
        {
            Err(resource_exhausted_error())
        }
        CapabilityValue::Available { value, .. }
            if !matches!(
                (&value.outcome, expected_tcp),
                (AttemptOutcome::Tcp(_) | AttemptOutcome::Icmp(_), true)
                    | (AttemptOutcome::Icmp(_), false)
            ) =>
        {
            Err(DiagnosticIoError::new(
                DiagnosticIoErrorKind::Internal,
                "platform adapter returned the wrong outcome type for a path Attempt",
            ))
        }
        CapabilityValue::Available { value, .. } => Ok(Some(value)),
        CapabilityValue::Unknown { reason, .. } | CapabilityValue::Unavailable { reason, .. } => {
            evidence.push(Evidence {
                id: EvidenceId(id.0),
                subject: EvidenceSubject::Run,
                role: EvidenceRole::CapabilityLimitation,
                fact: EvidenceFact::CapabilityUnavailable {
                    capability: "TTL/Hop-Limit path response correlation".into(),
                    reason,
                },
            });
            Ok(None)
        }
    }
}

fn finish_target(
    prepared: PreparedTarget,
    outcome: PrimaryOutcome,
    conclusion: Conclusion,
    facts: TargetNetworkFacts,
    attempts: Vec<Attempt>,
    evidence: Vec<Evidence>,
) -> TargetDiagnostic {
    TargetDiagnostic::new(
        prepared.formal.target,
        prepared.formal.resolver_ordinal,
        outcome,
        conclusion,
        facts,
        attempts,
        evidence,
    )
}

fn tcp_result(attempt: &Attempt) -> Result<&TcpAttemptResult, DiagnosticIoError> {
    let AttemptOutcome::Tcp(result) = &attempt.outcome else {
        return Err(DiagnosticIoError::new(
            DiagnosticIoErrorKind::Internal,
            "platform adapter returned a non-TCP outcome for a TCP Attempt",
        ));
    };
    Ok(result)
}

fn validate_icmp_attempt(attempt: &Attempt) -> Result<(), DiagnosticIoError> {
    if matches!(attempt.outcome, AttemptOutcome::Icmp(_)) {
        Ok(())
    } else {
        Err(DiagnosticIoError::new(
            DiagnosticIoErrorKind::Internal,
            "platform adapter returned a non-ICMP outcome for an ICMP Attempt",
        ))
    }
}

fn validate_dns_attempt(attempt: &Attempt) -> Result<(), DiagnosticIoError> {
    if matches!(attempt.outcome, AttemptOutcome::Dns(_)) {
        Ok(())
    } else {
        Err(DiagnosticIoError::new(
            DiagnosticIoErrorKind::Internal,
            "platform adapter returned a non-DNS outcome for a direct-DNS Attempt",
        ))
    }
}

fn resource_exhausted_error() -> DiagnosticIoError {
    DiagnosticIoError::new(
        DiagnosticIoErrorKind::ResourceExhausted,
        "local networking resources were exhausted",
    )
}

fn is_attempt_timeout(attempt: &Attempt) -> bool {
    matches!(
        attempt.outcome,
        AttemptOutcome::Tcp(TcpAttemptResult::Timeout)
            | AttemptOutcome::Icmp(IcmpAttemptResult::Timeout)
            | AttemptOutcome::Dns(crate::DnsAttemptResult::Timeout)
    )
}

fn is_icmp_echo_reply(attempt: &Attempt) -> bool {
    let AttemptSubject::Target(target) = &attempt.subject else {
        return false;
    };
    match &attempt.outcome {
        AttemptOutcome::Icmp(IcmpAttemptResult::Message {
            kind: IcmpMessageKind::EchoReply,
            responder,
            ..
        }) => *responder == target.address,
        AttemptOutcome::Icmp(IcmpAttemptResult::Messages(messages)) => {
            messages.iter().any(|message| {
                message.kind == IcmpMessageKind::EchoReply && message.responder == target.address
            })
        }
        AttemptOutcome::Tcp(_)
        | AttemptOutcome::Icmp(
            IcmpAttemptResult::Message { .. }
            | IcmpAttemptResult::ExplicitNetworkError { .. }
            | IcmpAttemptResult::Timeout,
        )
        | AttemptOutcome::Dns(_) => false,
    }
}

fn is_matching_icmp_message(attempt: &Attempt) -> bool {
    let expected = match &attempt.subject {
        AttemptSubject::Target(target) => target.address,
        AttemptSubject::NextHop(neighbor) => neighbor.address,
        AttemptSubject::Resolver { .. } => return false,
    };
    match &attempt.outcome {
        AttemptOutcome::Icmp(IcmpAttemptResult::Message { responder, .. }) => {
            *responder == expected
        }
        AttemptOutcome::Icmp(IcmpAttemptResult::Messages(messages)) => {
            messages.iter().any(|message| message.responder == expected)
        }
        AttemptOutcome::Tcp(_)
        | AttemptOutcome::Icmp(
            IcmpAttemptResult::ExplicitNetworkError { .. } | IcmpAttemptResult::Timeout,
        )
        | AttemptOutcome::Dns(_) => false,
    }
}

fn is_non_timeout_icmp_result(attempt: &Attempt) -> bool {
    matches!(attempt.outcome, AttemptOutcome::Icmp(ref result) if !matches!(result, IcmpAttemptResult::Timeout))
}

fn is_indeterminate_icmp_message(attempt: &Attempt) -> bool {
    match (&attempt.subject, &attempt.outcome) {
        (
            _,
            AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                kind: IcmpMessageKind::Other,
                ..
            }),
        ) => true,
        (
            AttemptSubject::Target(target),
            AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                kind: IcmpMessageKind::EchoReply,
                responder,
                ..
            }),
        ) => *responder != target.address,
        (_, AttemptOutcome::Icmp(IcmpAttemptResult::Messages(messages))) => {
            if messages.is_empty() {
                return true;
            }
            messages
                .iter()
                .any(|message| message.kind == IcmpMessageKind::Other)
                || match &attempt.subject {
                    AttemptSubject::Target(target) => messages.iter().any(|message| {
                        message.kind == IcmpMessageKind::EchoReply
                            && message.responder != target.address
                    }),
                    AttemptSubject::NextHop(_) | AttemptSubject::Resolver { .. } => false,
                }
        }
        _ => false,
    }
}

fn capability_neighbor_state(capability: &CapabilityValue<NeighborFact>) -> Option<NeighborState> {
    match capability {
        CapabilityValue::Available { value, .. } => Some(value.state),
        CapabilityValue::Unknown { .. } | CapabilityValue::Unavailable { .. } => None,
    }
}

fn current_relation(capability: &CapabilityValue<OperationPathContext>) -> Option<PathRelation> {
    match capability {
        CapabilityValue::Available { value, .. } => Some(value.relation),
        CapabilityValue::Unknown { .. } | CapabilityValue::Unavailable { .. } => None,
    }
}

fn initial_evidence(prepared: &PreparedTarget, base_id: u64) -> Vec<Evidence> {
    let mut evidence = vec![Evidence {
        id: EvidenceId(base_id),
        subject: EvidenceSubject::Target(prepared.formal.target.clone()),
        role: if prepared.initial_path.status == InitialPathStatus::DefinitiveNoPath {
            EvidenceRole::PrimaryDecision
        } else {
            EvidenceRole::Context
        },
        fact: EvidenceFact::InitialPath(format!("{:?}", prepared.initial_path.status)),
    }];
    match &prepared.current_path {
        CapabilityValue::Available { value, .. } => evidence.push(Evidence {
            id: EvidenceId(base_id + 1),
            subject: EvidenceSubject::Target(prepared.formal.target.clone()),
            role: EvidenceRole::Context,
            fact: EvidenceFact::CurrentPath(format!("{:?}", value.relation)),
        }),
        CapabilityValue::Unknown { reason, .. } | CapabilityValue::Unavailable { reason, .. } => {
            evidence.push(Evidence {
                id: EvidenceId(base_id + 1),
                subject: EvidenceSubject::Target(prepared.formal.target.clone()),
                role: EvidenceRole::Context,
                fact: EvidenceFact::CapabilityUnavailable {
                    capability: "current targeted path lookup".into(),
                    reason: reason.clone(),
                },
            })
        }
    }
    evidence
}

fn attempt_evidence(attempt: &Attempt, role: EvidenceRole) -> Evidence {
    Evidence {
        id: EvidenceId(attempt.id.0),
        subject: match &attempt.subject {
            crate::AttemptSubject::Target(target) => EvidenceSubject::Target(target.clone()),
            crate::AttemptSubject::NextHop(neighbor) => EvidenceSubject::Neighbor(neighbor.clone()),
            crate::AttemptSubject::Resolver { endpoint, .. } => {
                EvidenceSubject::Resolver(endpoint.to_string())
            }
        },
        role,
        fact: EvidenceFact::Attempt(attempt.id),
    }
}

fn optional_io_limitation(
    capability: &str,
    error: DiagnosticIoError,
    target: &TargetIp,
    id: AttemptId,
) -> Evidence {
    Evidence {
        id: EvidenceId(id.0),
        subject: EvidenceSubject::Target(target.clone()),
        role: EvidenceRole::CapabilityLimitation,
        fact: EvidenceFact::CapabilityUnavailable {
            capability: capability.into(),
            reason: CapabilityReason::Other(error.safe_message),
        },
    }
}

fn add_target_dependency_limitation(
    dependency: &NeighborDependency,
    target: &TargetIp,
    evidence: &mut Vec<Evidence>,
    id: AttemptId,
) -> bool {
    let NeighborDependency::Unknown { reason } = dependency else {
        return false;
    };
    evidence.push(Evidence {
        id: EvidenceId(id.0),
        subject: EvidenceSubject::Target(target.clone()),
        role: EvidenceRole::CapabilityLimitation,
        fact: EvidenceFact::CapabilityUnavailable {
            capability: "neighbor and deeper path diagnosis".into(),
            reason: CapabilityReason::Other(reason.clone()),
        },
    });
    true
}

fn add_target_neighbor_observation_limitation(
    dependency: &NeighborDependency,
    facts: &TargetNetworkFacts,
    target: &TargetIp,
    evidence: &mut Vec<Evidence>,
    id: AttemptId,
) -> bool {
    let NeighborDependency::Known(_) = dependency else {
        return false;
    };
    let Some(CapabilityValue::Unknown { reason, .. } | CapabilityValue::Unavailable { reason, .. }) =
        &facts.neighbor_post_state
    else {
        return false;
    };
    evidence.push(Evidence {
        id: EvidenceId(id.0),
        subject: EvidenceSubject::Target(target.clone()),
        role: EvidenceRole::CapabilityLimitation,
        fact: EvidenceFact::CapabilityUnavailable {
            capability: "post-failure Neighbor observation".into(),
            reason: reason.clone(),
        },
    });
    true
}

fn add_resolver_dependency_limitation(
    dependency: &NeighborDependency,
    endpoint: &ResolverEndpoint,
    evidence: &mut Vec<Evidence>,
    id: EvidenceId,
) {
    let NeighborDependency::Unknown { reason } = dependency else {
        return;
    };
    evidence.push(Evidence {
        id,
        subject: EvidenceSubject::Resolver(resolver_label(endpoint)),
        role: EvidenceRole::CapabilityLimitation,
        fact: EvidenceFact::CapabilityUnavailable {
            capability: "resolver neighbor diagnosis".into(),
            reason: CapabilityReason::Other(reason.clone()),
        },
    });
}

fn add_resolver_neighbor_observation_limitation(
    dependency: &NeighborDependency,
    facts: &TargetNetworkFacts,
    endpoint: &ResolverEndpoint,
    evidence: &mut Vec<Evidence>,
    id: EvidenceId,
) {
    let NeighborDependency::Known(_) = dependency else {
        return;
    };
    let Some(CapabilityValue::Unknown { reason, .. } | CapabilityValue::Unavailable { reason, .. }) =
        &facts.neighbor_post_state
    else {
        return;
    };
    evidence.push(Evidence {
        id,
        subject: EvidenceSubject::Resolver(resolver_label(endpoint)),
        role: EvidenceRole::CapabilityLimitation,
        fact: EvidenceFact::CapabilityUnavailable {
            capability: "resolver post-failure Neighbor observation".into(),
            reason: reason.clone(),
        },
    });
}

fn add_neighbor_evidence(
    facts: &TargetNetworkFacts,
    evidence: &mut Vec<Evidence>,
    role: EvidenceRole,
    id: AttemptId,
) {
    let Some(CapabilityValue::Available { value, .. }) = &facts.neighbor_post_state else {
        return;
    };
    evidence.push(Evidence {
        id: EvidenceId(id.0),
        subject: EvidenceSubject::Neighbor(value.identity.clone()),
        role,
        fact: EvidenceFact::NeighborTransition {
            before: facts
                .neighbor_pre_state
                .as_ref()
                .and_then(capability_neighbor_state),
            after: value.state,
        },
    });
}

fn add_tcp_path_comparison(
    result: &TcpAttemptResult,
    initial_path: &InitialPathAnalysis,
    evidence: &mut Vec<Evidence>,
    id: AttemptId,
) {
    if !matches!(
        result,
        TcpAttemptResult::NoRoute
            | TcpAttemptResult::NetworkUnreachable
            | TcpAttemptResult::HostUnreachable
    ) {
        return;
    }
    let comparison = match initial_path.status {
        InitialPathStatus::UsablePath => {
            "the socket returned a network-path error despite a usable initial snapshot path"
        }
        InitialPathStatus::DefinitiveNoPath => {
            "the socket network-path error agrees with the initial no-path snapshot"
        }
        InitialPathStatus::UnknownPath => {
            "the socket returned a network-path error while the initial path remained unknown"
        }
    };
    evidence.push(Evidence {
        id: EvidenceId(id.0),
        subject: EvidenceSubject::Target(initial_path.target.clone()),
        role: EvidenceRole::BoundaryNarrowing,
        fact: EvidenceFact::SocketPathComparison(comparison.into()),
    });
}

fn system_resolver_evidence(observation: &SystemResolverObservation) -> Evidence {
    let summary = match &observation.result {
        SystemResolverResult::Succeeded(addresses) => format!(
            "succeeded with {} raw and {} formal addresses",
            addresses.raw_addresses.len(),
            addresses.formal_targets.len()
        ),
        SystemResolverResult::Failed(failure) => format!("failed: {:?}", failure.kind),
    };
    Evidence {
        id: EvidenceId(1),
        subject: EvidenceSubject::Hostname,
        role: EvidenceRole::PrimaryDecision,
        fact: EvidenceFact::SystemResolverResult(summary),
    }
}

fn skipped_current_path(
    snapshot: &InitialNetworkSnapshot,
) -> CapabilityValue<OperationPathContext> {
    CapabilityValue::unavailable(
        CapabilityReason::QuerySemanticsUnavailable,
        Provenance::new(ProvenanceSource::TargetedPathQuery)
            .at(snapshot.capture_completed_at)
            .with_detail("skipped because initial path was definitively unusable"),
    )
}

fn terminal_io_error(
    error: DiagnosticIoError,
    cancellation: &CancellationToken,
) -> DiagnosticResult {
    if cancellation.is_cancelled() || error.kind == DiagnosticIoErrorKind::Cancelled {
        return cancelled();
    }
    let kind = match error.kind {
        DiagnosticIoErrorKind::Cancelled => unreachable!("handled above"),
        DiagnosticIoErrorKind::RequiredCapabilityUnavailable => {
            ExecutionErrorKind::RequiredCapabilityUnavailable
        }
        DiagnosticIoErrorKind::ResourceExhausted => ExecutionErrorKind::ResourceExhausted,
        DiagnosticIoErrorKind::Internal => ExecutionErrorKind::InternalFailure,
    };
    DiagnosticResult::ExecutionError(ExecutionError {
        kind,
        safe_message: error.safe_message,
        partial_evidence: Vec::new(),
    })
}

fn cancelled() -> DiagnosticResult {
    DiagnosticResult::Cancelled(Cancelled {
        safe_message: "interrupted".into(),
    })
}

struct IdSequence(u64);

impl IdSequence {
    const fn new(first: u64) -> Self {
        Self(first)
    }

    fn next(&mut self) -> AttemptId {
        let id = AttemptId(self.0);
        self.0 = self.0.checked_add(1).expect("Attempt ID space exhausted");
        id
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::Ipv4Addr,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use ipnet::Ipv4Net;

    use super::*;
    use crate::{
        AddressFamily, AttemptKind, AttemptSubject, AttemptTiming, InterfaceFact, InterfaceId,
        InterfaceState, PathSelectionFact, ResolverAddressSet, ResolverConfiguration,
        RouteBehavior, RouteFact, SystemResolverFailure, SystemResolverFailureKind, parse_request,
    };

    struct ScriptedIo {
        snapshot: InitialNetworkSnapshot,
        resolver: Mutex<Option<SystemResolverObservation>>,
        current_path: CapabilityValue<OperationPathContext>,
        neighbor_state: CapabilityValue<NeighborFact>,
        neighbor_states: Mutex<VecDeque<NeighborState>>,
        tcp: Mutex<VecDeque<TcpAttemptResult>>,
        tcp_errors: Mutex<VecDeque<DiagnosticIoErrorKind>>,
        icmp: Mutex<VecDeque<IcmpAttemptResult>>,
        icmp_errors: Mutex<VecDeque<DiagnosticIoErrorKind>>,
        path: Mutex<VecDeque<Option<AttemptOutcome>>>,
        udp_a: Mutex<VecDeque<DnsAttemptResult>>,
        udp_aaaa: Mutex<VecDeque<DnsAttemptResult>>,
        tcp_a: Mutex<VecDeque<DnsAttemptResult>>,
        tcp_aaaa: Mutex<VecDeque<DnsAttemptResult>>,
        dns_reasons: Mutex<Vec<DirectDnsTransportReason>>,
        tcp_operations: Mutex<Vec<TcpOperation>>,
        icmp_operations: Mutex<Vec<IcmpOperation>>,
        path_operations: Mutex<Vec<(bool, PathOperation)>>,
        dns_udp_operations: Mutex<Vec<DirectDnsOperation>>,
        dns_tcp_operations: Mutex<Vec<DirectDnsOperation>>,
        snapshot_calls: AtomicUsize,
        tcp_calls: AtomicUsize,
        icmp_calls: AtomicUsize,
        neighbor_calls: AtomicUsize,
        path_calls: AtomicUsize,
        active_tcp: AtomicUsize,
        max_active_tcp: AtomicUsize,
        active_dns: AtomicUsize,
        max_active_dns: AtomicUsize,
        active_started_before_neighbor_pre_state: AtomicBool,
        cancel_after_resolver: AtomicBool,
    }

    impl ScriptedIo {
        fn new(snapshot: InitialNetworkSnapshot) -> Self {
            let target = test_target();
            Self {
                snapshot,
                resolver: Mutex::new(None),
                current_path: CapabilityValue::available(
                    OperationPathContext {
                        captured_at: Duration::ZERO,
                        target_or_dependency: target.address,
                        family: AddressFamily::Ipv4,
                        egress_interface: None,
                        relation: PathRelation::Local,
                        next_hop: None,
                        preferred_source: None,
                        relation_to_initial_snapshot: None,
                        provenance: provenance(),
                    },
                    provenance(),
                ),
                neighbor_state: CapabilityValue::unavailable(
                    CapabilityReason::QuerySemanticsUnavailable,
                    provenance(),
                ),
                neighbor_states: Mutex::new(VecDeque::new()),
                tcp: Mutex::new(VecDeque::new()),
                tcp_errors: Mutex::new(VecDeque::new()),
                icmp: Mutex::new(VecDeque::new()),
                icmp_errors: Mutex::new(VecDeque::new()),
                path: Mutex::new(VecDeque::new()),
                udp_a: Mutex::new(VecDeque::new()),
                udp_aaaa: Mutex::new(VecDeque::new()),
                tcp_a: Mutex::new(VecDeque::new()),
                tcp_aaaa: Mutex::new(VecDeque::new()),
                dns_reasons: Mutex::new(Vec::new()),
                tcp_operations: Mutex::new(Vec::new()),
                icmp_operations: Mutex::new(Vec::new()),
                path_operations: Mutex::new(Vec::new()),
                dns_udp_operations: Mutex::new(Vec::new()),
                dns_tcp_operations: Mutex::new(Vec::new()),
                snapshot_calls: AtomicUsize::new(0),
                tcp_calls: AtomicUsize::new(0),
                icmp_calls: AtomicUsize::new(0),
                neighbor_calls: AtomicUsize::new(0),
                path_calls: AtomicUsize::new(0),
                active_tcp: AtomicUsize::new(0),
                max_active_tcp: AtomicUsize::new(0),
                active_dns: AtomicUsize::new(0),
                max_active_dns: AtomicUsize::new(0),
                active_started_before_neighbor_pre_state: AtomicBool::new(false),
                cancel_after_resolver: AtomicBool::new(false),
            }
        }

        fn with_tcp(self, outcomes: impl IntoIterator<Item = TcpAttemptResult>) -> Self {
            self.tcp.lock().expect("test TCP queue").extend(outcomes);
            self
        }

        fn with_tcp_errors(self, errors: impl IntoIterator<Item = DiagnosticIoErrorKind>) -> Self {
            self.tcp_errors
                .lock()
                .expect("test TCP error queue")
                .extend(errors);
            self
        }

        fn with_icmp(self, outcomes: impl IntoIterator<Item = IcmpAttemptResult>) -> Self {
            self.icmp.lock().expect("test ICMP queue").extend(outcomes);
            self
        }

        fn with_icmp_errors(self, errors: impl IntoIterator<Item = DiagnosticIoErrorKind>) -> Self {
            self.icmp_errors
                .lock()
                .expect("test ICMP error queue")
                .extend(errors);
            self
        }

        fn with_neighbor_states(self, states: impl IntoIterator<Item = NeighborState>) -> Self {
            self.neighbor_states
                .lock()
                .expect("test Neighbor queue")
                .extend(states);
            self
        }

        fn with_path(self, outcomes: impl IntoIterator<Item = Option<AttemptOutcome>>) -> Self {
            self.path.lock().expect("test path queue").extend(outcomes);
            self
        }

        fn with_resolver(self, observation: SystemResolverObservation) -> Self {
            *self.resolver.lock().expect("test resolver observation") = Some(observation);
            self
        }

        fn cancelling_after_resolver(self) -> Self {
            self.cancel_after_resolver.store(true, Ordering::SeqCst);
            self
        }

        fn with_remote_path(mut self) -> Self {
            self.current_path = CapabilityValue::available(
                OperationPathContext {
                    captured_at: Duration::ZERO,
                    target_or_dependency: test_target().address,
                    family: AddressFamily::Ipv4,
                    egress_interface: Some(InterfaceId::from_index(2)),
                    relation: PathRelation::Remote,
                    next_hop: Some(Ipv4Addr::new(192, 0, 2, 1).into()),
                    preferred_source: None,
                    relation_to_initial_snapshot: None,
                    provenance: provenance(),
                },
                provenance(),
            );
            let identity = NeighborIdentity {
                family: AddressFamily::Ipv4,
                interface: InterfaceId::from_index(2),
                address: Ipv4Addr::new(192, 0, 2, 1).into(),
            };
            self.neighbor_state = CapabilityValue::available(
                NeighborFact {
                    identity,
                    state: NeighborState::Usable,
                    observed_at: Duration::ZERO,
                    raw_state: Some("reachable".into()),
                    provenance: provenance(),
                },
                provenance(),
            );
            self
        }

        fn with_on_link_path(mut self) -> Self {
            self.current_path = CapabilityValue::available(
                OperationPathContext {
                    captured_at: Duration::ZERO,
                    target_or_dependency: test_target().address,
                    family: AddressFamily::Ipv4,
                    egress_interface: Some(InterfaceId::from_index(2)),
                    relation: PathRelation::OnLink,
                    next_hop: None,
                    preferred_source: None,
                    relation_to_initial_snapshot: None,
                    provenance: provenance(),
                },
                provenance(),
            );
            self.neighbor_state = CapabilityValue::available(
                NeighborFact {
                    identity: NeighborIdentity {
                        family: AddressFamily::Ipv4,
                        interface: InterfaceId::from_index(2),
                        address: test_target().address,
                    },
                    state: NeighborState::Usable,
                    observed_at: Duration::ZERO,
                    raw_state: Some("reachable".into()),
                    provenance: provenance(),
                },
                provenance(),
            );
            self
        }

        fn with_unavailable_current_path(mut self) -> Self {
            self.current_path = CapabilityValue::unavailable(
                CapabilityReason::QuerySemanticsUnavailable,
                provenance(),
            );
            self
        }

        fn with_unavailable_neighbor(mut self) -> Self {
            self.neighbor_state = CapabilityValue::unavailable(
                CapabilityReason::OrdinaryUserPermissionDenied,
                provenance(),
            );
            self
        }

        fn push_udp(&self, query_type: DnsQueryType, outcomes: &[DnsAttemptResult]) {
            dns_queue(query_type, &self.udp_a, &self.udp_aaaa)
                .lock()
                .expect("test UDP DNS queue")
                .extend(outcomes.iter().cloned());
        }

        fn push_dns_tcp(&self, query_type: DnsQueryType, outcomes: &[DnsAttemptResult]) {
            dns_queue(query_type, &self.tcp_a, &self.tcp_aaaa)
                .lock()
                .expect("test TCP DNS queue")
                .extend(outcomes.iter().cloned());
        }
    }

    impl DiagnosticIo for ScriptedIo {
        async fn capture_initial_snapshot(
            &self,
        ) -> Result<InitialNetworkSnapshot, DiagnosticIoError> {
            self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.snapshot.clone())
        }

        async fn system_resolve(
            &self,
            _hostname: &Hostname,
            cancellation: &CancellationToken,
        ) -> Result<SystemResolverObservation, DiagnosticIoError> {
            let result = self
                .resolver
                .lock()
                .expect("test resolver observation")
                .clone()
                .ok_or_else(|| {
                    DiagnosticIoError::new(
                        DiagnosticIoErrorKind::Internal,
                        "missing scripted system resolver result",
                    )
                });
            if self.cancel_after_resolver.load(Ordering::SeqCst) {
                cancellation.cancel();
            }
            result
        }

        async fn current_operation_path(
            &self,
            target: &TargetIp,
        ) -> Result<CapabilityValue<OperationPathContext>, DiagnosticIoError> {
            let mut result = self.current_path.clone();
            if let CapabilityValue::Available { value, .. } = &mut result {
                value.target_or_dependency = target.address;
                value.family = target.family();
            }
            Ok(result)
        }

        async fn neighbor(
            &self,
            identity: &NeighborIdentity,
        ) -> Result<CapabilityValue<NeighborFact>, DiagnosticIoError> {
            self.neighbor_calls.fetch_add(1, Ordering::SeqCst);
            let mut result = self.neighbor_state.clone();
            if let CapabilityValue::Available { value, .. } = &mut result {
                value.identity = identity.clone();
                if let Some(state) = self
                    .neighbor_states
                    .lock()
                    .expect("test Neighbor queue")
                    .pop_front()
                {
                    value.state = state;
                }
            }
            Ok(result)
        }

        async fn observe_neighbor_convergence(
            &self,
            identity: &NeighborIdentity,
            _cancellation: &CancellationToken,
        ) -> Result<CapabilityValue<NeighborFact>, DiagnosticIoError> {
            self.neighbor(identity).await
        }

        async fn tcp_connect(
            &self,
            operation: TcpOperation,
            _cancellation: &CancellationToken,
        ) -> Result<Attempt, DiagnosticIoError> {
            self.tcp_operations
                .lock()
                .expect("test TCP operation log")
                .push(operation.clone());
            if self.neighbor_calls.load(Ordering::SeqCst) == 0
                && matches!(self.current_path, CapabilityValue::Available { ref value, .. } if value.relation == PathRelation::Remote)
            {
                self.active_started_before_neighbor_pre_state
                    .store(true, Ordering::SeqCst);
            }
            self.tcp_calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active_tcp.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_tcp.fetch_max(active, Ordering::SeqCst);
            tokio::task::yield_now().await;
            if let Some(kind) = self
                .tcp_errors
                .lock()
                .expect("test TCP error queue")
                .pop_front()
            {
                self.active_tcp.fetch_sub(1, Ordering::SeqCst);
                return Err(DiagnosticIoError::new(kind, "scripted TCP execution error"));
            }
            let outcome = self
                .tcp
                .lock()
                .expect("test TCP queue")
                .pop_front()
                .ok_or_else(|| {
                    DiagnosticIoError::new(
                        DiagnosticIoErrorKind::Internal,
                        "missing scripted TCP result",
                    )
                })?;
            self.active_tcp.fetch_sub(1, Ordering::SeqCst);
            Ok(attempt(
                operation.attempt_id,
                AttemptSubject::Target(operation.target),
                AttemptKind::TcpConnect,
                AttemptOutcome::Tcp(outcome),
                operation.budget,
            ))
        }

        async fn icmp_echo(
            &self,
            operation: IcmpOperation,
            _cancellation: &CancellationToken,
        ) -> Result<Attempt, DiagnosticIoError> {
            self.icmp_operations
                .lock()
                .expect("test ICMP operation log")
                .push(operation.clone());
            self.icmp_calls.fetch_add(1, Ordering::SeqCst);
            let scripted_outcome = self.icmp.lock().expect("test ICMP queue").pop_front();
            if let Some(outcome) = scripted_outcome {
                let subject = match operation.subject {
                    IcmpEchoSubject::Target(target) => AttemptSubject::Target(target),
                    IcmpEchoSubject::NextHop(identity) => AttemptSubject::NextHop(identity),
                };
                let kind = match &subject {
                    AttemptSubject::Target(_) => AttemptKind::TargetIcmpEcho,
                    AttemptSubject::NextHop(_) => AttemptKind::NextHopIcmpEcho,
                    AttemptSubject::Resolver { .. } => {
                        unreachable!("ICMP subject cannot be resolver")
                    }
                };
                return Ok(attempt(
                    operation.attempt_id,
                    subject,
                    kind,
                    AttemptOutcome::Icmp(outcome),
                    operation.budget,
                ));
            }
            if let Some(kind) = self
                .icmp_errors
                .lock()
                .expect("test ICMP error queue")
                .pop_front()
            {
                return Err(DiagnosticIoError::new(
                    kind,
                    "scripted ICMP capability unavailable",
                ));
            }
            Err(DiagnosticIoError::new(
                DiagnosticIoErrorKind::Internal,
                "missing scripted ICMP result",
            ))
        }

        async fn tcp_path_attempt(
            &self,
            operation: PathOperation,
            _cancellation: &CancellationToken,
        ) -> Result<CapabilityValue<Attempt>, DiagnosticIoError> {
            self.path_attempt(operation, true)
        }

        async fn icmp_path_attempt(
            &self,
            operation: PathOperation,
            _cancellation: &CancellationToken,
        ) -> Result<CapabilityValue<Attempt>, DiagnosticIoError> {
            self.path_attempt(operation, false)
        }

        async fn direct_dns_udp(
            &self,
            operation: DirectDnsOperation,
            _cancellation: &CancellationToken,
        ) -> Result<Attempt, DiagnosticIoError> {
            self.dns_udp_operations
                .lock()
                .expect("test UDP DNS operation log")
                .push(operation.clone());
            let active = self.active_dns.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_dns.fetch_max(active, Ordering::SeqCst);
            tokio::task::yield_now().await;
            self.dns_reasons
                .lock()
                .expect("test DNS reason log")
                .push(operation.reason);
            let query_type = operation.query_type;
            let result = dns_attempt(
                operation,
                AttemptKind::DnsUdp { query_type },
                dns_queue(query_type, &self.udp_a, &self.udp_aaaa),
            );
            self.active_dns.fetch_sub(1, Ordering::SeqCst);
            result
        }

        async fn direct_dns_tcp(
            &self,
            operation: DirectDnsOperation,
            _cancellation: &CancellationToken,
        ) -> Result<Attempt, DiagnosticIoError> {
            self.dns_tcp_operations
                .lock()
                .expect("test TCP DNS operation log")
                .push(operation.clone());
            let active = self.active_dns.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_dns.fetch_max(active, Ordering::SeqCst);
            tokio::task::yield_now().await;
            self.dns_reasons
                .lock()
                .expect("test DNS reason log")
                .push(operation.reason);
            let query_type = operation.query_type;
            let result = dns_attempt(
                operation,
                AttemptKind::DnsTcp { query_type },
                dns_queue(query_type, &self.tcp_a, &self.tcp_aaaa),
            );
            self.active_dns.fetch_sub(1, Ordering::SeqCst);
            result
        }
    }

    impl ScriptedIo {
        fn path_attempt(
            &self,
            operation: PathOperation,
            tcp: bool,
        ) -> Result<CapabilityValue<Attempt>, DiagnosticIoError> {
            self.path_operations
                .lock()
                .expect("test path operation log")
                .push((tcp, operation.clone()));
            self.path_calls.fetch_add(1, Ordering::SeqCst);
            let scripted = self.path.lock().expect("test path queue").pop_front();
            let Some(Some(outcome)) = scripted else {
                return Ok(CapabilityValue::unavailable(
                    CapabilityReason::AttemptCorrelationUnavailable,
                    provenance(),
                ));
            };
            let kind = if tcp {
                AttemptKind::TcpPath {
                    hop_limit: operation.hop_limit,
                }
            } else {
                AttemptKind::IcmpPath {
                    hop_limit: operation.hop_limit,
                }
            };
            Ok(CapabilityValue::available(
                attempt(
                    operation.attempt_id,
                    AttemptSubject::Target(operation.target),
                    kind,
                    outcome,
                    operation.budget,
                ),
                provenance(),
            ))
        }
    }

    fn dns_queue<'a>(
        query_type: DnsQueryType,
        a: &'a Mutex<VecDeque<DnsAttemptResult>>,
        aaaa: &'a Mutex<VecDeque<DnsAttemptResult>>,
    ) -> &'a Mutex<VecDeque<DnsAttemptResult>> {
        match query_type {
            DnsQueryType::A => a,
            DnsQueryType::Aaaa => aaaa,
        }
    }

    fn dns_attempt(
        operation: DirectDnsOperation,
        kind: AttemptKind,
        queue: &Mutex<VecDeque<DnsAttemptResult>>,
    ) -> Result<Attempt, DiagnosticIoError> {
        let outcome = queue
            .lock()
            .expect("test DNS queue")
            .pop_front()
            .ok_or_else(|| {
                DiagnosticIoError::new(
                    DiagnosticIoErrorKind::Internal,
                    "missing scripted DNS result",
                )
            })?;
        Ok(attempt(
            operation.attempt_id,
            AttemptSubject::Resolver {
                endpoint: operation.resolver,
                query_name: operation.query_name,
            },
            kind,
            AttemptOutcome::Dns(outcome),
            operation.budget,
        ))
    }

    fn attempt(
        id: AttemptId,
        subject: AttemptSubject,
        kind: AttemptKind,
        outcome: AttemptOutcome,
        budget: Duration,
    ) -> Attempt {
        Attempt {
            id,
            subject,
            kind,
            timing: AttemptTiming {
                started_at: Duration::ZERO,
                deadline_at: budget,
                completed_at: budget,
            },
            outcome,
            provenance: provenance(),
        }
    }

    fn provenance() -> Provenance {
        Provenance::new(ProvenanceSource::SyntheticTest).at(Duration::ZERO)
    }

    fn test_target() -> TargetIp {
        TargetIp::v4(Ipv4Addr::new(203, 0, 113, 10))
    }

    fn connected() -> TcpAttemptResult {
        TcpAttemptResult::Connected {
            local: CapabilityValue::unavailable(
                CapabilityReason::QuerySemanticsUnavailable,
                provenance(),
            ),
            remote: CapabilityValue::unavailable(
                CapabilityReason::QuerySemanticsUnavailable,
                provenance(),
            ),
        }
    }

    fn snapshot(route_behavior: Option<RouteBehavior>) -> InitialNetworkSnapshot {
        let route = route_behavior.map(|behavior| RouteFact {
            destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0)
                .expect("valid test route")
                .into(),
            next_hop: Some(Ipv4Addr::new(192, 0, 2, 1).into()),
            egress_interface: Some(InterfaceId::from_index(2)),
            behavior,
            metric: Some(10),
            table_or_compartment: Some(254),
            preferred_source: None,
            multipath_weight: None,
            provenance: provenance(),
        });
        InitialNetworkSnapshot {
            capture_started_at: Duration::ZERO,
            capture_completed_at: Duration::ZERO,
            interfaces: CapabilityValue::available(
                vec![InterfaceFact {
                    id: InterfaceId::from_index(2),
                    system_name: "test0".into(),
                    display_name: "test0".into(),
                    administrative_state: InterfaceState::Up,
                    operational_state: InterfaceState::Up,
                    is_loopback: false,
                    addresses: Vec::new(),
                    provenance: provenance(),
                }],
                provenance(),
            ),
            routes_v4: route.map_or_else(
                || {
                    CapabilityValue::unavailable(
                        CapabilityReason::QuerySemanticsUnavailable,
                        provenance(),
                    )
                },
                |route| CapabilityValue::available(vec![route], provenance()),
            ),
            routes_v6: CapabilityValue::available(Vec::new(), provenance()),
            routing_policy_facts: CapabilityValue::available(
                crate::RoutingPolicyFacts {
                    facts: vec![PathSelectionFact {
                        family: AddressFamily::Ipv4,
                        priority: Some(0),
                        table_or_domain: Some(254),
                        description: "synthetic complete policy".into(),
                        provenance: provenance(),
                    }],
                    static_selection_complete: true,
                    limitations: Vec::new(),
                },
                provenance(),
            ),
            resolver_configuration: CapabilityValue::available(
                ResolverConfiguration {
                    endpoints: Vec::new(),
                    search_domains: Vec::new(),
                    non_dns_sources: Vec::new(),
                    dns_protocol_candidates_applicable: CapabilityValue::available(
                        true,
                        provenance(),
                    ),
                    ordering_is_semantic: true,
                    limitations: Vec::new(),
                    provenance: provenance(),
                },
                provenance(),
            ),
            inconsistencies: Vec::new(),
        }
    }

    fn with_dns_resolver(mut snapshot: InitialNetworkSnapshot) -> InitialNetworkSnapshot {
        snapshot.resolver_configuration = CapabilityValue::available(
            ResolverConfiguration {
                endpoints: vec![ResolverEndpoint {
                    address: Ipv4Addr::new(192, 0, 2, 53).into(),
                    port: 53,
                    transport: ResolverTransport::Udp,
                    interface: Some(InterfaceId::from_index(2)),
                    domains: Vec::new(),
                    priority: Some(0),
                    provenance: provenance(),
                }],
                search_domains: Vec::new(),
                non_dns_sources: Vec::new(),
                dns_protocol_candidates_applicable: CapabilityValue::available(true, provenance()),
                ordering_is_semantic: true,
                limitations: Vec::new(),
                provenance: provenance(),
            },
            provenance(),
        );
        snapshot
    }

    fn resolver_failure() -> SystemResolverObservation {
        SystemResolverObservation {
            started_at: Duration::ZERO,
            completed_at: Duration::from_millis(1),
            result: SystemResolverResult::Failed(SystemResolverFailure {
                kind: SystemResolverFailureKind::Timeout,
                platform_code: Some(110),
                platform_message: "synthetic timeout".into(),
            }),
            provenance: provenance(),
        }
    }

    fn definitive_resolver_failure() -> SystemResolverObservation {
        SystemResolverObservation {
            started_at: Duration::ZERO,
            completed_at: Duration::from_millis(1),
            result: SystemResolverResult::Failed(SystemResolverFailure {
                kind: SystemResolverFailureKind::DefinitiveNoName,
                platform_code: Some(1),
                platform_message: "synthetic no name".into(),
            }),
            provenance: provenance(),
        }
    }

    fn dns_response() -> DnsAttemptResult {
        DnsAttemptResult::Response {
            response_code: 0,
            addresses: Vec::new(),
            aliases: Vec::new(),
            truncated: false,
        }
    }

    fn resolver_success(targets: Vec<TargetIp>) -> SystemResolverObservation {
        SystemResolverObservation {
            started_at: Duration::ZERO,
            completed_at: Duration::from_millis(1),
            result: SystemResolverResult::Succeeded(ResolverAddressSet::from_raw(targets)),
            provenance: provenance(),
        }
    }

    fn icmp_message(kind: IcmpMessageKind, responder: Ipv4Addr) -> IcmpAttemptResult {
        IcmpAttemptResult::Message {
            kind,
            responder: responder.into(),
            raw_type: Some(1),
            raw_code: Some(0),
        }
    }

    fn completed(result: DiagnosticResult) -> Box<CompletedDiagnostic> {
        match result {
            DiagnosticResult::Completed(completed) => completed,
            other => panic!("expected completed diagnostic, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn definitive_no_path_suppresses_all_active_target_traffic() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Blackhole)));
        let result = run_diagnostic(
            parse_request("203.0.113.10", Some("443")).expect("valid request"),
            &io,
            &CancellationToken::new(),
        )
        .await;
        let completed = completed(result);
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::DefinitiveNoPath
        );
        assert!(completed.targets[0].attempts.is_empty());
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_initial_path_still_runs_the_real_primary_check() {
        let io = ScriptedIo::new(snapshot(None)).with_tcp([connected()]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::Satisfied
        );
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unused_path_capability_does_not_pollute_success_key_evidence() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_unavailable_current_path()
            .with_tcp([connected()]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        let target = &completed.targets[0];
        assert_eq!(target.primary_outcome, PrimaryOutcome::Satisfied);
        assert_eq!(target.key_evidence.len(), 1);
        assert!(matches!(
            target.key_evidence[0].fact,
            EvidenceFact::Attempt(_)
        ));
    }

    #[tokio::test]
    async fn unavailable_path_becomes_key_only_when_it_limits_failure_diagnosis() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_unavailable_current_path()
            .with_icmp([IcmpAttemptResult::Timeout, IcmpAttemptResult::Timeout]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        let target = &completed.targets[0];
        assert_eq!(target.conclusion, Conclusion::IcmpEchoTimedOut);
        assert_eq!(
            target.diagnostic_conclusions,
            vec![Conclusion::CapabilityLimited]
        );
        assert!(
            target
                .key_evidence
                .iter()
                .any(|item| matches!(item.fact, EvidenceFact::CapabilityUnavailable { .. }))
        );
    }

    #[tokio::test]
    async fn tcp_retries_only_timeout_and_preserves_retry_success_as_anomaly() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_tcp([TcpAttemptResult::Timeout, connected()]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::SatisfiedWithAnomaly
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::TcpConnectSucceededAfterTimeout
        );
        assert_eq!(
            completed.exit_status(),
            crate::ExitStatus::DiagnosticNonSuccess
        );
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 2);
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explicit_tcp_failure_is_not_retried_or_followed_by_icmp() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_tcp([TcpAttemptResult::ConnectionRefused]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::TcpConnectionRefused
        );
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 1);
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn address_check_retries_timeout_but_not_an_explicit_icmp_result() {
        let timeout_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_icmp([IcmpAttemptResult::Timeout, IcmpAttemptResult::Timeout]);
        let timed_out = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &timeout_io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            timed_out.targets[0].primary_outcome,
            PrimaryOutcome::Indeterminate
        );
        assert_eq!(timeout_io.icmp_calls.load(Ordering::SeqCst), 2);

        let explicit_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_icmp([IcmpAttemptResult::ExplicitNetworkError { os_code: Some(1) }]);
        let explicit = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &explicit_io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            explicit.targets[0].conclusion,
            Conclusion::IcmpExplicitFailure
        );
        assert_eq!(explicit_io.icmp_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_port_first_echo_reply_is_a_clean_satisfied_result() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast))).with_icmp([icmp_message(
            IcmpMessageKind::EchoReply,
            Ipv4Addr::new(203, 0, 113, 10),
        )]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::Satisfied
        );
        assert_eq!(completed.targets[0].conclusion, Conclusion::IcmpEchoReplied);
        assert_eq!(completed.exit_status(), crate::ExitStatus::Success);
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_port_unclassified_icmp_message_remains_indeterminate() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast))).with_icmp([icmp_message(
            IcmpMessageKind::Other,
            Ipv4Addr::new(203, 0, 113, 10),
        )]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::Indeterminate
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::IcmpResponseIndeterminate
        );
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_port_echo_reply_from_another_responder_is_not_target_success() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast))).with_icmp([icmp_message(
            IcmpMessageKind::EchoReply,
            Ipv4Addr::new(198, 51, 100, 7),
        )]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::Indeterminate
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::IcmpResponseIndeterminate
        );
    }

    #[tokio::test]
    async fn shared_neighbor_pre_state_is_read_once_before_concurrent_target_traffic() {
        let targets = (1..=6)
            .map(|last| TargetIp::v4(Ipv4Addr::new(203, 0, 113, last)))
            .collect::<Vec<_>>();
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_resolver(resolver_success(targets))
            .with_tcp((0..6).map(|_| connected()));
        let completed = completed(
            run_diagnostic(
                parse_request("example.com", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(completed.targets.len(), 6);
        assert_eq!(io.neighbor_calls.load(Ordering::SeqCst), 1);
        assert!(
            !io.active_started_before_neighbor_pre_state
                .load(Ordering::SeqCst)
        );
        assert!(io.max_active_tcp.load(Ordering::SeqCst) <= MAX_ACTIVE_TARGETS);
        assert_eq!(io.max_active_tcp.load(Ordering::SeqCst), MAX_ACTIVE_TARGETS);
    }

    #[tokio::test]
    async fn large_resolver_results_keep_only_four_target_diagnostics_active() {
        let targets = (0..128)
            .map(|ordinal| {
                let third = u8::try_from(ordinal / 250).expect("bounded test address");
                let fourth = u8::try_from(ordinal % 250 + 1).expect("bounded test address");
                TargetIp::v4(Ipv4Addr::new(198, 51, third, fourth))
            })
            .collect::<Vec<_>>();
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_resolver(resolver_success(targets))
            .with_tcp((0..128).map(|_| connected()));
        let completed = completed(
            run_diagnostic(
                parse_request("example.com", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );

        assert_eq!(completed.targets.len(), 128);
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 128);
        assert_eq!(io.max_active_tcp.load(Ordering::SeqCst), MAX_ACTIVE_TARGETS);
    }

    #[tokio::test]
    async fn one_completed_target_never_cancels_the_remaining_formal_targets() {
        let targets = (1..=6)
            .map(|last| TargetIp::v4(Ipv4Addr::new(203, 0, 113, last)))
            .collect::<Vec<_>>();
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_resolver(resolver_success(targets))
            .with_tcp(
                std::iter::once(TcpAttemptResult::ConnectionRefused)
                    .chain((0..5).map(|_| connected())),
            );
        let completed = completed(
            run_diagnostic(
                parse_request("example.com", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );

        assert_eq!(completed.targets.len(), 6);
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 6);
        assert_eq!(completed.aggregate_outcome, crate::AggregateOutcome::Mixed);
        assert_eq!(
            completed
                .targets
                .iter()
                .filter(|target| target.primary_outcome == PrimaryOutcome::Satisfied)
                .count(),
            5
        );
        assert_eq!(
            completed
                .targets
                .iter()
                .filter(|target| target.primary_outcome == PrimaryOutcome::NotSatisfied)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn direct_dns_success_never_forms_a_hostname_target() {
        let io = ScriptedIo::new(with_dns_resolver(snapshot(Some(RouteBehavior::Unicast))))
            .with_resolver(resolver_failure());
        let response = DnsAttemptResult::Response {
            response_code: 0,
            addresses: vec![Ipv4Addr::new(198, 51, 100, 8).into()],
            aliases: vec!["untrusted\nalias.example".into()],
            truncated: false,
        };
        io.push_udp(DnsQueryType::A, std::slice::from_ref(&response));
        io.push_udp(DnsQueryType::Aaaa, &[response]);
        let completed = completed(
            run_diagnostic(
                parse_request("example.com", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert!(completed.targets.is_empty());
        assert_eq!(completed.resolver_diagnostics.len(), 1);
        assert_eq!(completed.resolver_diagnostics[0].attempts.len(), 2);
        let summaries = completed
            .key_evidence
            .iter()
            .filter_map(|evidence| match &evidence.fact {
                EvidenceFact::DirectDnsResult(summary) => Some(summary),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|summary| {
            summary.contains("1 address(es), 1 alias(es)") && !summary.contains("untrusted")
        }));
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            completed.hostname_resolution,
            HostnameResolutionOutcome::NonDefinitiveFailure {
                direct_dns_was_diagnostic_only: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn inconsistent_resolver_snapshot_is_preserved_and_never_guessed_through() {
        let mut initial = with_dns_resolver(snapshot(Some(RouteBehavior::Unicast)));
        initial.inconsistencies.push(crate::SnapshotInconsistency {
            scope: SnapshotInconsistencyScope::ResolverSelection,
            detail: "resolver interface disappeared during capture".into(),
        });
        let io = ScriptedIo::new(initial).with_resolver(resolver_failure());
        let completed = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert!(completed.resolver_diagnostics.is_empty());
        assert!(
            completed
                .key_evidence
                .iter()
                .any(|evidence| matches!(evidence.fact, EvidenceFact::SnapshotInconsistency(_)))
        );
        assert_eq!(io.max_active_dns.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn definitive_negative_and_zero_address_resolution_never_probe_or_succeed() {
        let definitive_io =
            ScriptedIo::new(with_dns_resolver(snapshot(Some(RouteBehavior::Unicast))))
                .with_resolver(definitive_resolver_failure());
        let definitive = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid request"),
                &definitive_io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            definitive.conclusion,
            Conclusion::HostnameResolutionDefinitiveNegative
        );
        assert!(definitive.resolver_diagnostics.is_empty());
        assert_eq!(
            definitive.exit_status(),
            crate::ExitStatus::DiagnosticNonSuccess
        );

        let empty_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_resolver(resolver_success(Vec::new()));
        let empty = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid request"),
                &empty_io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(empty.conclusion, Conclusion::HostnameNoFormalTargets);
        assert!(empty.targets.is_empty());
        assert_eq!(empty.exit_status(), crate::ExitStatus::DiagnosticNonSuccess);
    }

    #[tokio::test]
    async fn hostname_target_order_is_resolver_order_even_for_mixed_results() {
        let targets = vec![
            TargetIp::v4(Ipv4Addr::new(203, 0, 113, 20)),
            TargetIp::v4(Ipv4Addr::new(203, 0, 113, 10)),
        ];
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_resolver(resolver_success(targets.clone()))
            .with_tcp([connected(), TcpAttemptResult::ConnectionRefused]);
        let result = completed(
            run_diagnostic(
                parse_request("example.com", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(result.aggregate_outcome, crate::AggregateOutcome::Mixed);
        assert_eq!(result.targets[0].target, targets[0]);
        assert_eq!(result.targets[1].target, targets[1]);
    }

    #[tokio::test]
    async fn search_domain_uncertainty_is_retained_as_a_query_semantics_limitation() {
        let mut snapshot = with_dns_resolver(snapshot(Some(RouteBehavior::Unicast)));
        let CapabilityValue::Available { value, .. } = &mut snapshot.resolver_configuration else {
            unreachable!("test resolver configuration is available");
        };
        value.search_domains.push("example.test".into());
        let io = ScriptedIo::new(snapshot).with_resolver(resolver_failure());
        io.push_udp(DnsQueryType::A, &[dns_response()]);
        io.push_udp(DnsQueryType::Aaaa, &[dns_response()]);
        let result = completed(
            run_diagnostic(
                parse_request("single-label", None).expect("valid hostname"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert!(result.evidence.iter().any(|evidence| matches!(
            &evidence.fact,
            EvidenceFact::CapabilityUnavailable { capability, .. }
                if capability == "system resolver actual query-name equivalence"
        )));
    }

    #[tokio::test]
    async fn unproven_resolver_transport_is_a_limitation_not_a_protocol_substitution() {
        let mut snapshot = with_dns_resolver(snapshot(Some(RouteBehavior::Unicast)));
        let CapabilityValue::Available { value, .. } = &mut snapshot.resolver_configuration else {
            unreachable!("test resolver configuration is available");
        };
        value.endpoints[0].transport = ResolverTransport::Https;
        let io = ScriptedIo::new(snapshot).with_resolver(resolver_failure());
        let result = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid hostname"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert!(result.resolver_diagnostics.is_empty());
        assert_eq!(io.max_active_dns.load(Ordering::SeqCst), 0);
        assert!(result.evidence.iter().any(|evidence| matches!(
            &evidence.fact,
            EvidenceFact::CapabilityUnavailable { capability, .. }
                if capability == "resolver transport diagnosis"
        )));
    }

    #[tokio::test]
    async fn nonsemantic_unsupported_resolver_order_does_not_change_key_evidence() {
        let mut observed = Vec::new();
        for reverse in [false, true] {
            let mut snapshot = with_dns_resolver(snapshot(Some(RouteBehavior::Unicast)));
            let CapabilityValue::Available { value, .. } = &mut snapshot.resolver_configuration
            else {
                unreachable!("test resolver configuration is available");
            };
            let template = value.endpoints[0].clone();
            value.ordering_is_semantic = false;
            value.endpoints = vec![
                ResolverEndpoint {
                    address: Ipv4Addr::new(192, 0, 2, 20).into(),
                    transport: ResolverTransport::Https,
                    priority: None,
                    ..template.clone()
                },
                ResolverEndpoint {
                    address: Ipv4Addr::new(192, 0, 2, 10).into(),
                    transport: ResolverTransport::Https,
                    priority: None,
                    ..template
                },
            ];
            if reverse {
                value.endpoints.reverse();
            }
            let io = ScriptedIo::new(snapshot).with_resolver(resolver_failure());
            observed.push(
                completed(
                    run_diagnostic(
                        parse_request("example.com", None).expect("valid hostname"),
                        &io,
                        &CancellationToken::new(),
                    )
                    .await,
                )
                .key_evidence,
            );
        }

        assert_eq!(observed[0], observed[1]);
    }

    #[tokio::test]
    async fn resolver_policy_without_a_dns_source_never_triggers_direct_dns() {
        let mut snapshot = with_dns_resolver(snapshot(Some(RouteBehavior::Unicast)));
        let CapabilityValue::Available { value, .. } = &mut snapshot.resolver_configuration else {
            unreachable!("test resolver configuration is available");
        };
        value.dns_protocol_candidates_applicable = CapabilityValue::available(false, provenance());
        let io = ScriptedIo::new(snapshot).with_resolver(resolver_failure());
        let result = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid hostname"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );

        assert!(result.resolver_diagnostics.is_empty());
        assert_eq!(io.max_active_dns.load(Ordering::SeqCst), 0);
        assert!(result.evidence.iter().any(|evidence| matches!(
            &evidence.fact,
            EvidenceFact::CapabilityUnavailable { capability, .. }
                if capability == "applicable DNS protocol source"
        )));
    }

    #[tokio::test]
    async fn resolver_candidate_scheduler_limits_active_candidate_work_to_four() {
        let mut snapshot = with_dns_resolver(snapshot(Some(RouteBehavior::Unicast)));
        let CapabilityValue::Available { value, .. } = &mut snapshot.resolver_configuration else {
            unreachable!("test resolver configuration is available");
        };
        let template = value.endpoints[0].clone();
        value.endpoints = (1..=7)
            .map(|last| ResolverEndpoint {
                address: Ipv4Addr::new(192, 0, 2, last).into(),
                ..template.clone()
            })
            .collect();
        let io = ScriptedIo::new(snapshot).with_resolver(resolver_failure());
        for query_type in [DnsQueryType::A, DnsQueryType::Aaaa] {
            io.push_udp(
                query_type,
                &(0..7).map(|_| dns_response()).collect::<Vec<_>>(),
            );
        }
        let result = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid hostname"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(result.resolver_diagnostics.len(), 7);
        // Each active candidate owns exactly two parallel A/AAAA queries.
        assert_eq!(
            io.max_active_dns.load(Ordering::SeqCst),
            MAX_ACTIVE_RESOLVERS * 2
        );
    }

    #[test]
    fn product_resolver_normalization_preserves_known_per_interface_priority() {
        let interface = InterfaceId {
            index: 7,
            stable_id: Some("resolver-interface".into()),
        };
        let mut endpoints = [
            ResolverEndpoint {
                address: Ipv4Addr::new(192, 0, 2, 20).into(),
                port: 53,
                transport: ResolverTransport::Udp,
                interface: Some(interface.clone()),
                domains: Vec::new(),
                priority: Some(1),
                provenance: provenance(),
            },
            ResolverEndpoint {
                address: Ipv4Addr::new(192, 0, 2, 10).into(),
                port: 53,
                transport: ResolverTransport::Udp,
                interface: Some(interface),
                domains: Vec::new(),
                priority: Some(0),
                provenance: provenance(),
            },
        ];
        endpoints.sort_by_key(resolver_sort_key);

        assert_eq!(endpoints[0].priority, Some(0));
        assert_eq!(endpoints[1].priority, Some(1));

        let mut first = endpoints[0].clone();
        first.domains = vec!["B.Example".into(), "a.example".into()];
        let mut second = first.clone();
        second.domains.reverse();
        assert_eq!(resolver_sort_key(&first), resolver_sort_key(&second));
    }

    #[tokio::test]
    async fn repeated_udp_timeout_enters_bounded_tcp_transport_comparison() {
        let io = ScriptedIo::new(with_dns_resolver(snapshot(Some(RouteBehavior::Unicast))))
            .with_resolver(resolver_failure());
        for query_type in [DnsQueryType::A, DnsQueryType::Aaaa] {
            io.push_udp(
                query_type,
                &[DnsAttemptResult::Timeout, DnsAttemptResult::Timeout],
            );
            io.push_dns_tcp(
                query_type,
                &[DnsAttemptResult::Response {
                    response_code: 0,
                    addresses: Vec::new(),
                    aliases: Vec::new(),
                    truncated: false,
                }],
            );
        }
        let completed = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        let attempts = &completed.resolver_diagnostics[0].attempts;
        assert_eq!(attempts.len(), 6);
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| matches!(attempt.kind, AttemptKind::DnsUdp { .. }))
                .count(),
            4
        );
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| matches!(attempt.kind, AttemptKind::DnsTcp { .. }))
                .count(),
            2
        );
        assert_eq!(
            io.dns_reasons
                .lock()
                .expect("test DNS reason log")
                .iter()
                .filter(|reason| { **reason == DirectDnsTransportReason::UdpTimeoutComparison })
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn udp_truncation_immediately_enters_tcp_for_only_that_question() {
        let io = ScriptedIo::new(with_dns_resolver(snapshot(Some(RouteBehavior::Unicast))))
            .with_resolver(resolver_failure());
        io.push_udp(
            DnsQueryType::A,
            &[DnsAttemptResult::Response {
                response_code: 0,
                addresses: Vec::new(),
                aliases: Vec::new(),
                truncated: true,
            }],
        );
        io.push_dns_tcp(
            DnsQueryType::A,
            &[DnsAttemptResult::Response {
                response_code: 0,
                addresses: Vec::new(),
                aliases: Vec::new(),
                truncated: false,
            }],
        );
        io.push_udp(
            DnsQueryType::Aaaa,
            &[DnsAttemptResult::Response {
                response_code: 0,
                addresses: Vec::new(),
                aliases: Vec::new(),
                truncated: false,
            }],
        );
        let completed = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        let attempts = &completed.resolver_diagnostics[0].attempts;
        assert_eq!(attempts.len(), 3);
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| matches!(attempt.kind, AttemptKind::DnsTcp { .. }))
                .count(),
            1
        );
        assert!(
            io.dns_reasons
                .lock()
                .expect("test DNS reason log")
                .contains(&DirectDnsTransportReason::UdpTruncationCompletion)
        );
    }

    #[tokio::test]
    async fn explicit_target_icmp_result_after_tcp_timeouts_stops_before_neighbor_followup() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([icmp_message(
                IcmpMessageKind::DestinationUnreachable,
                Ipv4Addr::new(192, 0, 2, 1),
            )]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::TcpTimedOutWithExplicitIcmpResult
        );
        assert_eq!(io.neighbor_calls.load(Ordering::SeqCst), 1);
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn neighbor_terminal_failure_and_unsettled_resolution_are_distinct() {
        let terminal_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::TerminalFailure])
            .with_icmp([IcmpAttemptResult::Timeout, IcmpAttemptResult::Timeout]);
        let terminal = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &terminal_io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            terminal.targets[0].conclusion,
            Conclusion::NeighborResolutionFailed
        );
        assert!(terminal.targets[0].key_evidence.iter().any(|evidence| {
            matches!(
                evidence.fact,
                EvidenceFact::NeighborTransition {
                    before: Some(NeighborState::Usable),
                    after: NeighborState::TerminalFailure,
                }
            )
        }));

        let resolving_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([
                NeighborState::Usable,
                NeighborState::Resolving,
                NeighborState::Resolving,
            ])
            .with_icmp([IcmpAttemptResult::Timeout, IcmpAttemptResult::Timeout]);
        let resolving = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &resolving_io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            resolving.targets[0].conclusion,
            Conclusion::NeighborResolutionIndeterminate
        );
        assert_eq!(
            resolving.targets[0].primary_outcome,
            PrimaryOutcome::Indeterminate
        );
        assert_eq!(resolving_io.neighbor_calls.load(Ordering::SeqCst), 3);

        let unknown_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Unknown])
            .with_icmp([IcmpAttemptResult::Timeout, IcmpAttemptResult::Timeout]);
        let unknown = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &unknown_io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(unknown.targets[0].conclusion, Conclusion::IcmpEchoTimedOut);
        assert_eq!(
            unknown.targets[0].diagnostic_conclusions,
            vec![Conclusion::NeighborResolutionIndeterminate]
        );
        assert!(
            unknown.targets[0]
                .key_evidence
                .iter()
                .any(|evidence| matches!(
                    evidence.fact,
                    EvidenceFact::NeighborTransition {
                        after: NeighborState::Unknown,
                        ..
                    }
                ))
        );
    }

    #[tokio::test]
    async fn unavailable_neighbor_read_is_key_evidence_only_after_primary_failure() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_unavailable_neighbor()
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([IcmpAttemptResult::Timeout, IcmpAttemptResult::Timeout]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::TcpConnectTimedOut
        );
        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![Conclusion::CapabilityLimited]
        );
        assert!(
            completed.targets[0]
                .key_evidence
                .iter()
                .any(|evidence| matches!(
                    evidence.fact,
                    EvidenceFact::CapabilityUnavailable {
                        ref capability,
                        reason: CapabilityReason::OrdinaryUserPermissionDenied,
                    } if capability == "post-failure Neighbor observation"
                ))
        );
    }

    #[tokio::test]
    async fn next_hop_timeout_never_unlocks_path_traffic() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
            ]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::IcmpEchoTimedOut
        );
        assert!(completed.targets[0].diagnostic_conclusions.is_empty());
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_icmp_message_from_another_address_does_not_claim_the_next_hop_responded() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(198, 51, 100, 7)),
            ])
            .with_path([Some(AttemptOutcome::Icmp(icmp_message(
                IcmpMessageKind::TimeExceeded,
                Ipv4Addr::new(198, 51, 100, 8),
            )))]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::IcmpEchoTimedOut
        );
        assert!(completed.targets[0].diagnostic_conclusions.is_empty());
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn first_hop_response_unlocks_only_the_matching_path_capability() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::TcpConnectTimedOut
        );
        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![Conclusion::FirstHopResponded, Conclusion::CapabilityLimited]
        );
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn path_attempts_retain_the_hard_hop_and_attempt_limits() {
        let path_timeouts = (0..usize::from(MAX_PATH_HOP_LIMIT) * 2)
            .map(|_| Some(AttemptOutcome::Tcp(TcpAttemptResult::Timeout)));
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path(path_timeouts);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![
                Conclusion::FirstHopResponded,
                Conclusion::PathLimitReachedWithoutEndpointEvidence
            ]
        );
        assert_eq!(
            io.path_calls.load(Ordering::SeqCst),
            usize::from(MAX_PATH_HOP_LIMIT) * 2
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::NotSatisfied
        );
        assert_eq!(
            completed.targets[0]
                .key_evidence
                .iter()
                .filter(|evidence| matches!(
                    evidence.fact,
                    EvidenceFact::Attempt(id)
                        if completed.targets[0]
                            .attempts
                            .iter()
                            .any(|attempt| attempt.id == id
                                && matches!(attempt.kind, AttemptKind::TcpPath { .. }))
                ))
                .count(),
            1,
            "the full path history is retained, but default key evidence contains only the final path boundary"
        );
    }

    #[tokio::test]
    async fn path_time_exceeded_advances_one_hop_and_retains_each_observation() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([
                Some(AttemptOutcome::Icmp(icmp_message(
                    IcmpMessageKind::TimeExceeded,
                    Ipv4Addr::new(192, 0, 2, 1),
                ))),
                Some(AttemptOutcome::Tcp(connected())),
            ]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        let path_attempts = completed.targets[0]
            .attempts
            .iter()
            .filter_map(|attempt| match attempt.kind {
                AttemptKind::TcpPath { hop_limit } => Some(hop_limit),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(path_attempts, vec![1, 2]);
        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![
                Conclusion::FirstHopResponded,
                Conclusion::PathEndpointResponded
            ]
        );
    }

    #[tokio::test]
    async fn multiple_same_attempt_path_responders_are_preserved_without_path_interpretation() {
        let first_responder = Ipv4Addr::new(198, 51, 100, 1);
        let second_responder = Ipv4Addr::new(198, 51, 100, 2);
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([
                Some(AttemptOutcome::Icmp(IcmpAttemptResult::Messages(vec![
                    crate::IcmpMessageObservation {
                        kind: IcmpMessageKind::TimeExceeded,
                        responder: first_responder.into(),
                        raw_type: Some(11),
                        raw_code: Some(0),
                    },
                    crate::IcmpMessageObservation {
                        kind: IcmpMessageKind::TimeExceeded,
                        responder: second_responder.into(),
                        raw_type: Some(11),
                        raw_code: Some(0),
                    },
                ]))),
                Some(AttemptOutcome::Tcp(connected())),
            ]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );

        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![
                Conclusion::FirstHopResponded,
                Conclusion::MultiplePathRespondersObserved,
                Conclusion::PathEndpointResponded,
            ]
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::NotSatisfied
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::TcpConnectTimedOut
        );
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 2);
        assert!(completed.targets[0].attempts.iter().any(|attempt| {
            matches!(
                &attempt.outcome,
                AttemptOutcome::Icmp(IcmpAttemptResult::Messages(messages))
                    if messages.iter().map(|message| message.responder).collect::<Vec<_>>()
                        == vec![
                            std::net::IpAddr::V4(first_responder),
                            std::net::IpAddr::V4(second_responder),
                        ]
            )
        }));
        assert!(completed.targets[0].key_evidence.iter().any(|evidence| {
            matches!(
                evidence.fact,
                EvidenceFact::Attempt(id)
                    if completed.targets[0].attempts.iter().any(|attempt| {
                        attempt.id == id
                            && matches!(attempt.outcome, AttemptOutcome::Icmp(IcmpAttemptResult::Messages(_)))
                    })
            )
        }));
    }

    #[tokio::test]
    async fn unknown_correlated_path_response_is_indeterminate_not_a_hard_termination() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([Some(AttemptOutcome::Icmp(icmp_message(
                IcmpMessageKind::Other,
                Ipv4Addr::new(198, 51, 100, 3),
            )))]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );

        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![
                Conclusion::FirstHopResponded,
                Conclusion::PathResponseIndeterminate,
            ]
        );
        assert!(
            !completed.targets[0]
                .diagnostic_conclusions
                .contains(&Conclusion::PathExplicitlyTerminated)
        );
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_port_timeout_chain_uses_icmp_path_without_inventing_a_tcp_port() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([
                Some(AttemptOutcome::Icmp(icmp_message(
                    IcmpMessageKind::TimeExceeded,
                    Ipv4Addr::new(192, 0, 2, 1),
                ))),
                Some(AttemptOutcome::Icmp(icmp_message(
                    IcmpMessageKind::EchoReply,
                    Ipv4Addr::new(203, 0, 113, 10),
                ))),
            ]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );

        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::Indeterminate
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::IcmpEchoTimedOut
        );
        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![
                Conclusion::FirstHopResponded,
                Conclusion::PathEndpointResponded
            ]
        );
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            completed.targets[0]
                .attempts
                .iter()
                .filter_map(|attempt| match attempt.kind {
                    AttemptKind::IcmpPath { hop_limit } => Some(hop_limit),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[tokio::test]
    async fn on_link_timeout_stops_without_next_hop_or_path_traffic() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_on_link_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_icmp([IcmpAttemptResult::Timeout, IcmpAttemptResult::Timeout]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::IcmpEchoTimedOut
        );
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 2);
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn later_path_endpoint_response_does_not_rewrite_the_failed_primary_check() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([Some(AttemptOutcome::Tcp(connected()))]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::NotSatisfied
        );
        assert_eq!(
            completed.targets[0].conclusion,
            Conclusion::TcpConnectTimedOut
        );
        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![
                Conclusion::FirstHopResponded,
                Conclusion::PathEndpointResponded
            ]
        );
    }

    #[tokio::test]
    async fn correlated_path_hard_error_terminates_without_advancing_the_hop() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([Some(AttemptOutcome::Icmp(icmp_message(
                IcmpMessageKind::DestinationUnreachable,
                Ipv4Addr::new(192, 0, 2, 1),
            )))]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].diagnostic_conclusions,
            vec![
                Conclusion::FirstHopResponded,
                Conclusion::PathExplicitlyTerminated
            ]
        );
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_port_retry_reply_is_an_anomaly_not_a_clean_success() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast))).with_icmp([
            IcmpAttemptResult::Timeout,
            icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(203, 0, 113, 10)),
        ]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            completed.targets[0].primary_outcome,
            PrimaryOutcome::SatisfiedWithAnomaly
        );
        assert_eq!(
            completed.exit_status(),
            crate::ExitStatus::DiagnosticNonSuccess
        );
    }

    #[tokio::test]
    async fn socket_network_error_is_cross_checked_against_the_initial_path() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_tcp([TcpAttemptResult::NoRoute]);
        let completed = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert!(
            completed.targets[0]
                .evidence
                .iter()
                .any(|evidence| matches!(evidence.fact, EvidenceFact::SocketPathComparison(_)))
        );
    }

    #[test]
    fn socket_no_route_comparison_preserves_consistent_and_conflicting_facts() {
        let target = test_target();
        let mut consistent =
            analyze_initial_path(&snapshot(Some(RouteBehavior::Blackhole)), &target);
        assert_eq!(consistent.status, InitialPathStatus::DefinitiveNoPath);
        let mut evidence = Vec::new();
        add_tcp_path_comparison(
            &TcpAttemptResult::NoRoute,
            &consistent,
            &mut evidence,
            AttemptId(1),
        );
        assert_eq!(
            evidence[0].fact,
            EvidenceFact::SocketPathComparison(
                "the socket network-path error agrees with the initial no-path snapshot".into()
            )
        );

        consistent.status = InitialPathStatus::UsablePath;
        let mut evidence = Vec::new();
        add_tcp_path_comparison(
            &TcpAttemptResult::NoRoute,
            &consistent,
            &mut evidence,
            AttemptId(2),
        );
        assert_eq!(
            evidence[0].fact,
            EvidenceFact::SocketPathComparison(
                "the socket returned a network-path error despite a usable initial snapshot path"
                    .into()
            )
        );
    }

    #[tokio::test]
    async fn scoped_ipv6_binding_failure_is_an_execution_error_before_active_io() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)));
        let result = run_diagnostic(
            parse_request("fe80::1%999", None).expect("valid scoped IPv6 syntax"),
            &io,
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(
            result,
            DiagnosticResult::ExecutionError(ExecutionError {
                kind: ExecutionErrorKind::ScopedIpv6BindingFailed,
                ..
            })
        ));
        assert_eq!(io.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dns_dependency_keeps_neighbor_pre_and_post_facts_without_recursive_probes() {
        let io = ScriptedIo::new(with_dns_resolver(snapshot(Some(RouteBehavior::Unicast))))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::TerminalFailure])
            .with_resolver(resolver_failure());
        for query_type in [DnsQueryType::A, DnsQueryType::Aaaa] {
            io.push_udp(
                query_type,
                &[DnsAttemptResult::Timeout, DnsAttemptResult::Timeout],
            );
            io.push_dns_tcp(
                query_type,
                &[DnsAttemptResult::Timeout, DnsAttemptResult::Timeout],
            );
        }
        let completed = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        let facts = &completed.resolver_diagnostics[0].network_facts;
        assert_eq!(
            facts
                .neighbor_pre_state
                .as_ref()
                .and_then(capability_neighbor_state),
            Some(NeighborState::Usable)
        );
        assert_eq!(
            facts
                .neighbor_post_state
                .as_ref()
                .and_then(capability_neighbor_state),
            Some(NeighborState::TerminalFailure)
        );
        assert_eq!(io.icmp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn resolver_root_scope_is_more_specific_than_an_unscoped_candidate() {
        let parsed = parse_request("example.com", None).expect("valid hostname");
        let crate::ParsedAddress::Hostname(hostname) = parsed.address else {
            panic!("expected hostname");
        };
        let mut configuration = match with_dns_resolver(snapshot(Some(RouteBehavior::Unicast)))
            .resolver_configuration
        {
            CapabilityValue::Available { value, .. } => value,
            _ => unreachable!("test resolver configuration is available"),
        };
        let mut root = configuration.endpoints[0].clone();
        root.address = Ipv4Addr::new(192, 0, 2, 54).into();
        root.domains = vec!["~.".into()];
        configuration.endpoints.push(root.clone());
        let (selected, unsupported) = select_resolver_candidates(&hostname, &configuration);
        assert!(unsupported.is_empty());
        assert_eq!(selected, vec![root]);
    }

    #[tokio::test]
    async fn pre_cancelled_run_has_top_priority_and_does_not_capture_a_snapshot() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)));
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = run_diagnostic(
            parse_request("203.0.113.10", None).expect("valid request"),
            &io,
            &cancellation,
        )
        .await;
        assert!(matches!(result, DiagnosticResult::Cancelled(_)));
        assert_eq!(io.snapshot_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_after_the_last_required_branch_still_outranks_completion() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_resolver(definitive_resolver_failure())
            .cancelling_after_resolver();
        let result = run_diagnostic(
            parse_request("example.com", None).expect("valid request"),
            &io,
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(result, DiagnosticResult::Cancelled(_)));
    }

    #[tokio::test]
    async fn resource_exhaustion_is_an_execution_error_not_a_network_result() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_tcp([TcpAttemptResult::ResourceExhausted]);
        let result = run_diagnostic(
            parse_request("203.0.113.10", Some("443")).expect("valid request"),
            &io,
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(
            result,
            DiagnosticResult::ExecutionError(ExecutionError {
                kind: ExecutionErrorKind::ResourceExhausted,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn wrong_path_attempt_outcome_is_an_execution_error() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([Some(AttemptOutcome::Dns(dns_response()))]);
        let result = run_diagnostic(
            parse_request("203.0.113.10", Some("443")).expect("valid request"),
            &io,
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(
            result,
            DiagnosticResult::ExecutionError(ExecutionError {
                kind: ExecutionErrorKind::InternalFailure,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn one_required_branch_error_cannot_be_hidden_by_another_target_success() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_resolver(resolver_success(vec![
                TargetIp::v4(Ipv4Addr::new(203, 0, 113, 1)),
                TargetIp::v4(Ipv4Addr::new(203, 0, 113, 2)),
            ]))
            .with_tcp([connected()])
            .with_tcp_errors([DiagnosticIoErrorKind::Internal]);
        let result = run_diagnostic(
            parse_request("example.com", Some("443")).expect("valid request"),
            &io,
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(
            result,
            DiagnosticResult::ExecutionError(ExecutionError {
                kind: ExecutionErrorKind::InternalFailure,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn cancelled_io_never_wraps_partial_work_as_completed() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_tcp_errors([DiagnosticIoErrorKind::Cancelled]);
        let result = run_diagnostic(
            parse_request("203.0.113.10", Some("443")).expect("valid request"),
            &io,
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(result, DiagnosticResult::Cancelled(_)));
    }

    #[tokio::test]
    async fn target_icmp_is_optional_for_port_diagnosis_but_required_without_a_port() {
        let port_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp_errors([DiagnosticIoErrorKind::RequiredCapabilityUnavailable]);
        let port_result = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &port_io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            port_result.targets[0].conclusion,
            Conclusion::TcpConnectTimedOut
        );
        assert_eq!(
            port_result.targets[0].diagnostic_conclusions,
            vec![Conclusion::CapabilityLimited]
        );

        let address_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_icmp_errors([DiagnosticIoErrorKind::RequiredCapabilityUnavailable]);
        let address_result = run_diagnostic(
            parse_request("203.0.113.10", None).expect("valid request"),
            &address_io,
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(
            address_result,
            DiagnosticResult::ExecutionError(ExecutionError {
                kind: ExecutionErrorKind::RequiredCapabilityUnavailable,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn missing_next_hop_icmp_only_limits_depth() {
        let io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_neighbor_states([NeighborState::Usable, NeighborState::Usable])
            .with_icmp([IcmpAttemptResult::Timeout, IcmpAttemptResult::Timeout])
            .with_icmp_errors([DiagnosticIoErrorKind::RequiredCapabilityUnavailable]);
        let result = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &io,
                &CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(
            result.targets[0].primary_outcome,
            PrimaryOutcome::Indeterminate
        );
        assert_eq!(
            result.targets[0].diagnostic_conclusions,
            vec![Conclusion::CapabilityLimited]
        );
        assert_eq!(io.path_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn every_state_machine_operation_receives_the_exact_fixed_product_budget() {
        let port_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_tcp([TcpAttemptResult::Timeout, TcpAttemptResult::Timeout])
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([None]);
        let _ = completed(
            run_diagnostic(
                parse_request("203.0.113.10", Some("443")).expect("valid request"),
                &port_io,
                &CancellationToken::new(),
            )
            .await,
        );
        {
            let tcp_operations = port_io
                .tcp_operations
                .lock()
                .expect("test TCP operation log");
            assert_eq!(tcp_operations.len(), 2);
            assert!(
                tcp_operations.iter().all(
                    |operation| operation.budget == TCP_CONNECT_BUDGET && operation.port == 443
                )
            );
            let icmp_operations = port_io
                .icmp_operations
                .lock()
                .expect("test ICMP operation log");
            assert_eq!(icmp_operations.len(), 3);
            assert!(icmp_operations[..2].iter().all(|operation| {
                operation.budget == TARGET_ICMP_BUDGET
                    && matches!(operation.subject, IcmpEchoSubject::Target(_))
            }));
            assert_eq!(icmp_operations[2].budget, NEXT_HOP_ICMP_BUDGET);
            assert!(matches!(
                icmp_operations[2].subject,
                IcmpEchoSubject::NextHop(_)
            ));
            let path_operations = port_io
                .path_operations
                .lock()
                .expect("test path operation log");
            assert_eq!(path_operations.len(), 1);
            assert!(path_operations[0].0);
            assert_eq!(path_operations[0].1.hop_limit, 1);
            assert_eq!(path_operations[0].1.budget, PATH_ATTEMPT_BUDGET);
        }

        let address_io = ScriptedIo::new(snapshot(Some(RouteBehavior::Unicast)))
            .with_remote_path()
            .with_icmp([
                IcmpAttemptResult::Timeout,
                IcmpAttemptResult::Timeout,
                icmp_message(IcmpMessageKind::EchoReply, Ipv4Addr::new(192, 0, 2, 1)),
            ])
            .with_path([None]);
        let _ = completed(
            run_diagnostic(
                parse_request("203.0.113.10", None).expect("valid request"),
                &address_io,
                &CancellationToken::new(),
            )
            .await,
        );
        {
            let address_path_operations = address_io
                .path_operations
                .lock()
                .expect("test address path operation log");
            assert_eq!(address_path_operations.len(), 1);
            assert!(!address_path_operations[0].0);
            assert_eq!(address_path_operations[0].1.hop_limit, 1);
            assert_eq!(address_path_operations[0].1.budget, PATH_ATTEMPT_BUDGET);
        }

        let dns_io = ScriptedIo::new(with_dns_resolver(snapshot(Some(RouteBehavior::Unicast))))
            .with_resolver(resolver_failure());
        dns_io.push_udp(
            DnsQueryType::A,
            &[DnsAttemptResult::Timeout, DnsAttemptResult::Timeout],
        );
        dns_io.push_udp(
            DnsQueryType::Aaaa,
            &[DnsAttemptResult::Timeout, DnsAttemptResult::Timeout],
        );
        dns_io.push_dns_tcp(DnsQueryType::A, &[dns_response()]);
        dns_io.push_dns_tcp(DnsQueryType::Aaaa, &[dns_response()]);
        let _ = completed(
            run_diagnostic(
                parse_request("example.com", None).expect("valid request"),
                &dns_io,
                &CancellationToken::new(),
            )
            .await,
        );
        let udp_operations = dns_io
            .dns_udp_operations
            .lock()
            .expect("test UDP DNS operation log");
        assert_eq!(udp_operations.len(), 4);
        assert!(
            udp_operations
                .iter()
                .all(|operation| operation.budget == DNS_UDP_BUDGET)
        );
        let tcp_dns_operations = dns_io
            .dns_tcp_operations
            .lock()
            .expect("test TCP DNS operation log");
        assert_eq!(tcp_dns_operations.len(), 2);
        assert!(
            tcp_dns_operations
                .iter()
                .all(|operation| operation.budget == DNS_TCP_BUDGET)
        );
    }
}
