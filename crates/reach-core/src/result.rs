use crate::{
    Attempt, AttemptId, CapabilityReason, CapabilityValue, InitialNetworkSnapshot,
    InitialPathAnalysis, NeighborFact, NeighborIdentity, OperationPathContext, ParsedRequest,
    ResolverAddressSet, ResolverEndpoint, SystemResolverObservation, TargetIp,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimaryOutcome {
    Satisfied,
    SatisfiedWithAnomaly,
    NotSatisfied,
    Indeterminate,
}

impl PrimaryOutcome {
    #[must_use]
    pub const fn is_cleanly_satisfied(self) -> bool {
        matches!(self, Self::Satisfied)
    }

    #[must_use]
    pub const fn is_eventually_satisfied(self) -> bool {
        matches!(self, Self::Satisfied | Self::SatisfiedWithAnomaly)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Conclusion {
    TcpConnectSucceeded,
    TcpConnectSucceededAfterTimeout,
    TcpConnectionRefused,
    TcpExplicitFailure,
    TcpConnectTimedOut,
    TcpTimedOutButTargetIcmpResponded,
    TcpTimedOutWithExplicitIcmpResult,
    IcmpEchoReplied,
    IcmpEchoRepliedAfterTimeout,
    IcmpExplicitFailure,
    IcmpEchoTimedOut,
    IcmpResponseIndeterminate,
    DefinitiveNoPath,
    NeighborResolutionFailed,
    NeighborResolutionIndeterminate,
    FirstHopResponded,
    MultiplePathRespondersObserved,
    PathEndpointResponded,
    PathExplicitlyTerminated,
    PathResponseIndeterminate,
    PathLimitReachedWithoutEndpointEvidence,
    HostnameResolved,
    HostnameNoFormalTargets,
    HostnameResolutionDefinitiveNegative,
    HostnameResolutionIndeterminate,
    AllTargetsSatisfied,
    TargetsSatisfiedWithAnomaly,
    TargetResultsMixed,
    NoTargetCleanlySatisfied,
    CapabilityLimited,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceSubject {
    Run,
    Hostname,
    Target(TargetIp),
    Neighbor(NeighborIdentity),
    Resolver(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRole {
    /// Directly establishes the primary outcome.
    PrimaryDecision,
    /// The first anomaly or later attempt that changes the observation.
    AnomalyHistory,
    /// Narrows a failure boundary without rewriting the primary outcome.
    BoundaryNarrowing,
    /// Explains why the failure boundary cannot be narrowed further.
    CapabilityLimitation,
    /// Retained internally but omitted from default key evidence.
    Context,
}

impl EvidenceRole {
    const fn key_priority(self) -> Option<u8> {
        match self {
            Self::PrimaryDecision => Some(0),
            Self::AnomalyHistory => Some(1),
            Self::BoundaryNarrowing => Some(2),
            Self::CapabilityLimitation => Some(3),
            Self::Context => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceFact {
    Attempt(AttemptId),
    InitialPath(String),
    CurrentPath(String),
    NeighborTransition {
        before: NeighborObservation,
        after: crate::NeighborState,
    },
    SystemResolverResult(String),
    DirectDnsResult(String),
    CapabilityUnavailable {
        capability: String,
        reason: CapabilityReason,
    },
    SnapshotInconsistency(String),
    SocketPathComparison(String),
}

/// Whether the pre-operation Neighbor fact was sampled and what that sample
/// could prove. This keeps a skipped read distinct from an observed absence or
/// a capability boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborObservation {
    NotSampled,
    Observed(crate::NeighborState),
    Unknown,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub id: EvidenceId,
    pub subject: EvidenceSubject,
    pub role: EvidenceRole,
    pub fact: EvidenceFact,
}

/// Applies the first deterministic evidence rule shared by all state machines.
/// Evidence IDs are allocated from formal target/dependency order, never task
/// completion order.
#[must_use]
pub fn select_key_evidence(evidence: &[Evidence]) -> Vec<Evidence> {
    let mut selected: Vec<_> = evidence
        .iter()
        .filter(|item| item.role.key_priority().is_some())
        .cloned()
        .collect();
    selected.sort_by_key(|item| (item.role.key_priority().unwrap_or(u8::MAX), item.id));
    selected
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDiagnostic {
    pub target: TargetIp,
    pub resolver_ordinal: Option<usize>,
    pub primary_outcome: PrimaryOutcome,
    pub conclusion: Conclusion,
    /// Explanatory failure-boundary conclusions. These never rewrite the
    /// primary outcome or its history.
    pub diagnostic_conclusions: Vec<Conclusion>,
    pub network_facts: TargetNetworkFacts,
    /// Attempts stay in semantic attempt order and are never overwritten.
    pub attempts: Vec<Attempt>,
    pub evidence: Vec<Evidence>,
    pub key_evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetNetworkFacts {
    pub initial_path: InitialPathAnalysis,
    pub current_path: CapabilityValue<OperationPathContext>,
    /// `None` means the read was not sampled for this diagnostic path.
    pub neighbor_pre_state: Option<CapabilityValue<NeighborFact>>,
    /// `None` means the post-operation read was not sampled because the state
    /// machine did not require it.
    pub neighbor_post_state: Option<CapabilityValue<NeighborFact>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverDependencyDiagnostic {
    pub endpoint: ResolverEndpoint,
    pub network_facts: TargetNetworkFacts,
    pub attempts: Vec<Attempt>,
    pub evidence: Vec<Evidence>,
    pub key_evidence: Vec<Evidence>,
}

impl ResolverDependencyDiagnostic {
    #[must_use]
    pub fn new(
        endpoint: ResolverEndpoint,
        network_facts: TargetNetworkFacts,
        attempts: Vec<Attempt>,
        evidence: Vec<Evidence>,
    ) -> Self {
        let key_evidence = select_key_evidence(&evidence);
        Self {
            endpoint,
            network_facts,
            attempts,
            evidence,
            key_evidence,
        }
    }
}

impl TargetDiagnostic {
    #[must_use]
    pub fn new(
        target: TargetIp,
        resolver_ordinal: Option<usize>,
        primary_outcome: PrimaryOutcome,
        conclusion: Conclusion,
        network_facts: TargetNetworkFacts,
        attempts: Vec<Attempt>,
        evidence: Vec<Evidence>,
    ) -> Self {
        let key_evidence = select_key_evidence(&evidence);
        Self {
            target,
            resolver_ordinal,
            primary_outcome,
            conclusion,
            diagnostic_conclusions: Vec::new(),
            network_facts,
            attempts,
            evidence,
            key_evidence,
        }
    }

    #[must_use]
    pub fn with_diagnostic_conclusions(mut self, conclusions: Vec<Conclusion>) -> Self {
        self.diagnostic_conclusions = conclusions;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostnameResolutionOutcome {
    NotRequested,
    Succeeded(ResolverAddressSet),
    SucceededWithoutUsableAddress,
    DefinitiveNegative {
        platform_code: Option<i32>,
    },
    NonDefinitiveFailure {
        platform_code: Option<i32>,
        direct_dns_was_diagnostic_only: bool,
    },
}

impl HostnameResolutionOutcome {
    #[must_use]
    pub const fn formed_targets(&self) -> bool {
        match self {
            Self::NotRequested => true,
            Self::Succeeded(addresses) => !addresses.formal_targets.is_empty(),
            Self::SucceededWithoutUsableAddress
            | Self::DefinitiveNegative { .. }
            | Self::NonDefinitiveFailure { .. } => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateOutcome {
    AllSatisfied,
    SatisfiedWithAnomaly,
    Mixed,
    NoneCleanlySatisfied,
    NoFormalTargets,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedDiagnostic {
    pub request: ParsedRequest,
    pub initial_snapshot: InitialNetworkSnapshot,
    pub system_resolver: Option<SystemResolverObservation>,
    pub hostname_resolution: HostnameResolutionOutcome,
    pub aggregate_outcome: AggregateOutcome,
    pub conclusion: Conclusion,
    pub targets: Vec<TargetDiagnostic>,
    pub resolver_diagnostics: Vec<ResolverDependencyDiagnostic>,
    pub evidence: Vec<Evidence>,
    pub key_evidence: Vec<Evidence>,
}

impl CompletedDiagnostic {
    #[must_use]
    pub fn new(
        request: ParsedRequest,
        initial_snapshot: InitialNetworkSnapshot,
        system_resolver: Option<SystemResolverObservation>,
        hostname_resolution: HostnameResolutionOutcome,
        mut targets: Vec<TargetDiagnostic>,
        resolver_diagnostics: Vec<ResolverDependencyDiagnostic>,
        run_evidence: Vec<Evidence>,
    ) -> Self {
        // Resolver order is semantic. IP-literal diagnostics keep their sole
        // target in place.
        targets.sort_by_key(|target| target.resolver_ordinal.unwrap_or(0));

        let aggregate_outcome = aggregate(&hostname_resolution, &targets);
        let conclusion = match aggregate_outcome {
            AggregateOutcome::AllSatisfied => Conclusion::AllTargetsSatisfied,
            AggregateOutcome::SatisfiedWithAnomaly => Conclusion::TargetsSatisfiedWithAnomaly,
            AggregateOutcome::Mixed => Conclusion::TargetResultsMixed,
            AggregateOutcome::NoneCleanlySatisfied => Conclusion::NoTargetCleanlySatisfied,
            AggregateOutcome::NoFormalTargets => match &hostname_resolution {
                HostnameResolutionOutcome::DefinitiveNegative { .. } => {
                    Conclusion::HostnameResolutionDefinitiveNegative
                }
                HostnameResolutionOutcome::NonDefinitiveFailure { .. } => {
                    Conclusion::HostnameResolutionIndeterminate
                }
                HostnameResolutionOutcome::SucceededWithoutUsableAddress
                | HostnameResolutionOutcome::NotRequested
                | HostnameResolutionOutcome::Succeeded(_) => Conclusion::HostnameNoFormalTargets,
            },
        };

        let mut aggregate_candidates = run_evidence.clone();
        let mut represented_results = Vec::<(PrimaryOutcome, Conclusion, Vec<Conclusion>)>::new();
        for target in &targets {
            let result_identity = (
                target.primary_outcome,
                target.conclusion.clone(),
                target.diagnostic_conclusions.clone(),
            );
            if represented_results.contains(&result_identity) {
                continue;
            }
            represented_results.push(result_identity);
            aggregate_candidates.extend(target.key_evidence.iter().cloned());
        }
        let key_evidence = select_key_evidence(&aggregate_candidates);

        let mut evidence = run_evidence;
        for target in &targets {
            evidence.extend(target.evidence.iter().cloned());
        }

        Self {
            request,
            initial_snapshot,
            system_resolver,
            hostname_resolution,
            aggregate_outcome,
            conclusion,
            targets,
            resolver_diagnostics,
            evidence,
            key_evidence,
        }
    }

    #[must_use]
    pub const fn exit_status(&self) -> ExitStatus {
        if matches!(self.aggregate_outcome, AggregateOutcome::AllSatisfied) {
            ExitStatus::Success
        } else {
            ExitStatus::DiagnosticNonSuccess
        }
    }
}

fn aggregate(
    hostname_resolution: &HostnameResolutionOutcome,
    targets: &[TargetDiagnostic],
) -> AggregateOutcome {
    if !hostname_resolution.formed_targets() || targets.is_empty() {
        return AggregateOutcome::NoFormalTargets;
    }

    if targets
        .iter()
        .all(|target| target.primary_outcome.is_cleanly_satisfied())
    {
        return AggregateOutcome::AllSatisfied;
    }

    if targets
        .iter()
        .all(|target| target.primary_outcome.is_eventually_satisfied())
    {
        return AggregateOutcome::SatisfiedWithAnomaly;
    }

    let first = targets[0].primary_outcome;
    if targets.iter().any(|target| target.primary_outcome != first) {
        AggregateOutcome::Mixed
    } else {
        AggregateOutcome::NoneCleanlySatisfied
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionErrorKind {
    InvalidInput,
    ScopedIpv6BindingFailed,
    RequiredCapabilityUnavailable,
    ResourceExhausted,
    InternalFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionError {
    pub kind: ExecutionErrorKind,
    pub safe_message: String,
    pub partial_evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cancelled {
    pub safe_message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticResult {
    Completed(Box<CompletedDiagnostic>),
    ExecutionError(ExecutionError),
    Cancelled(Cancelled),
}

impl DiagnosticResult {
    #[must_use]
    pub const fn exit_status(&self) -> ExitStatus {
        match self {
            Self::Completed(completed) => completed.exit_status(),
            Self::ExecutionError(_) => ExitStatus::ExecutionError,
            Self::Cancelled(_) => ExitStatus::Cancelled,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExitStatus {
    Success = 0,
    DiagnosticNonSuccess = 1,
    ExecutionError = 2,
    Cancelled = 130,
}

impl ExitStatus {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use crate::{
        CapabilityReason, InterfaceFact, ParsedAddress, Provenance, ProvenanceSource,
        ResolverConfiguration, RouteFact, analyze_initial_path, parse_request,
    };

    use super::*;

    fn target(outcome: PrimaryOutcome, ordinal: usize) -> TargetDiagnostic {
        let target = TargetIp::v4(Ipv4Addr::new(192, 0, 2, ordinal as u8 + 1));
        let snapshot = snapshot();
        let provenance = provenance();
        TargetDiagnostic::new(
            target.clone(),
            Some(ordinal),
            outcome,
            match outcome {
                PrimaryOutcome::Satisfied => Conclusion::TcpConnectSucceeded,
                PrimaryOutcome::SatisfiedWithAnomaly => Conclusion::TcpConnectSucceededAfterTimeout,
                PrimaryOutcome::NotSatisfied => Conclusion::TcpConnectTimedOut,
                PrimaryOutcome::Indeterminate => Conclusion::IcmpResponseIndeterminate,
            },
            TargetNetworkFacts {
                initial_path: analyze_initial_path(&snapshot, &target),
                current_path: CapabilityValue::unavailable(
                    CapabilityReason::QuerySemanticsUnavailable,
                    provenance,
                ),
                neighbor_pre_state: None,
                neighbor_post_state: None,
            },
            Vec::new(),
            vec![Evidence {
                id: EvidenceId(100 + ordinal as u64),
                subject: EvidenceSubject::Target(target),
                role: EvidenceRole::PrimaryDecision,
                fact: EvidenceFact::Attempt(AttemptId(100 + ordinal as u64)),
            }],
        )
    }

    fn provenance() -> Provenance {
        Provenance::new(ProvenanceSource::SyntheticTest).at(Duration::ZERO)
    }

    fn snapshot() -> InitialNetworkSnapshot {
        let provenance = provenance();
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
            routing_policy_facts: CapabilityValue::<crate::RoutingPolicyFacts>::unavailable(
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

    fn completed(
        hostname_resolution: HostnameResolutionOutcome,
        targets: Vec<TargetDiagnostic>,
    ) -> CompletedDiagnostic {
        CompletedDiagnostic::new(
            hostname_request(),
            snapshot(),
            None,
            hostname_resolution,
            targets,
            Vec::new(),
            Vec::new(),
        )
    }

    fn hostname_request() -> ParsedRequest {
        let request = parse_request("example.com", Some("443")).expect("valid request");
        assert!(matches!(request.address, ParsedAddress::Hostname(_)));
        request
    }

    fn successful_resolution(count: usize) -> HostnameResolutionOutcome {
        let addresses = (0..count)
            .map(|ordinal| TargetIp::v4(Ipv4Addr::new(192, 0, 2, ordinal as u8 + 1)))
            .collect();
        HostnameResolutionOutcome::Succeeded(ResolverAddressSet::from_raw(addresses))
    }

    #[test]
    fn only_all_clean_targets_return_zero() {
        let completed = completed(
            successful_resolution(2),
            vec![
                target(PrimaryOutcome::Satisfied, 0),
                target(PrimaryOutcome::Satisfied, 1),
            ],
        );
        assert_eq!(completed.aggregate_outcome, AggregateOutcome::AllSatisfied);
        assert_eq!(completed.exit_status(), ExitStatus::Success);
    }

    #[test]
    fn retry_success_is_not_clean_success() {
        let completed = completed(
            successful_resolution(1),
            vec![target(PrimaryOutcome::SatisfiedWithAnomaly, 0)],
        );
        assert_eq!(
            completed.aggregate_outcome,
            AggregateOutcome::SatisfiedWithAnomaly
        );
        assert_eq!(completed.exit_status(), ExitStatus::DiagnosticNonSuccess);
    }

    #[test]
    fn mixed_target_results_are_preserved() {
        let completed = completed(
            successful_resolution(2),
            vec![
                target(PrimaryOutcome::NotSatisfied, 1),
                target(PrimaryOutcome::Satisfied, 0),
            ],
        );
        assert_eq!(completed.aggregate_outcome, AggregateOutcome::Mixed);
        assert_eq!(completed.targets[0].resolver_ordinal, Some(0));
        assert_eq!(completed.targets[1].resolver_ordinal, Some(1));
        assert_eq!(completed.exit_status(), ExitStatus::DiagnosticNonSuccess);
    }

    #[test]
    fn hostname_aggregate_selects_representatives_without_erasing_per_target_evidence() {
        let targets = (0..8)
            .map(|ordinal| target(PrimaryOutcome::Satisfied, ordinal))
            .collect::<Vec<_>>();
        let completed = completed(successful_resolution(8), targets);

        assert!(
            completed
                .targets
                .iter()
                .all(|target| target.key_evidence.len() == 1)
        );
        assert_eq!(
            completed
                .key_evidence
                .iter()
                .filter(|evidence| matches!(evidence.subject, EvidenceSubject::Target(_)))
                .count(),
            1
        );
        assert_eq!(completed.evidence.len(), 8);
    }

    #[test]
    fn empty_formal_target_set_never_uses_vacuous_success() {
        let completed = completed(
            HostnameResolutionOutcome::SucceededWithoutUsableAddress,
            Vec::new(),
        );
        assert_eq!(
            completed.aggregate_outcome,
            AggregateOutcome::NoFormalTargets
        );
        assert_eq!(completed.exit_status(), ExitStatus::DiagnosticNonSuccess);
    }

    #[test]
    fn key_evidence_selection_is_role_then_semantic_id() {
        let evidence = vec![
            Evidence {
                id: EvidenceId(8),
                subject: EvidenceSubject::Run,
                role: EvidenceRole::BoundaryNarrowing,
                fact: EvidenceFact::InitialPath("usable".into()),
            },
            Evidence {
                id: EvidenceId(9),
                subject: EvidenceSubject::Run,
                role: EvidenceRole::Context,
                fact: EvidenceFact::CurrentPath("unchanged".into()),
            },
            Evidence {
                id: EvidenceId(3),
                subject: EvidenceSubject::Run,
                role: EvidenceRole::PrimaryDecision,
                fact: EvidenceFact::Attempt(AttemptId(1)),
            },
            Evidence {
                id: EvidenceId(2),
                subject: EvidenceSubject::Run,
                role: EvidenceRole::AnomalyHistory,
                fact: EvidenceFact::Attempt(AttemptId(0)),
            },
        ];

        let selected = select_key_evidence(&evidence);
        assert_eq!(
            selected.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![EvidenceId(3), EvidenceId(2), EvidenceId(8)]
        );
    }

    #[test]
    fn cancellation_and_execution_error_outrank_completed_results() {
        let cancelled = DiagnosticResult::Cancelled(Cancelled {
            safe_message: "interrupted".into(),
        });
        let error = DiagnosticResult::ExecutionError(ExecutionError {
            kind: ExecutionErrorKind::InternalFailure,
            safe_message: "internal failure".into(),
            partial_evidence: Vec::new(),
        });
        assert_eq!(cancelled.exit_status(), ExitStatus::Cancelled);
        assert_eq!(error.exit_status(), ExitStatus::ExecutionError);
    }
}
