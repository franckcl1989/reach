//! Platform-independent contracts and deterministic diagnostic semantics.

#![forbid(unsafe_code)]

mod capability;
mod engine;
mod formation;
mod input;
mod io;
mod model;
mod path;
mod policy;
mod result;

pub use capability::{CapabilityReason, CapabilityValue, Provenance, ProvenanceSource};
pub use engine::run_diagnostic;
pub use formation::{ScopeBindingError, bind_diagnostic_request, form_literal_target};
pub use input::{
    BoundAddressInput, DiagnosticRequest, Hostname, InputError, ParsedAddress, ParsedRequest,
    ScopeSyntax, parse_request,
};
pub use io::{
    DiagnosticIo, DiagnosticIoError, DiagnosticIoErrorKind, DirectDnsOperation,
    DirectDnsTransportReason, IcmpEchoSubject, IcmpOperation, PathOperation, TcpOperation,
};
pub use model::{
    AddressFamily, Attempt, AttemptId, AttemptKind, AttemptOutcome, AttemptSubject, AttemptTiming,
    DnsAttemptResult, DnsExchangeObservation, DnsExchangeOutcome, DnsExchangePurpose,
    DnsExchangeTransport, DnsQueryType, DnsResponseCode, FormalTarget, IcmpAttemptResult,
    IcmpMessageKind, IcmpMessageObservation, IcmpNativeStatus, InitialNetworkSnapshot,
    InterfaceAddress, InterfaceFact, InterfaceId, InterfaceState, IpEndpoint,
    NameResolutionObservation, NameResolutionSource, NameResolutionStep, NameResolutionStepOutcome,
    NeighborFact, NeighborIdentity, NeighborState, OperationPathContext, PathRelation,
    PathSelectionFact, ResolverAddressSet, ResolverConfiguration, ResolverEndpoint,
    ResolverTransport, RouteBehavior, RouteFact, RoutingPolicyFacts, SnapshotInconsistency,
    SnapshotInconsistencyScope, SystemResolverFailure, SystemResolverFailureKind,
    SystemResolverObservation, SystemResolverResult, TargetIp, TcpAttemptResult,
    stable_deduplicate_targets,
};
pub use path::{
    InitialPathAnalysis, InitialPathStatus, NeighborDependency, analyze_initial_path,
    neighbor_dependency_for_path, reconcile_current_operation_path,
};
pub use policy::{
    DNS_TCP_BUDGET, DNS_UDP_BUDGET, MAX_ACTIVE_RESOLVERS, MAX_ACTIVE_TARGETS, MAX_PATH_HOP_LIMIT,
    NEIGHBOR_CONVERGENCE_BUDGET, NEIGHBOR_POLL_INTERVAL, NEXT_HOP_ICMP_BUDGET, PATH_ATTEMPT_BUDGET,
    TARGET_ICMP_BUDGET, TCP_CONNECT_BUDGET,
};
pub use result::{
    AggregateOutcome, Cancelled, CompletedDiagnostic, Conclusion, DiagnosticResult,
    DnsExchangeEvidence, Evidence, EvidenceFact, EvidenceId, EvidenceRole, EvidenceSubject,
    ExecutionError, ExecutionErrorKind, ExitStatus, HostnameResolutionOutcome,
    NameResolutionEvidence, NameResolutionEvidenceOutcome, NeighborObservation, PrimaryOutcome,
    ResolverDependencyDiagnostic, TargetDiagnostic, TargetNetworkFacts, select_key_evidence,
};
