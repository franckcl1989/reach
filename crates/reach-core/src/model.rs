use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use ipnet::IpNet;

use crate::{CapabilityValue, Provenance};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl From<IpAddr> for AddressFamily {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceId {
    pub index: u32,
    /// A platform stable identity when the numeric index alone is not enough
    /// to detect replacement during a diagnostic run.
    pub stable_id: Option<String>,
}

impl InterfaceId {
    #[must_use]
    pub const fn from_index(index: u32) -> Self {
        Self {
            index,
            stable_id: None,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TargetIp {
    pub address: IpAddr,
    pub scope: Option<InterfaceId>,
}

impl TargetIp {
    #[must_use]
    pub const fn v4(address: Ipv4Addr) -> Self {
        Self {
            address: IpAddr::V4(address),
            scope: None,
        }
    }

    #[must_use]
    pub const fn v6(address: Ipv6Addr, scope: Option<InterfaceId>) -> Self {
        Self {
            address: IpAddr::V6(address),
            scope,
        }
    }

    #[must_use]
    pub fn family(&self) -> AddressFamily {
        self.address.into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormalTarget {
    pub target: TargetIp,
    pub resolver_ordinal: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverAddressSet {
    /// Exact addresses returned by the system resolver, including duplicates.
    pub raw_addresses: Vec<TargetIp>,
    /// Stable-deduplicated targets; the first occurrence defines the order.
    pub formal_targets: Vec<FormalTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemResolverFailureKind {
    DefinitiveNoName,
    Temporary,
    Timeout,
    ResolverFailure,
    OtherPlatformFailure,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemResolverFailure {
    pub kind: SystemResolverFailureKind,
    pub platform_code: Option<i32>,
    pub platform_message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SystemResolverResult {
    Succeeded(ResolverAddressSet),
    Failed(SystemResolverFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemResolverObservation {
    pub started_at: Duration,
    pub completed_at: Duration,
    pub result: SystemResolverResult,
    pub provenance: Provenance,
}

impl ResolverAddressSet {
    #[must_use]
    pub fn from_raw(raw_addresses: Vec<TargetIp>) -> Self {
        let formal_targets = stable_deduplicate_targets(&raw_addresses);
        Self {
            raw_addresses,
            formal_targets,
        }
    }
}

#[must_use]
pub fn stable_deduplicate_targets(raw: &[TargetIp]) -> Vec<FormalTarget> {
    let mut seen = HashSet::with_capacity(raw.len());
    let mut targets = Vec::with_capacity(raw.len());
    for (ordinal, target) in raw.iter().enumerate() {
        if seen.insert(target.clone()) {
            targets.push(FormalTarget {
                target: target.clone(),
                resolver_ordinal: Some(ordinal),
            });
        }
    }
    targets
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceState {
    Up,
    Down,
    Dormant,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceAddress {
    pub network: IpNet,
    pub scope_id: Option<u32>,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceFact {
    pub id: InterfaceId,
    pub system_name: String,
    pub display_name: String,
    pub administrative_state: InterfaceState,
    pub operational_state: InterfaceState,
    pub is_loopback: bool,
    pub addresses: Vec<InterfaceAddress>,
    pub provenance: Provenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteBehavior {
    Unicast,
    Local,
    Broadcast,
    Multicast,
    Reject,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteFact {
    pub destination: IpNet,
    pub next_hop: Option<IpAddr>,
    pub egress_interface: Option<InterfaceId>,
    pub behavior: RouteBehavior,
    pub metric: Option<u64>,
    pub table_or_compartment: Option<u64>,
    pub preferred_source: Option<IpAddr>,
    /// ECMP weight when this fact represents one leg of a multipath route.
    pub multipath_weight: Option<u16>,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathSelectionFact {
    pub family: AddressFamily,
    pub priority: Option<u64>,
    pub table_or_domain: Option<u64>,
    pub description: String,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingPolicyFacts {
    pub facts: Vec<PathSelectionFact>,
    /// True only when the captured facts are sufficient for Core to reproduce
    /// the relevant static policy decision without guessing.
    pub static_selection_complete: bool,
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverTransport {
    Udp,
    Tcp,
    Tls,
    Https,
    SystemPrivate,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverEndpoint {
    pub address: IpAddr,
    pub port: u16,
    pub transport: ResolverTransport,
    pub interface: Option<InterfaceId>,
    pub domains: Vec<String>,
    pub priority: Option<u64>,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverConfiguration {
    pub endpoints: Vec<ResolverEndpoint>,
    pub search_domains: Vec<String>,
    pub non_dns_sources: Vec<String>,
    /// Whether the captured name-resolution source policy proves that classic
    /// DNS endpoints can participate at all. This does not prove which
    /// endpoint, query name, or transport the system resolver actually used.
    pub dns_protocol_candidates_applicable: CapabilityValue<bool>,
    pub ordering_is_semantic: bool,
    /// Explicitly records exposed facts that the selected platform APIs cannot
    /// represent completely. Partial data must never masquerade as complete.
    pub limitations: Vec<String>,
    pub provenance: Provenance,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SnapshotInconsistencyScope {
    PathSelection,
    ResolverSelection,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotInconsistency {
    pub scope: SnapshotInconsistencyScope,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialNetworkSnapshot {
    pub capture_started_at: Duration,
    pub capture_completed_at: Duration,
    pub interfaces: CapabilityValue<Vec<InterfaceFact>>,
    pub routes_v4: CapabilityValue<Vec<RouteFact>>,
    pub routes_v6: CapabilityValue<Vec<RouteFact>>,
    pub routing_policy_facts: CapabilityValue<RoutingPolicyFacts>,
    pub resolver_configuration: CapabilityValue<ResolverConfiguration>,
    pub inconsistencies: Vec<SnapshotInconsistency>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathRelation {
    Local,
    OnLink,
    Remote,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPathContext {
    pub captured_at: Duration,
    pub target_or_dependency: IpAddr,
    pub family: AddressFamily,
    pub egress_interface: Option<InterfaceId>,
    pub relation: PathRelation,
    pub next_hop: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub relation_to_initial_snapshot: Option<String>,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NeighborIdentity {
    pub family: AddressFamily,
    pub interface: InterfaceId,
    pub address: IpAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborState {
    Resolving,
    Usable,
    TerminalFailure,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighborFact {
    pub identity: NeighborIdentity,
    pub state: NeighborState,
    pub observed_at: Duration,
    pub raw_state: Option<String>,
    pub provenance: Provenance,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttemptId(pub u64);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum AttemptSubject {
    Target(TargetIp),
    NextHop(NeighborIdentity),
    Resolver {
        endpoint: SocketAddr,
        query_name: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsQueryType {
    A,
    Aaaa,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptKind {
    TcpConnect,
    TargetIcmpEcho,
    NextHopIcmpEcho,
    TcpPath { hop_limit: u8 },
    IcmpPath { hop_limit: u8 },
    DnsUdp { query_type: DnsQueryType },
    DnsTcp { query_type: DnsQueryType },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptTiming {
    pub started_at: Duration,
    pub deadline_at: Duration,
    pub completed_at: Duration,
}

impl AttemptTiming {
    #[must_use]
    pub fn duration(self) -> Duration {
        self.completed_at.saturating_sub(self.started_at)
    }

    #[must_use]
    pub fn completed_within_deadline(self) -> bool {
        self.completed_at < self.deadline_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpEndpoint {
    pub address: IpAddr,
    pub port: u16,
    pub scope_id: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpAttemptResult {
    Connected {
        local: CapabilityValue<IpEndpoint>,
        remote: CapabilityValue<IpEndpoint>,
    },
    ConnectionRefused,
    NoRoute,
    NetworkUnreachable,
    HostUnreachable,
    PermissionDenied,
    ResourceExhausted,
    OtherExplicitError {
        os_code: Option<i32>,
    },
    Timeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpMessageKind {
    EchoReply,
    DestinationUnreachable,
    TimeExceeded,
    PacketTooBig,
    ParameterProblem,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpMessageObservation {
    pub kind: IcmpMessageKind,
    pub responder: IpAddr,
    pub raw_type: Option<u16>,
    pub raw_code: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IcmpAttemptResult {
    Message {
        kind: IcmpMessageKind,
        responder: IpAddr,
        raw_type: Option<u16>,
        raw_code: Option<u16>,
    },
    /// Multiple responses reliably correlated to the same path Attempt. This
    /// preserves responder identities without interpreting why they differ.
    Messages(Vec<IcmpMessageObservation>),
    ExplicitNetworkError {
        os_code: Option<i32>,
    },
    Timeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsAttemptResult {
    Response {
        response_code: u16,
        addresses: Vec<IpAddr>,
        aliases: Vec<String>,
        truncated: bool,
    },
    TransportError {
        os_code: Option<i32>,
    },
    ProtocolError,
    Timeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    Tcp(TcpAttemptResult),
    Icmp(IcmpAttemptResult),
    Dns(DnsAttemptResult),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    pub id: AttemptId,
    pub subject: AttemptSubject,
    pub kind: AttemptKind,
    pub timing: AttemptTiming,
    pub outcome: AttemptOutcome,
    pub provenance: Provenance,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn stable_dedup_keeps_raw_facts_and_first_occurrence_order() {
        let first = TargetIp::v4(Ipv4Addr::new(192, 0, 2, 1));
        let second = TargetIp::v6(Ipv6Addr::LOCALHOST, None);
        let raw = vec![first.clone(), second.clone(), first.clone()];
        let set = ResolverAddressSet::from_raw(raw.clone());

        assert_eq!(set.raw_addresses, raw);
        assert_eq!(set.formal_targets.len(), 2);
        assert_eq!(set.formal_targets[0].target, first);
        assert_eq!(set.formal_targets[0].resolver_ordinal, Some(0));
        assert_eq!(set.formal_targets[1].target, second);
        assert_eq!(set.formal_targets[1].resolver_ordinal, Some(1));
    }

    #[test]
    fn scoped_and_unscoped_ipv6_are_different_target_identities() {
        let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let raw = vec![
            TargetIp::v6(address, Some(InterfaceId::from_index(2))),
            TargetIp::v6(address, Some(InterfaceId::from_index(3))),
            TargetIp::v6(address, Some(InterfaceId::from_index(2))),
        ];

        let unique = stable_deduplicate_targets(&raw);
        assert_eq!(unique.len(), 2);
        assert_eq!(unique[0].resolver_ordinal, Some(0));
        assert_eq!(unique[1].resolver_ordinal, Some(1));
    }

    #[test]
    fn exact_deadline_boundary_is_not_classified_as_within_the_attempt() {
        let at_boundary = AttemptTiming {
            started_at: Duration::ZERO,
            deadline_at: Duration::from_secs(1),
            completed_at: Duration::from_secs(1),
        };
        let before_boundary = AttemptTiming {
            completed_at: Duration::from_millis(999),
            ..at_boundary
        };

        assert!(!at_boundary.completed_within_deadline());
        assert!(before_boundary.completed_within_deadline());
    }

    proptest! {
        #[test]
        fn stable_target_dedup_is_idempotent_and_keeps_first_occurrence(
            raw in prop::collection::vec(any::<u32>(), 0..128),
        ) {
            let targets: Vec<_> = raw
                .iter()
                .map(|value| TargetIp::v4(Ipv4Addr::from(*value)))
                .collect();
            let first = stable_deduplicate_targets(&targets);
            let once: Vec<_> = first.iter().map(|item| item.target.clone()).collect();
            let twice = stable_deduplicate_targets(&once);
            prop_assert_eq!(
                twice.iter().map(|item| &item.target).collect::<Vec<_>>(),
                first.iter().map(|item| &item.target).collect::<Vec<_>>(),
            );
            for item in &first {
                prop_assert_eq!(
                    targets.iter().position(|target| target == &item.target),
                    item.resolver_ordinal,
                );
            }
        }
    }
}
