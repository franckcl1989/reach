use std::net::IpAddr;

use crate::{
    CapabilityValue, InitialNetworkSnapshot, InterfaceId, InterfaceState, PathRelation,
    RouteBehavior, RouteFact, SnapshotInconsistencyScope, TargetIp,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialPathStatus {
    UsablePath,
    DefinitiveNoPath,
    UnknownPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialPathAnalysis {
    pub target: TargetIp,
    pub status: InitialPathStatus,
    pub matching_routes: Vec<RouteFact>,
    pub egress_interface: Option<InterfaceId>,
    pub relation: PathRelation,
    pub next_hop: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NeighborDependency {
    NotApplicable,
    Known(crate::NeighborIdentity),
    Unknown { reason: String },
}

impl InitialPathAnalysis {
    fn unknown(target: &TargetIp, limitations: Vec<String>) -> Self {
        Self {
            target: target.clone(),
            status: InitialPathStatus::UnknownPath,
            matching_routes: Vec::new(),
            egress_interface: None,
            relation: PathRelation::Unknown,
            next_hop: None,
            preferred_source: None,
            limitations,
        }
    }
}

/// Conservatively analyzes the immutable initial snapshot. Any missing or
/// conflicting fact degrades to `UnknownPath`; only complete, internally
/// consistent evidence may suppress the real primary network operation.
#[must_use]
pub fn analyze_initial_path(
    snapshot: &InitialNetworkSnapshot,
    target: &TargetIp,
) -> InitialPathAnalysis {
    let mut limitations = snapshot
        .inconsistencies
        .iter()
        .filter(|item| item.scope == SnapshotInconsistencyScope::PathSelection)
        .map(|item| item.detail.clone())
        .collect::<Vec<_>>();
    if !limitations.is_empty() {
        limitations.push("snapshot inconsistency prevents a definitive path decision".into());
        return InitialPathAnalysis::unknown(target, limitations);
    }

    let routes = match target.address {
        IpAddr::V4(_) => {
            capability_value(&snapshot.routes_v4, "IPv4 route snapshot", &mut limitations)
        }
        IpAddr::V6(_) => {
            capability_value(&snapshot.routes_v6, "IPv6 route snapshot", &mut limitations)
        }
    };
    let Some(routes) = routes else {
        return InitialPathAnalysis::unknown(target, limitations);
    };
    let Some(policy) = capability_value(
        &snapshot.routing_policy_facts,
        "routing policy snapshot",
        &mut limitations,
    ) else {
        return InitialPathAnalysis::unknown(target, limitations);
    };
    if !policy.static_selection_complete {
        limitations.extend(policy.limitations.iter().cloned());
        limitations.push(
            "captured routing-policy facts are insufficient for a definitive static path decision"
                .into(),
        );
        return InitialPathAnalysis::unknown(target, limitations);
    }
    let Some(interfaces) =
        capability_value(&snapshot.interfaces, "interface snapshot", &mut limitations)
    else {
        return InitialPathAnalysis::unknown(target, limitations);
    };

    let mut candidates: Vec<_> = routes
        .iter()
        .filter(|route| route.destination.contains(&target.address))
        .filter(|route| {
            target.scope.as_ref().is_none_or(|scope| {
                route
                    .egress_interface
                    .as_ref()
                    .is_none_or(|interface| interface.index == scope.index)
            })
        })
        .cloned()
        .collect();
    normalize_routes(&mut candidates);
    let Some(longest_prefix) = candidates
        .iter()
        .map(|route| route.destination.prefix_len())
        .max()
    else {
        return InitialPathAnalysis {
            target: target.clone(),
            status: InitialPathStatus::DefinitiveNoPath,
            matching_routes: Vec::new(),
            egress_interface: None,
            relation: PathRelation::Unknown,
            next_hop: None,
            preferred_source: None,
            limitations,
        };
    };
    candidates.retain(|route| route.destination.prefix_len() == longest_prefix);

    if candidates.iter().all(definitively_blocks_traffic) {
        return InitialPathAnalysis {
            target: target.clone(),
            status: InitialPathStatus::DefinitiveNoPath,
            matching_routes: candidates,
            egress_interface: None,
            relation: PathRelation::Unknown,
            next_hop: None,
            preferred_source: None,
            limitations,
        };
    }
    if candidates.iter().any(definitively_blocks_traffic) {
        limitations.push("equally specific route facts conflict on forwarding behavior".into());
        let mut analysis = InitialPathAnalysis::unknown(target, limitations);
        analysis.matching_routes = candidates;
        return analysis;
    }
    if candidates.iter().any(|route| {
        !matches!(
            route.behavior,
            RouteBehavior::Local | RouteBehavior::Unicast
        )
    }) {
        limitations.push(
            "matching route behavior does not prove ordinary unicast forwarding semantics".into(),
        );
        let mut analysis = InitialPathAnalysis::unknown(target, limitations);
        analysis.matching_routes = candidates;
        return analysis;
    }

    let metric_shape_is_known = candidates.iter().all(|route| route.metric.is_some())
        || candidates.iter().all(|route| route.metric.is_none());
    if !metric_shape_is_known {
        limitations.push("equally specific routes mix known and unknown metrics".into());
        let mut analysis = InitialPathAnalysis::unknown(target, limitations);
        analysis.matching_routes = candidates;
        return analysis;
    }
    if let Some(best_metric) = candidates.iter().filter_map(|route| route.metric).min() {
        candidates.retain(|route| route.metric == Some(best_metric));
    }

    let Some(first) = candidates.first().cloned() else {
        unreachable!("longest-prefix candidate set cannot become empty");
    };
    if candidates
        .iter()
        .any(|route| !same_path_semantics(&first, route))
    {
        limitations.push(
            "equally preferred route facts do not identify one deterministic dependency".into(),
        );
        let mut analysis = InitialPathAnalysis::unknown(target, limitations);
        analysis.matching_routes = candidates;
        return analysis;
    }

    let Some(interface_id) = first.egress_interface.clone() else {
        if first.behavior != RouteBehavior::Local {
            limitations.push("selected forwarding route has no egress interface identity".into());
            let mut analysis = InitialPathAnalysis::unknown(target, limitations);
            analysis.matching_routes = candidates;
            return analysis;
        }
        return usable_analysis(target, candidates, &first, limitations);
    };
    let matching_interfaces: Vec<_> = interfaces
        .iter()
        .filter(|interface| same_interface(&interface.id, &interface_id))
        .collect();
    if matching_interfaces.len() != 1 {
        limitations.push(format!(
            "egress interface index {} does not map to exactly one snapshot identity",
            interface_id.index
        ));
        let mut analysis = InitialPathAnalysis::unknown(target, limitations);
        analysis.matching_routes = candidates;
        return analysis;
    }
    let interface = matching_interfaces[0];
    if interface.administrative_state == InterfaceState::Down {
        return InitialPathAnalysis {
            target: target.clone(),
            status: InitialPathStatus::DefinitiveNoPath,
            matching_routes: candidates,
            egress_interface: Some(interface.id.clone()),
            relation: PathRelation::Unknown,
            next_hop: first.next_hop,
            preferred_source: first.preferred_source,
            limitations,
        };
    }
    if !matches!(
        interface.operational_state,
        InterfaceState::Up | InterfaceState::Dormant
    ) || interface.administrative_state == InterfaceState::Unknown
    {
        limitations.push("egress interface usability is not definitive in the snapshot".into());
        let mut analysis = InitialPathAnalysis::unknown(target, limitations);
        analysis.matching_routes = candidates;
        analysis.egress_interface = Some(interface.id.clone());
        return analysis;
    }

    usable_analysis(target, candidates, &first, limitations)
}

/// Rebinds an index-only targeted-path observation to the immutable interface
/// identity captured for this run and records whether the dependency changed.
/// It never lets the initial prediction overwrite the current kernel fact.
pub fn reconcile_current_operation_path(
    mut current: crate::OperationPathContext,
    initial: &InitialPathAnalysis,
    interfaces: &CapabilityValue<Vec<crate::InterfaceFact>>,
) -> crate::OperationPathContext {
    if let (Some(current_interface), CapabilityValue::Available { value, .. }) =
        (&current.egress_interface, interfaces)
    {
        let matches: Vec<_> = value
            .iter()
            .filter(|interface| interface.id.index == current_interface.index)
            .collect();
        if matches.len() == 1 {
            current.egress_interface = Some(matches[0].id.clone());
        }
    }
    let relation = if initial.status == InitialPathStatus::UnknownPath {
        "initial path was unknown; current kernel dependency retained".to_owned()
    } else if current.egress_interface == initial.egress_interface
        && current.relation == initial.relation
        && current.next_hop == initial.next_hop
    {
        "consistent with initial snapshot".to_owned()
    } else {
        "current kernel dependency differs from initial snapshot".to_owned()
    };
    current.relation_to_initial_snapshot = Some(relation);
    current
}

#[must_use]
pub fn neighbor_dependency_for_path(path: &crate::OperationPathContext) -> NeighborDependency {
    if path.relation == PathRelation::Local {
        return NeighborDependency::NotApplicable;
    }
    let Some(interface) = path.egress_interface.clone() else {
        return NeighborDependency::Unknown {
            reason: "current operation path has no egress interface identity".into(),
        };
    };
    let address = match path.relation {
        PathRelation::OnLink => path.target_or_dependency,
        PathRelation::Remote => {
            let Some(next_hop) = path.next_hop else {
                return NeighborDependency::Unknown {
                    reason: "remote current operation path has no next-hop address".into(),
                };
            };
            next_hop
        }
        PathRelation::Unknown => {
            return NeighborDependency::Unknown {
                reason: "current operation path relation is unknown".into(),
            };
        }
        PathRelation::Local => unreachable!("local relation returned above"),
    };
    NeighborDependency::Known(crate::NeighborIdentity {
        family: address.into(),
        interface,
        address,
    })
}

fn capability_value<'a, T>(
    capability: &'a CapabilityValue<T>,
    name: &str,
    limitations: &mut Vec<String>,
) -> Option<&'a T> {
    match capability {
        CapabilityValue::Available { value, .. } => Some(value),
        CapabilityValue::Unknown { reason, .. } => {
            limitations.push(format!("{name} is unknown: {reason:?}"));
            None
        }
        CapabilityValue::Unavailable { reason, .. } => {
            limitations.push(format!("{name} is unavailable: {reason:?}"));
            None
        }
    }
}

fn usable_analysis(
    target: &TargetIp,
    candidates: Vec<RouteFact>,
    selected: &RouteFact,
    limitations: Vec<String>,
) -> InitialPathAnalysis {
    let relation = if selected.behavior == RouteBehavior::Local {
        PathRelation::Local
    } else if selected.next_hop.is_some() {
        PathRelation::Remote
    } else {
        PathRelation::OnLink
    };
    InitialPathAnalysis {
        target: target.clone(),
        status: InitialPathStatus::UsablePath,
        matching_routes: candidates,
        egress_interface: selected.egress_interface.clone(),
        relation,
        next_hop: selected.next_hop,
        preferred_source: selected.preferred_source,
        limitations,
    }
}

const fn definitively_blocks_traffic(route: &RouteFact) -> bool {
    matches!(
        route.behavior,
        RouteBehavior::Reject
            | RouteBehavior::Blackhole
            | RouteBehavior::Unreachable
            | RouteBehavior::Prohibit
    )
}

fn same_path_semantics(left: &RouteFact, right: &RouteFact) -> bool {
    left.behavior == right.behavior
        && left.next_hop == right.next_hop
        && left.egress_interface == right.egress_interface
        && left.preferred_source == right.preferred_source
        && left.table_or_compartment == right.table_or_compartment
}

fn same_interface(left: &InterfaceId, right: &InterfaceId) -> bool {
    left.index == right.index
        && match (&left.stable_id, &right.stable_id) {
            (Some(left), Some(right)) => left == right,
            _ => true,
        }
}

fn normalize_routes(routes: &mut [RouteFact]) {
    routes.sort_by(|left, right| {
        right
            .destination
            .prefix_len()
            .cmp(&left.destination.prefix_len())
            .then_with(|| left.table_or_compartment.cmp(&right.table_or_compartment))
            .then_with(|| left.metric.cmp(&right.metric))
            .then_with(|| {
                left.egress_interface
                    .as_ref()
                    .map(|value| value.index)
                    .cmp(&right.egress_interface.as_ref().map(|value| value.index))
            })
            .then_with(|| left.next_hop.cmp(&right.next_hop))
            .then_with(|| {
                route_behavior_order(left.behavior).cmp(&route_behavior_order(right.behavior))
            })
    });
}

const fn route_behavior_order(behavior: RouteBehavior) -> u8 {
    match behavior {
        RouteBehavior::Local => 0,
        RouteBehavior::Unicast => 1,
        RouteBehavior::Reject => 2,
        RouteBehavior::Blackhole => 3,
        RouteBehavior::Unreachable => 4,
        RouteBehavior::Prohibit => 5,
        RouteBehavior::Throw => 6,
        RouteBehavior::Broadcast => 7,
        RouteBehavior::Multicast => 8,
        RouteBehavior::Unknown => 9,
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use ipnet::Ipv4Net;

    use crate::{
        CapabilityReason, InterfaceFact, PathSelectionFact, Provenance, ProvenanceSource,
        ResolverConfiguration,
    };

    use super::*;

    fn provenance() -> Provenance {
        Provenance::new(ProvenanceSource::SyntheticTest).at(Duration::ZERO)
    }

    fn interface(state: InterfaceState) -> InterfaceFact {
        InterfaceFact {
            id: InterfaceId::from_index(2),
            system_name: "test0".into(),
            display_name: "test0".into(),
            administrative_state: state,
            operational_state: state,
            is_loopback: false,
            addresses: Vec::new(),
            provenance: provenance(),
        }
    }

    fn route(behavior: RouteBehavior) -> RouteFact {
        RouteFact {
            destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap().into(),
            next_hop: Some(Ipv4Addr::new(192, 0, 2, 1).into()),
            egress_interface: Some(InterfaceId::from_index(2)),
            behavior,
            metric: Some(10),
            table_or_compartment: Some(254),
            preferred_source: None,
            multipath_weight: None,
            provenance: provenance(),
        }
    }

    fn snapshot(routes: CapabilityValue<Vec<RouteFact>>) -> InitialNetworkSnapshot {
        InitialNetworkSnapshot {
            capture_started_at: Duration::ZERO,
            capture_completed_at: Duration::ZERO,
            interfaces: CapabilityValue::available(
                vec![interface(InterfaceState::Up)],
                provenance(),
            ),
            routes_v4: routes,
            routes_v6: CapabilityValue::available(Vec::new(), provenance()),
            routing_policy_facts: CapabilityValue::available(
                crate::RoutingPolicyFacts {
                    facts: vec![PathSelectionFact {
                        family: crate::AddressFamily::Ipv4,
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

    fn target() -> TargetIp {
        TargetIp::v4(Ipv4Addr::new(203, 0, 113, 10))
    }

    #[test]
    fn complete_unambiguous_route_is_usable() {
        let result = analyze_initial_path(
            &snapshot(CapabilityValue::available(
                vec![route(RouteBehavior::Unicast)],
                provenance(),
            )),
            &target(),
        );
        assert_eq!(result.status, InitialPathStatus::UsablePath);
        assert_eq!(result.relation, PathRelation::Remote);
    }

    #[test]
    fn explicit_blocking_route_is_definitive_no_path() {
        let result = analyze_initial_path(
            &snapshot(CapabilityValue::available(
                vec![route(RouteBehavior::Blackhole)],
                provenance(),
            )),
            &target(),
        );
        assert_eq!(result.status, InitialPathStatus::DefinitiveNoPath);
    }

    #[test]
    fn unavailable_route_snapshot_cannot_suppress_real_probe() {
        let result = analyze_initial_path(
            &snapshot(CapabilityValue::unavailable(
                CapabilityReason::QuerySemanticsUnavailable,
                provenance(),
            )),
            &target(),
        );
        assert_eq!(result.status, InitialPathStatus::UnknownPath);
    }

    #[test]
    fn enumerable_but_incompletely_modeled_policy_cannot_suppress_the_real_probe() {
        let mut snapshot = snapshot(CapabilityValue::available(
            vec![route(RouteBehavior::Blackhole)],
            provenance(),
        ));
        let CapabilityValue::Available { value, .. } = &mut snapshot.routing_policy_facts else {
            unreachable!("synthetic policy is available")
        };
        value.static_selection_complete = false;
        value
            .limitations
            .push("a selector is not modeled structurally".into());

        let result = analyze_initial_path(&snapshot, &target());
        assert_eq!(result.status, InitialPathStatus::UnknownPath);
        assert!(
            result
                .limitations
                .iter()
                .any(|item| item.contains("selector is not modeled"))
        );
    }

    #[test]
    fn inconsistency_downgrades_even_an_explicit_blocking_route() {
        let mut snapshot = snapshot(CapabilityValue::available(
            vec![route(RouteBehavior::Blackhole)],
            provenance(),
        ));
        snapshot.inconsistencies.push(crate::SnapshotInconsistency {
            scope: SnapshotInconsistencyScope::PathSelection,
            detail: "route changed during capture".into(),
        });
        let result = analyze_initial_path(&snapshot, &target());
        assert_eq!(result.status, InitialPathStatus::UnknownPath);
    }

    #[test]
    fn unrelated_resolver_inconsistency_does_not_change_target_path_analysis() {
        let mut snapshot = snapshot(CapabilityValue::available(
            vec![route(RouteBehavior::Blackhole)],
            provenance(),
        ));
        snapshot.inconsistencies.push(crate::SnapshotInconsistency {
            scope: SnapshotInconsistencyScope::ResolverSelection,
            detail: "resolver binding changed during capture".into(),
        });
        let result = analyze_initial_path(&snapshot, &target());
        assert_eq!(result.status, InitialPathStatus::DefinitiveNoPath);
    }

    #[test]
    fn conflicting_equal_routes_are_unknown() {
        let result = analyze_initial_path(
            &snapshot(CapabilityValue::available(
                vec![
                    route(RouteBehavior::Unicast),
                    route(RouteBehavior::Blackhole),
                ],
                provenance(),
            )),
            &target(),
        );
        assert_eq!(result.status, InitialPathStatus::UnknownPath);
    }

    #[test]
    fn non_forwarding_or_unknown_route_types_never_become_usable_paths() {
        for behavior in [
            RouteBehavior::Throw,
            RouteBehavior::Broadcast,
            RouteBehavior::Multicast,
            RouteBehavior::Unknown,
        ] {
            let analysis = analyze_initial_path(
                &snapshot(CapabilityValue::available(
                    vec![route(behavior)],
                    provenance(),
                )),
                &target(),
            );
            assert_eq!(analysis.status, InitialPathStatus::UnknownPath);
        }
    }

    #[test]
    fn nonsemantic_route_enumeration_order_does_not_change_analysis() {
        let default = route(RouteBehavior::Unicast);
        let mut specific = default.clone();
        specific.destination = Ipv4Net::new(Ipv4Addr::new(203, 0, 113, 0), 24)
            .expect("valid test route")
            .into();
        specific.metric = Some(20);

        let forward = analyze_initial_path(
            &snapshot(CapabilityValue::available(
                vec![default.clone(), specific.clone()],
                provenance(),
            )),
            &target(),
        );
        let reverse = analyze_initial_path(
            &snapshot(CapabilityValue::available(
                vec![specific, default],
                provenance(),
            )),
            &target(),
        );
        assert_eq!(forward, reverse);
    }

    #[test]
    fn current_path_change_binds_neighbor_to_current_dependency() {
        let initial = analyze_initial_path(
            &snapshot(CapabilityValue::available(
                vec![route(RouteBehavior::Unicast)],
                provenance(),
            )),
            &target(),
        );
        let current = crate::OperationPathContext {
            captured_at: Duration::from_secs(1),
            target_or_dependency: target().address,
            family: crate::AddressFamily::Ipv4,
            egress_interface: Some(InterfaceId::from_index(3)),
            relation: PathRelation::Remote,
            next_hop: Some(Ipv4Addr::new(198, 51, 100, 1).into()),
            preferred_source: None,
            relation_to_initial_snapshot: None,
            provenance: provenance(),
        };
        let interfaces = CapabilityValue::available(
            vec![
                interface(InterfaceState::Up),
                InterfaceFact {
                    id: InterfaceId {
                        index: 3,
                        stable_id: Some("replacement-safe-id".into()),
                    },
                    system_name: "test1".into(),
                    display_name: "test1".into(),
                    administrative_state: InterfaceState::Up,
                    operational_state: InterfaceState::Up,
                    is_loopback: false,
                    addresses: Vec::new(),
                    provenance: provenance(),
                },
            ],
            provenance(),
        );
        let current = reconcile_current_operation_path(current, &initial, &interfaces);
        let NeighborDependency::Known(neighbor) = neighbor_dependency_for_path(&current) else {
            panic!("current remote path should identify its next-hop Neighbor");
        };
        assert_eq!(neighbor.interface.index, 3);
        assert_eq!(
            neighbor.interface.stable_id.as_deref(),
            Some("replacement-safe-id")
        );
        assert_eq!(neighbor.address, Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(
            current.relation_to_initial_snapshot.as_deref(),
            Some("current kernel dependency differs from initial snapshot")
        );
    }
}
