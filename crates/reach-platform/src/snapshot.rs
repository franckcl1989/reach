use std::collections::BTreeMap;

use reach_core::{
    CapabilityValue, InitialNetworkSnapshot, InterfaceFact, InterfaceId, ResolverConfiguration,
    RouteFact, SnapshotInconsistency, SnapshotInconsistencyScope,
};

use crate::{
    ContinuousClock, PlatformError, capture_interfaces, capture_resolver_configuration,
    capture_routes, capture_routing_policy,
};

pub async fn capture_initial_snapshot(
    clock: &impl ContinuousClock,
) -> Result<InitialNetworkSnapshot, PlatformError> {
    let capture_started_at = clock.now()?;

    let interfaces_observed_at = clock.now()?;
    let interfaces = capture_interfaces(interfaces_observed_at);

    let routes_observed_at = clock.now()?;
    let routes = capture_routes(routes_observed_at).await;
    let (routes_v4, routes_v6) = split_routes(routes);

    let policy_observed_at = clock.now()?;
    let routing_policy_facts = capture_routing_policy(policy_observed_at).await;

    let resolver_observed_at = clock.now()?;
    let resolver_configuration = capture_resolver_configuration(resolver_observed_at, &interfaces);
    let inconsistencies = detect_snapshot_inconsistencies(
        &interfaces,
        &routes_v4,
        &routes_v6,
        &resolver_configuration,
    );

    Ok(InitialNetworkSnapshot {
        capture_started_at,
        capture_completed_at: clock.now()?,
        interfaces,
        routes_v4,
        routes_v6,
        routing_policy_facts,
        resolver_configuration,
        inconsistencies,
    })
}

fn detect_snapshot_inconsistencies(
    interfaces: &CapabilityValue<Vec<InterfaceFact>>,
    routes_v4: &CapabilityValue<Vec<RouteFact>>,
    routes_v6: &CapabilityValue<Vec<RouteFact>>,
    resolver: &CapabilityValue<ResolverConfiguration>,
) -> Vec<SnapshotInconsistency> {
    let CapabilityValue::Available {
        value: interfaces, ..
    } = interfaces
    else {
        return Vec::new();
    };

    let mut by_index = BTreeMap::<u32, &InterfaceId>::new();
    let mut inconsistencies = Vec::new();
    for interface in interfaces {
        if let Some(previous) = by_index.insert(interface.id.index, &interface.id)
            && previous != &interface.id
        {
            for scope in [
                SnapshotInconsistencyScope::PathSelection,
                SnapshotInconsistencyScope::ResolverSelection,
            ] {
                inconsistencies.push(SnapshotInconsistency {
                    scope,
                    detail: format!(
                        "interface index {} was observed with conflicting stable identities",
                        interface.id.index
                    ),
                });
            }
        }
    }

    for routes in [routes_v4, routes_v6] {
        let CapabilityValue::Available { value: routes, .. } = routes else {
            continue;
        };
        for route in routes {
            if let Some(interface) = &route.egress_interface {
                check_interface_reference(
                    "route",
                    SnapshotInconsistencyScope::PathSelection,
                    interface,
                    &by_index,
                    &mut inconsistencies,
                );
            }
            let route_is_v4 = route.destination.addr().is_ipv4();
            if route
                .next_hop
                .is_some_and(|address| address.is_ipv4() != route_is_v4)
            {
                inconsistencies.push(SnapshotInconsistency {
                    scope: SnapshotInconsistencyScope::PathSelection,
                    detail: format!(
                        "route {} has a next hop from a different address family",
                        route.destination
                    ),
                });
            }
            if route
                .preferred_source
                .is_some_and(|address| address.is_ipv4() != route_is_v4)
            {
                inconsistencies.push(SnapshotInconsistency {
                    scope: SnapshotInconsistencyScope::PathSelection,
                    detail: format!(
                        "route {} has a preferred source from a different address family",
                        route.destination
                    ),
                });
            }
        }
    }

    if let CapabilityValue::Available {
        value: resolver, ..
    } = resolver
    {
        for endpoint in &resolver.endpoints {
            if let Some(interface) = &endpoint.interface {
                check_interface_reference(
                    "resolver endpoint",
                    SnapshotInconsistencyScope::ResolverSelection,
                    interface,
                    &by_index,
                    &mut inconsistencies,
                );
            }
        }
    }

    inconsistencies.sort();
    inconsistencies.dedup();
    inconsistencies
}

fn check_interface_reference(
    source: &str,
    scope: SnapshotInconsistencyScope,
    reference: &InterfaceId,
    interfaces: &BTreeMap<u32, &InterfaceId>,
    inconsistencies: &mut Vec<SnapshotInconsistency>,
) {
    match interfaces.get(&reference.index) {
        None => inconsistencies.push(SnapshotInconsistency {
            scope,
            detail: format!(
                "{source} references interface index {} absent from the interface snapshot",
                reference.index
            ),
        }),
        Some(observed)
            if reference.stable_id.is_some()
                && observed.stable_id.is_some()
                && reference.stable_id != observed.stable_id =>
        {
            inconsistencies.push(SnapshotInconsistency {
                scope,
                detail: format!(
                    "{source} references interface index {} with a conflicting stable identity",
                    reference.index
                ),
            });
        }
        Some(_) => {}
    }
}

fn split_routes(
    routes: CapabilityValue<Vec<reach_core::RouteFact>>,
) -> (
    CapabilityValue<Vec<reach_core::RouteFact>>,
    CapabilityValue<Vec<reach_core::RouteFact>>,
) {
    match routes {
        CapabilityValue::Available { value, provenance } => {
            let (v4, v6) = value
                .into_iter()
                .partition(|route| route.destination.addr().is_ipv4());
            (
                CapabilityValue::available(v4, provenance.clone()),
                CapabilityValue::available(v6, provenance),
            )
        }
        CapabilityValue::Unknown { reason, provenance } => (
            CapabilityValue::unknown(reason.clone(), provenance.clone()),
            CapabilityValue::unknown(reason, provenance),
        ),
        CapabilityValue::Unavailable { reason, provenance } => (
            CapabilityValue::unavailable(reason.clone(), provenance.clone()),
            CapabilityValue::unavailable(reason, provenance),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, net::Ipv4Addr, time::Duration};

    use ipnet::IpNet;
    use reach_core::{
        InterfaceState, Provenance, ProvenanceSource, ResolverEndpoint, ResolverTransport,
        RouteBehavior,
    };

    use super::*;

    struct FakeClock(Cell<u64>);

    impl ContinuousClock for FakeClock {
        fn now(&self) -> Result<Duration, PlatformError> {
            let current = self.0.get();
            self.0.set(current + 1);
            Ok(Duration::from_millis(current))
        }
    }

    #[tokio::test]
    async fn snapshot_records_a_bounded_capture_window() {
        let snapshot = capture_initial_snapshot(&FakeClock(Cell::new(10)))
            .await
            .expect("fake clock cannot fail");
        assert_eq!(snapshot.capture_started_at, Duration::from_millis(10));
        assert_eq!(snapshot.capture_completed_at, Duration::from_millis(15));
        assert!(snapshot.capture_completed_at >= snapshot.capture_started_at);
    }

    #[tokio::test]
    async fn native_snapshot_capabilities_are_observed_and_reported() {
        let snapshot = capture_initial_snapshot(&crate::SystemContinuousClock)
            .await
            .expect("native snapshot capture must return a typed result");
        println!(
            "native capability interface_snapshot={}",
            capability_state(&snapshot.interfaces)
        );
        println!(
            "native capability route_snapshot_v4={} route_snapshot_v6={}",
            capability_state(&snapshot.routes_v4),
            capability_state(&snapshot.routes_v6)
        );
        println!(
            "native capability routing_policy_snapshot={}",
            capability_state(&snapshot.routing_policy_facts)
        );
        println!(
            "native capability resolver_configuration_snapshot={}",
            capability_state(&snapshot.resolver_configuration)
        );
        assert!(snapshot.capture_completed_at >= snapshot.capture_started_at);
        assert!(
            matches!(snapshot.interfaces, CapabilityValue::Available { .. }),
            "all supported release targets must expose the ordinary-user interface snapshot"
        );
        assert!(
            matches!(snapshot.routes_v4, CapabilityValue::Available { .. })
                && matches!(snapshot.routes_v6, CapabilityValue::Available { .. }),
            "all supported release targets must expose IPv4 and IPv6 route snapshots"
        );
        assert!(
            matches!(
                snapshot.resolver_configuration,
                CapabilityValue::Available { .. }
            ),
            "all supported release targets must expose a typed resolver-configuration snapshot"
        );
        #[cfg(target_os = "linux")]
        {
            let CapabilityValue::Available { value, .. } = snapshot.routing_policy_facts else {
                panic!("Linux must retain the enumerated RPDB facts");
            };
            assert!(
                !value.static_selection_complete,
                "enumerating RPDB rules must not claim full kernel-policy reconstruction"
            );
        }
        #[cfg(not(target_os = "linux"))]
        assert!(matches!(
            snapshot.routing_policy_facts,
            CapabilityValue::Unavailable {
                reason: reach_core::CapabilityReason::QuerySemanticsUnavailable,
                ..
            }
        ));
        #[cfg(any(windows, target_os = "macos"))]
        {
            let CapabilityValue::Available { value, .. } = &snapshot.resolver_configuration else {
                unreachable!("resolver configuration availability was asserted above");
            };
            assert!(
                value
                    .endpoints
                    .iter()
                    .all(|endpoint| endpoint.transport == reach_core::ResolverTransport::Unknown),
                "public resolver configuration must not invent a classic transport"
            );
        }
    }

    const fn capability_state<T>(value: &CapabilityValue<T>) -> &'static str {
        match value {
            CapabilityValue::Available { .. } => "Available",
            CapabilityValue::Unknown { .. } => "Unknown",
            CapabilityValue::Unavailable { .. } => "Unavailable",
        }
    }

    #[test]
    fn cross_capture_interface_conflicts_are_preserved_deterministically() {
        let provenance = Provenance::new(ProvenanceSource::SyntheticTest);
        let interfaces = CapabilityValue::available(
            vec![InterfaceFact {
                id: InterfaceId::from_index(7),
                system_name: "if7".into(),
                display_name: "if7".into(),
                administrative_state: InterfaceState::Up,
                operational_state: InterfaceState::Up,
                is_loopback: false,
                addresses: Vec::new(),
                provenance: provenance.clone(),
            }],
            provenance.clone(),
        );
        let routes_v4 = CapabilityValue::available(
            vec![RouteFact {
                destination: IpNet::new(Ipv4Addr::UNSPECIFIED.into(), 0)
                    .expect("valid test network"),
                next_hop: Some(Ipv4Addr::new(192, 0, 2, 1).into()),
                egress_interface: Some(InterfaceId::from_index(8)),
                behavior: RouteBehavior::Unicast,
                metric: None,
                table_or_compartment: None,
                preferred_source: None,
                multipath_weight: None,
                provenance: provenance.clone(),
            }],
            provenance.clone(),
        );
        let routes_v6 = CapabilityValue::available(Vec::new(), provenance.clone());
        let resolver = CapabilityValue::available(
            ResolverConfiguration {
                endpoints: vec![ResolverEndpoint {
                    address: Ipv4Addr::new(192, 0, 2, 53).into(),
                    port: 53,
                    transport: ResolverTransport::Udp,
                    interface: Some(InterfaceId::from_index(9)),
                    domains: Vec::new(),
                    priority: None,
                    provenance: provenance.clone(),
                }],
                search_domains: Vec::new(),
                non_dns_sources: Vec::new(),
                dns_protocol_candidates_applicable: CapabilityValue::available(
                    true,
                    provenance.clone(),
                ),
                ordering_is_semantic: true,
                limitations: Vec::new(),
                provenance: provenance.clone(),
            },
            provenance,
        );

        assert_eq!(
            detect_snapshot_inconsistencies(&interfaces, &routes_v4, &routes_v6, &resolver),
            vec![
                SnapshotInconsistency {
                    scope: SnapshotInconsistencyScope::PathSelection,
                    detail: "route references interface index 8 absent from the interface snapshot"
                        .into(),
                },
                SnapshotInconsistency {
                    scope: SnapshotInconsistencyScope::ResolverSelection,
                    detail: "resolver endpoint references interface index 9 absent from the interface snapshot"
                        .into(),
                },
            ]
        );
    }
}
