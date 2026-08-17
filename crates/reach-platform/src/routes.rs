use std::time::Duration;

use reach_core::{
    CapabilityReason, CapabilityValue, OperationPathContext, Provenance, ProvenanceSource,
    RouteFact, TargetIp,
};

#[cfg(windows)]
use reach_core::PathRelation;
#[cfg(any(windows, target_os = "macos"))]
use reach_core::{InterfaceId, RouteBehavior};

pub async fn capture_routes(observed_at: Duration) -> CapabilityValue<Vec<RouteFact>> {
    let provenance = Provenance::new(ProvenanceSource::RouteSnapshot)
        .at(observed_at)
        .with_detail(route_source_detail());
    platform_routes(&provenance).await
}

/// Reads the kernel's current path decision without creating a target socket
/// or sending target traffic. This observation supplements, and never mutates,
/// the initial route snapshot.
pub async fn capture_current_operation_path(
    target: &TargetIp,
    observed_at: Duration,
) -> CapabilityValue<OperationPathContext> {
    let provenance = Provenance::new(ProvenanceSource::TargetedPathQuery)
        .at(observed_at)
        .with_detail(targeted_path_source_detail());
    platform_current_operation_path(target, observed_at, &provenance).await
}

#[cfg(target_os = "linux")]
async fn platform_current_operation_path(
    _target: &TargetIp,
    _observed_at: Duration,
    provenance: &Provenance,
) -> CapabilityValue<OperationPathContext> {
    CapabilityValue::unavailable(
        CapabilityReason::QuerySemanticsUnavailable,
        provenance.clone(),
    )
}

#[cfg(windows)]
async fn platform_current_operation_path(
    target: &TargetIp,
    observed_at: Duration,
    provenance: &Provenance,
) -> CapabilityValue<OperationPathContext> {
    match windows_current_operation_path(target, observed_at, provenance) {
        Ok(context) => CapabilityValue::available(context, provenance.clone()),
        Err(error) => CapabilityValue::unknown(
            CapabilityReason::Other(format!("GetBestRoute2 failed with Windows error {error}")),
            provenance.clone(),
        ),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
async fn platform_current_operation_path(
    _target: &TargetIp,
    _observed_at: Duration,
    provenance: &Provenance,
) -> CapabilityValue<OperationPathContext> {
    CapabilityValue::unavailable(
        CapabilityReason::QuerySemanticsUnavailable,
        provenance.clone(),
    )
}

#[cfg(any(windows, target_os = "macos"))]
async fn platform_routes(provenance: &Provenance) -> CapabilityValue<Vec<RouteFact>> {
    match netroute::list_routes() {
        Ok(routes) => {
            let mut facts = Vec::with_capacity(routes.len());
            for route in routes {
                let destination =
                    match ipnet::IpNet::new(route.destination.addr, route.destination.prefix_len) {
                        Ok(destination) => destination,
                        Err(error) => {
                            return CapabilityValue::unknown(
                                CapabilityReason::SnapshotInconsistent,
                                provenance.clone().with_detail(format!(
                                    "netroute returned an invalid prefix: {error}"
                                )),
                            );
                        }
                    };
                let behavior = if route.flags.contains(&netroute::RouteFlag::Reject) {
                    RouteBehavior::Reject
                } else if route.flags.contains(&netroute::RouteFlag::Loopback)
                    || route.scope == Some(netroute::RouteScope::Host)
                {
                    RouteBehavior::Local
                } else {
                    RouteBehavior::Unicast
                };
                facts.push(RouteFact {
                    destination,
                    next_hop: route.gateway,
                    egress_interface: route.ifindex.map(InterfaceId::from_index),
                    behavior,
                    metric: route.metric.map(u64::from),
                    table_or_compartment: route.table.map(u64::from),
                    preferred_source: None,
                    multipath_weight: None,
                    provenance: provenance.clone(),
                });
            }
            CapabilityValue::available(facts, provenance.clone())
        }
        Err(error) => CapabilityValue::unavailable(
            CapabilityReason::Other(format!("netroute enumeration failed: {error}")),
            provenance.clone(),
        ),
    }
}

#[cfg(target_os = "linux")]
async fn platform_routes(provenance: &Provenance) -> CapabilityValue<Vec<RouteFact>> {
    match linux::routes(provenance).await {
        Ok(routes) => CapabilityValue::available(routes, provenance.clone()),
        Err(error) => CapabilityValue::unavailable(
            CapabilityReason::Other(format!("rtnetlink route enumeration failed: {error}")),
            provenance.clone(),
        ),
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
async fn platform_routes(provenance: &Provenance) -> CapabilityValue<Vec<RouteFact>> {
    CapabilityValue::unavailable(CapabilityReason::UnsupportedEnvironment, provenance.clone())
}

pub async fn capture_routing_policy(
    observed_at: Duration,
) -> CapabilityValue<reach_core::RoutingPolicyFacts> {
    let provenance = Provenance::new(ProvenanceSource::RoutingPolicySnapshot)
        .at(observed_at)
        .with_detail(policy_source_detail());
    platform_routing_policy(&provenance).await
}

#[cfg(target_os = "linux")]
async fn platform_routing_policy(
    provenance: &Provenance,
) -> CapabilityValue<reach_core::RoutingPolicyFacts> {
    match linux::routing_policy(provenance).await {
        Ok(facts) => CapabilityValue::available(
            reach_core::RoutingPolicyFacts {
                facts,
                static_selection_complete: false,
                limitations: vec![
                    "Linux rule selectors and actions are retained, but Reach does not claim to reproduce the kernel's full RPDB decision from the snapshot"
                        .into(),
                ],
            },
            provenance.clone(),
        ),
        Err(error) => CapabilityValue::unavailable(
            CapabilityReason::Other(format!(
                "rtnetlink routing-policy enumeration failed: {error}"
            )),
            provenance.clone(),
        ),
    }
}

#[cfg(not(target_os = "linux"))]
async fn platform_routing_policy(
    provenance: &Provenance,
) -> CapabilityValue<reach_core::RoutingPolicyFacts> {
    CapabilityValue::unavailable(
        CapabilityReason::QuerySemanticsUnavailable,
        provenance.clone(),
    )
}

const fn route_source_detail() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "rtnetlink route enumeration"
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        "netroute native route enumeration"
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        "no route adapter"
    }
}

const fn policy_source_detail() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "rtnetlink policy-rule enumeration"
    }
    #[cfg(not(target_os = "linux"))]
    {
        "no equivalent ordered policy-rule dump is exposed by the selected mature crate"
    }
}

const fn targeted_path_source_detail() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "destination-only RTM_GETROUTE cannot prove the later socket's flow-dependent route without creating or reusing that socket"
    }
    #[cfg(windows)]
    {
        "Windows GetBestRoute2; read-only and no target traffic"
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        "no proven read-only kernel-targeted path API in the selected mature crate"
    }
}

#[cfg(windows)]
fn windows_current_operation_path(
    target: &TargetIp,
    observed_at: Duration,
    provenance: &Provenance,
) -> Result<OperationPathContext, u32> {
    use windows_sys::Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2},
        Networking::WinSock::SOCKADDR_INET,
    };

    let destination = windows_sockaddr(
        target.address,
        target.scope.as_ref().map_or(0, |id| id.index),
    );
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: destination and output pointers are valid for the synchronous,
    // read-only call. A null LUID/source asks Windows to perform its normal
    // route selection, optionally constrained by the scoped interface index.
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            target.scope.as_ref().map_or(0, |id| id.index),
            std::ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    };
    if status != NO_ERROR {
        return Err(status);
    }
    let raw_next_hop = windows_ip_addr(&route.NextHop);
    let next_hop = raw_next_hop.filter(|address| !address.is_unspecified());
    let relation = if route.Loopback {
        PathRelation::Local
    } else if next_hop.is_some() {
        PathRelation::Remote
    } else {
        PathRelation::OnLink
    };
    Ok(OperationPathContext {
        captured_at: observed_at,
        target_or_dependency: target.address,
        family: target.family(),
        egress_interface: Some(InterfaceId::from_index(route.InterfaceIndex)),
        relation,
        next_hop,
        preferred_source: windows_ip_addr(&source).filter(|address| !address.is_unspecified()),
        relation_to_initial_snapshot: None,
        provenance: provenance.clone(),
    })
}

#[cfg(windows)]
pub(crate) fn windows_sockaddr(
    address: std::net::IpAddr,
    scope_index: u32,
) -> windows_sys::Win32::Networking::WinSock::SOCKADDR_INET {
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_IN6_0, SOCKADDR_INET,
    };

    match address {
        std::net::IpAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.octets()),
                    },
                },
                ..Default::default()
            },
        },
        std::net::IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: scope_index,
                },
                ..Default::default()
            },
        },
    }
}

#[cfg(windows)]
pub(crate) fn windows_ip_addr(
    address: &windows_sys::Win32::Networking::WinSock::SOCKADDR_INET,
) -> Option<std::net::IpAddr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    // SAFETY: reading the common address-family member of SOCKADDR_INET is
    // valid regardless of the active address union variant.
    let family = unsafe { address.si_family };
    match family {
        AF_INET => {
            // SAFETY: the family identifies the IPv4 union variant.
            let address = unsafe { address.Ipv4 };
            // SAFETY: S_addr is the initialized IN_ADDR union member returned
            // by Windows for an IPv4 SOCKADDR_INET.
            let octets = unsafe { address.sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(std::net::Ipv4Addr::from(octets).into())
        }
        AF_INET6 => {
            // SAFETY: the family identifies the IPv6 union variant.
            let address = unsafe { address.Ipv6 };
            // SAFETY: Byte is the initialized IN6_ADDR union member returned
            // by Windows for an IPv6 SOCKADDR_INET.
            let octets = unsafe { address.sin6_addr.u.Byte };
            Some(std::net::Ipv6Addr::from(octets).into())
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use futures_util::TryStreamExt;
    use netlink_packet_route::{
        AddressFamily as NetlinkAddressFamily,
        route::{RouteAddress, RouteAttribute, RouteMessage, RouteNextHop, RouteType, RouteVia},
        rule::{RuleAttribute, RuleMessage},
    };
    use reach_core::{
        AddressFamily, InterfaceId, PathSelectionFact, Provenance, RouteBehavior, RouteFact,
    };
    use rtnetlink::{Handle, IpVersion, RouteMessageBuilder, new_connection};

    pub async fn routes(provenance: &Provenance) -> Result<Vec<RouteFact>, String> {
        let (connection, handle, _) = new_connection().map_err(|error| error.to_string())?;
        tokio::spawn(connection);

        let mut facts = Vec::new();
        dump_routes(&handle, IpVersion::V4, provenance, &mut facts).await?;
        dump_routes(&handle, IpVersion::V6, provenance, &mut facts).await?;
        Ok(facts)
    }

    async fn dump_routes(
        handle: &Handle,
        version: IpVersion,
        provenance: &Provenance,
        facts: &mut Vec<RouteFact>,
    ) -> Result<(), String> {
        let request = match version {
            IpVersion::V4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
            IpVersion::V6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
        };
        let mut messages = handle.route().get(request).execute();
        while let Some(message) = messages
            .try_next()
            .await
            .map_err(|error| error.to_string())?
        {
            facts.extend(map_route(message, provenance)?);
        }
        Ok(())
    }

    fn map_route(message: RouteMessage, provenance: &Provenance) -> Result<Vec<RouteFact>, String> {
        let destination_address = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Destination(address) => route_address(address),
                _ => None,
            })
            .or(match message.header.address_family {
                NetlinkAddressFamily::Inet => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                NetlinkAddressFamily::Inet6 => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                _ => None,
            })
            .ok_or_else(|| "route has a non-IP address family".to_owned())?;
        let destination = ipnet::IpNet::new(
            destination_address,
            message.header.destination_prefix_length,
        )
        .map_err(|error| format!("route has an invalid destination prefix: {error}"))?;

        let base = RouteParts::from_attributes(&message.attributes);
        let behavior = map_behavior(message.header.kind);
        let table = base
            .table
            .or_else(|| (message.header.table != 0).then(|| u32::from(message.header.table)));
        let multipath = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::MultiPath(next_hops) => Some(next_hops),
                _ => None,
            });
        let fact_provenance = provenance
            .clone()
            .with_detail("rtnetlink decoded RTM_NEWROUTE");

        if let Some(next_hops) = multipath {
            Ok(next_hops
                .iter()
                .map(|next_hop| {
                    let leg = RouteParts::from_next_hop(next_hop);
                    RouteFact {
                        destination,
                        next_hop: leg.gateway.or(base.gateway),
                        egress_interface: leg.interface.or(base.interface.clone()),
                        behavior,
                        metric: base.metric.map(u64::from),
                        table_or_compartment: table.map(u64::from),
                        preferred_source: base.preferred_source,
                        multipath_weight: Some(u16::from(next_hop.hops) + 1),
                        provenance: fact_provenance.clone(),
                    }
                })
                .collect())
        } else {
            Ok(vec![RouteFact {
                destination,
                next_hop: base.gateway,
                egress_interface: base.interface,
                behavior,
                metric: base.metric.map(u64::from),
                table_or_compartment: table.map(u64::from),
                preferred_source: base.preferred_source,
                multipath_weight: None,
                provenance: fact_provenance,
            }])
        }
    }

    #[derive(Clone, Debug, Default)]
    struct RouteParts {
        gateway: Option<IpAddr>,
        interface: Option<InterfaceId>,
        metric: Option<u32>,
        table: Option<u32>,
        preferred_source: Option<IpAddr>,
    }

    impl RouteParts {
        fn from_attributes(attributes: &[RouteAttribute]) -> Self {
            let mut value = Self::default();
            for attribute in attributes {
                match attribute {
                    RouteAttribute::Gateway(address) => value.gateway = route_address(address),
                    RouteAttribute::Via(via) => value.gateway = route_via(via),
                    RouteAttribute::Oif(index) => {
                        value.interface = Some(InterfaceId::from_index(*index));
                    }
                    RouteAttribute::Priority(metric) => value.metric = Some(*metric),
                    RouteAttribute::Table(table) => value.table = Some(*table),
                    RouteAttribute::PrefSource(address) => {
                        value.preferred_source = route_address(address);
                    }
                    _ => {}
                }
            }
            value
        }

        fn from_next_hop(next_hop: &RouteNextHop) -> Self {
            let mut value = Self::from_attributes(&next_hop.attributes);
            value.interface = (next_hop.interface_index != 0)
                .then(|| InterfaceId::from_index(next_hop.interface_index));
            value
        }
    }

    fn route_address(address: &RouteAddress) -> Option<IpAddr> {
        match address {
            RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
            RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
            _ => None,
        }
    }

    fn route_via(via: &RouteVia) -> Option<IpAddr> {
        match via {
            RouteVia::Inet(address) => Some(IpAddr::V4(*address)),
            RouteVia::Inet6(address) => Some(IpAddr::V6(*address)),
            _ => None,
        }
    }

    const fn map_behavior(kind: RouteType) -> RouteBehavior {
        match kind {
            RouteType::Unicast => RouteBehavior::Unicast,
            RouteType::Local => RouteBehavior::Local,
            RouteType::Broadcast => RouteBehavior::Broadcast,
            RouteType::Multicast => RouteBehavior::Multicast,
            RouteType::BlackHole => RouteBehavior::Blackhole,
            RouteType::Unreachable => RouteBehavior::Unreachable,
            RouteType::Prohibit => RouteBehavior::Prohibit,
            RouteType::Throw => RouteBehavior::Throw,
            _ => RouteBehavior::Unknown,
        }
    }

    pub async fn routing_policy(provenance: &Provenance) -> Result<Vec<PathSelectionFact>, String> {
        let (connection, handle, _) = new_connection().map_err(|error| error.to_string())?;
        tokio::spawn(connection);
        let mut facts = Vec::new();
        dump_rules(&handle, IpVersion::V4, provenance, &mut facts).await?;
        dump_rules(&handle, IpVersion::V6, provenance, &mut facts).await?;
        Ok(facts)
    }

    async fn dump_rules(
        handle: &Handle,
        version: IpVersion,
        provenance: &Provenance,
        facts: &mut Vec<PathSelectionFact>,
    ) -> Result<(), String> {
        let family = match version {
            IpVersion::V4 => AddressFamily::Ipv4,
            IpVersion::V6 => AddressFamily::Ipv6,
        };
        let mut messages = handle.rule().get(version).execute();
        while let Some(message) = messages
            .try_next()
            .await
            .map_err(|error| error.to_string())?
        {
            facts.push(map_rule(family, message, provenance));
        }
        Ok(())
    }

    fn map_rule(
        family: AddressFamily,
        message: RuleMessage,
        provenance: &Provenance,
    ) -> PathSelectionFact {
        let priority = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RuleAttribute::Priority(priority) => Some(u64::from(*priority)),
                _ => None,
            });
        let table = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RuleAttribute::Table(table) => Some(u64::from(*table)),
                _ => None,
            })
            .or_else(|| (message.header.table != 0).then(|| u64::from(message.header.table)));
        PathSelectionFact {
            family,
            priority,
            table_or_domain: table,
            description: format!(
                "action={:?}; flags={:?}; selectors={:?}",
                message.header.action, message.header.flags, message.attributes
            ),
            provenance: provenance.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    #[cfg(windows)]
    use reach_core::PathRelation;

    use super::*;

    #[test]
    #[cfg(windows)]
    fn windows_sockaddr_round_trip_preserves_address() {
        let address = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(
            windows_ip_addr(&windows_sockaddr(address, 0)),
            Some(address)
        );
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn targeted_loopback_path_uses_read_only_kernel_query() {
        let observed = Duration::from_secs(1);
        for target in [
            TargetIp::v4(Ipv4Addr::LOCALHOST),
            TargetIp::v6(Ipv6Addr::LOCALHOST, None),
        ] {
            let result = capture_current_operation_path(&target, observed).await;
            let CapabilityValue::Available { value, .. } = result else {
                panic!("ordinary-user targeted loopback path query must be available: {result:?}");
            };
            assert_eq!(value.target_or_dependency, target.address);
            assert_eq!(value.captured_at, observed);
            assert!(matches!(
                value.relation,
                PathRelation::Local | PathRelation::OnLink
            ));
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn linux_targeted_path_reports_the_flow_correlation_boundary() {
        for target in [
            TargetIp::v4(Ipv4Addr::LOCALHOST),
            TargetIp::v6(Ipv6Addr::LOCALHOST, None),
        ] {
            let result = capture_current_operation_path(&target, Duration::from_secs(1)).await;
            assert!(matches!(
                result,
                CapabilityValue::Unavailable {
                    reason: CapabilityReason::QuerySemanticsUnavailable,
                    ..
                }
            ));
        }
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn macos_targeted_path_reports_the_proven_capability_boundary() {
        for target in [
            TargetIp::v4(Ipv4Addr::LOCALHOST),
            TargetIp::v6(Ipv6Addr::LOCALHOST, None),
        ] {
            let result = capture_current_operation_path(&target, Duration::from_secs(1)).await;
            assert!(matches!(
                result,
                CapabilityValue::Unavailable {
                    reason: CapabilityReason::QuerySemanticsUnavailable,
                    ..
                }
            ));
        }
    }
}
