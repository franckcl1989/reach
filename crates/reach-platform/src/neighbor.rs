use std::{future::Future, time::Duration};

use reach_core::{
    CapabilityReason, CapabilityValue, NeighborFact, NeighborIdentity, NeighborState, Provenance,
    ProvenanceSource,
};
pub use reach_core::{NEIGHBOR_CONVERGENCE_BUDGET, NEIGHBOR_POLL_INTERVAL};
use tokio_util::sync::CancellationToken;

use crate::{ContinuousClock, PlatformError, clock::wait_until_continuous_deadline};

/// Performs a passive, identity-specific Neighbor cache read. The call never
/// initiates Neighbor resolution and is therefore safe at the pre-state time
/// boundary defined by the product contract.
pub async fn capture_neighbor(
    identity: &NeighborIdentity,
    observed_at: Duration,
) -> CapabilityValue<NeighborFact> {
    let provenance = Provenance::new(ProvenanceSource::NeighborQuery)
        .at(observed_at)
        .with_detail(neighbor_source_detail());
    match platform_neighbor(identity).await {
        Ok(Some((state, raw_state))) => CapabilityValue::available(
            NeighborFact {
                identity: identity.clone(),
                state,
                observed_at,
                raw_state: Some(raw_state),
                provenance: provenance.clone(),
            },
            provenance,
        ),
        Ok(None) => CapabilityValue::available(
            NeighborFact {
                identity: identity.clone(),
                state: NeighborState::Absent,
                observed_at,
                raw_state: Some("absent".into()),
                provenance: provenance.clone(),
            },
            provenance,
        ),
        Err(NeighborQueryError::Unavailable(reason)) => {
            CapabilityValue::unavailable(reason, provenance)
        }
        #[cfg(target_os = "linux")]
        Err(NeighborQueryError::Inconsistent(detail)) => CapabilityValue::unknown(
            CapabilityReason::SnapshotInconsistent,
            provenance.with_detail(detail),
        ),
    }
}

/// Passively waits for a resolving Neighbor entry to reach a terminal or
/// usable state. It performs only cache reads and never sends a packet.
pub async fn observe_neighbor_convergence(
    identity: &NeighborIdentity,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<CapabilityValue<NeighborFact>, PlatformError> {
    observe_neighbor_convergence_with(
        identity,
        cancellation,
        clock,
        |identity, observed_at| async move { capture_neighbor(&identity, observed_at).await },
    )
    .await
}

async fn observe_neighbor_convergence_with<F, Fut>(
    identity: &NeighborIdentity,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
    mut capture: F,
) -> Result<CapabilityValue<NeighborFact>, PlatformError>
where
    F: FnMut(NeighborIdentity, Duration) -> Fut,
    Fut: Future<Output = CapabilityValue<NeighborFact>>,
{
    let started_at = clock.now()?;
    let deadline_at = started_at.saturating_add(NEIGHBOR_CONVERGENCE_BUDGET);
    loop {
        if cancellation.is_cancelled() {
            return Err(PlatformError::OperationCancelled);
        }
        let observed_at = clock.now()?;
        let observation = capture(identity.clone(), observed_at).await;
        if !matches!(
            &observation,
            CapabilityValue::Available {
                value: NeighborFact {
                    state: NeighborState::Resolving,
                    ..
                },
                ..
            }
        ) || observed_at >= deadline_at
        {
            return Ok(observation);
        }
        let next_observation_at = observed_at
            .saturating_add(NEIGHBOR_POLL_INTERVAL)
            .min(deadline_at);
        wait_until_continuous_deadline(next_observation_at, cancellation, clock).await?;
    }
}

#[derive(Debug)]
enum NeighborQueryError {
    Unavailable(CapabilityReason),
    #[cfg(target_os = "linux")]
    Inconsistent(String),
}

#[cfg(target_os = "linux")]
async fn platform_neighbor(
    identity: &NeighborIdentity,
) -> Result<Option<(NeighborState, String)>, NeighborQueryError> {
    use futures_util::TryStreamExt;
    use netlink_packet_route::{
        AddressFamily as NetlinkAddressFamily,
        neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourState as LinuxState},
    };
    use rtnetlink::new_connection;

    let (connection, handle, _) = new_connection().map_err(|error| {
        NeighborQueryError::Unavailable(CapabilityReason::Other(format!(
            "rtnetlink connection failed: {error}"
        )))
    })?;
    tokio::spawn(connection);
    let family = match identity.family {
        reach_core::AddressFamily::Ipv4 => NetlinkAddressFamily::Inet,
        reach_core::AddressFamily::Ipv6 => NetlinkAddressFamily::Inet6,
    };
    let mut messages = handle
        .neighbours()
        .get()
        .set_address_family(family)
        .execute();
    let mut matches = Vec::new();
    while let Some(message) = messages.try_next().await.map_err(|error| {
        NeighborQueryError::Unavailable(CapabilityReason::Other(format!(
            "rtnetlink Neighbor dump failed: {error}"
        )))
    })? {
        if message.header.ifindex != identity.interface.index {
            continue;
        }
        let destination = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                NeighbourAttribute::Destination(NeighbourAddress::Inet(address)) => {
                    Some(std::net::IpAddr::V4(*address))
                }
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(address)) => {
                    Some(std::net::IpAddr::V6(*address))
                }
                _ => None,
            });
        if destination != Some(identity.address) {
            continue;
        }
        let state = match message.header.state {
            LinuxState::Incomplete => NeighborState::Resolving,
            LinuxState::Reachable
            | LinuxState::Stale
            | LinuxState::Delay
            | LinuxState::Probe
            | LinuxState::Noarp
            | LinuxState::Permanent => NeighborState::Usable,
            LinuxState::Failed => NeighborState::TerminalFailure,
            LinuxState::None | LinuxState::Other(_) => NeighborState::Unknown,
            _ => NeighborState::Unknown,
        };
        matches.push((state, message.header.state.to_string()));
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        count => Err(NeighborQueryError::Inconsistent(format!(
            "rtnetlink returned {count} entries for one Neighbor identity"
        ))),
    }
}

#[cfg(windows)]
async fn platform_neighbor(
    identity: &NeighborIdentity,
) -> Result<Option<(NeighborState, String)>, NeighborQueryError> {
    use windows_sys::Win32::{
        Foundation::{ERROR_NOT_FOUND, NO_ERROR},
        NetworkManagement::IpHelper::{GetIpNetEntry2, MIB_IPNET_ROW2},
        Networking::WinSock::{
            NlnsDelay as NLNS_DELAY, NlnsIncomplete as NLNS_INCOMPLETE,
            NlnsPermanent as NLNS_PERMANENT, NlnsProbe as NLNS_PROBE,
            NlnsReachable as NLNS_REACHABLE, NlnsStale as NLNS_STALE,
            NlnsUnreachable as NLNS_UNREACHABLE,
        },
    };

    let mut row = MIB_IPNET_ROW2 {
        Address: crate::routes::windows_sockaddr(identity.address, identity.interface.index),
        InterfaceIndex: identity.interface.index,
        ..Default::default()
    };
    // SAFETY: row is initialized with the exact address/interface identity and
    // points to writable storage for the synchronous, read-only query.
    let status = unsafe { GetIpNetEntry2(&mut row) };
    if status == ERROR_NOT_FOUND {
        return Ok(None);
    }
    if status != NO_ERROR {
        return Err(NeighborQueryError::Unavailable(CapabilityReason::Other(
            format!("GetIpNetEntry2 failed with Windows error {status}"),
        )));
    }
    let state = match row.State {
        NLNS_INCOMPLETE => NeighborState::Resolving,
        NLNS_REACHABLE | NLNS_STALE | NLNS_DELAY | NLNS_PROBE | NLNS_PERMANENT => {
            NeighborState::Usable
        }
        NLNS_UNREACHABLE => NeighborState::TerminalFailure,
        _ => NeighborState::Unknown,
    };
    Ok(Some((state, format!("NL_NEIGHBOR_STATE({})", row.State))))
}

#[cfg(not(any(windows, target_os = "linux")))]
async fn platform_neighbor(
    _identity: &NeighborIdentity,
) -> Result<Option<(NeighborState, String)>, NeighborQueryError> {
    Err(NeighborQueryError::Unavailable(
        CapabilityReason::QuerySemanticsUnavailable,
    ))
}

const fn neighbor_source_detail() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "rtnetlink targeted filter over passive Neighbor dump"
    }
    #[cfg(windows)]
    {
        "Windows GetIpNetEntry2 identity-specific passive query"
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        "no selected mature ordinary-user Neighbor cache reader"
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, Ipv6Addr},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use reach_core::AddressFamily;

    use super::*;

    struct SequenceClock(Mutex<VecDeque<Duration>>);

    impl ContinuousClock for SequenceClock {
        fn now(&self) -> Result<Duration, PlatformError> {
            self.0
                .lock()
                .expect("test clock")
                .pop_front()
                .ok_or_else(|| PlatformError::ClockUnavailable("test clock exhausted".into()))
        }
    }

    #[tokio::test]
    async fn resolving_neighbor_observation_stops_at_the_exact_two_second_budget() {
        let identity = NeighborIdentity {
            family: AddressFamily::Ipv4,
            interface: reach_core::InterfaceId::from_index(1),
            address: Ipv4Addr::LOCALHOST.into(),
        };
        let clock = SequenceClock(Mutex::new(VecDeque::from([
            Duration::ZERO,
            Duration::ZERO,
            NEIGHBOR_CONVERGENCE_BUDGET,
            NEIGHBOR_CONVERGENCE_BUDGET,
        ])));
        let reads = AtomicUsize::new(0);
        let result = observe_neighbor_convergence_with(
            &identity,
            &CancellationToken::new(),
            &clock,
            |identity, observed_at| {
                reads.fetch_add(1, Ordering::SeqCst);
                std::future::ready(CapabilityValue::available(
                    NeighborFact {
                        identity,
                        state: NeighborState::Resolving,
                        observed_at,
                        raw_state: Some("synthetic resolving".into()),
                        provenance: Provenance::new(ProvenanceSource::SyntheticTest)
                            .at(observed_at),
                    },
                    Provenance::new(ProvenanceSource::SyntheticTest).at(observed_at),
                ))
            },
        )
        .await
        .expect("synthetic observation succeeds");
        let CapabilityValue::Available { value, .. } = result else {
            panic!("synthetic resolving fact must remain available");
        };
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(value.observed_at, NEIGHBOR_CONVERGENCE_BUDGET);
        assert_eq!(value.state, NeighborState::Resolving);
    }

    #[tokio::test]
    #[cfg(any(windows, target_os = "linux"))]
    async fn passive_missing_neighbor_is_observed_as_absent() {
        let interfaces = crate::capture_interfaces(Duration::ZERO);
        let CapabilityValue::Available {
            value: interfaces, ..
        } = interfaces
        else {
            panic!("interface enumeration is required by this native conformance test");
        };
        let interface = interfaces
            .into_iter()
            .find(|interface| interface.is_loopback)
            .expect("the native platform must expose a loopback interface");
        for identity in [
            NeighborIdentity {
                family: AddressFamily::Ipv4,
                interface: interface.id.clone(),
                address: Ipv4Addr::new(192, 0, 2, 254).into(),
            },
            NeighborIdentity {
                family: AddressFamily::Ipv6,
                interface: interface.id.clone(),
                address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x00fe).into(),
            },
        ] {
            let result = capture_neighbor(&identity, Duration::from_secs(1)).await;
            let CapabilityValue::Available { value, .. } = result else {
                panic!("a successful query with no entry is a known absence: {result:?}");
            };
            assert_eq!(value.identity, identity);
            assert_eq!(value.state, NeighborState::Absent);
            assert_eq!(value.raw_state.as_deref(), Some("absent"));
        }
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn macos_neighbor_read_reports_the_proven_capability_boundary() {
        for (family, address) in [
            (AddressFamily::Ipv4, Ipv4Addr::LOCALHOST.into()),
            (AddressFamily::Ipv6, Ipv6Addr::LOCALHOST.into()),
        ] {
            let identity = NeighborIdentity {
                family,
                interface: reach_core::InterfaceId::from_index(1),
                address,
            };
            let result = capture_neighbor(&identity, Duration::from_secs(1)).await;
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
