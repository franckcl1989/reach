use std::time::Duration;

use netdev::interface::state::OperState;
use reach_core::{
    CapabilityReason, CapabilityValue, InterfaceAddress, InterfaceFact, InterfaceId,
    InterfaceState, Provenance, ProvenanceSource,
};

#[must_use]
pub fn capture_interfaces(observed_at: Duration) -> CapabilityValue<Vec<InterfaceFact>> {
    let provenance = Provenance::new(ProvenanceSource::InterfaceSnapshot)
        .at(observed_at)
        .with_detail("netdev passive interface enumeration; gateway feature disabled");
    let interfaces = netdev::get_interfaces();

    if interfaces.is_empty() {
        return CapabilityValue::unknown(
            CapabilityReason::Other(
                "netdev returned no interfaces and exposes no enumeration error".into(),
            ),
            provenance,
        );
    }

    let facts =
        interfaces
            .into_iter()
            .map(|interface| {
                let fact_provenance = provenance.clone();
                let administrative_state = if interface.is_up() {
                    InterfaceState::Up
                } else {
                    InterfaceState::Down
                };
                let is_loopback = interface.is_loopback();
                let operational_state = map_operational_state(interface.oper_state);
                let stable_id = stable_interface_id(&interface.name);
                let display_name = interface
                    .friendly_name
                    .clone()
                    .unwrap_or_else(|| interface.name.clone());
                let mut addresses = Vec::with_capacity(interface.ipv4.len() + interface.ipv6.len());
                addresses.extend(interface.ipv4.into_iter().map(|network| InterfaceAddress {
                    network: network.into(),
                    scope_id: None,
                    provenance: fact_provenance.clone(),
                }));
                addresses.extend(interface.ipv6.into_iter().enumerate().map(
                    |(ordinal, network)| {
                        InterfaceAddress {
                            network: network.into(),
                            scope_id: interface
                                .ipv6_scope_ids
                                .get(ordinal)
                                .copied()
                                .filter(|scope_id| *scope_id != 0),
                            provenance: fact_provenance.clone(),
                        }
                    },
                ));

                InterfaceFact {
                    id: InterfaceId {
                        index: interface.index,
                        stable_id,
                    },
                    system_name: interface.name,
                    display_name,
                    administrative_state,
                    operational_state,
                    is_loopback,
                    addresses,
                    provenance: fact_provenance,
                }
            })
            .collect();

    CapabilityValue::available(facts, provenance)
}

fn map_operational_state(state: OperState) -> InterfaceState {
    match state {
        OperState::Up => InterfaceState::Up,
        OperState::Dormant | OperState::Testing => InterfaceState::Dormant,
        OperState::Down | OperState::LowerLayerDown | OperState::NotPresent => InterfaceState::Down,
        OperState::Unknown => InterfaceState::Unknown,
    }
}

fn stable_interface_id(system_name: &str) -> Option<String> {
    #[cfg(windows)]
    {
        Some(system_name.to_owned())
    }
    #[cfg(not(windows))]
    {
        let _ = system_name;
        None
    }
}
