use thiserror::Error;

use crate::{
    BoundAddressInput, CapabilityValue, DiagnosticRequest, FormalTarget, InterfaceFact,
    InterfaceId, ParsedAddress, ParsedRequest, ScopeSyntax, TargetIp,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScopeBindingError {
    #[error("the interface snapshot is unavailable, so the IPv6 scope cannot be confirmed")]
    InterfacesUnavailable,
    #[error("the IPv6 scope does not identify an interface in the initial snapshot")]
    InterfaceNotFound,
    #[error("the IPv6 scope maps to more than one interface in the initial snapshot")]
    AmbiguousInterface,
}

/// Forms an IP-literal target after the initial snapshot exists. Hostnames
/// return `None` because their targets must come only from the system resolver.
pub fn form_literal_target(
    address: &ParsedAddress,
    interfaces: &CapabilityValue<Vec<InterfaceFact>>,
) -> Result<Option<FormalTarget>, ScopeBindingError> {
    let target = match address {
        ParsedAddress::Ipv4(address) => TargetIp::v4(*address),
        ParsedAddress::Ipv6 {
            address,
            scope: None,
        } => TargetIp::v6(*address, None),
        ParsedAddress::Ipv6 {
            address,
            scope: Some(scope),
        } => TargetIp::v6(*address, Some(bind_scope(scope, interfaces)?)),
        ParsedAddress::Hostname(_) => return Ok(None),
    };
    Ok(Some(FormalTarget {
        target,
        resolver_ordinal: None,
    }))
}

pub fn bind_diagnostic_request(
    parsed: &ParsedRequest,
    interfaces: &CapabilityValue<Vec<InterfaceFact>>,
) -> Result<DiagnosticRequest, ScopeBindingError> {
    let address = match &parsed.address {
        ParsedAddress::Hostname(hostname) => BoundAddressInput::Hostname(hostname.clone()),
        ParsedAddress::Ipv4(_) => {
            let target = form_literal_target(&parsed.address, interfaces)?
                .expect("an IPv4 literal always forms a literal target")
                .target;
            BoundAddressInput::Ipv4Literal(target)
        }
        ParsedAddress::Ipv6 { .. } => {
            let target = form_literal_target(&parsed.address, interfaces)?
                .expect("an IPv6 literal always forms a literal target")
                .target;
            BoundAddressInput::Ipv6Literal(target)
        }
    };
    Ok(DiagnosticRequest {
        original_address: parsed.original_address.clone(),
        address,
        port: parsed.port,
    })
}

fn bind_scope(
    scope: &ScopeSyntax,
    interfaces: &CapabilityValue<Vec<InterfaceFact>>,
) -> Result<InterfaceId, ScopeBindingError> {
    let CapabilityValue::Available { value, .. } = interfaces else {
        return Err(ScopeBindingError::InterfacesUnavailable);
    };
    let mut matches = value.iter().filter(|interface| match scope {
        ScopeSyntax::InterfaceIndex(index) => interface.id.index == index.get(),
        ScopeSyntax::InterfaceName(name) => {
            interface.system_name == *name || interface.display_name == *name
        }
    });
    let Some(interface) = matches.next() else {
        return Err(ScopeBindingError::InterfaceNotFound);
    };
    if matches.next().is_some() {
        return Err(ScopeBindingError::AmbiguousInterface);
    }
    Ok(interface.id.clone())
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv6Addr, time::Duration};

    use ipnet::IpNet;

    use super::*;
    use crate::{InterfaceAddress, InterfaceState, Provenance, ProvenanceSource, parse_request};

    fn interface(index: u32, system_name: &str, display_name: &str) -> InterfaceFact {
        let provenance = Provenance::new(ProvenanceSource::SyntheticTest).at(Duration::ZERO);
        InterfaceFact {
            id: InterfaceId {
                index,
                stable_id: Some(format!("stable-{index}")),
            },
            system_name: system_name.into(),
            display_name: display_name.into(),
            administrative_state: InterfaceState::Up,
            operational_state: InterfaceState::Up,
            is_loopback: false,
            addresses: vec![InterfaceAddress {
                network: IpNet::new(Ipv6Addr::LOCALHOST.into(), 128).unwrap(),
                scope_id: Some(index),
                provenance: provenance.clone(),
            }],
            provenance,
        }
    }

    fn snapshot(interfaces: Vec<InterfaceFact>) -> CapabilityValue<Vec<InterfaceFact>> {
        CapabilityValue::available(interfaces, Provenance::new(ProvenanceSource::SyntheticTest))
    }

    #[test]
    fn binds_numeric_scope_to_snapshot_identity() {
        let request = parse_request("fe80::1%7", None).unwrap();
        let target = form_literal_target(
            &request.address,
            &snapshot(vec![interface(7, "eth0", "Ethernet")]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            target.target.scope.unwrap().stable_id.as_deref(),
            Some("stable-7")
        );
    }

    #[test]
    fn binds_system_or_display_name_only_when_unique() {
        let request = parse_request("fe80::1%Ethernet", None).unwrap();
        let target = form_literal_target(
            &request.address,
            &snapshot(vec![interface(7, "eth0", "Ethernet")]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(target.target.scope.unwrap().index, 7);

        let ambiguous = snapshot(vec![
            interface(7, "eth0", "Ethernet"),
            interface(8, "eth1", "Ethernet"),
        ]);
        assert_eq!(
            form_literal_target(&request.address, &ambiguous),
            Err(ScopeBindingError::AmbiguousInterface)
        );
    }

    #[test]
    fn refuses_to_guess_when_interface_facts_are_missing() {
        let request = parse_request("fe80::1%7", None).unwrap();
        let unavailable = CapabilityValue::unavailable(
            crate::CapabilityReason::UnsupportedEnvironment,
            Provenance::new(ProvenanceSource::SyntheticTest),
        );
        assert_eq!(
            form_literal_target(&request.address, &unavailable),
            Err(ScopeBindingError::InterfacesUnavailable)
        );
    }

    #[test]
    fn bound_request_keeps_hostname_without_inventing_a_target() {
        let parsed = parse_request("example.com", Some("443")).unwrap();
        let request = bind_diagnostic_request(&parsed, &snapshot(Vec::new())).unwrap();
        assert!(matches!(request.address, BoundAddressInput::Hostname(_)));
        assert_eq!(request.port.map(std::num::NonZeroU16::get), Some(443));
    }
}
