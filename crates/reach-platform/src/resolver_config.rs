use std::time::Duration;

use reach_core::{
    CapabilityReason, CapabilityValue, InterfaceFact, Provenance, ProvenanceSource,
    ResolverConfiguration,
};

pub fn capture_resolver_configuration(
    observed_at: Duration,
    interfaces: &CapabilityValue<Vec<InterfaceFact>>,
) -> CapabilityValue<ResolverConfiguration> {
    let provenance = Provenance::new(ProvenanceSource::ResolverConfigurationSnapshot)
        .at(observed_at)
        .with_detail(platform::SOURCE_DETAIL);
    match platform::capture(interfaces, &provenance) {
        Ok(configuration) => CapabilityValue::available(configuration, provenance),
        Err(error) => CapabilityValue::unavailable(CapabilityReason::Other(error), provenance),
    }
}

#[cfg(windows)]
mod platform {
    use std::collections::HashSet;

    use reach_core::{
        CapabilityReason, CapabilityValue, InterfaceFact, InterfaceId, Provenance,
        ResolverConfiguration, ResolverEndpoint, ResolverTransport,
    };

    pub const SOURCE_DETAIL: &str = "ipconfig typed IP Helper and registry configuration";

    pub fn capture(
        interfaces: &CapabilityValue<Vec<InterfaceFact>>,
        provenance: &Provenance,
    ) -> Result<ResolverConfiguration, String> {
        let adapters = ipconfig::get_adapters().map_err(|error| error.to_string())?;
        let mut endpoints = Vec::new();
        let mut limitations = Vec::new();

        for adapter in adapters {
            if !matches!(
                adapter.oper_status(),
                ipconfig::OperStatus::IfOperStatusUp | ipconfig::OperStatus::IfOperStatusDormant
            ) {
                if !adapter.dns_servers().is_empty() {
                    limitations.push(format!(
                        "DNS servers on inactive adapter {} were retained only as a limitation, not as active candidates",
                        adapter.adapter_name()
                    ));
                }
                continue;
            }
            let interface = bind_adapter(adapter.adapter_name(), interfaces);
            if interface.is_none() && !adapter.dns_servers().is_empty() {
                limitations.push(format!(
                    "DNS adapter {} could not be bound to the interface snapshot",
                    adapter.adapter_name()
                ));
            }
            for (ordinal, address) in adapter.dns_servers().iter().enumerate() {
                endpoints.push(ResolverEndpoint {
                    address: *address,
                    port: 53,
                    // IP Helper exposes the server address but not whether the
                    // system resolver selected classic DNS, DoH, or another
                    // policy-managed transport for this query. Core must not
                    // silently substitute UDP for an unproven real transport.
                    transport: ResolverTransport::Unknown,
                    interface: interface.clone(),
                    domains: Vec::new(),
                    priority: Some(ordinal as u64),
                    provenance: provenance.clone().with_detail(format!(
                        "adapter={}; per-adapter DNS ordinal={ordinal}",
                        adapter.adapter_name()
                    )),
                });
            }
        }

        let mut search_domains = match ipconfig::computer::get_search_list() {
            Ok(domains) => domains,
            Err(error) => {
                limitations.push(format!("global DNS search list unavailable: {error}"));
                Vec::new()
            }
        };
        match ipconfig::computer::get_domain() {
            Ok(Some(domain)) if !domain.is_empty() => search_domains.push(domain),
            Ok(_) => {}
            Err(error) => limitations.push(format!("primary DNS suffix unavailable: {error}")),
        }
        stable_deduplicate(&mut search_domains);
        limitations.push(
            "ipconfig exposes server addresses but not the selected DNS transport; connection-specific suffixes and non-DNS resolver sources are also incomplete"
                .into(),
        );

        let dns_protocol_candidates_applicable = if endpoints.is_empty() {
            CapabilityValue::unknown(
                CapabilityReason::QuerySemanticsUnavailable,
                provenance
                    .clone()
                    .with_detail("no classic endpoint was exposed, but DNS policy is incomplete"),
            )
        } else {
            CapabilityValue::available(
                true,
                provenance
                    .clone()
                    .with_detail("active-adapter DNS endpoint presence"),
            )
        };
        Ok(ResolverConfiguration {
            endpoints,
            search_domains,
            non_dns_sources: Vec::new(),
            dns_protocol_candidates_applicable,
            // DNS order is semantic inside one adapter, but IP Helper does not
            // expose a total semantic order across adapters.
            ordering_is_semantic: false,
            limitations,
            provenance: provenance.clone(),
        })
    }

    fn bind_adapter(
        adapter_name: &str,
        interfaces: &CapabilityValue<Vec<InterfaceFact>>,
    ) -> Option<InterfaceId> {
        let CapabilityValue::Available { value, .. } = interfaces else {
            return None;
        };
        let mut matches = value.iter().filter(|interface| {
            interface.id.stable_id.as_deref() == Some(adapter_name)
                || interface.system_name == adapter_name
        });
        let first = matches.next()?;
        matches.next().is_none().then(|| first.id.clone())
    }

    fn stable_deduplicate(values: &mut Vec<String>) {
        let mut seen = HashSet::new();
        values.retain(|value| seen.insert(value.clone()));
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{fs, net::IpAddr, path::Path};

    use gai_core::{config::parse_nsswitch, types::NssSource};
    use reach_core::{
        CapabilityReason, CapabilityValue, InterfaceFact, InterfaceId, Provenance,
        ResolverConfiguration, ResolverEndpoint, ResolverTransport,
    };
    use resolv_conf::{Config, ScopedIp};

    pub const SOURCE_DETAIL: &str =
        "resolv-conf /etc/resolv.conf plus gai-core /etc/nsswitch.conf snapshot";

    pub fn capture(
        interfaces: &CapabilityValue<Vec<InterfaceFact>>,
        provenance: &Provenance,
    ) -> Result<ResolverConfiguration, String> {
        let path = Path::new("/etc/resolv.conf");
        let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let (configuration, parse_errors) = Config::parse_with_errors(&bytes);
        let mut limitations: Vec<String> = parse_errors
            .into_iter()
            .map(|error| format!("resolv.conf parse limitation: {error}"))
            .collect();
        let transport = if configuration.use_vc {
            ResolverTransport::Tcp
        } else {
            ResolverTransport::Udp
        };
        let mut endpoints = Vec::with_capacity(configuration.nameservers.len());
        for (ordinal, server) in configuration.nameservers.iter().enumerate() {
            let (address, interface) = scoped_server(server, interfaces, &mut limitations);
            endpoints.push(ResolverEndpoint {
                address,
                port: 53,
                transport,
                interface,
                domains: Vec::new(),
                priority: (!configuration.rotate).then_some(ordinal as u64),
                provenance: provenance
                    .clone()
                    .with_detail(format!("/etc/resolv.conf nameserver ordinal={ordinal}")),
            });
        }
        if endpoints
            .iter()
            .any(|endpoint| endpoint.address == IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 53)))
        {
            limitations.push(
                "127.0.0.53 is a systemd-resolved stub; upstream resolver identity is not exposed by resolv.conf"
                    .into(),
            );
        }
        let (non_dns_sources, dns_protocol_candidates_applicable) =
            match parse_nsswitch(Path::new("/etc/nsswitch.conf")) {
                Ok(configuration) => {
                    let applicable = nss_dns_is_applicable(&configuration);
                    (
                        nss_non_dns_sources(&configuration),
                        CapabilityValue::available(
                            applicable,
                            provenance
                                .clone()
                                .with_detail("gai-core parsed nsswitch hosts source policy"),
                        ),
                    )
                }
                Err(error) => {
                    limitations.push(format!("nsswitch hosts source order unavailable: {error}"));
                    (
                        Vec::new(),
                        CapabilityValue::unknown(
                            CapabilityReason::QuerySemanticsUnavailable,
                            provenance
                                .clone()
                                .with_detail("nsswitch hosts source policy could not be parsed"),
                        ),
                    )
                }
            };
        limitations.push("split-DNS state is not represented by resolv.conf alone".into());

        Ok(ResolverConfiguration {
            endpoints,
            search_domains: configuration.get_last_search_or_domain().cloned().collect(),
            non_dns_sources,
            dns_protocol_candidates_applicable,
            ordering_is_semantic: !configuration.rotate,
            limitations,
            provenance: provenance.clone(),
        })
    }

    fn nss_non_dns_sources(configuration: &gai_core::types::NsswitchConfig) -> Vec<String> {
        configuration
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, entry)| !matches!(entry.source, NssSource::Dns))
            .map(|(ordinal, entry)| {
                format!(
                    "hosts source ordinal={ordinal}; source={:?}; criteria={:?}",
                    entry.source, entry.criteria
                )
            })
            .collect()
    }

    fn nss_dns_is_applicable(configuration: &gai_core::types::NsswitchConfig) -> bool {
        configuration
            .hosts
            .iter()
            .any(|entry| matches!(entry.source, NssSource::Dns))
    }

    fn scoped_server(
        server: &ScopedIp,
        interfaces: &CapabilityValue<Vec<InterfaceFact>>,
        limitations: &mut Vec<String>,
    ) -> (IpAddr, Option<InterfaceId>) {
        match server {
            ScopedIp::V4(address) => (IpAddr::V4(*address), None),
            ScopedIp::V6(address, None) => (IpAddr::V6(*address), None),
            ScopedIp::V6(address, Some(name)) => {
                let interface = bind_interface_name(name, interfaces);
                if interface.is_none() {
                    limitations.push(format!(
                        "resolver scope {name} could not be bound to the interface snapshot"
                    ));
                }
                (IpAddr::V6(*address), interface)
            }
        }
    }

    fn bind_interface_name(
        name: &str,
        interfaces: &CapabilityValue<Vec<InterfaceFact>>,
    ) -> Option<InterfaceId> {
        let CapabilityValue::Available { value, .. } = interfaces else {
            return None;
        };
        let mut matches = value
            .iter()
            .filter(|interface| interface.system_name == name);
        let first = matches.next()?;
        matches.next().is_none().then(|| first.id.clone())
    }

    #[cfg(test)]
    mod tests {
        use gai_core::types::{NssEntry, NsswitchConfig};

        use super::*;

        #[test]
        fn nss_mapping_preserves_non_dns_source_order_without_promoting_dns() {
            let configuration = NsswitchConfig {
                hosts: vec![
                    NssEntry {
                        source: NssSource::Files,
                        criteria: Vec::new(),
                    },
                    NssEntry {
                        source: NssSource::Dns,
                        criteria: Vec::new(),
                    },
                    NssEntry {
                        source: NssSource::Mdns4Minimal,
                        criteria: Vec::new(),
                    },
                ],
            };
            let facts = nss_non_dns_sources(&configuration);
            assert_eq!(facts.len(), 2);
            assert!(facts[0].contains("ordinal=0"));
            assert!(facts[0].contains("Files"));
            assert!(facts[1].contains("ordinal=2"));
            assert!(facts[1].contains("Mdns4Minimal"));
            assert!(facts.iter().all(|fact| !fact.contains("Dns")));
            assert!(nss_dns_is_applicable(&configuration));

            let without_dns = NsswitchConfig {
                hosts: configuration
                    .hosts
                    .into_iter()
                    .filter(|entry| !matches!(entry.source, NssSource::Dns))
                    .collect(),
            };
            assert!(!nss_dns_is_applicable(&without_dns));
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{collections::HashSet, net::IpAddr};

    use reach_core::{
        CapabilityReason, CapabilityValue, InterfaceFact, InterfaceId, Provenance,
        ResolverConfiguration, ResolverEndpoint, ResolverTransport,
    };
    use system_configuration::{
        core_foundation::{
            array::CFArray,
            base::{CFType, TCFType, ToVoid},
            dictionary::CFDictionary,
            number::CFNumber,
            propertylist::CFPropertyList,
            string::CFString,
        },
        dynamic_store::SCDynamicStoreBuilder,
    };

    pub const SOURCE_DETAIL: &str = "SystemConfiguration dynamic-store DNS snapshot";

    struct DnsDictionary {
        key: String,
        addresses: Vec<IpAddr>,
        search_domains: Vec<String>,
        match_domains: Vec<String>,
        interface_name: Option<String>,
        port: u16,
        priority: Option<u64>,
    }

    pub fn capture(
        interfaces: &CapabilityValue<Vec<InterfaceFact>>,
        provenance: &Provenance,
    ) -> Result<ResolverConfiguration, String> {
        let store = SCDynamicStoreBuilder::new("reach-resolver-snapshot")
            .build()
            .ok_or_else(|| {
                "unable to create SystemConfiguration dynamic-store session".to_owned()
            })?;
        let keys = store
            .get_keys("State:/Network/(Global|Service/.+)/DNS")
            .ok_or_else(|| "unable to enumerate SystemConfiguration DNS keys".to_owned())?;
        let mut dictionaries = Vec::new();
        let mut limitations = Vec::new();

        for key in keys.iter() {
            let key_string = key.to_string();
            let Some(dictionary) = store
                .get(key.clone())
                .and_then(CFPropertyList::downcast_into::<CFDictionary>)
            else {
                limitations.push(format!(
                    "DNS dynamic-store value {key_string} is not a dictionary"
                ));
                continue;
            };
            let mut addresses = Vec::new();
            for raw in read_string_array(
                &dictionary,
                "ServerAddresses",
                &key_string,
                &mut limitations,
            ) {
                match raw.parse() {
                    Ok(address) => addresses.push(address),
                    Err(_) => limitations.push(format!(
                        "DNS dynamic-store value {key_string} contains invalid server address {raw}"
                    )),
                }
            }
            let search_domains =
                read_string_array(&dictionary, "SearchDomains", &key_string, &mut limitations);
            let match_domains = read_string_array(
                &dictionary,
                "SupplementalMatchDomains",
                &key_string,
                &mut limitations,
            );
            let interface_name =
                read_string(&dictionary, "InterfaceName", &key_string, &mut limitations);
            let (port, port_is_valid) =
                read_port(&dictionary, "ServerPort", &key_string, &mut limitations);
            if !port_is_valid {
                addresses.clear();
            }
            let (supplemental_priorities, supplemental_priority_is_valid) = read_number_array(
                &dictionary,
                "SupplementalMatchOrders",
                &key_string,
                &mut limitations,
            );
            let (search_priority, search_priority_is_valid) =
                read_number(&dictionary, "SearchOrder", &key_string, &mut limitations);
            let raw_priority = if supplemental_priority_is_valid && search_priority_is_valid {
                supplemental_priorities
                    .and_then(|values| values.first().copied())
                    .or(search_priority)
            } else {
                None
            };
            let priority = raw_priority.and_then(|value| match u64::try_from(value) {
                Ok(value) => Some(value),
                Err(_) => {
                    limitations.push(format!(
                        "DNS dynamic-store value {key_string} contains a negative resolver priority"
                    ));
                    None
                }
            });
            dictionaries.push(DnsDictionary {
                key: key_string,
                addresses,
                search_domains,
                match_domains,
                interface_name,
                port,
                priority,
            });
        }
        dictionaries.sort_by(|left, right| {
            left.priority
                .unwrap_or(u64::MAX)
                .cmp(&right.priority.unwrap_or(u64::MAX))
                .then_with(|| left.key.cmp(&right.key))
        });

        let ordering_is_semantic = dictionaries.len() <= 1
            || dictionaries
                .iter()
                .all(|dictionary| dictionary.priority.is_some());
        let mut endpoints = Vec::new();
        let mut search_domains = Vec::new();
        for dictionary in dictionaries {
            search_domains.extend(dictionary.search_domains.clone());
            let interface = dictionary.interface_name.as_deref().and_then(|name| {
                let bound = bind_interface_name(name, interfaces);
                if bound.is_none() {
                    limitations.push(format!(
                        "DNS interface {name} could not be bound to the interface snapshot"
                    ));
                }
                bound
            });
            for (ordinal, address) in dictionary.addresses.into_iter().enumerate() {
                endpoints.push(ResolverEndpoint {
                    address,
                    port: dictionary.port,
                    // The public dynamic store identifies resolver addresses
                    // but does not reliably prove the transport selected for
                    // this query (including encrypted/private resolver paths).
                    transport: ResolverTransport::Unknown,
                    interface: interface.clone(),
                    domains: dictionary.match_domains.clone(),
                    priority: dictionary
                        .priority
                        .map(|priority| priority.saturating_add(ordinal as u64)),
                    provenance: provenance
                        .clone()
                        .with_detail(format!("SystemConfiguration key={}", dictionary.key)),
                });
            }
        }
        stable_deduplicate(&mut search_domains);
        limitations.push(
            "encrypted/private resolver transports and non-DNS resolver sources may not be represented in the public dynamic store"
                .into(),
        );

        let dns_protocol_candidates_applicable = if endpoints.is_empty() {
            CapabilityValue::unknown(
                CapabilityReason::QuerySemanticsUnavailable,
                provenance.clone().with_detail(
                    "no classic endpoint was exposed, but private resolver policy may be hidden",
                ),
            )
        } else {
            CapabilityValue::available(
                true,
                provenance
                    .clone()
                    .with_detail("SystemConfiguration DNS endpoint presence"),
            )
        };
        Ok(ResolverConfiguration {
            endpoints,
            search_domains,
            non_dns_sources: Vec::new(),
            dns_protocol_candidates_applicable,
            ordering_is_semantic,
            limitations,
            provenance: provenance.clone(),
        })
    }

    fn dictionary_value(dictionary: &CFDictionary, key: &str) -> Option<CFType> {
        let key = CFString::new(key);
        dictionary
            .find(key.to_void())
            .map(|pointer| unsafe { CFType::wrap_under_get_rule(*pointer) })
    }

    fn string_value(dictionary: &CFDictionary, key: &str) -> Result<Option<String>, ()> {
        let Some(value) = dictionary_value(dictionary, key) else {
            return Ok(None);
        };
        value
            .downcast_into::<CFString>()
            .map(|value| Some(value.to_string()))
            .ok_or(())
    }

    fn string_array(dictionary: &CFDictionary, key: &str) -> Result<Option<Vec<String>>, ()> {
        let Some(value) = dictionary_value(dictionary, key) else {
            return Ok(None);
        };
        let array = value.downcast_into::<CFArray>().ok_or(())?;
        let mut values = Vec::with_capacity(array.len() as usize);
        for pointer in &array {
            let value =
                unsafe { CFType::wrap_under_get_rule(*pointer) }.downcast_into::<CFString>();
            let value = value.ok_or(())?;
            values.push(value.to_string());
        }
        Ok(Some(values))
    }

    fn number_value(dictionary: &CFDictionary, key: &str) -> Result<Option<i64>, ()> {
        let Some(value) = dictionary_value(dictionary, key) else {
            return Ok(None);
        };
        value
            .downcast_into::<CFNumber>()
            .and_then(|value| value.to_i64())
            .map(Some)
            .ok_or(())
    }

    fn number_array(dictionary: &CFDictionary, key: &str) -> Result<Option<Vec<i64>>, ()> {
        let Some(value) = dictionary_value(dictionary, key) else {
            return Ok(None);
        };
        let array = value.downcast_into::<CFArray>().ok_or(())?;
        let mut values = Vec::with_capacity(array.len() as usize);
        for pointer in &array {
            let value = unsafe { CFType::wrap_under_get_rule(*pointer) }
                .downcast_into::<CFNumber>()
                .ok_or(())?
                .to_i64()
                .ok_or(())?;
            values.push(value);
        }
        Ok(Some(values))
    }

    fn read_string_array(
        dictionary: &CFDictionary,
        field: &str,
        source: &str,
        limitations: &mut Vec<String>,
    ) -> Vec<String> {
        match string_array(dictionary, field) {
            Ok(Some(values)) => values,
            Ok(None) => Vec::new(),
            Err(()) => {
                limitations.push(format!(
                    "DNS dynamic-store value {source} has a malformed {field} field"
                ));
                Vec::new()
            }
        }
    }

    fn read_string(
        dictionary: &CFDictionary,
        field: &str,
        source: &str,
        limitations: &mut Vec<String>,
    ) -> Option<String> {
        match string_value(dictionary, field) {
            Ok(value) => value,
            Err(()) => {
                limitations.push(format!(
                    "DNS dynamic-store value {source} has a malformed {field} field"
                ));
                None
            }
        }
    }

    fn read_number(
        dictionary: &CFDictionary,
        field: &str,
        source: &str,
        limitations: &mut Vec<String>,
    ) -> (Option<i64>, bool) {
        match number_value(dictionary, field) {
            Ok(value) => (value, true),
            Err(()) => {
                limitations.push(format!(
                    "DNS dynamic-store value {source} has a malformed {field} field"
                ));
                (None, false)
            }
        }
    }

    fn read_number_array(
        dictionary: &CFDictionary,
        field: &str,
        source: &str,
        limitations: &mut Vec<String>,
    ) -> (Option<Vec<i64>>, bool) {
        match number_array(dictionary, field) {
            Ok(value) => (value, true),
            Err(()) => {
                limitations.push(format!(
                    "DNS dynamic-store value {source} has a malformed {field} field"
                ));
                (None, false)
            }
        }
    }

    fn read_port(
        dictionary: &CFDictionary,
        field: &str,
        source: &str,
        limitations: &mut Vec<String>,
    ) -> (u16, bool) {
        match number_value(dictionary, field) {
            Ok(None) => (53, true),
            Ok(Some(value)) => match u16::try_from(value).ok().filter(|port| *port != 0) {
                Some(port) => (port, true),
                None => {
                    limitations.push(format!(
                        "DNS dynamic-store value {source} contains an invalid {field} field"
                    ));
                    (53, false)
                }
            },
            Err(()) => {
                limitations.push(format!(
                    "DNS dynamic-store value {source} has a malformed {field} field"
                ));
                (53, false)
            }
        }
    }

    fn bind_interface_name(
        name: &str,
        interfaces: &CapabilityValue<Vec<InterfaceFact>>,
    ) -> Option<InterfaceId> {
        let CapabilityValue::Available { value, .. } = interfaces else {
            return None;
        };
        let mut matches = value
            .iter()
            .filter(|interface| interface.system_name == name);
        let first = matches.next()?;
        matches.next().is_none().then(|| first.id.clone())
    }

    fn stable_deduplicate(values: &mut Vec<String>) {
        let mut seen = HashSet::new();
        values.retain(|value| seen.insert(value.clone()));
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    use reach_core::{CapabilityValue, InterfaceFact, Provenance, ResolverConfiguration};

    pub const SOURCE_DETAIL: &str = "no resolver configuration adapter";

    pub fn capture(
        _interfaces: &CapabilityValue<Vec<InterfaceFact>>,
        _provenance: &Provenance,
    ) -> Result<ResolverConfiguration, String> {
        Err("resolver configuration is unsupported on this target".into())
    }
}
