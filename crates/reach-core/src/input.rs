use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::{NonZeroU16, NonZeroU32},
    str::FromStr,
};

use thiserror::Error;

const MAX_SCOPE_NAME_BYTES: usize = 255;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRequest {
    pub original_address: String,
    pub address: ParsedAddress,
    pub port: Option<NonZeroU16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticRequest {
    pub original_address: String,
    pub address: BoundAddressInput,
    pub port: Option<NonZeroU16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundAddressInput {
    Ipv4Literal(crate::TargetIp),
    Ipv6Literal(crate::TargetIp),
    Hostname(Hostname),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedAddress {
    Ipv4(Ipv4Addr),
    Ipv6 {
        address: Ipv6Addr,
        scope: Option<ScopeSyntax>,
    },
    Hostname(Hostname),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ScopeSyntax {
    InterfaceIndex(NonZeroU32),
    InterfaceName(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Hostname {
    original: String,
    ascii: String,
}

impl Hostname {
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }

    #[must_use]
    pub fn ascii(&self) -> &str {
        &self.ascii
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InputError {
    #[error("address must not be empty")]
    EmptyAddress,
    #[error("address is not a valid hostname or IP literal")]
    InvalidAddress,
    #[error("IPv6 scope syntax is invalid")]
    InvalidIpv6Scope,
    #[error("port must contain only decimal digits")]
    InvalidPortSyntax,
    #[error("port must be in the range 1..=65535")]
    PortOutOfRange,
}

/// Performs only local parsing. Calling this function must never collect an OS
/// network snapshot, invoke a resolver, or produce network traffic.
pub fn parse_request(address: &str, port: Option<&str>) -> Result<ParsedRequest, InputError> {
    if address.is_empty() {
        return Err(InputError::EmptyAddress);
    }

    let port = port.map(parse_port).transpose()?;
    let parsed_address = parse_address(address)?;

    Ok(ParsedRequest {
        original_address: address.to_owned(),
        address: parsed_address,
        port,
    })
}

fn parse_port(raw: &str) -> Result<NonZeroU16, InputError> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(InputError::InvalidPortSyntax);
    }

    let value = raw.parse::<u32>().map_err(|_| InputError::PortOutOfRange)?;
    let value = u16::try_from(value).map_err(|_| InputError::PortOutOfRange)?;
    NonZeroU16::new(value).ok_or(InputError::PortOutOfRange)
}

fn parse_address(raw: &str) -> Result<ParsedAddress, InputError> {
    if let Ok(address) = Ipv4Addr::from_str(raw) {
        return Ok(ParsedAddress::Ipv4(address));
    }

    if let Ok(address) = Ipv6Addr::from_str(raw) {
        return Ok(ParsedAddress::Ipv6 {
            address,
            scope: None,
        });
    }

    if raw.contains('%') {
        return parse_scoped_ipv6(raw);
    }

    parse_hostname(raw).map(ParsedAddress::Hostname)
}

fn parse_scoped_ipv6(raw: &str) -> Result<ParsedAddress, InputError> {
    let (address, scope) = raw.split_once('%').ok_or(InputError::InvalidIpv6Scope)?;
    if scope.is_empty() || scope.contains('%') {
        return Err(InputError::InvalidIpv6Scope);
    }

    let address = Ipv6Addr::from_str(address).map_err(|_| InputError::InvalidIpv6Scope)?;
    let scope = parse_scope(scope)?;
    Ok(ParsedAddress::Ipv6 {
        address,
        scope: Some(scope),
    })
}

fn parse_scope(raw: &str) -> Result<ScopeSyntax, InputError> {
    if raw.bytes().all(|byte| byte.is_ascii_digit()) {
        let index = raw
            .parse::<u32>()
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(InputError::InvalidIpv6Scope)?;
        return Ok(ScopeSyntax::InterfaceIndex(index));
    }

    if raw.len() > MAX_SCOPE_NAME_BYTES
        || raw.chars().any(char::is_control)
        || raw.contains(['/', '\\', '[', ']'])
    {
        return Err(InputError::InvalidIpv6Scope);
    }

    Ok(ScopeSyntax::InterfaceName(raw.to_owned()))
}

fn parse_hostname(raw: &str) -> Result<Hostname, InputError> {
    // The crate deliberately rejects a terminal root dot. Reach accepts an
    // explicitly fully-qualified hostname, so that presentation marker is
    // removed before both mature parsers and restored in the normalized value.
    let (idna_input, fully_qualified) = match raw.strip_suffix('.') {
        Some(without_root_dot) => (without_root_dot, true),
        None => (raw, false),
    };
    let ascii_base =
        idna::domain_to_ascii_strict(idna_input).map_err(|_| InputError::InvalidAddress)?;
    if !hostname_validator::is_valid(&ascii_base) {
        return Err(InputError::InvalidAddress);
    }
    let ascii = if fully_qualified {
        format!("{ascii_base}.")
    } else {
        ascii_base
    };

    Ok(Hostname {
        original: raw.to_owned(),
        ascii,
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn parses_port_strictly() {
        assert_eq!(parse_port("1").map(NonZeroU16::get), Ok(1));
        assert_eq!(parse_port("65535").map(NonZeroU16::get), Ok(65_535));
        assert_eq!(parse_port("00080").map(NonZeroU16::get), Ok(80));
        assert_eq!(parse_port("0"), Err(InputError::PortOutOfRange));
        assert_eq!(parse_port("65536"), Err(InputError::PortOutOfRange));
        assert_eq!(parse_port("+80"), Err(InputError::InvalidPortSyntax));
        assert_eq!(parse_port(" 80"), Err(InputError::InvalidPortSyntax));
    }

    #[test]
    fn parses_scoped_ipv6_without_binding_it() {
        let parsed = parse_request("fe80::1%12", None).expect("valid scoped IPv6");
        assert!(matches!(
            parsed.address,
            ParsedAddress::Ipv6 {
                scope: Some(ScopeSyntax::InterfaceIndex(index)),
                ..
            } if index.get() == 12
        ));

        let parsed = parse_request("fe80::1%Ethernet 2", None).expect("valid interface name");
        assert!(matches!(
            parsed.address,
            ParsedAddress::Ipv6 {
                scope: Some(ScopeSyntax::InterfaceName(name)),
                ..
            } if name == "Ethernet 2"
        ));
    }

    #[test]
    fn hostname_contract_corpus_is_versioned_in_tests() {
        let accepted = [
            "localhost",
            "example.com",
            "EXAMPLE.COM.",
            "xn--bcher-kva.example",
            "bücher.example",
            "123.example",
            "999.999.999.999",
        ];
        for value in accepted {
            assert!(
                parse_request(value, None).is_ok(),
                "expected acceptance: {value}"
            );
        }

        let rejected = [
            "",
            ".",
            "example..com",
            "-example.com",
            "example-.com",
            "_service.example",
            "https://example.com",
            "user@example.com",
            "example.com/path",
            "example.com:443",
            "[::1]",
            "example.com\nforged",
        ];
        for value in rejected {
            assert!(
                parse_request(value, None).is_err(),
                "expected rejection: {value:?}"
            );
        }
    }

    #[test]
    fn invalid_input_does_not_require_a_platform_dependency() {
        assert_eq!(
            parse_request("example.com", Some("not-a-port")),
            Err(InputError::InvalidPortSyntax)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_untrusted_arguments_never_escape_the_input_result_model(
            address in any::<String>(),
            port in prop::option::of(any::<String>()),
        ) {
            let _ = parse_request(&address, port.as_deref());
        }
    }
}
