use std::fmt::Write as _;

use reach_core::{
    AggregateOutcome, Attempt, AttemptOutcome, AttemptSubject, CompletedDiagnostic,
    DnsAttemptResult, DnsExchangeEvidence, DnsExchangeObservation, DnsExchangeOutcome,
    DnsExchangePurpose, DnsQueryType, DnsResponseCode, NameResolutionSource,
};

use super::{Theme, field, human_duration, section, terminal_escape};

pub(super) fn render_name_resolution_sections(
    output: &mut String,
    completed: &CompletedDiagnostic,
    theme: Theme,
) {
    if completed.aggregate_outcome != AggregateOutcome::NoFormalTargets {
        return;
    }
    let Some(observation) = &completed.system_resolver else {
        return;
    };

    section(output, theme, "NAME RESOLUTION");
    if let Some(step) = observation.name_resolution.steps.last() {
        field(output, theme, "Source", source_label(step.source));
    }

    let exchanges = formal_exchanges(completed);
    let endpoints = distinct_endpoints(exchanges.iter());
    match endpoints.len() {
        0 => {
            if observation
                .name_resolution
                .steps
                .last()
                .is_some_and(|step| step.source == NameResolutionSource::SystemResolverOpaque)
            {
                field(
                    output,
                    theme,
                    "Formal DNS server",
                    "Not exposed by this platform",
                );
            }
        }
        1 => field(output, theme, "DNS server", &endpoints[0]),
        _ => field(
            output,
            theme,
            "DNS servers",
            endpoints
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ),
    }

    let query_names = distinct_query_names(exchanges.iter());
    if !query_names.is_empty() {
        let input = observation
            .name_resolution
            .input_name
            .trim_end_matches('.')
            .to_owned();
        if query_names == [input.clone()] {
            field(output, theme, "Query", terminal_escape(&input));
        } else {
            field(
                output,
                theme,
                "Input",
                terminal_escape(&observation.name_resolution.input_name),
            );
            field(
                output,
                theme,
                "Query",
                terminal_escape(&query_names.join(", ")),
            );
        }
    }

    for query_type in [DnsQueryType::A, DnsQueryType::Aaaa] {
        if let Some(exchange) = decisive_exchange(exchanges.iter(), query_type) {
            field(
                output,
                theme,
                dns_query_type_label(query_type),
                formal_exchange_summary(exchange),
            );
        }
    }

    for limitation in &observation.name_resolution.limitations {
        field(output, theme, "Note", terminal_escape(limitation));
    }
    let _ = writeln!(output);

    let diagnostic_attempts = diagnostic_attempts(completed);
    if diagnostic_attempts.is_empty() {
        return;
    }
    section(output, theme, "DNS DIAGNOSTIC");
    let endpoints = distinct_diagnostic_endpoints(diagnostic_attempts.iter());
    match endpoints.len() {
        0 => {}
        1 => field(output, theme, "Server", &endpoints[0]),
        _ => field(
            output,
            theme,
            "Servers",
            endpoints
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ),
    }
    let query_names = distinct_diagnostic_query_names(diagnostic_attempts.iter());
    if !query_names.is_empty() {
        field(
            output,
            theme,
            "Query",
            terminal_escape(&query_names.join(", ")),
        );
    }
    for query_type in [DnsQueryType::A, DnsQueryType::Aaaa] {
        if let Some(attempt) = decisive_diagnostic_attempt(diagnostic_attempts.iter(), query_type) {
            field(
                output,
                theme,
                dns_query_type_label(query_type),
                diagnostic_attempt_summary(attempt),
            );
        }
    }
    let _ = writeln!(output);
}

pub(super) fn source_label(source: NameResolutionSource) -> &'static str {
    match source {
        NameResolutionSource::Hosts => "hosts",
        NameResolutionSource::Dns => "DNS",
        NameResolutionSource::SystemResolverOpaque => "System resolver",
        NameResolutionSource::OtherPlatformSource => "platform source",
        NameResolutionSource::Unknown => "unknown",
    }
}

pub(super) fn dns_response_code_label(code: DnsResponseCode) -> &'static str {
    match code {
        DnsResponseCode::NoError => "No error",
        DnsResponseCode::FormErr => "FORMERR",
        DnsResponseCode::ServFail => "SERVFAIL",
        DnsResponseCode::NxDomain => "NXDOMAIN",
        DnsResponseCode::NotImp => "NOTIMP",
        DnsResponseCode::Refused => "REFUSED",
        DnsResponseCode::Other(_) => "other response code",
    }
}

pub(super) fn formal_exchanges(completed: &CompletedDiagnostic) -> Vec<DnsExchangeObservation> {
    let Some(observation) = &completed.system_resolver else {
        return Vec::new();
    };
    observation
        .name_resolution
        .steps
        .iter()
        .filter(|step| step.source == NameResolutionSource::Dns)
        .flat_map(|step| step.dns_exchanges.iter())
        .filter(|exchange| exchange.purpose == DnsExchangePurpose::FormalResolution)
        .cloned()
        .collect()
}

pub(super) fn diagnostic_attempts(completed: &CompletedDiagnostic) -> Vec<Attempt> {
    completed
        .resolver_diagnostics
        .iter()
        .flat_map(|diagnostic| diagnostic.attempts.iter())
        .cloned()
        .collect()
}

pub(super) fn is_diagnostic_attempt(
    completed: &CompletedDiagnostic,
    id: reach_core::AttemptId,
) -> bool {
    diagnostic_attempts(completed)
        .iter()
        .any(|attempt| attempt.id == id)
}

pub(super) fn diagnostic_dns_ran(completed: &CompletedDiagnostic) -> bool {
    !diagnostic_attempts(completed).is_empty()
}

pub(super) fn evidence_is_distinct(
    completed: &CompletedDiagnostic,
    fact: &reach_core::EvidenceFact,
) -> bool {
    if completed.aggregate_outcome != AggregateOutcome::NoFormalTargets {
        return true;
    }
    match fact {
        reach_core::EvidenceFact::NameResolution(_) => false,
        reach_core::EvidenceFact::DnsExchange(DnsExchangeEvidence::Formal(_)) => false,
        reach_core::EvidenceFact::DnsExchange(DnsExchangeEvidence::Diagnostic(_)) => false,
        reach_core::EvidenceFact::Attempt(id) => !is_diagnostic_attempt(completed, *id),
        _ => true,
    }
}

fn distinct_endpoints<'a>(
    exchanges: impl Iterator<Item = &'a DnsExchangeObservation>,
) -> Vec<String> {
    let mut endpoints = Vec::new();
    for exchange in exchanges {
        let endpoint = format!("{}:{}", exchange.endpoint.address, exchange.endpoint.port);
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

fn distinct_query_names<'a>(
    exchanges: impl Iterator<Item = &'a DnsExchangeObservation>,
) -> Vec<String> {
    let mut names = Vec::new();
    for exchange in exchanges {
        let name = exchange.query_name.trim_end_matches('.').to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn decisive_exchange<'a>(
    exchanges: impl Iterator<Item = &'a DnsExchangeObservation>,
    query_type: DnsQueryType,
) -> Option<&'a DnsExchangeObservation> {
    exchanges
        .filter(|exchange| exchange.query_type == query_type)
        .last()
}

pub(super) fn formal_exchange_summary(exchange: &DnsExchangeObservation) -> String {
    let outcome = exchange_outcome_label(&exchange.outcome, exchange.query_type);
    attach_timing(outcome, exchange.timing.duration())
}

fn diagnostic_attempt_summary(attempt: &Attempt) -> String {
    let AttemptOutcome::Dns(outcome) = &attempt.outcome else {
        return "Unexpected attempt type".to_owned();
    };
    let query_type = match attempt.kind {
        reach_core::AttemptKind::DnsUdp { query_type }
        | reach_core::AttemptKind::DnsTcp { query_type } => query_type,
        _ => return "Unexpected attempt type".to_owned(),
    };
    let outcome = match outcome {
        DnsAttemptResult::Response {
            response_code,
            addresses,
            truncated,
            ..
        } => dns_attempt_response_label(*response_code, addresses, *truncated, query_type),
        DnsAttemptResult::TransportError { .. } => "Transport error".to_owned(),
        DnsAttemptResult::ProtocolError => "Protocol error".to_owned(),
        DnsAttemptResult::Timeout => "Timed out".to_owned(),
    };
    attach_timing(outcome, attempt.timing.duration())
}

pub(super) fn dns_attempt_response_label(
    response_code: u16,
    addresses: &[std::net::IpAddr],
    truncated: bool,
    query_type: DnsQueryType,
) -> String {
    let code = DnsResponseCode::from(response_code);
    if !addresses.is_empty() {
        return addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
    }
    match code {
        DnsResponseCode::NxDomain => dns_response_code_label(code).to_owned(),
        DnsResponseCode::NoError if truncated => "Response truncated".to_owned(),
        DnsResponseCode::NoError => match query_type {
            DnsQueryType::A => "No A address returned".to_owned(),
            DnsQueryType::Aaaa => "No AAAA address returned".to_owned(),
        },
        code if truncated => format!("{}; response truncated", dns_response_code_label(code)),
        DnsResponseCode::Other(value) => format!("DNS response code {value}"),
        code => dns_response_code_label(code).to_owned(),
    }
}

fn exchange_outcome_label(outcome: &DnsExchangeOutcome, query_type: DnsQueryType) -> String {
    match outcome {
        DnsExchangeOutcome::Response {
            response_code,
            addresses,
            truncated,
            ..
        } => dns_attempt_response_label((*response_code).into(), addresses, *truncated, query_type),
        DnsExchangeOutcome::TransportError { .. } => "Transport error".to_owned(),
        DnsExchangeOutcome::ProtocolError => "Protocol error".to_owned(),
        DnsExchangeOutcome::Timeout => "Timed out".to_owned(),
    }
}

fn attach_timing(mut outcome: String, duration: std::time::Duration) -> String {
    if !duration.is_zero() {
        outcome.push_str(", ");
        outcome.push_str(&human_duration(duration));
    }
    outcome
}

fn distinct_diagnostic_endpoints<'a>(attempts: impl Iterator<Item = &'a Attempt>) -> Vec<String> {
    let mut endpoints = Vec::new();
    for attempt in attempts {
        let AttemptSubject::Resolver { endpoint, .. } = &attempt.subject else {
            continue;
        };
        let endpoint = endpoint.to_string();
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

fn distinct_diagnostic_query_names<'a>(attempts: impl Iterator<Item = &'a Attempt>) -> Vec<String> {
    let mut names = Vec::new();
    for attempt in attempts {
        let AttemptSubject::Resolver { query_name, .. } = &attempt.subject else {
            continue;
        };
        let name = query_name.trim_end_matches('.').to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn decisive_diagnostic_attempt<'a>(
    attempts: impl Iterator<Item = &'a Attempt>,
    query_type: DnsQueryType,
) -> Option<&'a Attempt> {
    attempts
        .filter(|attempt| match attempt.kind {
            reach_core::AttemptKind::DnsUdp { query_type: kind }
            | reach_core::AttemptKind::DnsTcp { query_type: kind } => kind == query_type,
            _ => false,
        })
        .last()
}

const fn dns_query_type_label(query_type: DnsQueryType) -> &'static str {
    match query_type {
        DnsQueryType::A => "A",
        DnsQueryType::Aaaa => "AAAA",
    }
}
