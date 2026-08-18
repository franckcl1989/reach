use std::{net::IpAddr, time::Duration};

use reach_core::{
    AttemptTiming, DnsAttemptResult, DnsExchangeObservation, DnsExchangeOutcome,
    DnsExchangePurpose, DnsExchangeTransport, DnsQueryType, DnsResponseCode, IpEndpoint,
    Provenance, ProvenanceSource,
};
use tokio_util::sync::CancellationToken;

use crate::{ContinuousClock, PlatformError, dns_wire};

/// Bounded, Reach-controlled formal DNS client for the Linux self-contained
/// resolver. Every wire exchange is recorded as a formal-resolution
/// observation, so the reported endpoint is the one actually used.
pub(crate) struct FormalDnsConfig {
    pub servers: Vec<(IpAddr, u16)>,
    pub search: Vec<String>,
    pub ndots: u32,
    pub timeout: Duration,
    pub attempts: u32,
    /// resolv.conf `options inet6`: IPv6 addresses are ordered before IPv4
    /// addresses and the AAAA series carries the decisive error.
    pub ipv6_first: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FormalDnsStepOutcome {
    Found(Vec<IpAddr>),
    NotFound,
    Unavailable(String),
}

pub(crate) struct FormalDnsOutcome {
    pub outcome: FormalDnsStepOutcome,
    pub query_names: Vec<String>,
    pub exchanges: Vec<DnsExchangeObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TypeSeriesOutcome {
    Ok(Vec<IpAddr>),
    NoRecords,
    Failed(DnsExchangeOutcome),
}

pub(crate) async fn formal_dns_lookup(
    name: &str,
    config: &FormalDnsConfig,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<FormalDnsOutcome, PlatformError> {
    let candidates = candidate_names(name, config);
    let mut exchanges = Vec::new();
    let mut query_names = Vec::new();
    let mut last = FormalDnsStepOutcome::NotFound;
    for candidate in &candidates {
        let (a, aaaa) = tokio::join!(
            query_type_series(candidate, DnsQueryType::A, config, cancellation, clock),
            query_type_series(candidate, DnsQueryType::Aaaa, config, cancellation, clock),
        );
        let (a, mut a_exchanges) = a?;
        let (aaaa, mut aaaa_exchanges) = aaaa?;
        query_names.push(candidate.clone());
        if config.ipv6_first {
            exchanges.append(&mut aaaa_exchanges);
            exchanges.append(&mut a_exchanges);
        } else {
            exchanges.append(&mut a_exchanges);
            exchanges.append(&mut aaaa_exchanges);
        }
        let outcome = candidate_outcome(a, aaaa, config.ipv6_first);
        if let FormalDnsStepOutcome::Found(_) = &outcome {
            return Ok(FormalDnsOutcome {
                outcome,
                query_names,
                exchanges,
            });
        }
        last = outcome;
    }
    Ok(FormalDnsOutcome {
        outcome: last,
        query_names,
        exchanges,
    })
}

fn candidate_outcome(
    a: TypeSeriesOutcome,
    aaaa: TypeSeriesOutcome,
    ipv6_first: bool,
) -> FormalDnsStepOutcome {
    let (first, second) = if ipv6_first { (aaaa, a) } else { (a, aaaa) };
    match (first, second) {
        (TypeSeriesOutcome::Ok(mut first), TypeSeriesOutcome::Ok(second)) => {
            first.extend(second);
            FormalDnsStepOutcome::Found(first)
        }
        (TypeSeriesOutcome::Ok(first), _) => FormalDnsStepOutcome::Found(first),
        (TypeSeriesOutcome::NoRecords, TypeSeriesOutcome::Ok(second)) => {
            FormalDnsStepOutcome::Found(second)
        }
        (TypeSeriesOutcome::Failed(_), TypeSeriesOutcome::Ok(second)) => {
            FormalDnsStepOutcome::Found(second)
        }
        (TypeSeriesOutcome::NoRecords, TypeSeriesOutcome::NoRecords)
        | (TypeSeriesOutcome::NoRecords, TypeSeriesOutcome::Failed(_)) => {
            FormalDnsStepOutcome::NotFound
        }
        (TypeSeriesOutcome::Failed(error), TypeSeriesOutcome::NoRecords)
        | (TypeSeriesOutcome::Failed(error), TypeSeriesOutcome::Failed(_)) => {
            FormalDnsStepOutcome::Unavailable(format!(
                "DNS source failed: {}",
                formal_failure_reason(&error)
            ))
        }
    }
}

fn formal_failure_reason(outcome: &DnsExchangeOutcome) -> String {
    match outcome {
        DnsExchangeOutcome::Response {
            response_code,
            truncated: false,
            ..
        } => format!("the DNS response carried response code {response_code:?}"),
        DnsExchangeOutcome::Response {
            truncated: true, ..
        } => "the DNS response was truncated even after the TCP fallback".into(),
        DnsExchangeOutcome::TransportError { os_code: None } => {
            "no configured DNS server was usable".into()
        }
        DnsExchangeOutcome::TransportError {
            os_code: Some(code),
        } => format!("a DNS transport error occurred (OS code {code})"),
        DnsExchangeOutcome::ProtocolError => "the DNS response could not be decoded".into(),
        DnsExchangeOutcome::Timeout => "all configured DNS servers timed out".into(),
    }
}

fn candidate_names(name: &str, config: &FormalDnsConfig) -> Vec<String> {
    if name.ends_with('.') {
        return vec![name.to_owned()];
    }
    let dots = name.chars().filter(|character| *character == '.').count() as u32;
    let mut candidates = Vec::new();
    if dots >= config.ndots {
        candidates.push(name.to_owned());
    }
    for domain in &config.search {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() {
            continue;
        }
        candidates.push(format!("{name}.{domain}"));
    }
    if dots < config.ndots {
        candidates.push(name.to_owned());
    }
    candidates
}

async fn query_type_series(
    name: &str,
    query_type: DnsQueryType,
    config: &FormalDnsConfig,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<(TypeSeriesOutcome, Vec<DnsExchangeObservation>), PlatformError> {
    let mut exchanges = Vec::new();
    let mut any_timeout = false;
    let mut last_transport_error = None;
    for (server, port) in &config.servers {
        for _attempt in 0..config.attempts {
            if cancellation.is_cancelled() {
                return Err(PlatformError::OperationCancelled);
            }
            let endpoint = std::net::SocketAddr::new(*server, *port);
            let (outcome, observation) = one_exchange(
                endpoint,
                DnsExchangeTransport::Udp,
                name,
                query_type,
                config.timeout,
                cancellation,
                clock,
            )
            .await?;
            exchanges.push(observation);
            match outcome {
                DnsAttemptResult::Response {
                    truncated: true, ..
                } => {
                    if cancellation.is_cancelled() {
                        return Err(PlatformError::OperationCancelled);
                    }
                    let (outcome, observation) = one_exchange(
                        endpoint,
                        DnsExchangeTransport::Tcp,
                        name,
                        query_type,
                        config.timeout,
                        cancellation,
                        clock,
                    )
                    .await?;
                    exchanges.push(observation);
                    return Ok((classify_response(outcome), exchanges));
                }
                DnsAttemptResult::Response { .. } => {
                    return Ok((classify_response(outcome), exchanges));
                }
                DnsAttemptResult::Timeout => {
                    any_timeout = true;
                }
                DnsAttemptResult::TransportError { os_code } => {
                    last_transport_error = Some(os_code);
                    break;
                }
                DnsAttemptResult::ProtocolError => {
                    return Ok((
                        TypeSeriesOutcome::Failed(DnsExchangeOutcome::ProtocolError),
                        exchanges,
                    ));
                }
            }
        }
    }
    let outcome = if any_timeout {
        DnsExchangeOutcome::Timeout
    } else {
        DnsExchangeOutcome::TransportError {
            os_code: last_transport_error.flatten(),
        }
    };
    Ok((TypeSeriesOutcome::Failed(outcome), exchanges))
}

fn classify_response(outcome: DnsAttemptResult) -> TypeSeriesOutcome {
    match outcome {
        DnsAttemptResult::Response {
            response_code,
            addresses,
            truncated: false,
            ..
        } => match DnsResponseCode::from(response_code) {
            DnsResponseCode::NoError | DnsResponseCode::NxDomain if addresses.is_empty() => {
                TypeSeriesOutcome::NoRecords
            }
            DnsResponseCode::NoError | DnsResponseCode::NxDomain => {
                TypeSeriesOutcome::Ok(addresses)
            }
            code => TypeSeriesOutcome::Failed(DnsExchangeOutcome::Response {
                response_code: code,
                addresses,
                aliases: Vec::new(),
                truncated: false,
            }),
        },
        DnsAttemptResult::Response {
            response_code,
            addresses,
            aliases,
            truncated: true,
        } => TypeSeriesOutcome::Failed(DnsExchangeOutcome::Response {
            response_code: DnsResponseCode::from(response_code),
            addresses,
            aliases,
            truncated: true,
        }),
        DnsAttemptResult::TransportError { os_code } => {
            TypeSeriesOutcome::Failed(DnsExchangeOutcome::TransportError { os_code })
        }
        DnsAttemptResult::ProtocolError => {
            TypeSeriesOutcome::Failed(DnsExchangeOutcome::ProtocolError)
        }
        DnsAttemptResult::Timeout => TypeSeriesOutcome::Failed(DnsExchangeOutcome::Timeout),
    }
}

async fn one_exchange(
    endpoint: std::net::SocketAddr,
    transport: DnsExchangeTransport,
    query_name: &str,
    query_type: DnsQueryType,
    budget: Duration,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<(DnsAttemptResult, DnsExchangeObservation), PlatformError> {
    let wire_name = if query_name.ends_with('.') {
        query_name.to_owned()
    } else {
        format!("{query_name}.")
    };
    // Every formal exchange carries its own transaction id so a mismatched
    // datagram can never be mistaken for this exchange's response.
    let message_id = next_message_id();
    let query = dns_wire::build_query(message_id, &wire_name, query_type)?;
    let wire = query
        .to_vec()
        .map_err(|error| PlatformError::InvalidDnsQueryName(error.to_string()))?;
    let started_at = clock.now()?;
    let deadline_at = started_at.saturating_add(budget);
    let exchange =
        match transport {
            DnsExchangeTransport::Udp => futures_util::future::Either::Left(
                dns_wire::udp_exchange(endpoint, &wire, &query, cancellation),
            ),
            DnsExchangeTransport::Tcp => {
                futures_util::future::Either::Right(dns_wire::tcp_exchange(endpoint, &wire, &query))
            }
        };
    tokio::pin!(exchange);
    let timeout = crate::clock::wait_until_continuous_deadline(deadline_at, cancellation, clock);
    tokio::pin!(timeout);
    let mut outcome = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(PlatformError::OperationCancelled),
        result = &mut timeout => {
            result?;
            DnsAttemptResult::Timeout
        },
        result = &mut exchange => result?,
    };
    let completed_at = clock.now()?;
    if completed_at >= deadline_at {
        outcome = DnsAttemptResult::Timeout;
    }
    let observation = DnsExchangeObservation {
        purpose: DnsExchangePurpose::FormalResolution,
        endpoint: IpEndpoint {
            address: endpoint.ip(),
            port: endpoint.port(),
            scope_id: match endpoint {
                std::net::SocketAddr::V6(address) if address.scope_id() != 0 => {
                    Some(address.scope_id())
                }
                _ => None,
            },
        },
        transport,
        query_name: wire_name,
        query_type,
        outcome: exchange_outcome(outcome.clone()),
        timing: AttemptTiming {
            started_at,
            deadline_at,
            completed_at,
        },
        provenance: Provenance::new(ProvenanceSource::FormalDns)
            .at(completed_at)
            .with_detail("self-contained Linux formal resolver; one bounded exchange"),
    };
    Ok((outcome, observation))
}

fn exchange_outcome(outcome: DnsAttemptResult) -> DnsExchangeOutcome {
    match outcome {
        DnsAttemptResult::Response {
            response_code,
            addresses,
            aliases,
            truncated,
        } => DnsExchangeOutcome::Response {
            response_code: DnsResponseCode::from(response_code),
            addresses,
            aliases,
            truncated,
        },
        DnsAttemptResult::TransportError { os_code } => {
            DnsExchangeOutcome::TransportError { os_code }
        }
        DnsAttemptResult::ProtocolError => DnsExchangeOutcome::ProtocolError,
        DnsAttemptResult::Timeout => DnsExchangeOutcome::Timeout,
    }
}

fn next_message_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT_MESSAGE_ID: AtomicU16 = AtomicU16::new(1);
    NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use hickory_proto::{
        op::{Message, OpCode, ResponseCode},
        rr::{RData, Record, RecordType, rdata::A, rdata::AAAA},
    };
    use reach_core::{DnsQueryType, DnsResponseCode, ProvenanceSource};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::SystemContinuousClock;

    struct ServerScript {
        requests: Arc<Mutex<Vec<(String, RecordType)>>>,
        responder: Box<dyn Fn(&Message) -> Option<Message> + Send + Sync>,
    }

    async fn serve(script: Arc<ServerScript>, receive_limit: usize) -> std::net::SocketAddrV4 {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("ordinary-user local DNS fixture");
        let address = socket.local_addr().expect("DNS fixture address");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("DNS fixture timeout");
        tokio::spawn(async move {
            let socket = tokio::net::UdpSocket::from_std(socket).expect("tokio UDP socket");
            let mut buffer = [0_u8; 2048];
            for _ in 0..receive_limit {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let Ok(query) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let question = query.queries.first().expect("one DNS question");
                script
                    .requests
                    .lock()
                    .expect("request log")
                    .push((question.name().to_string(), question.query_type()));
                if let Some(response) = (script.responder)(&query) {
                    if socket
                        .send_to(&response.to_vec().expect("encode DNS response"), peer)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        let std::net::SocketAddr::V4(address) = address else {
            panic!("local fixture must be IPv4");
        };
        address
    }

    #[tokio::test(flavor = "current_thread")]
    async fn formal_dns_records_actual_endpoint_query_names_and_negative_results() {
        let script = Arc::new(ServerScript {
            requests: Arc::new(Mutex::new(Vec::new())),
            responder: Box::new(|query| {
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.queries = query.queries.clone();
                response.metadata.response_code = ResponseCode::NXDomain;
                Some(response)
            }),
        });
        let address = serve(script, 4).await;
        let config = FormalDnsConfig {
            servers: vec![(IpAddr::V4(*address.ip()), address.port())],
            search: vec!["corp.example".into()],
            ndots: 1,
            timeout: Duration::from_secs(2),
            attempts: 1,
            ipv6_first: false,
        };
        let outcome = formal_dns_lookup(
            "admin",
            &config,
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("formal DNS lookup");
        assert_eq!(outcome.query_names, vec!["admin.corp.example", "admin"]);
        assert_eq!(outcome.exchanges.len(), 4);
        assert!(outcome.exchanges.iter().all(|exchange| {
            exchange.purpose == DnsExchangePurpose::FormalResolution
                && exchange.endpoint.port == address.port()
                && exchange.provenance.source == ProvenanceSource::FormalDns
        }));
        let a = outcome
            .exchanges
            .iter()
            .filter(|exchange| exchange.query_type == DnsQueryType::A)
            .collect::<Vec<_>>();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].query_name, "admin.corp.example.");
        assert_eq!(a[1].query_name, "admin.");
        for exchange in &a {
            assert!(matches!(
                exchange.outcome,
                DnsExchangeOutcome::Response {
                    response_code: DnsResponseCode::NxDomain,
                    ref addresses,
                    truncated: false,
                    ..
                } if addresses.is_empty()
            ));
        }
        assert_eq!(
            outcome
                .exchanges
                .iter()
                .filter(|exchange| exchange.query_type == DnsQueryType::Aaaa)
                .count(),
            2
        );
        assert!(matches!(outcome.outcome, FormalDnsStepOutcome::NotFound));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn formal_dns_preserves_address_order_and_stops_at_the_first_found_candidate() {
        let script = Arc::new(ServerScript {
            requests: Arc::new(Mutex::new(Vec::new())),
            responder: Box::new(|query| {
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.queries = query.queries.clone();
                response.metadata.response_code = ResponseCode::NoError;
                let question = query.queries.first().expect("one question");
                let name = question.name().clone();
                if question.query_type() == RecordType::A {
                    let answer =
                        Record::from_rdata(name.clone(), 60, RData::A(A::new(192, 0, 2, 53)));
                    response.add_answers([answer.clone(), answer]);
                } else {
                    let answer = Record::from_rdata(
                        name,
                        60,
                        RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    );
                    response.add_answer(answer);
                }
                Some(response)
            }),
        });
        let address = serve(script.clone(), 4).await;
        let config = FormalDnsConfig {
            servers: vec![(IpAddr::V4(*address.ip()), address.port())],
            search: vec!["example".into()],
            ndots: 1,
            timeout: Duration::from_secs(2),
            attempts: 1,
            ipv6_first: false,
        };
        let outcome = formal_dns_lookup(
            "host",
            &config,
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("formal DNS lookup");
        assert_eq!(outcome.query_names, vec!["host.example"]);
        assert!(matches!(
            outcome.outcome,
            FormalDnsStepOutcome::Found(ref addresses)
                if addresses
                    == &vec![
                        "192.0.2.53".parse::<IpAddr>().unwrap(),
                        "192.0.2.53".parse::<IpAddr>().unwrap(),
                        "2001:db8::1".parse::<IpAddr>().unwrap(),
                    ]
        ));
        let names = script.requests.lock().expect("request log");
        let all = names
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert!(all.contains(&"host.example."));
        assert!(!all.contains(&"host."));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn formal_dns_server_timeout_moves_to_the_next_configured_server() {
        let script = Arc::new(ServerScript {
            requests: Arc::new(Mutex::new(Vec::new())),
            responder: Box::new(|query| {
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.queries = query.queries.clone();
                response.metadata.response_code = ResponseCode::NoError;
                let question = query.queries.first().expect("one question");
                if question.query_type() == RecordType::A {
                    let answer = Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::A(A::new(203, 0, 113, 7)),
                    );
                    response.add_answer(answer);
                }
                Some(response)
            }),
        });
        let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("silent fixture socket");
        let silent_address = silent.local_addr().expect("silent fixture address");
        std::mem::forget(silent);
        let std::net::SocketAddr::V4(silent_address) = silent_address else {
            panic!("silent fixture must be IPv4");
        };
        let answering = serve(script, 4).await;
        let config = FormalDnsConfig {
            servers: vec![
                (IpAddr::V4(*silent_address.ip()), silent_address.port()),
                (IpAddr::V4(*answering.ip()), answering.port()),
            ],
            search: Vec::new(),
            ndots: 1,
            timeout: Duration::from_millis(300),
            attempts: 1,
            ipv6_first: false,
        };
        let outcome = formal_dns_lookup(
            "host.example.",
            &config,
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("formal DNS lookup");
        assert!(matches!(
            outcome.outcome,
            FormalDnsStepOutcome::Found(ref addresses)
                if addresses == &vec!["203.0.113.7".parse::<IpAddr>().unwrap()]
        ));
        assert_eq!(outcome.exchanges.len(), 4);
        assert!(matches!(
            outcome.exchanges[0].outcome,
            DnsExchangeOutcome::Timeout
        ));
        assert_eq!(
            outcome.exchanges[0].endpoint.port,
            silent_address.port(),
            "the recorded endpoint is the server actually tried"
        );
        assert_eq!(
            outcome.exchanges[1].endpoint.port,
            answering.port(),
            "the second exchange used the next configured server"
        );
        assert!(matches!(
            outcome.exchanges[1].outcome,
            DnsExchangeOutcome::Response {
                response_code: DnsResponseCode::NoError,
                ..
            }
        ));
    }

    #[test]
    fn candidate_order_follows_ndots_and_trailing_dot_rules() {
        let config = FormalDnsConfig {
            servers: Vec::new(),
            search: vec!["corp.example".into(), "example".into()],
            ndots: 2,
            timeout: Duration::from_secs(5),
            attempts: 2,
            ipv6_first: false,
        };
        assert_eq!(
            candidate_names("admin", &config),
            vec!["admin.corp.example", "admin.example", "admin"]
        );
        assert_eq!(
            candidate_names("host.internal", &config),
            vec![
                "host.internal",
                "host.internal.corp.example",
                "host.internal.example"
            ]
        );
        assert_eq!(candidate_names("absolute.", &config), vec!["absolute."]);
        assert_eq!(
            candidate_names("deep.name.internal", &config),
            vec![
                "deep.name.internal",
                "deep.name.internal.corp.example",
                "deep.name.internal.example"
            ]
        );
    }

    #[test]
    fn ipv6_first_orders_aaaa_addresses_before_a_and_keeps_aaaa_errors_decisive() {
        let v4 = "192.0.2.1".parse::<IpAddr>().expect("test address");
        let v6 = "2001:db8::1".parse::<IpAddr>().expect("test address");
        assert_eq!(
            candidate_outcome(
                TypeSeriesOutcome::Ok(vec![v4]),
                TypeSeriesOutcome::Ok(vec![v6]),
                true,
            ),
            FormalDnsStepOutcome::Found(vec![v6, v4])
        );
        assert_eq!(
            candidate_outcome(
                TypeSeriesOutcome::Ok(vec![v4]),
                TypeSeriesOutcome::Ok(vec![v6]),
                false,
            ),
            FormalDnsStepOutcome::Found(vec![v4, v6])
        );
        let timeout = DnsExchangeOutcome::Timeout;
        assert_eq!(
            candidate_outcome(
                TypeSeriesOutcome::Failed(timeout.clone()),
                TypeSeriesOutcome::NoRecords,
                true,
            ),
            FormalDnsStepOutcome::Unavailable(format!(
                "DNS source failed: {}",
                formal_failure_reason(&timeout)
            ))
        );
        assert_eq!(
            candidate_outcome(
                TypeSeriesOutcome::Failed(timeout),
                TypeSeriesOutcome::NoRecords,
                false,
            ),
            FormalDnsStepOutcome::Unavailable(format!(
                "DNS source failed: {}",
                formal_failure_reason(&DnsExchangeOutcome::Timeout)
            ))
        );
    }

    #[test]
    fn response_codes_map_to_typed_series_outcomes() {
        assert_eq!(
            classify_response(DnsAttemptResult::Response {
                response_code: 3,
                addresses: Vec::new(),
                aliases: Vec::new(),
                truncated: false,
            }),
            TypeSeriesOutcome::NoRecords
        );
        assert_eq!(
            classify_response(DnsAttemptResult::Response {
                response_code: 0,
                addresses: Vec::new(),
                aliases: Vec::new(),
                truncated: false,
            }),
            TypeSeriesOutcome::NoRecords
        );
        assert_eq!(
            classify_response(DnsAttemptResult::Response {
                response_code: 2,
                addresses: Vec::new(),
                aliases: Vec::new(),
                truncated: false,
            }),
            TypeSeriesOutcome::Failed(DnsExchangeOutcome::Response {
                response_code: DnsResponseCode::ServFail,
                addresses: Vec::new(),
                aliases: Vec::new(),
                truncated: false,
            })
        );
        assert_eq!(
            classify_response(DnsAttemptResult::Response {
                response_code: 0,
                addresses: vec!["192.0.2.1".parse().expect("test address")],
                aliases: Vec::new(),
                truncated: false,
            }),
            TypeSeriesOutcome::Ok(vec!["192.0.2.1".parse().expect("test address")])
        );
    }
}
