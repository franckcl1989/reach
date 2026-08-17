use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, RecordType},
};
use reach_core::{
    Attempt, AttemptId, AttemptKind, AttemptOutcome, AttemptSubject, AttemptTiming,
    DirectDnsTransportReason, DnsAttemptResult, DnsQueryType, Provenance, ProvenanceSource,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::{ContinuousClock, PlatformError, clock::wait_until_continuous_deadline};

#[derive(Clone, Copy, Debug)]
pub struct DirectDnsRequest<'a> {
    pub attempt_id: AttemptId,
    pub message_id: u16,
    pub resolver: SocketAddr,
    pub query_name: &'a str,
    pub query_type: DnsQueryType,
    pub budget: Duration,
    pub reason: DirectDnsTransportReason,
}

pub async fn dns_udp_once(
    request: DirectDnsRequest<'_>,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<Attempt, PlatformError> {
    let query = build_query(request.message_id, request.query_name, request.query_type)?;
    let wire = query
        .to_vec()
        .map_err(|error| PlatformError::InvalidDnsQueryName(error.to_string()))?;
    let started_at = clock.now()?;
    let deadline_at = started_at.saturating_add(request.budget);
    let exchange = udp_exchange(request.resolver, &wire, &query, cancellation);
    tokio::pin!(exchange);
    let timeout = wait_until_continuous_deadline(deadline_at, cancellation, clock);
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
    Ok(dns_attempt(
        &request,
        AttemptKind::DnsUdp {
            query_type: request.query_type,
        },
        AttemptTiming {
            started_at,
            deadline_at,
            completed_at,
        },
        outcome,
        &format!(
            "Hickory DNS codec over one Tokio UDP exchange; trigger={:?}",
            request.reason
        ),
    ))
}

pub async fn dns_tcp_once(
    request: DirectDnsRequest<'_>,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<Attempt, PlatformError> {
    let query = build_query(request.message_id, request.query_name, request.query_type)?;
    let wire = query
        .to_vec()
        .map_err(|error| PlatformError::InvalidDnsQueryName(error.to_string()))?;
    let started_at = clock.now()?;
    let deadline_at = started_at.saturating_add(request.budget);
    let exchange = tcp_exchange(request.resolver, &wire, &query);
    tokio::pin!(exchange);
    let timeout = wait_until_continuous_deadline(deadline_at, cancellation, clock);
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
    Ok(dns_attempt(
        &request,
        AttemptKind::DnsTcp {
            query_type: request.query_type,
        },
        AttemptTiming {
            started_at,
            deadline_at,
            completed_at,
        },
        outcome,
        &format!(
            "Hickory DNS codec over one Tokio TCP exchange; trigger={:?}",
            request.reason
        ),
    ))
}

fn build_query(
    message_id: u16,
    query_name: &str,
    query_type: DnsQueryType,
) -> Result<Message, PlatformError> {
    let name = Name::from_ascii(query_name)
        .map_err(|error| PlatformError::InvalidDnsQueryName(error.to_string()))?;
    let record_type = match query_type {
        DnsQueryType::A => RecordType::A,
        DnsQueryType::Aaaa => RecordType::AAAA,
    };
    let mut message = Message::new(message_id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type));
    Ok(message)
}

async fn udp_exchange(
    resolver: SocketAddr,
    wire: &[u8],
    query: &Message,
    cancellation: &CancellationToken,
) -> Result<DnsAttemptResult, PlatformError> {
    let bind_address = if resolver.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = match tokio::net::UdpSocket::bind(bind_address).await {
        Ok(socket) => socket,
        Err(error) => return transport_error(error),
    };
    if let Err(error) = socket.connect(resolver).await {
        return transport_error(error);
    }
    if let Err(error) = socket.send(wire).await {
        return transport_error(error);
    }

    let mut buffer = vec![0_u8; 65_535];
    loop {
        let received = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(PlatformError::OperationCancelled),
            result = socket.recv(&mut buffer) => result,
        };
        let length = match received {
            Ok(length) => length,
            Err(error) => return transport_error(error),
        };
        let response = match Message::from_vec(&buffer[..length]) {
            Ok(response) => response,
            Err(_) => return Ok(DnsAttemptResult::ProtocolError),
        };
        if response.metadata.id != query.metadata.id {
            continue;
        }
        return Ok(parse_correlated_response(response, query));
    }
}

async fn tcp_exchange(
    resolver: SocketAddr,
    wire: &[u8],
    query: &Message,
) -> Result<DnsAttemptResult, PlatformError> {
    let mut stream = match tokio::net::TcpStream::connect(resolver).await {
        Ok(stream) => stream,
        Err(error) => return transport_error(error),
    };
    let length = match u16::try_from(wire.len()) {
        Ok(length) => length,
        Err(_) => return Ok(DnsAttemptResult::ProtocolError),
    };
    if let Err(error) = stream.write_all(&length.to_be_bytes()).await {
        return transport_error(error);
    }
    if let Err(error) = stream.write_all(wire).await {
        return transport_error(error);
    }
    let mut length_prefix = [0_u8; 2];
    if let Err(error) = stream.read_exact(&mut length_prefix).await {
        return transport_error(error);
    }
    let response_length = usize::from(u16::from_be_bytes(length_prefix));
    let mut response_wire = vec![0_u8; response_length];
    if let Err(error) = stream.read_exact(&mut response_wire).await {
        return transport_error(error);
    }
    let response = match Message::from_vec(&response_wire) {
        Ok(response) => response,
        Err(_) => return Ok(DnsAttemptResult::ProtocolError),
    };
    Ok(parse_correlated_response(response, query))
}

fn parse_correlated_response(response: Message, query: &Message) -> DnsAttemptResult {
    if response.metadata.id != query.metadata.id
        || response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
        || response.queries != query.queries
    {
        return DnsAttemptResult::ProtocolError;
    }

    let mut addresses = Vec::new();
    let mut aliases = Vec::new();
    for record in &response.answers {
        match &record.data {
            RData::A(address) => addresses.push(IpAddr::V4(address.0)),
            RData::AAAA(address) => addresses.push(IpAddr::V6(address.0)),
            RData::CNAME(name) => aliases.push(name.to_string()),
            _ => {}
        }
    }
    DnsAttemptResult::Response {
        response_code: response.metadata.response_code.into(),
        addresses,
        aliases,
        truncated: response.metadata.truncation,
    }
}

fn transport_error(error: io::Error) -> Result<DnsAttemptResult, PlatformError> {
    if crate::is_resource_exhaustion(&error) {
        Err(PlatformError::ResourceExhausted(error.to_string()))
    } else if error.kind() == io::ErrorKind::TimedOut {
        Ok(DnsAttemptResult::Timeout)
    } else {
        Ok(DnsAttemptResult::TransportError {
            os_code: error.raw_os_error(),
        })
    }
}

fn dns_attempt(
    request: &DirectDnsRequest<'_>,
    kind: AttemptKind,
    timing: AttemptTiming,
    outcome: DnsAttemptResult,
    detail: &str,
) -> Attempt {
    let completed_at = timing.completed_at;
    Attempt {
        id: request.attempt_id,
        subject: AttemptSubject::Resolver {
            endpoint: request.resolver,
            query_name: request.query_name.to_owned(),
        },
        kind,
        timing,
        outcome: AttemptOutcome::Dns(outcome),
        provenance: Provenance::new(ProvenanceSource::DirectDns)
            .at(completed_at)
            .with_detail(detail),
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::ResponseCode,
        rr::{Record, rdata::A},
    };
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn codec_preserves_answer_order_and_duplicates() {
        let query = build_query(17, "example.com.", DnsQueryType::A).unwrap();
        let mut response = Message::response(17, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NoError;
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));

        let DnsAttemptResult::Response { addresses, .. } =
            parse_correlated_response(response, &query)
        else {
            panic!("expected parsed response");
        };
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], addresses[1]);
    }

    #[test]
    fn wrong_transaction_id_is_a_protocol_error_on_a_correlated_stream() {
        let query = build_query(17, "example.com.", DnsQueryType::A).unwrap();
        let mut response = Message::response(18, OpCode::Query);
        response.queries = query.queries.clone();
        assert_eq!(
            parse_correlated_response(response, &query),
            DnsAttemptResult::ProtocolError
        );
    }

    fn response_for(query: &Message) -> Vec<u8> {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NoError;
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").expect("valid test name"),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        response.to_vec().expect("encode test DNS response")
    }

    async fn exercise_local_direct_dns(loopback: IpAddr) {
        use reach_core::DirectDnsTransportReason;
        use tokio_util::sync::CancellationToken;

        use crate::SystemContinuousClock;

        let udp = tokio::net::UdpSocket::bind(SocketAddr::new(loopback, 0))
            .await
            .expect("bind UDP DNS fixture");
        let udp_address = udp.local_addr().expect("UDP fixture address");
        let udp_server = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (length, peer) = udp.recv_from(&mut buffer).await.expect("receive UDP query");
            let query = Message::from_vec(&buffer[..length]).expect("decode UDP query");
            udp.send_to(&response_for(&query), peer)
                .await
                .expect("send UDP response");
        });
        let request = DirectDnsRequest {
            attempt_id: AttemptId(1),
            message_id: 17,
            resolver: udp_address,
            query_name: "example.com.",
            query_type: DnsQueryType::A,
            budget: Duration::from_secs(1),
            reason: DirectDnsTransportReason::ConfiguredTransport,
        };
        let udp_attempt = dns_udp_once(request, &CancellationToken::new(), &SystemContinuousClock)
            .await
            .expect("UDP DNS attempt executes");
        udp_server.await.expect("UDP fixture task");
        assert!(matches!(
            udp_attempt.outcome,
            AttemptOutcome::Dns(DnsAttemptResult::Response {
                response_code: 0,
                ..
            })
        ));

        let tcp = tokio::net::TcpListener::bind(SocketAddr::new(loopback, 0))
            .await
            .expect("bind TCP DNS fixture");
        let tcp_address = tcp.local_addr().expect("TCP fixture address");
        let tcp_server = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.expect("accept TCP DNS query");
            let length = stream.read_u16().await.expect("read DNS length");
            let mut wire = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut wire).await.expect("read DNS query");
            let query = Message::from_vec(&wire).expect("decode TCP query");
            let response = response_for(&query);
            stream
                .write_u16(u16::try_from(response.len()).expect("bounded fixture response"))
                .await
                .expect("write DNS length");
            stream
                .write_all(&response)
                .await
                .expect("write DNS response");
        });
        let request = DirectDnsRequest {
            attempt_id: AttemptId(2),
            message_id: 18,
            resolver: tcp_address,
            query_name: "example.com.",
            query_type: DnsQueryType::A,
            budget: Duration::from_secs(1),
            reason: DirectDnsTransportReason::ConfiguredTransport,
        };
        let tcp_attempt = dns_tcp_once(request, &CancellationToken::new(), &SystemContinuousClock)
            .await
            .expect("TCP DNS attempt executes");
        tcp_server.await.expect("TCP fixture task");
        assert!(matches!(
            tcp_attempt.outcome,
            AttemptOutcome::Dns(DnsAttemptResult::Response {
                response_code: 0,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn ordinary_user_direct_dns_udp_and_tcp_work_against_local_servers() {
        exercise_local_direct_dns(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
        exercise_local_direct_dns(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)).await;
    }

    proptest! {
        #[test]
        fn malformed_dns_wire_never_panics_or_becomes_a_validated_fact(
            wire in prop::collection::vec(any::<u8>(), 0..2048),
        ) {
            let parsed = Message::from_vec(&wire);
            if let Ok(message) = parsed {
                let query = build_query(17, "example.com.", DnsQueryType::A)
                    .expect("fixed test query is valid");
                let result = parse_correlated_response(message, &query);
                let stayed_in_result_model = matches!(
                    result,
                    DnsAttemptResult::ProtocolError | DnsAttemptResult::Response { .. }
                );
                prop_assert!(stayed_in_result_model);
            }
        }
    }
}
