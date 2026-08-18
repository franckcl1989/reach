use std::{net::SocketAddr, time::Duration};

use reach_core::{
    Attempt, AttemptId, AttemptKind, AttemptOutcome, AttemptSubject, AttemptTiming,
    DirectDnsTransportReason, DnsAttemptResult, DnsQueryType, Provenance, ProvenanceSource,
};
use tokio_util::sync::CancellationToken;

use crate::{ContinuousClock, PlatformError, clock::wait_until_continuous_deadline, dns_wire};

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
    let query = dns_wire::build_query(request.message_id, request.query_name, request.query_type)?;
    let wire = query
        .to_vec()
        .map_err(|error| PlatformError::InvalidDnsQueryName(error.to_string()))?;
    let started_at = clock.now()?;
    let deadline_at = started_at.saturating_add(request.budget);
    let exchange = dns_wire::udp_exchange(request.resolver, &wire, &query, cancellation);
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
    let query = dns_wire::build_query(request.message_id, request.query_name, request.query_type)?;
    let wire = query
        .to_vec()
        .map_err(|error| PlatformError::InvalidDnsQueryName(error.to_string()))?;
    let started_at = clock.now()?;
    let deadline_at = started_at.saturating_add(request.budget);
    let exchange = dns_wire::tcp_exchange(request.resolver, &wire, &query);
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
    use std::net::IpAddr;

    use hickory_proto::{
        op::{Message, OpCode, ResponseCode},
        rr::{Name, RData, Record, rdata::A},
    };
    use proptest::prelude::*;

    use super::*;
    use crate::SystemContinuousClock;

    #[test]
    fn codec_preserves_answer_order_and_duplicates() {
        let query = dns_wire::build_query(17, "example.com.", DnsQueryType::A).unwrap();
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
            dns_wire::parse_correlated_response(response, &query)
        else {
            panic!("expected parsed response");
        };
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], addresses[1]);
    }

    #[test]
    fn wrong_transaction_id_is_a_protocol_error_on_a_correlated_stream() {
        let query = dns_wire::build_query(17, "example.com.", DnsQueryType::A).unwrap();
        let mut response = Message::response(18, OpCode::Query);
        response.queries = query.queries.clone();
        assert_eq!(
            dns_wire::parse_correlated_response(response, &query),
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
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
                let query = dns_wire::build_query(17, "example.com.", DnsQueryType::A)
                    .expect("fixed test query is valid");
                let result = dns_wire::parse_correlated_response(message, &query);
                let stayed_in_result_model = matches!(
                    result,
                    DnsAttemptResult::ProtocolError | DnsAttemptResult::Response { .. }
                );
                prop_assert!(stayed_in_result_model);
            }
        }
    }
}
