use std::{io, net::SocketAddr, time::Duration};

use reach_core::{
    Attempt, AttemptId, AttemptKind, AttemptOutcome, AttemptSubject, AttemptTiming,
    CapabilityReason, CapabilityValue, IpEndpoint, Provenance, ProvenanceSource, TargetIp,
    TcpAttemptResult,
};
use tokio_util::sync::CancellationToken;

use crate::{ContinuousClock, PlatformError, clock::wait_until_continuous_deadline};

pub async fn tcp_connect_once(
    attempt_id: AttemptId,
    target: TargetIp,
    port: u16,
    budget: Duration,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<Attempt, PlatformError> {
    let started_at = clock.now()?;
    let deadline_at = started_at.saturating_add(budget);
    let address = socket_address(&target, port);
    let connect = tokio::net::TcpStream::connect(address);
    tokio::pin!(connect);
    let timeout = wait_until_continuous_deadline(deadline_at, cancellation, clock);
    tokio::pin!(timeout);

    enum ConnectCompletion {
        Timeout,
        Socket(io::Result<tokio::net::TcpStream>),
    }

    let operation = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(PlatformError::OperationCancelled),
        result = &mut timeout => {
            result?;
            ConnectCompletion::Timeout
        },
        result = &mut connect => ConnectCompletion::Socket(result),
    };
    let completed_at = clock.now()?;
    let attempt_provenance = Provenance::new(ProvenanceSource::TcpSocket)
        .at(completed_at)
        .with_detail("Tokio TCP connect; one product-visible attempt");

    let outcome = if completed_at >= deadline_at {
        TcpAttemptResult::Timeout
    } else {
        match operation {
            ConnectCompletion::Timeout => TcpAttemptResult::Timeout,
            ConnectCompletion::Socket(Ok(stream)) => TcpAttemptResult::Connected {
                local: observed_endpoint(stream.local_addr(), &attempt_provenance, "local_addr"),
                remote: observed_endpoint(stream.peer_addr(), &attempt_provenance, "peer_addr"),
            },
            ConnectCompletion::Socket(Err(error)) if crate::is_resource_exhaustion(&error) => {
                return Err(PlatformError::ResourceExhausted(error.to_string()));
            }
            ConnectCompletion::Socket(Err(error)) => classify_connect_error(&error),
        }
    };

    Ok(Attempt {
        id: attempt_id,
        subject: AttemptSubject::Target(target),
        kind: AttemptKind::TcpConnect,
        timing: AttemptTiming {
            started_at,
            deadline_at,
            completed_at,
        },
        outcome: AttemptOutcome::Tcp(outcome),
        provenance: attempt_provenance,
    })
}

fn socket_address(target: &TargetIp, port: u16) -> SocketAddr {
    match target.address {
        std::net::IpAddr::V4(address) => SocketAddr::new(address.into(), port),
        std::net::IpAddr::V6(address) => SocketAddr::V6(std::net::SocketAddrV6::new(
            address,
            port,
            0,
            target.scope.as_ref().map_or(0, |scope| scope.index),
        )),
    }
}

fn observed_endpoint(
    result: io::Result<SocketAddr>,
    provenance: &Provenance,
    operation: &str,
) -> CapabilityValue<IpEndpoint> {
    match result {
        Ok(address) => CapabilityValue::available(endpoint(address), provenance.clone()),
        Err(error) => CapabilityValue::unknown(
            CapabilityReason::Other(format!("{operation} failed after connect: {error}")),
            provenance.clone(),
        ),
    }
}

fn endpoint(address: SocketAddr) -> IpEndpoint {
    match address {
        SocketAddr::V4(address) => IpEndpoint {
            address: (*address.ip()).into(),
            port: address.port(),
            scope_id: None,
        },
        SocketAddr::V6(address) => IpEndpoint {
            address: (*address.ip()).into(),
            port: address.port(),
            scope_id: (address.scope_id() != 0).then(|| address.scope_id()),
        },
    }
}

fn classify_connect_error(error: &io::Error) -> TcpAttemptResult {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => TcpAttemptResult::ConnectionRefused,
        io::ErrorKind::NetworkUnreachable => TcpAttemptResult::NetworkUnreachable,
        io::ErrorKind::HostUnreachable => TcpAttemptResult::HostUnreachable,
        io::ErrorKind::PermissionDenied => TcpAttemptResult::PermissionDenied,
        io::ErrorKind::TimedOut => TcpAttemptResult::Timeout,
        _ => TcpAttemptResult::OtherExplicitError {
            os_code: error.raw_os_error(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use std::net::{IpAddr, Ipv6Addr};

    use super::*;
    use reach_core::InterfaceId;

    #[test]
    fn scoped_ipv6_socket_address_keeps_interface_index() {
        let target = TargetIp::v6(Ipv6Addr::LOCALHOST, Some(InterfaceId::from_index(11)));
        let address = socket_address(&target, 443);
        let SocketAddr::V6(address) = address else {
            panic!("expected IPv6 socket address");
        };
        assert_eq!(address.scope_id(), 11);
    }

    #[test]
    fn endpoint_preserves_ipv6_scope() {
        let observed = endpoint(SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            443,
            0,
            11,
        )));
        assert_eq!(observed.address, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(observed.scope_id, Some(11));
    }

    #[tokio::test]
    async fn ordinary_user_loopback_tcp_connect_preserves_actual_endpoints() {
        use tokio_util::sync::CancellationToken;

        use crate::SystemContinuousClock;

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let address = listener.local_addr().expect("listener address");
        let accept = tokio::spawn(async move { listener.accept().await });
        let attempt = tcp_connect_once(
            AttemptId(1),
            TargetIp::v4(Ipv4Addr::LOCALHOST),
            address.port(),
            Duration::from_secs(1),
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("ordinary-user TCP connect must execute");
        accept
            .await
            .expect("accept task")
            .expect("loopback connection accepted");
        let AttemptOutcome::Tcp(TcpAttemptResult::Connected { local, remote }) = attempt.outcome
        else {
            panic!("expected connected attempt: {attempt:?}");
        };
        assert!(local.is_available());
        assert!(remote.is_available());
    }

    #[tokio::test]
    async fn ordinary_user_ipv6_loopback_tcp_connect_preserves_actual_endpoints() {
        use tokio_util::sync::CancellationToken;

        use crate::SystemContinuousClock;

        let listener = tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind IPv6 loopback listener");
        let address = listener.local_addr().expect("listener address");
        let accept = tokio::spawn(async move { listener.accept().await });
        let attempt = tcp_connect_once(
            AttemptId(1),
            TargetIp::v6(Ipv6Addr::LOCALHOST, None),
            address.port(),
            Duration::from_secs(1),
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("ordinary-user IPv6 TCP connect must execute");
        accept
            .await
            .expect("accept task")
            .expect("IPv6 loopback connection accepted");
        let AttemptOutcome::Tcp(TcpAttemptResult::Connected { local, remote }) = attempt.outcome
        else {
            panic!("expected connected attempt: {attempt:?}");
        };
        assert!(matches!(
            local,
            CapabilityValue::Available {
                value: IpEndpoint {
                    address: IpAddr::V6(_),
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            remote,
            CapabilityValue::Available {
                value: IpEndpoint {
                    address: IpAddr::V6(_),
                    ..
                },
                ..
            }
        ));
    }
}
