use std::{net::IpAddr, time::Duration};

use reach_core::{
    Attempt, AttemptId, AttemptKind, AttemptOutcome, AttemptSubject, AttemptTiming,
    IcmpAttemptResult, IcmpMessageKind, NeighborIdentity, Provenance, ProvenanceSource, TargetIp,
};
use tokio_util::sync::CancellationToken;

use crate::{ContinuousClock, PlatformError, clock::wait_until_continuous_deadline};

const ECHO_PAYLOAD: &[u8] = b"reach-icmp";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IcmpEchoSubject {
    Target(TargetIp),
    NextHop(NeighborIdentity),
}

impl IcmpEchoSubject {
    fn address(&self) -> IpAddr {
        match self {
            Self::Target(target) => target.address,
            Self::NextHop(neighbor) => neighbor.address,
        }
    }

    fn scope_index(&self) -> Option<u32> {
        match self {
            Self::Target(target) => target.scope.as_ref().map(|interface| interface.index),
            Self::NextHop(neighbor) => Some(neighbor.interface.index),
        }
    }

    fn attempt_kind(&self) -> AttemptKind {
        match self {
            Self::Target(_) => AttemptKind::TargetIcmpEcho,
            Self::NextHop(_) => AttemptKind::NextHopIcmpEcho,
        }
    }

    fn attempt_subject(&self) -> AttemptSubject {
        match self {
            Self::Target(target) => AttemptSubject::Target(target.clone()),
            Self::NextHop(neighbor) => AttemptSubject::NextHop(neighbor.clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpEchoRequest {
    pub attempt_id: AttemptId,
    pub subject: IcmpEchoSubject,
    pub budget: Duration,
}

pub async fn icmp_echo_once(
    request: IcmpEchoRequest,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<Attempt, PlatformError> {
    let started_at = clock.now()?;
    let deadline_at = started_at.saturating_add(request.budget);
    let exchange = platform_echo(request.clone());
    tokio::pin!(exchange);
    let timeout = wait_until_continuous_deadline(deadline_at, cancellation, clock);
    tokio::pin!(timeout);

    let mut outcome = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(PlatformError::OperationCancelled),
        result = &mut timeout => {
            result?;
            IcmpAttemptResult::Timeout
        },
        result = &mut exchange => result?,
    };
    let completed_at = clock.now()?;
    if completed_at >= deadline_at {
        outcome = IcmpAttemptResult::Timeout;
    }

    let detail = if cfg!(windows) {
        "Windows IP Helper ordinary-user ICMP API; one product-visible attempt"
    } else {
        "surge-ping ordinary-user ICMP socket; one product-visible attempt"
    };
    Ok(Attempt {
        id: request.attempt_id,
        subject: request.subject.attempt_subject(),
        kind: request.subject.attempt_kind(),
        timing: AttemptTiming {
            started_at,
            deadline_at,
            completed_at,
        },
        outcome: AttemptOutcome::Icmp(outcome),
        provenance: Provenance::new(ProvenanceSource::IcmpApi)
            .at(completed_at)
            .with_detail(detail),
    })
}

#[cfg(unix)]
async fn platform_echo(request: IcmpEchoRequest) -> Result<IcmpAttemptResult, PlatformError> {
    use surge_ping::{Client, Config, ICMP, IcmpPacket, PingIdentifier, PingSequence, SurgeError};

    let kind = match request.subject.address() {
        IpAddr::V4(_) => ICMP::V4,
        IpAddr::V6(_) => ICMP::V6,
    };
    let config = Config::builder().kind(kind).build();
    let client = match Client::new(&config) {
        Ok(client) => client,
        Err(error) if crate::is_resource_exhaustion(&error) => {
            return Err(PlatformError::ResourceExhausted(error.to_string()));
        }
        Err(error) => return Err(PlatformError::IcmpUnavailable(error.to_string())),
    };
    let correlation = request.attempt_id.0 as u16;
    let mut pinger = client
        .pinger(request.subject.address(), PingIdentifier(correlation))
        .await;
    if let Some(scope_index) = request.subject.scope_index() {
        pinger.scope_id(scope_index);
    }
    pinger.timeout(request.budget);

    match pinger.ping(PingSequence(correlation), ECHO_PAYLOAD).await {
        Ok((packet, _library_rtt)) => Ok(match packet {
            IcmpPacket::V4(packet) => icmpv4_result(
                packet.get_source().into(),
                packet.get_icmp_type().0,
                packet.get_icmp_code().0,
            ),
            IcmpPacket::V6(packet) => icmpv6_result(
                packet.get_source().into(),
                packet.get_icmpv6_type().0,
                packet.get_icmpv6_code().0,
            ),
        }),
        Err(SurgeError::Timeout { .. }) => Ok(IcmpAttemptResult::Timeout),
        Err(SurgeError::IOError(error)) if crate::is_resource_exhaustion(&error) => {
            Err(PlatformError::ResourceExhausted(error.to_string()))
        }
        Err(SurgeError::IOError(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(PlatformError::IcmpUnavailable(error.to_string()))
        }
        Err(SurgeError::IOError(error)) if error.kind() == std::io::ErrorKind::TimedOut => {
            Ok(IcmpAttemptResult::Timeout)
        }
        Err(SurgeError::IOError(error)) => Ok(IcmpAttemptResult::ExplicitNetworkError {
            os_code: error.raw_os_error(),
        }),
        Err(_) => Ok(IcmpAttemptResult::ExplicitNetworkError { os_code: None }),
    }
}

#[cfg(any(unix, test))]
fn icmpv4_result(responder: IpAddr, raw_type: u8, raw_code: u8) -> IcmpAttemptResult {
    let kind = match (raw_type, raw_code) {
        (0, 0) => IcmpMessageKind::EchoReply,
        (3, 4) => IcmpMessageKind::PacketTooBig,
        (3, _) => IcmpMessageKind::DestinationUnreachable,
        (11, _) => IcmpMessageKind::TimeExceeded,
        (12, _) => IcmpMessageKind::ParameterProblem,
        _ => IcmpMessageKind::Other,
    };
    IcmpAttemptResult::Message {
        kind,
        responder,
        raw_type: Some(u16::from(raw_type)),
        raw_code: Some(u16::from(raw_code)),
    }
}

#[cfg(any(unix, test))]
fn icmpv6_result(responder: IpAddr, raw_type: u8, raw_code: u8) -> IcmpAttemptResult {
    let kind = match (raw_type, raw_code) {
        (129, 0) => IcmpMessageKind::EchoReply,
        (1, _) => IcmpMessageKind::DestinationUnreachable,
        (2, _) => IcmpMessageKind::PacketTooBig,
        (3, _) => IcmpMessageKind::TimeExceeded,
        (4, _) => IcmpMessageKind::ParameterProblem,
        _ => IcmpMessageKind::Other,
    };
    IcmpAttemptResult::Message {
        kind,
        responder,
        raw_type: Some(u16::from(raw_type)),
        raw_code: Some(u16::from(raw_code)),
    }
}

#[cfg(windows)]
async fn platform_echo(request: IcmpEchoRequest) -> Result<IcmpAttemptResult, PlatformError> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let worker = std::thread::Builder::new()
        .name("reach-windows-icmp".into())
        .spawn(move || {
            let _ = sender.send(windows_echo(&request));
        });
    if let Err(error) = worker {
        return if crate::is_resource_exhaustion(&error) {
            Err(PlatformError::ResourceExhausted(error.to_string()))
        } else {
            Err(PlatformError::IcmpUnavailable(error.to_string()))
        };
    }
    receiver
        .await
        .map_err(|error| PlatformError::IcmpUnavailable(error.to_string()))?
}

#[cfg(windows)]
fn windows_echo(request: &IcmpEchoRequest) -> Result<IcmpAttemptResult, PlatformError> {
    match request.subject.address() {
        IpAddr::V4(address) => windows_echo_v4(address, request.budget),
        IpAddr::V6(address) => windows_echo_v6(
            address,
            request.subject.scope_index().unwrap_or_default(),
            request.budget,
        ),
    }
}

#[cfg(windows)]
#[repr(align(16))]
struct ReplyBuffer([u8; 512]);

#[cfg(windows)]
struct IcmpHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is returned by an ICMP create function and is owned by this guard.
        let _ = unsafe { windows_sys::Win32::NetworkManagement::IpHelper::IcmpCloseHandle(self.0) };
    }
}

#[cfg(windows)]
fn windows_echo_v4(
    destination: std::net::Ipv4Addr,
    budget: Duration,
) -> Result<IcmpAttemptResult, PlatformError> {
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::{GetLastError, INVALID_HANDLE_VALUE},
        NetworkManagement::IpHelper::{ICMP_ECHO_REPLY, IcmpCreateFile, IcmpSendEcho2},
    };

    // SAFETY: IcmpCreateFile has no preconditions and returns an owned handle on success.
    let raw_handle = unsafe { IcmpCreateFile() };
    if raw_handle == INVALID_HANDLE_VALUE {
        // SAFETY: this reads the calling thread's last-error value immediately after failure.
        let error = unsafe { GetLastError() };
        let io_error = std::io::Error::from_raw_os_error(error as i32);
        if crate::is_resource_exhaustion(&io_error) {
            return Err(PlatformError::ResourceExhausted(io_error.to_string()));
        }
        return Err(PlatformError::IcmpUnavailable(format!(
            "IcmpCreateFile failed with Windows error {error}"
        )));
    }
    let handle = IcmpHandle(raw_handle);
    let mut reply_buffer = ReplyBuffer([0; 512]);
    let destination = u32::from_ne_bytes(destination.octets());
    // SAFETY: all pointers refer to live buffers for the synchronous call; sizes match those buffers.
    let count = unsafe {
        IcmpSendEcho2(
            handle.0,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            destination,
            ECHO_PAYLOAD.as_ptr().cast::<c_void>(),
            ECHO_PAYLOAD.len() as u16,
            std::ptr::null(),
            reply_buffer.0.as_mut_ptr().cast::<c_void>(),
            reply_buffer.0.len() as u32,
            timeout_millis(budget),
        )
    };
    if count == 0 {
        // SAFETY: this reads the calling thread's last-error value immediately after failure.
        return windows_no_reply_status(unsafe { GetLastError() });
    }
    // SAFETY: a positive reply count guarantees the buffer begins with ICMP_ECHO_REPLY.
    let reply =
        unsafe { std::ptr::read_unaligned(reply_buffer.0.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
    let responder = std::net::Ipv4Addr::from(reply.Address.to_ne_bytes()).into();
    windows_status(reply.Status, responder)
}

#[cfg(windows)]
fn windows_echo_v6(
    destination: std::net::Ipv6Addr,
    scope_index: u32,
    budget: Duration,
) -> Result<IcmpAttemptResult, PlatformError> {
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::{GetLastError, INVALID_HANDLE_VALUE},
        NetworkManagement::IpHelper::{ICMPV6_ECHO_REPLY_LH, Icmp6CreateFile, Icmp6SendEcho2},
        Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6, SOCKADDR_IN6_0},
    };

    // SAFETY: Icmp6CreateFile has no preconditions and returns an owned handle on success.
    let raw_handle = unsafe { Icmp6CreateFile() };
    if raw_handle == INVALID_HANDLE_VALUE {
        // SAFETY: this reads the calling thread's last-error value immediately after failure.
        let error = unsafe { GetLastError() };
        let io_error = std::io::Error::from_raw_os_error(error as i32);
        if crate::is_resource_exhaustion(&io_error) {
            return Err(PlatformError::ResourceExhausted(io_error.to_string()));
        }
        return Err(PlatformError::IcmpUnavailable(format!(
            "Icmp6CreateFile failed with Windows error {error}"
        )));
    }
    let handle = IcmpHandle(raw_handle);
    let source = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        ..Default::default()
    };
    let destination_address = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: destination.octets(),
            },
        },
        Anonymous: SOCKADDR_IN6_0 {
            sin6_scope_id: scope_index,
        },
        ..Default::default()
    };
    let mut reply_buffer = ReplyBuffer([0; 512]);
    // SAFETY: all pointers refer to live buffers for the synchronous call; sizes match those buffers.
    let count = unsafe {
        Icmp6SendEcho2(
            handle.0,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            &source,
            &destination_address,
            ECHO_PAYLOAD.as_ptr().cast::<c_void>(),
            ECHO_PAYLOAD.len() as u16,
            std::ptr::null(),
            reply_buffer.0.as_mut_ptr().cast::<c_void>(),
            reply_buffer.0.len() as u32,
            timeout_millis(budget),
        )
    };
    if count == 0 {
        // SAFETY: this reads the calling thread's last-error value immediately after failure.
        return windows_no_reply_status(unsafe { GetLastError() });
    }
    // SAFETY: a positive reply count guarantees the buffer begins with ICMPV6_ECHO_REPLY_LH.
    let reply =
        unsafe { std::ptr::read_unaligned(reply_buffer.0.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>()) };
    let words = reply.Address.sin6_addr;
    let mut octets = [0_u8; 16];
    for (chunk, word) in octets.chunks_exact_mut(2).zip(words) {
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    windows_status(reply.Status, std::net::Ipv6Addr::from(octets).into())
}

#[cfg(windows)]
fn windows_no_reply_status(status: u32) -> Result<IcmpAttemptResult, PlatformError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{IP_NO_RESOURCES, IP_REQ_TIMED_OUT};

    let io_error = std::io::Error::from_raw_os_error(status as i32);
    if status == IP_NO_RESOURCES || crate::is_resource_exhaustion(&io_error) {
        return Err(PlatformError::ResourceExhausted(format!(
            "Windows ICMP status {status}"
        )));
    }
    if io_error.kind() == std::io::ErrorKind::PermissionDenied {
        return Err(PlatformError::IcmpUnavailable(io_error.to_string()));
    }
    if status == IP_REQ_TIMED_OUT {
        return Ok(IcmpAttemptResult::Timeout);
    }
    Ok(IcmpAttemptResult::ExplicitNetworkError {
        os_code: i32::try_from(status).ok(),
    })
}

#[cfg(windows)]
fn windows_status(status: u32, responder: IpAddr) -> Result<IcmpAttemptResult, PlatformError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        IP_DEST_ADDR_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE,
        IP_DEST_PROHIBITED, IP_DEST_SCOPE_MISMATCH, IP_DEST_UNREACHABLE, IP_HOP_LIMIT_EXCEEDED,
        IP_NO_RESOURCES, IP_PACKET_TOO_BIG, IP_PARAMETER_PROBLEM, IP_REASSEMBLY_TIME_EXCEEDED,
        IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TIME_EXCEEDED,
    };

    if status == IP_NO_RESOURCES {
        return Err(PlatformError::ResourceExhausted(format!(
            "Windows ICMP status {status}"
        )));
    }
    if status == IP_REQ_TIMED_OUT {
        return Ok(IcmpAttemptResult::Timeout);
    }
    let kind = match status {
        IP_SUCCESS => IcmpMessageKind::EchoReply,
        IP_DEST_NET_UNREACHABLE
        | IP_DEST_ADDR_UNREACHABLE
        | IP_DEST_PORT_UNREACHABLE
        | IP_DEST_PROHIBITED
        | IP_DEST_SCOPE_MISMATCH
        | IP_DEST_UNREACHABLE => IcmpMessageKind::DestinationUnreachable,
        IP_HOP_LIMIT_EXCEEDED | IP_REASSEMBLY_TIME_EXCEEDED | IP_TIME_EXCEEDED => {
            IcmpMessageKind::TimeExceeded
        }
        IP_PACKET_TOO_BIG => IcmpMessageKind::PacketTooBig,
        IP_PARAMETER_PROBLEM => IcmpMessageKind::ParameterProblem,
        _ => {
            return Ok(IcmpAttemptResult::ExplicitNetworkError {
                os_code: i32::try_from(status).ok(),
            });
        }
    };
    Ok(IcmpAttemptResult::Message {
        kind,
        responder,
        raw_type: None,
        raw_code: u16::try_from(status).ok(),
    })
}

#[cfg(windows)]
fn timeout_millis(budget: Duration) -> u32 {
    u32::try_from(budget.as_millis().clamp(1, u128::from(u32::MAX))).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn classifies_icmpv4_messages_without_erasing_raw_values() {
        assert_eq!(
            icmpv4_result(Ipv4Addr::LOCALHOST.into(), 3, 4),
            IcmpAttemptResult::Message {
                kind: IcmpMessageKind::PacketTooBig,
                responder: IpAddr::V4(Ipv4Addr::LOCALHOST),
                raw_type: Some(3),
                raw_code: Some(4),
            }
        );
        assert!(matches!(
            icmpv4_result(Ipv4Addr::LOCALHOST.into(), 0, 1),
            IcmpAttemptResult::Message {
                kind: IcmpMessageKind::Other,
                ..
            }
        ));
    }

    #[test]
    fn classifies_icmpv6_messages_without_erasing_raw_values() {
        assert_eq!(
            icmpv6_result(Ipv6Addr::LOCALHOST.into(), 3, 0),
            IcmpAttemptResult::Message {
                kind: IcmpMessageKind::TimeExceeded,
                responder: IpAddr::V6(Ipv6Addr::LOCALHOST),
                raw_type: Some(3),
                raw_code: Some(0),
            }
        );
        assert!(matches!(
            icmpv6_result(Ipv6Addr::LOCALHOST.into(), 129, 1),
            IcmpAttemptResult::Message {
                kind: IcmpMessageKind::Other,
                ..
            }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_status_preserves_native_status_code() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IP_DEST_NET_UNREACHABLE, IP_PACKET_TOO_BIG, IP_REQ_TIMED_OUT,
        };

        assert_eq!(
            windows_status(IP_PACKET_TOO_BIG, Ipv4Addr::LOCALHOST.into())
                .expect("packet-too-big is a network result"),
            IcmpAttemptResult::Message {
                kind: IcmpMessageKind::PacketTooBig,
                responder: IpAddr::V4(Ipv4Addr::LOCALHOST),
                raw_type: None,
                raw_code: u16::try_from(IP_PACKET_TOO_BIG).ok(),
            }
        );
        assert_eq!(
            windows_no_reply_status(IP_DEST_NET_UNREACHABLE)
                .expect("a no-reply network status is an explicit result"),
            IcmpAttemptResult::ExplicitNetworkError {
                os_code: i32::try_from(IP_DEST_NET_UNREACHABLE).ok(),
            }
        );
        assert_eq!(
            windows_no_reply_status(IP_REQ_TIMED_OUT).expect("timeout is a network result"),
            IcmpAttemptResult::Timeout
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_ip_helper_echo_works_without_elevation_on_loopback() {
        use crate::SystemContinuousClock;

        let attempt = icmp_echo_once(
            IcmpEchoRequest {
                attempt_id: AttemptId(1),
                subject: IcmpEchoSubject::Target(TargetIp::v4(Ipv4Addr::LOCALHOST)),
                budget: Duration::from_secs(1),
            },
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("Windows IP Helper must be available to an ordinary user");

        assert!(matches!(
            attempt.outcome,
            AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                kind: IcmpMessageKind::EchoReply,
                responder: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ..
            })
        ));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_ip_helper_ipv6_echo_works_without_elevation_on_loopback() {
        use crate::SystemContinuousClock;

        let attempt = icmp_echo_once(
            IcmpEchoRequest {
                attempt_id: AttemptId(1),
                subject: IcmpEchoSubject::Target(TargetIp::v6(Ipv6Addr::LOCALHOST, None)),
                budget: Duration::from_secs(1),
            },
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("Windows IP Helper IPv6 Echo must be available to an ordinary user");

        assert!(matches!(
            attempt.outcome,
            AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                kind: IcmpMessageKind::EchoReply,
                responder: IpAddr::V6(Ipv6Addr::LOCALHOST),
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_echo_works_without_elevation_on_loopback() {
        use crate::SystemContinuousClock;

        let attempt = icmp_echo_once(
            IcmpEchoRequest {
                attempt_id: AttemptId(1),
                subject: IcmpEchoSubject::Target(TargetIp::v4(Ipv4Addr::LOCALHOST)),
                budget: Duration::from_secs(1),
            },
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("surge-ping ordinary-user loopback Echo must be available");

        assert!(matches!(
            attempt.outcome,
            AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                kind: IcmpMessageKind::EchoReply,
                responder: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_ipv6_echo_works_without_elevation_on_loopback() {
        use crate::SystemContinuousClock;

        let attempt = icmp_echo_once(
            IcmpEchoRequest {
                attempt_id: AttemptId(1),
                subject: IcmpEchoSubject::Target(TargetIp::v6(Ipv6Addr::LOCALHOST, None)),
                budget: Duration::from_secs(1),
            },
            &CancellationToken::new(),
            &SystemContinuousClock,
        )
        .await
        .expect("surge-ping ordinary-user IPv6 loopback Echo must be available");

        assert!(matches!(
            attempt.outcome,
            AttemptOutcome::Icmp(IcmpAttemptResult::Message {
                kind: IcmpMessageKind::EchoReply,
                responder: IpAddr::V6(Ipv6Addr::LOCALHOST),
                ..
            })
        ));
    }
}
