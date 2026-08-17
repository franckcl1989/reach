use std::{fmt::Display, net::SocketAddr, time::Duration};

use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    Attempt, AttemptId, CapabilityValue, DnsQueryType, Hostname, InitialNetworkSnapshot,
    NeighborFact, NeighborIdentity, OperationPathContext, SystemResolverObservation, TargetIp,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticIoErrorKind {
    Cancelled,
    RequiredCapabilityUnavailable,
    ResourceExhausted,
    Internal,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{safe_message}")]
pub struct DiagnosticIoError {
    pub kind: DiagnosticIoErrorKind,
    pub safe_message: String,
}

impl DiagnosticIoError {
    #[must_use]
    pub fn new(kind: DiagnosticIoErrorKind, message: impl Display) -> Self {
        Self {
            kind,
            safe_message: message.to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IcmpEchoSubject {
    Target(TargetIp),
    NextHop(NeighborIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpOperation {
    pub attempt_id: AttemptId,
    pub target: TargetIp,
    pub port: u16,
    pub budget: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpOperation {
    pub attempt_id: AttemptId,
    pub subject: IcmpEchoSubject,
    pub budget: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathOperation {
    pub attempt_id: AttemptId,
    pub target: TargetIp,
    pub port: Option<u16>,
    pub hop_limit: u8,
    pub budget: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectDnsOperation {
    pub attempt_id: AttemptId,
    pub message_id: u16,
    pub resolver: SocketAddr,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub budget: Duration,
    pub reason: DirectDnsTransportReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectDnsTransportReason {
    ConfiguredTransport,
    UdpTimeoutComparison,
    UdpTruncationCompletion,
}

#[allow(async_fn_in_trait)]
pub trait DiagnosticIo: Sync {
    async fn capture_initial_snapshot(&self) -> Result<InitialNetworkSnapshot, DiagnosticIoError>;

    async fn system_resolve(
        &self,
        hostname: &Hostname,
        cancellation: &CancellationToken,
    ) -> Result<SystemResolverObservation, DiagnosticIoError>;

    async fn current_operation_path(
        &self,
        target: &TargetIp,
    ) -> Result<CapabilityValue<OperationPathContext>, DiagnosticIoError>;

    async fn neighbor(
        &self,
        identity: &NeighborIdentity,
    ) -> Result<CapabilityValue<NeighborFact>, DiagnosticIoError>;

    async fn observe_neighbor_convergence(
        &self,
        identity: &NeighborIdentity,
        cancellation: &CancellationToken,
    ) -> Result<CapabilityValue<NeighborFact>, DiagnosticIoError>;

    async fn tcp_connect(
        &self,
        operation: TcpOperation,
        cancellation: &CancellationToken,
    ) -> Result<Attempt, DiagnosticIoError>;

    async fn icmp_echo(
        &self,
        operation: IcmpOperation,
        cancellation: &CancellationToken,
    ) -> Result<Attempt, DiagnosticIoError>;

    async fn tcp_path_attempt(
        &self,
        operation: PathOperation,
        cancellation: &CancellationToken,
    ) -> Result<CapabilityValue<Attempt>, DiagnosticIoError>;

    async fn icmp_path_attempt(
        &self,
        operation: PathOperation,
        cancellation: &CancellationToken,
    ) -> Result<CapabilityValue<Attempt>, DiagnosticIoError>;

    async fn direct_dns_udp(
        &self,
        operation: DirectDnsOperation,
        cancellation: &CancellationToken,
    ) -> Result<Attempt, DiagnosticIoError>;

    async fn direct_dns_tcp(
        &self,
        operation: DirectDnsOperation,
        cancellation: &CancellationToken,
    ) -> Result<Attempt, DiagnosticIoError>;
}
