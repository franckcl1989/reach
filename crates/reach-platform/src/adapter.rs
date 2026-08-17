use reach_core::{
    CapabilityReason, CapabilityValue, DiagnosticIo, DiagnosticIoError, DiagnosticIoErrorKind,
    DirectDnsOperation, IcmpEchoSubject as CoreIcmpSubject, IcmpOperation, PathOperation,
    Provenance, ProvenanceSource, TcpOperation,
};
use tokio_util::sync::CancellationToken;

use crate::{
    ContinuousClock, DirectDnsRequest, IcmpEchoRequest, IcmpEchoSubject, PlatformError,
    SystemContinuousClock, SystemResolverAdapter, capture_current_operation_path,
    capture_initial_snapshot, capture_neighbor, dns_tcp_once, dns_udp_once, icmp_echo_once,
    observe_neighbor_convergence, tcp_connect_once,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformDiagnosticIo {
    clock: SystemContinuousClock,
    resolver: SystemResolverAdapter,
}

impl PlatformDiagnosticIo {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            clock: SystemContinuousClock,
            resolver: SystemResolverAdapter::new(),
        }
    }

    fn path_unavailable(
        &self,
        detail: &'static str,
    ) -> Result<CapabilityValue<reach_core::Attempt>, DiagnosticIoError> {
        let observed_at = self.clock.now().map_err(map_platform_error)?;
        Ok(CapabilityValue::unavailable(
            CapabilityReason::AttemptCorrelationUnavailable,
            Provenance::new(ProvenanceSource::PlatformCapabilityProbe)
                .at(observed_at)
                .with_detail(detail),
        ))
    }
}

impl DiagnosticIo for PlatformDiagnosticIo {
    async fn capture_initial_snapshot(
        &self,
    ) -> Result<reach_core::InitialNetworkSnapshot, DiagnosticIoError> {
        capture_initial_snapshot(&self.clock)
            .await
            .map_err(map_platform_error)
    }

    async fn system_resolve(
        &self,
        hostname: &reach_core::Hostname,
        cancellation: &CancellationToken,
    ) -> Result<reach_core::SystemResolverObservation, DiagnosticIoError> {
        self.resolver
            .resolve_hostname(hostname, cancellation, &self.clock)
            .await
            .map_err(map_platform_error)
    }

    async fn current_operation_path(
        &self,
        target: &reach_core::TargetIp,
    ) -> Result<CapabilityValue<reach_core::OperationPathContext>, DiagnosticIoError> {
        let observed_at = self.clock.now().map_err(map_platform_error)?;
        Ok(capture_current_operation_path(target, observed_at).await)
    }

    async fn neighbor(
        &self,
        identity: &reach_core::NeighborIdentity,
    ) -> Result<CapabilityValue<reach_core::NeighborFact>, DiagnosticIoError> {
        let observed_at = self.clock.now().map_err(map_platform_error)?;
        Ok(capture_neighbor(identity, observed_at).await)
    }

    async fn observe_neighbor_convergence(
        &self,
        identity: &reach_core::NeighborIdentity,
        cancellation: &CancellationToken,
    ) -> Result<CapabilityValue<reach_core::NeighborFact>, DiagnosticIoError> {
        observe_neighbor_convergence(identity, cancellation, &self.clock)
            .await
            .map_err(map_platform_error)
    }

    async fn tcp_connect(
        &self,
        operation: TcpOperation,
        cancellation: &CancellationToken,
    ) -> Result<reach_core::Attempt, DiagnosticIoError> {
        tcp_connect_once(
            operation.attempt_id,
            operation.target,
            operation.port,
            operation.budget,
            cancellation,
            &self.clock,
        )
        .await
        .map_err(map_platform_error)
    }

    async fn icmp_echo(
        &self,
        operation: IcmpOperation,
        cancellation: &CancellationToken,
    ) -> Result<reach_core::Attempt, DiagnosticIoError> {
        let subject = match operation.subject {
            CoreIcmpSubject::Target(target) => IcmpEchoSubject::Target(target),
            CoreIcmpSubject::NextHop(neighbor) => IcmpEchoSubject::NextHop(neighbor),
        };
        icmp_echo_once(
            IcmpEchoRequest {
                attempt_id: operation.attempt_id,
                subject,
                budget: operation.budget,
            },
            cancellation,
            &self.clock,
        )
        .await
        .map_err(map_platform_error)
    }

    async fn tcp_path_attempt(
        &self,
        _operation: PathOperation,
        _cancellation: &CancellationToken,
    ) -> Result<CapabilityValue<reach_core::Attempt>, DiagnosticIoError> {
        self.path_unavailable(
            "no selected ordinary-user mechanism reliably correlates TCP TTL/Hop-Limit responses to the originating Attempt",
        )
    }

    async fn icmp_path_attempt(
        &self,
        _operation: PathOperation,
        _cancellation: &CancellationToken,
    ) -> Result<CapabilityValue<reach_core::Attempt>, DiagnosticIoError> {
        self.path_unavailable(
            "no selected ordinary-user mechanism reliably correlates router-originated ICMP TTL/Hop-Limit responses to the originating target Attempt",
        )
    }

    async fn direct_dns_udp(
        &self,
        operation: DirectDnsOperation,
        cancellation: &CancellationToken,
    ) -> Result<reach_core::Attempt, DiagnosticIoError> {
        dns_udp_once(
            DirectDnsRequest {
                attempt_id: operation.attempt_id,
                message_id: operation.message_id,
                resolver: operation.resolver,
                query_name: &operation.query_name,
                query_type: operation.query_type,
                budget: operation.budget,
                reason: operation.reason,
            },
            cancellation,
            &self.clock,
        )
        .await
        .map_err(map_platform_error)
    }

    async fn direct_dns_tcp(
        &self,
        operation: DirectDnsOperation,
        cancellation: &CancellationToken,
    ) -> Result<reach_core::Attempt, DiagnosticIoError> {
        dns_tcp_once(
            DirectDnsRequest {
                attempt_id: operation.attempt_id,
                message_id: operation.message_id,
                resolver: operation.resolver,
                query_name: &operation.query_name,
                query_type: operation.query_type,
                budget: operation.budget,
                reason: operation.reason,
            },
            cancellation,
            &self.clock,
        )
        .await
        .map_err(map_platform_error)
    }
}

fn map_platform_error(error: PlatformError) -> DiagnosticIoError {
    let kind = match error {
        PlatformError::OperationCancelled => DiagnosticIoErrorKind::Cancelled,
        PlatformError::ResourceExhausted(_) => DiagnosticIoErrorKind::ResourceExhausted,
        PlatformError::IcmpUnavailable(_) => DiagnosticIoErrorKind::RequiredCapabilityUnavailable,
        PlatformError::ClockUnavailable(_)
        | PlatformError::ResolverWorkerFailed(_)
        | PlatformError::InvalidDnsQueryName(_) => DiagnosticIoErrorKind::Internal,
    };
    DiagnosticIoError::new(kind, error)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use reach_core::{AttemptId, DiagnosticIo, PathOperation, TargetIp};

    use super::*;

    #[tokio::test]
    async fn unproven_path_correlation_is_an_explicit_native_capability_state() {
        let io = PlatformDiagnosticIo::new();
        for (ordinal, target) in [
            TargetIp::v4(Ipv4Addr::LOCALHOST),
            TargetIp::v6(Ipv6Addr::LOCALHOST, None),
        ]
        .into_iter()
        .enumerate()
        {
            let operation = PathOperation {
                attempt_id: AttemptId(ordinal as u64 + 1),
                target,
                port: Some(443),
                hop_limit: 1,
                budget: Duration::from_secs(1),
            };
            let tcp = io
                .tcp_path_attempt(operation.clone(), &CancellationToken::new())
                .await
                .expect("capability query succeeds");
            let icmp = io
                .icmp_path_attempt(operation, &CancellationToken::new())
                .await
                .expect("capability query succeeds");
            assert!(matches!(
                tcp,
                CapabilityValue::Unavailable {
                    reason: CapabilityReason::AttemptCorrelationUnavailable,
                    ..
                }
            ));
            assert!(matches!(
                icmp,
                CapabilityValue::Unavailable {
                    reason: CapabilityReason::AttemptCorrelationUnavailable,
                    ..
                }
            ));
        }
    }

    #[test]
    fn local_resource_exhaustion_is_not_downgraded_to_a_network_result() {
        let error = map_platform_error(PlatformError::ResourceExhausted("synthetic".into()));
        assert_eq!(error.kind, DiagnosticIoErrorKind::ResourceExhausted);
    }
}
