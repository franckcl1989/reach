use std::{io, net::SocketAddr};

use dns_lookup::{AddrInfo, AddrInfoHints, LookupErrorKind, SockType, getaddrinfo};
use reach_core::{
    Hostname, InterfaceId, Provenance, ProvenanceSource, ResolverAddressSet, SystemResolverFailure,
    SystemResolverFailureKind, SystemResolverObservation, SystemResolverResult, TargetIp,
};
use tokio_util::sync::CancellationToken;

use crate::{ContinuousClock, PlatformError};

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolverAdapter;

impl SystemResolverAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub async fn resolve_hostname(
        &self,
        hostname: &Hostname,
        cancellation: &CancellationToken,
        clock: &impl ContinuousClock,
    ) -> Result<SystemResolverObservation, PlatformError> {
        if cancellation.is_cancelled() {
            return Err(PlatformError::OperationCancelled);
        }
        let started_at = clock.now()?;
        let hostname = hostname.ascii().to_owned();
        let (sender, worker) = tokio::sync::oneshot::channel();
        let worker_thread = std::thread::Builder::new()
            .name("reach-system-resolver".into())
            .spawn(move || {
                let _ = sender.send(system_lookup(&hostname));
            });
        if let Err(error) = worker_thread {
            return if crate::is_resource_exhaustion(&error) {
                Err(PlatformError::ResourceExhausted(error.to_string()))
            } else {
                Err(PlatformError::ResolverWorkerFailed(error.to_string()))
            };
        }

        let result = await_worker(worker, cancellation).await?;
        let completed_at = clock.now()?;
        let result = match result {
            Ok(records) => {
                let raw_addresses = records
                    .into_iter()
                    .map(|record| target_from_socket_address(record.sockaddr))
                    .collect();
                SystemResolverResult::Succeeded(ResolverAddressSet::from_raw(raw_addresses))
            }
            Err(ResolverWorkerError::Resolution(failure)) => SystemResolverResult::Failed(failure),
            Err(ResolverWorkerError::ResourceExhausted(message)) => {
                return Err(PlatformError::ResourceExhausted(message));
            }
        };

        Ok(SystemResolverObservation {
            started_at,
            completed_at,
            result,
            provenance: Provenance::new(ProvenanceSource::SystemResolver)
                .at(completed_at)
                .with_detail("dns-lookup getaddrinfo on a detached OS thread; one call, no product timeout or retry; cancellation does not wait for an uninterruptible OS lookup"),
        })
    }
}

async fn await_worker(
    worker: tokio::sync::oneshot::Receiver<Result<Vec<AddrInfo>, ResolverWorkerError>>,
    cancellation: &CancellationToken,
) -> Result<Result<Vec<AddrInfo>, ResolverWorkerError>, PlatformError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(PlatformError::OperationCancelled),
        result = worker => result.map_err(|error| {
            PlatformError::ResolverWorkerFailed(error.to_string())
        }),
    }
}

fn system_lookup(hostname: &str) -> Result<Vec<AddrInfo>, ResolverWorkerError> {
    let hints = AddrInfoHints {
        // This matches Rust's standard ToSocketAddrs query shape while leaving
        // the address family unspecified, so both IPv4 and IPv6 remain OS-owned.
        socktype: SockType::Stream.into(),
        ..AddrInfoHints::default()
    };
    let records = getaddrinfo(Some(hostname), None, Some(hints)).map_err(|error| {
        let kind = error.kind();
        let platform_code = error.error_num();
        let error: io::Error = error.into();
        if matches!(&kind, LookupErrorKind::Memory) || crate::is_resource_exhaustion(&error) {
            ResolverWorkerError::ResourceExhausted(error.to_string())
        } else {
            ResolverWorkerError::Resolution(SystemResolverFailure {
                kind: classify_lookup_error(kind),
                platform_code: Some(platform_code),
                platform_message: error.to_string(),
            })
        }
    })?;

    records.collect::<io::Result<Vec<_>>>().map_err(|error| {
        if crate::is_resource_exhaustion(&error) {
            ResolverWorkerError::ResourceExhausted(error.to_string())
        } else {
            ResolverWorkerError::Resolution(SystemResolverFailure {
                kind: classify_io_error(&error),
                platform_code: error.raw_os_error(),
                platform_message: error.to_string(),
            })
        }
    })
}

#[derive(Debug)]
enum ResolverWorkerError {
    Resolution(SystemResolverFailure),
    ResourceExhausted(String),
}

const fn classify_lookup_error(kind: LookupErrorKind) -> SystemResolverFailureKind {
    match kind {
        LookupErrorKind::NoName | LookupErrorKind::NoData => {
            SystemResolverFailureKind::DefinitiveNoName
        }
        LookupErrorKind::Again => SystemResolverFailureKind::Temporary,
        LookupErrorKind::Fail => SystemResolverFailureKind::ResolverFailure,
        LookupErrorKind::Badflags
        | LookupErrorKind::Family
        | LookupErrorKind::Socktype
        | LookupErrorKind::Service
        | LookupErrorKind::Memory
        | LookupErrorKind::System
        | LookupErrorKind::IO => SystemResolverFailureKind::OtherPlatformFailure,
        LookupErrorKind::Unknown => SystemResolverFailureKind::Unknown,
    }
}

fn classify_io_error(error: &io::Error) -> SystemResolverFailureKind {
    match error.kind() {
        io::ErrorKind::TimedOut => SystemResolverFailureKind::Timeout,
        _ => SystemResolverFailureKind::OtherPlatformFailure,
    }
}

fn target_from_socket_address(address: SocketAddr) -> TargetIp {
    match address {
        SocketAddr::V4(address) => TargetIp::v4(*address.ip()),
        SocketAddr::V6(address) => TargetIp::v6(
            *address.ip(),
            (address.scope_id() != 0).then(|| InterfaceId::from_index(address.scope_id())),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddrV6};

    use super::*;

    #[test]
    fn resolver_ipv6_scope_is_part_of_target_identity() {
        let target = target_from_socket_address(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            7,
        )));
        assert_eq!(target.scope, Some(InterfaceId::from_index(7)));
    }

    #[test]
    fn resolver_zero_scope_stays_unscoped() {
        let target = target_from_socket_address(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        )));
        assert_eq!(target.scope, None);
    }

    #[tokio::test]
    async fn ordinary_user_system_resolver_resolves_localhost() {
        let parsed = reach_core::parse_request("localhost", None).expect("valid hostname");
        let reach_core::ParsedAddress::Hostname(hostname) = parsed.address else {
            panic!("expected hostname");
        };
        let observation = SystemResolverAdapter::new()
            .resolve_hostname(
                &hostname,
                &CancellationToken::new(),
                &crate::SystemContinuousClock,
            )
            .await
            .expect("ordinary-user OS resolver call must execute");
        let SystemResolverResult::Succeeded(addresses) = observation.result else {
            panic!("localhost must resolve through the OS resolver: {observation:?}");
        };
        assert!(!addresses.raw_addresses.is_empty());
        assert!(!addresses.formal_targets.is_empty());
    }

    #[tokio::test]
    async fn cancellation_preempts_the_os_resolver_without_a_product_timeout() {
        let parsed = reach_core::parse_request("example.com", None).expect("valid hostname");
        let reach_core::ParsedAddress::Hostname(hostname) = parsed.address else {
            panic!("expected hostname");
        };
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = SystemResolverAdapter::new()
            .resolve_hostname(&hostname, &cancellation, &crate::SystemContinuousClock)
            .await;
        assert!(matches!(result, Err(PlatformError::OperationCancelled)));
    }

    #[tokio::test]
    async fn in_flight_uninterruptible_resolver_worker_does_not_delay_cancellation() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            signal.cancel();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            await_worker(receiver, &cancellation),
        )
        .await
        .expect("cancellation must not wait for the unresolved worker channel");
        cancel_task.await.expect("cancellation task");
        assert!(matches!(result, Err(PlatformError::OperationCancelled)));

        drop(sender);
    }
}
