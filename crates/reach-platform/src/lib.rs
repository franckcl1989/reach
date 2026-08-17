//! Operating-system capability adapters.
//!
//! The implementation is intentionally introduced capability by capability.
//! General networking behavior must first pass the ADR 0002 dependency audit;
//! any unavoidable unsafe platform glue stays inside this crate.

mod adapter;
mod clock;
mod direct_dns;
mod icmp;
mod interfaces;
mod neighbor;
mod resolver_config;
mod routes;
mod snapshot;
mod system_resolver;
mod tcp;

pub use adapter::PlatformDiagnosticIo;
pub use clock::{ContinuousClock, SystemContinuousClock};
pub use direct_dns::{DirectDnsRequest, dns_tcp_once, dns_udp_once};
pub use icmp::{IcmpEchoRequest, IcmpEchoSubject, icmp_echo_once};
pub use interfaces::capture_interfaces;
pub use neighbor::{
    NEIGHBOR_CONVERGENCE_BUDGET, NEIGHBOR_POLL_INTERVAL, capture_neighbor,
    observe_neighbor_convergence,
};
pub use resolver_config::capture_resolver_configuration;
pub use routes::{capture_current_operation_path, capture_routes, capture_routing_policy};
pub use snapshot::capture_initial_snapshot;
pub use system_resolver::SystemResolverAdapter;
pub use tcp::tcp_connect_once;

use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PlatformError {
    #[error("the operating system continuous clock is unavailable: {0}")]
    ClockUnavailable(String),
    #[error("the operation was cancelled")]
    OperationCancelled,
    #[error("the system resolver worker failed: {0}")]
    ResolverWorkerFailed(String),
    #[error("the required Linux name-resolution capability is unavailable: {0}")]
    NameResolutionCapabilityUnavailable(String),
    #[error("the DNS query name cannot be encoded: {0}")]
    InvalidDnsQueryName(String),
    #[error("the ordinary-user ICMP facility is unavailable: {0}")]
    IcmpUnavailable(String),
    #[error("local networking resources are exhausted: {0}")]
    ResourceExhausted(String),
}

pub(crate) fn is_resource_exhaustion(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::OutOfMemory {
        return true;
    }
    let code = error.raw_os_error();
    #[cfg(unix)]
    {
        matches!(code, Some(value) if value == libc::EMFILE
            || value == libc::ENFILE
            || value == libc::ENOBUFS
            || value == libc::ENOMEM)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
        matches!(code, Some(value) if value == WSAEMFILE || value == WSAENOBUFS)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}
