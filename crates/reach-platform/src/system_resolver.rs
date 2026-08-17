#[cfg(not(target_os = "linux"))]
use std::{io, net::SocketAddr};

#[cfg(not(target_os = "linux"))]
use dns_lookup::{AddrInfoHints, LookupErrorKind, SockType, getaddrinfo};
#[cfg(target_os = "linux")]
use gai_core::{
    NssEntry, NssSource, NssStatus, StepResult,
    config::{parse_hosts, parse_nsswitch},
    sim::SourceResolver,
    simulate,
};
#[cfg(target_os = "linux")]
use hickory_resolver::{
    Resolver,
    config::{LookupIpStrategy, ResolveHosts, ServerOrderingStrategy},
    net::runtime::TokioRuntimeProvider,
};
#[cfg(not(target_os = "linux"))]
use reach_core::InterfaceId;
use reach_core::{
    Hostname, Provenance, ProvenanceSource, ResolverAddressSet, SystemResolverFailure,
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
            Ok(raw_addresses) => {
                SystemResolverResult::Succeeded(ResolverAddressSet::from_raw(raw_addresses))
            }
            Err(ResolverWorkerError::Resolution(failure)) => SystemResolverResult::Failed(failure),
            #[cfg(target_os = "linux")]
            Err(ResolverWorkerError::CapabilityUnavailable(message)) => {
                return Err(PlatformError::NameResolutionCapabilityUnavailable(message));
            }
            #[cfg(not(target_os = "linux"))]
            Err(ResolverWorkerError::ResourceExhausted(message)) => {
                return Err(PlatformError::ResourceExhausted(message));
            }
        };

        #[cfg(target_os = "linux")]
        let detail = "self-contained Linux resolver; gai-core NSS order/action simulation with /etc/hosts and hickory-resolver DNS using /etc/resolv.conf; unsupported policy on the executed path is a required-capability error";
        #[cfg(not(target_os = "linux"))]
        let detail = "dns-lookup getaddrinfo on a detached OS thread; one call, no product timeout or retry; cancellation does not wait for an uninterruptible OS lookup";

        Ok(SystemResolverObservation {
            started_at,
            completed_at,
            result,
            provenance: Provenance::new(ProvenanceSource::SystemResolver)
                .at(completed_at)
                .with_detail(detail),
        })
    }
}

async fn await_worker(
    worker: tokio::sync::oneshot::Receiver<Result<Vec<TargetIp>, ResolverWorkerError>>,
    cancellation: &CancellationToken,
) -> Result<Result<Vec<TargetIp>, ResolverWorkerError>, PlatformError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(PlatformError::OperationCancelled),
        result = worker => result.map_err(|error| {
            PlatformError::ResolverWorkerFailed(error.to_string())
        }),
    }
}

#[cfg(not(target_os = "linux"))]
fn system_lookup(hostname: &str) -> Result<Vec<TargetIp>, ResolverWorkerError> {
    let hints = AddrInfoHints {
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

    records
        .map(|record| record.map(|record| target_from_socket_address(record.sockaddr)))
        .collect::<io::Result<Vec<_>>>()
        .map_err(|error| {
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

#[cfg(target_os = "linux")]
fn system_lookup(hostname: &str) -> Result<Vec<TargetIp>, ResolverWorkerError> {
    linux_lookup_with_paths(
        hostname,
        std::path::Path::new("/etc/nsswitch.conf"),
        std::path::Path::new("/etc/hosts"),
        std::path::Path::new("/etc/resolv.conf"),
    )
}

#[cfg(target_os = "linux")]
fn linux_lookup_with_paths(
    hostname: &str,
    nsswitch_path: &std::path::Path,
    hosts_path: &std::path::Path,
    resolv_path: &std::path::Path,
) -> Result<Vec<TargetIp>, ResolverWorkerError> {
    linux_lookup_with_paths_and_dns_port(hostname, nsswitch_path, hosts_path, resolv_path, None)
}

#[cfg(target_os = "linux")]
fn linux_lookup_with_paths_and_dns_port(
    hostname: &str,
    nsswitch_path: &std::path::Path,
    hosts_path: &std::path::Path,
    resolv_path: &std::path::Path,
    dns_port_override: Option<u16>,
) -> Result<Vec<TargetIp>, ResolverWorkerError> {
    let policy = parse_nsswitch(nsswitch_path).map_err(capability_error)?;
    if policy.hosts.is_empty() {
        return Err(capability_error(format!(
            "{} does not contain a usable hosts: policy",
            nsswitch_path.display()
        )));
    }
    let hosts = parse_hosts(hosts_path).map_err(capability_error)?;
    let mut source_resolver =
        LinuxSourceResolver::new(&policy.hosts, hosts, resolv_path, dns_port_override);
    let outcome = simulate(&policy, hostname, &mut source_resolver);
    if let Some(message) = source_resolver.capability_failure {
        return Err(capability_error(message));
    }
    if outcome.final_addresses.is_empty() {
        if let Some(message) = source_resolver.resolution_failure {
            return Err(ResolverWorkerError::Resolution(SystemResolverFailure {
                kind: SystemResolverFailureKind::ResolverFailure,
                platform_code: None,
                platform_message: message,
            }));
        }
        return Err(ResolverWorkerError::Resolution(SystemResolverFailure {
            kind: SystemResolverFailureKind::NoUsableAddress,
            platform_code: None,
            platform_message:
                "the executed Linux NSS policy returned no usable IPv4 or IPv6 address".into(),
        }));
    }
    Ok(outcome
        .final_addresses
        .into_iter()
        .map(target_from_ip_address)
        .collect())
}

#[cfg(target_os = "linux")]
fn capability_error(message: impl std::fmt::Display) -> ResolverWorkerError {
    ResolverWorkerError::CapabilityUnavailable(message.to_string())
}

#[cfg(target_os = "linux")]
struct LinuxSourceResolver<'a> {
    policy: &'a [NssEntry],
    hosts: Vec<gai_core::HostsEntry>,
    resolv_path: &'a std::path::Path,
    cursor: usize,
    capability_failure: Option<String>,
    resolution_failure: Option<String>,
    runtime: Option<tokio::runtime::Runtime>,
    dns: Option<hickory_resolver::TokioResolver>,
    dns_port_override: Option<u16>,
}

#[cfg(target_os = "linux")]
impl<'a> LinuxSourceResolver<'a> {
    fn new(
        policy: &'a [NssEntry],
        hosts: Vec<gai_core::HostsEntry>,
        resolv_path: &'a std::path::Path,
        dns_port_override: Option<u16>,
    ) -> Self {
        Self {
            policy,
            hosts,
            resolv_path,
            cursor: 0,
            capability_failure: None,
            resolution_failure: None,
            runtime: None,
            dns: None,
            dns_port_override,
        }
    }

    fn fail(&mut self, message: impl Into<String>) -> StepResult {
        let message = message.into();
        self.capability_failure
            .get_or_insert_with(|| message.clone());
        StepResult::Skipped { reason: message }
    }

    fn lookup_files(&self, name: &str) -> StepResult {
        let query = name.trim_end_matches('.');
        let addresses =
            self.hosts
                .iter()
                .filter(|entry| {
                    entry.names.iter().any(|candidate| {
                        candidate.trim_end_matches('.').eq_ignore_ascii_case(query)
                    })
                })
                .map(|entry| entry.ip)
                .collect::<Vec<_>>();
        if addresses.is_empty() {
            StepResult::NotFound
        } else {
            StepResult::Found(addresses)
        }
    }

    fn prepare_dns(&mut self, entry: &NssEntry) -> Result<(), String> {
        if entry
            .criteria
            .iter()
            .any(|criterion| matches!(criterion.status, NssStatus::TryAgain | NssStatus::Unavail))
        {
            return Err(
                "the executed dns NSS entry distinguishes TRYAGAIN/UNAVAIL, which the selected self-contained DNS adapter cannot faithfully classify"
                    .into(),
            );
        }
        if self.dns.is_some() {
            return Ok(());
        }
        let bytes = std::fs::read(self.resolv_path)
            .map_err(|error| format!("cannot read {}: {error}", self.resolv_path.display()))?;
        let parsed = resolv_conf::Config::parse(&bytes)
            .map_err(|error| format!("cannot parse {}: {error}", self.resolv_path.display()))?;
        validate_resolv_options(&parsed)?;
        let (config, mut options) = hickory_resolver::system_conf::parse_resolv_conf(&bytes)
            .map_err(|error| format!("cannot apply {}: {error}", self.resolv_path.display()))?;
        let config = if let Some(port) = self.dns_port_override {
            let (domain, search, mut name_servers) = config.into_parts();
            for name_server in &mut name_servers {
                for connection in &mut name_server.connections {
                    connection.port = port;
                }
            }
            hickory_resolver::config::ResolverConfig::from_parts(domain, search, name_servers)
        } else {
            config
        };
        options.use_hosts_file = ResolveHosts::Never;
        options.ip_strategy = if parsed.inet6 {
            LookupIpStrategy::Ipv6AndIpv4
        } else {
            LookupIpStrategy::Ipv4AndIpv6
        };
        options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        options.num_concurrent_reqs = 1;
        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
            .map_err(|error| format!("cannot initialize DNS source: {error}"))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("cannot initialize DNS runtime: {error}"))?;
        self.dns = Some(resolver);
        self.runtime = Some(runtime);
        Ok(())
    }

    fn lookup_dns(&mut self, entry: &NssEntry, name: &str) -> StepResult {
        if let Err(message) = self.prepare_dns(entry) {
            return self.fail(message);
        }
        let (Some(runtime), Some(resolver)) = (&self.runtime, &self.dns) else {
            return self.fail("DNS source was not initialized");
        };
        match runtime.block_on(resolver.lookup_ip(name)) {
            Ok(lookup) => {
                let addresses = lookup.iter().collect::<Vec<_>>();
                if addresses.is_empty() {
                    StepResult::NotFound
                } else {
                    StepResult::Found(addresses)
                }
            }
            Err(error) if error.is_no_records_found() => StepResult::NotFound,
            Err(error) => {
                let message = format!("DNS source failed: {error}");
                self.resolution_failure = Some(message.clone());
                StepResult::Skipped { reason: message }
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl SourceResolver for LinuxSourceResolver<'_> {
    fn resolve(&mut self, source: &NssSource, name: &str) -> StepResult {
        let Some(entry) = self.policy.get(self.cursor).cloned() else {
            return self.fail("NSS simulator executed beyond the parsed hosts policy");
        };
        self.cursor += 1;
        if &entry.source != source {
            return self.fail("NSS simulator source order differs from the parsed hosts policy");
        }
        if self.capability_failure.is_some() {
            return StepResult::Skipped {
                reason: "a prior required NSS capability was unavailable".into(),
            };
        }
        match source {
            NssSource::Files => self.lookup_files(name),
            NssSource::Dns => self.lookup_dns(&entry, name),
            unsupported => self.fail(format!(
                "executed NSS source {unsupported:?} is not supported by the self-contained Linux resolver"
            )),
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_resolv_options(config: &resolv_conf::Config) -> Result<(), String> {
    let mut unsupported = Vec::new();
    if config.rotate {
        unsupported.push("rotate");
    }
    if config.single_request {
        unsupported.push("single-request");
    }
    if config.single_request_reopen {
        unsupported.push("single-request-reopen");
    }
    if config.no_tld_query {
        unsupported.push("no-tld-query");
    }
    if config.use_vc {
        unsupported.push("use-vc");
    }
    if config.no_aaaa {
        unsupported.push("no-aaaa");
    }
    if !config.sortlist.is_empty() {
        unsupported.push("sortlist");
    }
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "unsupported resolv.conf option(s) affect formal resolution: {}",
            unsupported.join(", ")
        ))
    }
}

#[derive(Debug)]
enum ResolverWorkerError {
    Resolution(SystemResolverFailure),
    #[cfg(target_os = "linux")]
    CapabilityUnavailable(String),
    #[cfg(not(target_os = "linux"))]
    ResourceExhausted(String),
}

#[cfg(not(target_os = "linux"))]
const fn classify_lookup_error(kind: LookupErrorKind) -> SystemResolverFailureKind {
    match kind {
        LookupErrorKind::NoName | LookupErrorKind::NoData => {
            SystemResolverFailureKind::NoUsableAddress
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

#[cfg(not(target_os = "linux"))]
fn classify_io_error(error: &io::Error) -> SystemResolverFailureKind {
    match error.kind() {
        io::ErrorKind::TimedOut => SystemResolverFailureKind::Timeout,
        _ => SystemResolverFailureKind::OtherPlatformFailure,
    }
}

#[cfg(not(target_os = "linux"))]
fn target_from_socket_address(address: SocketAddr) -> TargetIp {
    match address {
        SocketAddr::V4(address) => TargetIp::v4(*address.ip()),
        SocketAddr::V6(address) => TargetIp::v6(
            *address.ip(),
            (address.scope_id() != 0).then(|| InterfaceId::from_index(address.scope_id())),
        ),
    }
}

#[cfg(target_os = "linux")]
fn target_from_ip_address(address: std::net::IpAddr) -> TargetIp {
    match address {
        std::net::IpAddr::V4(address) => TargetIp::v4(address),
        std::net::IpAddr::V6(address) => TargetIp::v6(address, None),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use std::net::{Ipv6Addr, SocketAddrV6};

    use super::*;

    #[cfg(target_os = "linux")]
    struct LinuxFixture {
        directory: tempfile::TempDir,
    }

    #[cfg(target_os = "linux")]
    impl LinuxFixture {
        fn new(nsswitch: &str, hosts: &str, resolv: &str) -> Self {
            let directory = tempfile::tempdir().expect("temporary resolver fixture");
            std::fs::write(directory.path().join("nsswitch.conf"), nsswitch)
                .expect("nsswitch fixture");
            std::fs::write(directory.path().join("hosts"), hosts).expect("hosts fixture");
            std::fs::write(directory.path().join("resolv.conf"), resolv).expect("resolv fixture");
            Self { directory }
        }

        fn resolve(&self, name: &str) -> Result<Vec<TargetIp>, ResolverWorkerError> {
            linux_lookup_with_paths(
                name,
                &self.directory.path().join("nsswitch.conf"),
                &self.directory.path().join("hosts"),
                &self.directory.path().join("resolv.conf"),
            )
        }

        fn resolve_with_dns_port(
            &self,
            name: &str,
            port: u16,
        ) -> Result<Vec<TargetIp>, ResolverWorkerError> {
            linux_lookup_with_paths_and_dns_port(
                name,
                &self.directory.path().join("nsswitch.conf"),
                &self.directory.path().join("hosts"),
                &self.directory.path().join("resolv.conf"),
                Some(port),
            )
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn files_hit_preserves_order_duplicates_and_short_circuits_unsupported_sources() {
        let fixture = LinuxFixture::new(
            "hosts: files sss dns\n",
            "192.0.2.20 admin\n2001:db8::20 admin\n192.0.2.20 admin\n",
            "this is deliberately not a resolv.conf\n",
        );
        let addresses = fixture
            .resolve("admin")
            .expect("files must terminate first");
        assert_eq!(
            addresses,
            vec![
                TargetIp::v4("192.0.2.20".parse().expect("IPv4")),
                TargetIp::v6("2001:db8::20".parse().expect("IPv6"), None),
                TargetIp::v4("192.0.2.20".parse().expect("IPv4")),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_source_on_the_executed_path_is_a_capability_error_before_dns() {
        let fixture = LinuxFixture::new(
            "hosts: files sss dns\n",
            "127.0.0.1 localhost\n",
            "this is deliberately not a resolv.conf\n",
        );
        let error = fixture
            .resolve("admin")
            .expect_err("sss must not be skipped");
        let ResolverWorkerError::CapabilityUnavailable(message) = error else {
            panic!("expected required capability failure");
        };
        assert!(message.contains("Other(\"sss\")"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nss_notfound_return_stops_before_a_later_unsupported_source() {
        let fixture = LinuxFixture::new(
            "hosts: files [NOTFOUND=return] sss dns\n",
            "127.0.0.1 localhost\n",
            "this is deliberately not a resolv.conf\n",
        );
        let error = fixture
            .resolve("admin")
            .expect_err("negative result has no addresses");
        let ResolverWorkerError::Resolution(failure) = error else {
            panic!("unsupported source must remain unexecuted");
        };
        assert_eq!(failure.kind, SystemResolverFailureKind::NoUsableAddress);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_nss_policy_is_a_required_capability_error() {
        let fixture = LinuxFixture::new(
            "hosts: files [NOTFOUND=guess] dns\n",
            "127.0.0.1 localhost\n",
            "nameserver 192.0.2.53\n",
        );
        assert!(matches!(
            fixture.resolve("admin"),
            Err(ResolverWorkerError::CapabilityUnavailable(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn selected_resolv_parser_retains_search_domain_and_ndots() {
        let bytes = b"nameserver 192.0.2.53\nsearch corp.example\noptions ndots:2\n";
        let (config, options) = hickory_resolver::system_conf::parse_resolv_conf(bytes)
            .expect("supported resolver config");
        assert_eq!(options.ndots, 2);
        assert_eq!(
            config
                .search()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["corp.example"]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dns_source_applies_single_label_search_and_preserves_trailing_dot() {
        use std::sync::{Arc, Mutex};

        use hickory_proto::{
            op::{Message, OpCode, ResponseCode},
            rr::{RData, Record, RecordType, rdata::A},
        };

        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("ordinary-user local DNS fixture on an ephemeral port");
        let dns_port = socket.local_addr().expect("DNS fixture address").port();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("DNS fixture timeout");
        let observed_names = Arc::new(Mutex::new(Vec::new()));
        let server_names = observed_names.clone();
        let server = std::thread::spawn(move || {
            for _ in 0..4 {
                let mut wire = [0_u8; 2048];
                let (length, peer) = socket.recv_from(&mut wire).expect("receive DNS query");
                let query = Message::from_vec(&wire[..length]).expect("decode DNS query");
                let question = query.queries.first().expect("one DNS question");
                server_names
                    .lock()
                    .expect("query-name lock")
                    .push(question.name().to_string());
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.queries = query.queries.clone();
                response.metadata.response_code = ResponseCode::NoError;
                if question.query_type() == RecordType::A {
                    let answer = Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::A(A::new(192, 0, 2, 53)),
                    );
                    response.add_answers([answer.clone(), answer]);
                }
                socket
                    .send_to(&response.to_vec().expect("encode DNS response"), peer)
                    .expect("send DNS response");
            }
        });

        let fixture = LinuxFixture::new(
            "hosts: files dns\n",
            "127.0.0.1 localhost\n",
            "nameserver 127.0.0.1\nsearch corp.example\noptions ndots:1 timeout:1 attempts:1\n",
        );
        let searched = fixture
            .resolve_with_dns_port("admin", dns_port)
            .expect("search-domain lookup");
        let absolute = fixture
            .resolve_with_dns_port("admin.", dns_port)
            .expect("absolute lookup");
        server.join().expect("DNS fixture thread");

        let expected = vec![
            TargetIp::v4(std::net::Ipv4Addr::new(192, 0, 2, 53)),
            TargetIp::v4(std::net::Ipv4Addr::new(192, 0, 2, 53)),
        ];
        assert_eq!(searched, expected);
        assert_eq!(absolute, expected);
        let names = observed_names.lock().expect("query-name lock");
        assert!(names.iter().any(|name| name == "admin.corp.example."));
        assert!(names.iter().any(|name| name == "admin."));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_resolv_behavior_is_rejected_instead_of_ignored() {
        for (text, option) in [
            ("options rotate", "rotate"),
            ("options single-request", "single-request"),
            ("options use-vc", "use-vc"),
            ("options no-aaaa", "no-aaaa"),
        ] {
            let config = resolv_conf::Config::parse(text).expect("recognized resolver option");
            let error = validate_resolv_options(&config).expect_err("unsupported option");
            assert!(error.contains(option));
        }
    }

    #[cfg(not(target_os = "linux"))]
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

    #[cfg(not(target_os = "linux"))]
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
            .expect("ordinary-user system resolver call must execute");
        let SystemResolverResult::Succeeded(addresses) = observation.result else {
            panic!("localhost must resolve through the system policy: {observation:?}");
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
