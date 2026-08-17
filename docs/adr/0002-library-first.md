# ADR 0002: Mature-library-first implementation policy

- Status: Accepted
- Date: 2026-08-17
- Supersedes: any implementation shortcut implied by ADR 0001

## Decision

Do not implement a general capability in first-party code when a popular or
mature Rust crate provides that capability with the semantics required by the
product baseline. Code size, apparent simplicity, or a desire to avoid a
dependency are not valid reasons to reimplement it.

First-party code is allowed only for:

1. Reach-specific state machines, attempt histories, fact/evidence models,
   conclusions, aggregation, and CLI rendering contracts;
2. small semantic adapters between a selected crate and the Core model;
3. a capability or required observable detail not supplied by a suitable
   mature crate;
4. platform API glue after a documented crate search shows that available
   crates omit required facts, hide retries/fallbacks, require elevation, or
   otherwise change the product semantics.

An available crate is not automatically suitable. It must expose enough
control and observability to preserve Reach's traffic trigger, attempt,
deadline, retry, transport, source-selection, cancellation, and provenance
contracts. If a crate silently retries, changes protocols, hides the raw result
class, or performs active traffic during a passive query, it does not provide
the required capability.

## Required dependency audit

Before first-party implementation of a general capability:

- search crates.io and official crate documentation;
- inspect the public API and, for behavior-bearing operations, the relevant
  implementation path;
- record why the selected crate is sufficient or why the closest candidates
  are insufficient;
- add a conformance test that protects the product semantic at the boundary;
- revisit the exception before a release and when related dependencies are
  upgraded.

Dependencies are pinned through `Cargo.lock`. Security, license, maintenance,
and target support are release gates alongside functional suitability.

## Initial capability audit

| Capability | Decision | Rationale |
|---|---|---|
| CLI structure | `clap` | Mature positional parsing/help; Core still owns address and port semantics. |
| Adaptive terminal streams and style | `anstream` + `anstyle` | Rust CLI ecosystem primitives add color only when supported and strip ANSI automatically from redirected output. Reach owns only its semantic hierarchy and wording. |
| Structured tables and width | `comfy-table` + `terminal_size` | Mature Unicode-aware table layout, content wrapping, and cross-platform terminal sizing replace handwritten column and border logic. |
| Prose wrapping | `textwrap` | Mature Unicode-aware line breaking keeps explanations and actions readable at the detected terminal width. |
| Display-width conformance | `unicode-width` | Mature Unicode display-width measurement verifies that adaptive layouts stay within the requested terminal width without first-party width tables. |
| Transient progress | `indicatif` | Mature cross-platform TTY spinner and clearing behavior; redirected stderr remains empty. |
| Duration presentation | `humantime` | Mature, deterministic human-readable formatting for observed durations and Attempt limits. |
| Terminal-safe Unicode | `unicode-general-category` | Unicode category data identifies format controls such as bidirectional overrides without rejecting ordinary readable non-ASCII hostnames or OS text. |
| IPv4/IPv6 literal | `std::net` | Standard-library strict parser. |
| IDN + hostname | `idna` + `hostname-validator` | Mature UTS #46 preparation and RFC 1123 validation; only FQDN terminal-dot composition remains first-party. |
| IP prefixes | `ipnet` | Mature typed prefix validation and operations. |
| Interfaces | `netdev` without its `gateway` feature | Mature cross-platform interface/address/state inventory. The gateway feature is disabled because it performs active UDP connects, which would violate passive-snapshot semantics. |
| Windows/macOS ordinary routes | `netroute` | Mature native route enumeration with destination, gateway, interface, metric, table, scope, protocol, and reject flags. Missing platform details remain explicit unknowns. |
| Cross-platform route alternatives | `getifs` rejected as sole provider | It intentionally omits policy tables and reject/blackhole route types, so it cannot represent the required route semantics. |
| Linux policy route/Neighbor | `rtnetlink` family | Mature netlink encoding/decoding; Reach maps facts and owns no netlink packet codec. A destination-only route query is not promoted to current-path Available because it cannot prove the later socket's flow-dependent selection. |
| Continuous clock | `rustix` / `mach2` / `windows-sys` | Mature bindings expose Linux `CLOCK_BOOTTIME`, macOS `mach_continuous_time`, and Windows `GetTickCount64`; Reach only normalizes units to `Duration`. |
| TCP and UDP sockets | Tokio | Mature nonblocking I/O; Reach owns each explicit Attempt and does not retain an unused direct socket-options dependency while path correlation is unavailable. |
| Unix ICMP Echo | `surge-ping` | Exposes decoded ICMP packets, ordinary-user DGRAM sockets, IPv6 scope, raw type/code, and a single-send `Pinger::ping` operation. Reach ignores its `Instant`-based RTT and classifies completion against the product continuous clock. It is not used for TCP path correlation because its reply map keys by outer source address, so a router-originated Time Exceeded cannot match the original target. |
| Cross-platform high-level ICMP | `ping-async` rejected as sole provider | It collapses explicit Time Exceeded into timeout and exposes only four statuses, losing a required fact. |
| Windows ICMP detail | Windows IP Helper through `windows-sys` | No suitable mature high-level crate found that exposes all required IP status classes at ordinary-user privilege. Reach uses generated `windows-sys` declarations for `IcmpSendEcho2`/`Icmp6SendEcho2`, not handwritten FFI, and has a real ordinary-user loopback conformance test. |
| System resolver | `dns-lookup` + detached standard thread | Mature cross-platform `getaddrinfo` wrapper that preserves native order, duplicates, and classified native errors. Reach makes one `AF_UNSPEC` call with no product timeout; a detached thread prevents an uninterruptible OS lookup from delaying process cancellation. `tokio-system-resolver` 0.5.0 was rejected because it does not compile for Windows. |
| Resolver configuration | `resolv-conf` + `gai-core` / `ipconfig` / `system-configuration` | Linux uses the mature resolv.conf parser plus gai-core's dedicated NSS `hosts:` parser instead of first-party config parsing; the parsed NSS policy must explicitly include `dns` before classic endpoints become diagnostic candidates. Windows uses IP Helper/registry-backed typed APIs; macOS uses Mullvad's SystemConfiguration bindings and rejects malformed endpoint fields instead of inventing defaults. Platform-internal resolver choices and transports that these APIs do not prove stay explicit limitations and do not trigger substitute UDP traffic. |
| Direct DNS message codec | `hickory-proto` | Mature codec; Reach owns UDP/TCP attempts and transport transitions so library policy cannot hide traffic. |
| Cancellation | `ctrlc` + `tokio-util::CancellationToken` | The mature cross-platform handler covers Unix SIGINT and Windows Ctrl+C/Ctrl+Break; the token propagates cancellation and Core defines terminal priority. `send_ctrlc` and `wait-timeout` provide bounded cross-platform child-process acceptance tests without first-party signal/process-control code. |
| Errors | `thiserror` | Mature typed error derivation. |
| Property/fault testing | `proptest` | Mature generation and shrinking for untrusted input, target identity, and malformed DNS wire contracts. |
| CLI process testing | `assert_cmd` | Mature cross-platform binary invocation and stdout/stderr/exit assertions. |
| Output contract snapshots | `snapbox` | Mature snapshot/diff tooling protects complete plain-text error reports and presentation structure. |

The lockfile has no known RustSec vulnerability advisory at the recorded
release audit. RustSec does report
`RUSTSEC-2024-0436` as an allowed maintenance warning for `paste 1.0.15`,
which is transitive through `netlink-packet-core`. Version 0.8.2 of that
upstream crate deliberately reverted to `paste` and documents its judgment
that the finished macro crate is preferable to unvetted replacements. Reach
therefore neither forks nor hand-reimplements the macro. Re-audit this explicit
exception when the netlink stack changes.

The table is updated as platform implementation proceeds. A “candidate” is not
promoted to a release dependency until its API and native conformance tests
demonstrate the required semantic coverage.

## Consequences

The dependency graph will be larger than a minimal handcrafted implementation,
but protocol and OS edge cases remain owned by specialized libraries. Reach's
first-party code is concentrated where no general crate can know the product's
diagnostic semantics.
