# ADR 0001: Rust and native platform adapters

- Status: Accepted
- Date: 2026-08-17
- Decision owner: project implementation
- Product baseline: `network-diagnostic-cli-design.md`

## Context

The product must ship one executable for each combination of macOS, Windows,
and Linux with x86-64 and ARM64. It must preserve exact attempt, deadline,
retry, cancellation, resolver, route, Neighbor, and evidence semantics without
calling external diagnostic programs or requiring an application runtime.

The low-level observation surfaces differ materially by operating system. A
single lowest-common-denominator networking library cannot provide the required
facts without either losing provenance or silently changing probe semantics.

## Decision

Use stable Rust, edition 2024, in a workspace with three responsibility
boundaries:

- `reach-core`: input contracts, immutable facts, attempts, evidence,
  deterministic state machines, aggregation, and conclusions. It contains no
  operating-system calls and forbids unsafe code.
- `reach-platform`: the platform capability contract and the Linux, macOS, and
  Windows adapters. Unsafe FFI is confined here, reviewed locally, and covered
  by native integration tests.
- `reach-cli`: positional argument structure, TTY handling, rendering,
  cancellation wiring, and exit-code mapping. It contains no diagnostic
  decisions.

The executable is named `reach`; `abc` in the design baseline is treated as
the documented placeholder.

The project follows the current stable Rust toolchain and does not pin a
compiler version or promise compatibility with older toolchains. A stable
toolchain or behavior-bearing dependency upgrade requires rerunning the
contract and cross-platform conformance suites.

## Runtime and concurrency

Use Tokio for cancellable sockets, bounded asynchronous scheduling, and local
attempt timers. Use the mature cross-platform `ctrlc` crate to translate
interactive console interrupts into a `tokio-util::CancellationToken`. Core
concurrency remains explicitly bounded to four active target diagnostics and
four active resolver-candidate diagnostics; queued items do not receive a task
or socket until admitted.

System resolver calls are isolated from product-controlled probe timers. Where
an OS resolver call cannot be cancelled, Ctrl+C stops new work and the process
is allowed to terminate without waiting for that blocking call, as required by
the baseline.

Attempt deadlines use a platform continuous clock abstraction:

- Linux: `CLOCK_BOOTTIME`;
- macOS: `mach_continuous_time`;
- Windows: a boot-time counter whose suspend behavior is verified by the
  platform conformance test.

Tokio timers provide 25 ms wakeup checkpoints, but the platform continuous
clock alone decides whether the semantic deadline has elapsed. Every network
completion is checked against that clock as well, so a suspend/resume jump is
classified as Timeout instead of silently granting another full Attempt budget.

## Protocol and OS dependencies

- `idna` plus `hostname-validator`: UTS #46 preparation followed by RFC 1123
  hostname validation. Reach only composes them and locks the accepted/rejected
  corpus in tests.
- `hickory-proto`: direct DNS message encoding and decoding. Reach owns the
  failure-only Direct DNS UDP/TCP sockets, query attempts, transaction matching,
  timeout, retry, and transport-transition state machine.
- `gai-core` plus `hickory-resolver`: Linux static-release system resolution.
  `gai-core` parses and executes NSS source order/actions; Hickory executes only
  a reached `dns` source with the parsed search/domain/ndots and resolver order.
  This is separate from Direct DNS and may form formal targets.
- Tokio networking: mature nonblocking TCP/UDP I/O. Reach owns each explicit
  Attempt, deadline, retry, and transport transition.
- `windows-sys`: Windows IP Helper, ICMP, resolver, adapter, clock, and route
  APIs where no suitable higher-level crate exposes the required fact.
- `libc` plus focused Rust netlink packet crates: Unix sockets, Linux rtnetlink,
  and continuous clocks.
- macOS SystemConfiguration bindings plus `netroute`; an exact targeted-path
  or Neighbor surface that is not provided at ordinary-user privilege remains
  explicitly unavailable.

macOS and Windows use the normal OS resolver for the first hostname-resolution
path. A fully static Linux executable cannot load arbitrary glibc NSS modules,
so it reproduces only policy paths that the selected self-contained libraries
can faithfully execute and fails with a required-capability error for a reached
unsupported source or option. Higher-level resolver policy remains forbidden in
failure-only Direct DNS, where Core must retain exact Reach-owned Attempts.

## Platform mapping

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Interfaces | mature cross-platform enumeration crate, supplemented only for missing facts | same | same |
| Routes/policy | rtnetlink route and rule messages | routing sysctl/socket + scoped facts | `GetIpForwardTable2` and compartment facts |
| Targeted path | explicit `Unavailable`: destination-only `RTM_GETROUTE` cannot prove the later socket's flow-dependent route | explicit `Unavailable`: no selected mature crate proves a traffic-free targeted query | `GetBestRoute2` |
| Neighbor | rtnetlink neighbor messages | explicit `Unavailable`: no selected mature ordinary-user reader | `GetIpNetEntry2` |
| TCP connect | nonblocking socket | nonblocking socket | Winsock |
| ICMP | unprivileged datagram ICMP when available | unprivileged datagram ICMP when available | IP Helper ICMP APIs |
| Resolver | `gai-core` NSS policy plus `/etc/hosts` and Hickory `/etc/resolv.conf` DNS; reached unsupported policy is an execution error | OS `getaddrinfo` semantics | OS `getaddrinfo` semantics |
| Resolver config | resolver files/APIs with provenance and limitations | SystemConfiguration dynamic store | adapter/DNS policy APIs with limitations |

Every mapping reports `Available`, `Unknown`, or `Unavailable`; a missing
observation surface is never replaced with an active probe. In particular, TCP
TTL path diagnosis remains unavailable on platforms where responses cannot be
reliably correlated at ordinary-user privilege.

The dependency-first selection and exception process is defined by ADR 0002.

## Build and release

Build and test on native GitHub-hosted runners for all six targets. Native jobs
are required because compilation alone cannot validate ordinary-user ICMP,
Neighbor, route, DNS transport, or cancellation capabilities. Linux release
targets are `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` and must
pass static-ELF inspection. Windows uses target-specific `+crt-static` and must
pass a versioned PE import allowlist. macOS must load only supported system
paths. Every archive is extracted, hash-compared, inspected again, and executed
before a tag release can leave draft state.

## Alternatives considered

### Go

Go is strong for small static CLIs, but this project requires extensive native
API and packet-level integration whose cross-platform abstractions still need
per-OS implementations. Rust provides tighter unsafe-code confinement, richer
sum types for fact/error/capability boundaries, and deterministic ownership of
sockets and cancellation without adding a garbage-collected runtime to every
artifact.

### C++

C++ offers direct native access but increases the cost of safely handling
untrusted variable-length OS and network data. Rust keeps that exposure inside
small adapter modules while the state machine remains memory-safe.

### One cross-platform ping/traceroute library

Rejected because ordinary-user ICMP permissions and reply correlation differ
by OS, and because silently changing a TCP path probe into ICMP would violate
the product contract.

## Consequences

The Core can be exhaustively tested with synthetic facts on any host. Platform
work is more explicit and initially slower than a demo built around shell
commands, but every unavailable capability remains honest and testable. All six
native environments are release gates, not optional smoke tests.

## Authoritative references

- Rust platform support: <https://doc.rust-lang.org/rustc/platform-support.html>
- Tokio cancellation primitive: <https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html>
- Hickory DNS message model: <https://docs.rs/hickory-proto/latest/hickory_proto/op/message/struct.Message.html>
- GitHub-hosted runner reference: <https://docs.github.com/en/actions/reference/runners/github-hosted-runners>
