# reach

`reach` is a conservative cross-platform network diagnostic CLI for Linux,
macOS, and Windows on x86-64 and ARM64. Its complete 0.1.0 behavior is defined
by `network-diagnostic-cli-design.md`.

## Usage

```text
reach <address> [port]
```

- With a port, the primary check is TCP Connect to that exact address and port.
- Without a port, the primary check is ICMP Echo to that exact address.
- `address` accepts a hostname, IPv4 literal, IPv6 literal, or scoped IPv6.
- Hostnames use the normal OS resolver first. Direct DNS is failure diagnosis
  only and can never create formal targets.

Completed diagnostics go to stdout. Execution errors, cancellation, and
TTY-only transient progress go to stderr.

| Exit | Meaning |
|---:|---|
| 0 | Completed and every formal target was cleanly satisfied |
| 1 | Completed, but failed, mixed, anomalous, or indeterminate |
| 2 | Invalid input or the request could not be executed reliably |
| 130 | User cancellation |

## Capability boundaries

The tool runs without root, Administrator, sudo, UAC, external diagnostic
commands, or persistent network changes. Missing deep capabilities remain
typed and visible; Reach never swaps protocols to manufacture equivalent-looking
evidence.

The current audited implementation reports TCP and ICMP TTL/Hop-Limit response
correlation as unavailable on all platforms. Exact targeted-path lookup is
unavailable on Linux and macOS; macOS also reports exact Neighbor lookup as
unavailable. These limitations reduce failure localization depth but do not
change an already-completed primary check.

See `docs/0.1.0-native-capability-matrix.md` for the exact platform matrix and
native release status.

## Build and verify

Build with the current stable Rust toolchain. The project does not pin a Rust
version or declare compatibility with older compilers.

```text
cargo build --release --locked -p reach-cli
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

The six-target native GitHub Actions matrix is the release gate. The 0.1.0
release run passed on Linux, macOS, and Windows for x86-64 and ARM64; every job
produced one archive containing exactly one `reach` executable. Exact evidence
and artifact digests are recorded in `docs/0.1.0-native-capability-matrix.md`.

## Architecture and dependency policy

- `reach-core`: platform-independent facts, state machines, conclusions,
  evidence, aggregation, and fixed product policy.
- `reach-platform`: mature crate and native-API adapters.
- `reach-cli`: positional CLI, terminal-safe rendering, progress, cancellation,
  and exit routing; it contains no diagnostic decisions.

ADR 0002 makes mature-library-first mandatory: first-party code is limited to
Reach-specific semantics and unavoidable adapter glue when no mature crate
provides the required observable behavior.
