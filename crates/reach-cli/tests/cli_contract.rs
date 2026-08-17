use assert_cmd::cargo::{cargo_bin, cargo_bin_cmd};
use send_ctrlc::{Interruptible as _, InterruptibleCommand as _};
use std::{
    io::Read,
    net::TcpListener,
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use wait_timeout::ChildExt as _;

#[test]
fn invalid_input_is_stderr_only_exit_two_and_cannot_inject_a_line() {
    let assertion = cargo_bin_cmd!("reach")
        .arg("bad\n\u{1b}[31m")
        .assert()
        .code(2);
    let output = assertion.get_output();
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("× ADDRESS IS NOT VALID\n"));
    assert!(stderr.contains("Reach could not read the address"));
    assert!(stderr.contains("Address            bad\\n\\u{1b}[31m"));
    assert!(stderr.contains("Exit code          2"));
    assert!(!stderr.contains('\u{1b}'));
}

#[test]
fn redirected_help_is_plain_stdout_without_progress_or_ansi() {
    let assertion = cargo_bin_cmd!("reach").arg("--help").assert().code(0);
    let output = assertion.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: reach <ADDRESS> [PORT]"));
    assert!(!stdout.contains('\u{1b}'));
    assert!(output.stderr.is_empty());
}

#[test]
fn version_reports_the_0_1_2_release() {
    let assertion = cargo_bin_cmd!("reach").arg("--version").assert().code(0);
    let output = assertion.get_output();
    assert_eq!(String::from_utf8_lossy(&output.stdout), "reach 0.1.2\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn ordinary_user_loopback_success_is_a_completed_stdout_result() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local TCP success fixture");
    let port = listener.local_addr().expect("local fixture address").port();

    let assertion = cargo_bin_cmd!("reach")
        .args(["127.0.0.1", &port.to_string()])
        .assert()
        .code(0);
    let output = assertion.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("✓ TCP CONNECTION SUCCEEDED\n"));
    assert!(stdout.contains(&format!("A TCP connection to 127.0.0.1:{port} succeeded")));
    assert!(stdout.contains("The TCP handshake completed"));
    assert!(stdout.contains("Reach sent no application data"));
    assert!(!stdout.contains("EVIDENCE"));
    assert!(!stdout.contains("TECHNICAL DETAILS"));
    assert!(!stdout.contains("NETWORK ATTEMPTS"));
    assert!(!stdout.contains("formal target"));
    assert!(!stdout.contains('\u{1b}'));
    assert!(output.stderr.is_empty());
}

#[test]
fn completed_network_failure_is_stdout_only_and_exit_one() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an unused local port");
    let port = listener.local_addr().expect("local fixture address").port();
    drop(listener);

    let assertion = cargo_bin_cmd!("reach")
        .args(["127.0.0.1", &port.to_string()])
        .assert()
        .code(1);
    let output = assertion.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("× TCP CONNECTION WAS REFUSED\n"));
    assert!(stdout.contains("TCP connection was explicitly refused"));
    assert!(stdout.contains("The refusal may come from the destination or an intermediate device"));
    assert!(stdout.contains("WHAT TO DO"));
    assert!(stdout.contains("EVIDENCE"));
    assert!(!stdout.contains("PATH AND NEIGHBOR FACTS"));
    assert!(!stdout.contains("NETWORK ATTEMPTS"));
    assert!(!stdout.contains("TECHNICAL DETAILS"));
    assert!(!stdout.contains('\u{1b}'));
    assert!(output.stderr.is_empty());
}

#[test]
fn console_interrupt_is_a_bounded_cancelled_process_result() {
    let candidates = [
        "203.0.113.1",
        "198.51.100.1",
        "192.0.2.1",
        "10.255.255.1",
        "172.31.255.254",
        "169.254.255.254",
    ];
    let mut child = candidates
        .into_iter()
        .find_map(|address| {
            let mut command = Command::new(cargo_bin!("reach"));
            command
                .args([address, "443"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command
                .spawn_interruptible()
                .expect("spawn interruptible reach process");
            thread::sleep(Duration::from_millis(250));
            child
                .try_wait()
                .expect("query child status")
                .is_none()
                .then_some(child)
        })
        .expect("at least one non-routable probe must remain active for cancellation");
    #[cfg(unix)]
    child.interrupt().expect("send SIGINT to reach");
    #[cfg(windows)]
    child
        .terminate()
        .expect("send targeted CTRL_BREAK_EVENT to reach");
    let Some(status) = child
        .wait_timeout(Duration::from_secs(3))
        .expect("wait for cancelled reach process")
    else {
        child.kill().expect("clean up unresponsive test child");
        child.wait().expect("reap unresponsive test child");
        panic!("reach did not terminate promptly after the console interrupt");
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("captured stdout")
        .read_to_end(&mut stdout)
        .expect("read stdout");
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("captured stderr")
        .read_to_end(&mut stderr)
        .expect("read stderr");
    assert_eq!(status.code(), Some(130));
    assert!(stdout.is_empty());
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(stderr.starts_with("! CHECK CANCELLED\n"));
    assert!(stderr.contains("No final network result was produced"));
    assert!(stderr.contains("Exit code          130"));
    assert!(!stderr.contains('\u{1b}'));
}

#[test]
fn missing_address_has_friendly_usage_and_examples() {
    let assertion = cargo_bin_cmd!("reach").assert().code(2);
    let output = assertion.get_output();
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("× ADDRESS IS MISSING\n"));
    assert!(stderr.contains("reach <ADDRESS> [PORT]"));
    assert!(stderr.contains("reach example.com 443"));
    assert!(stderr.contains("Exit code          2"));
}

#[test]
fn invalid_port_explains_the_allowed_value() {
    let assertion = cargo_bin_cmd!("reach")
        .args(["example.com", "eighty"])
        .assert()
        .code(2);
    let output = assertion.get_output();
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("× TCP PORT IS NOT VALID\n"));
    assert!(stderr.contains("must contain digits only"));
    assert!(stderr.contains("Use a number from 1 through 65535"));
    assert!(stderr.contains("Port               eighty"));
}

#[test]
fn extra_arguments_get_friendly_command_guidance() {
    let assertion = cargo_bin_cmd!("reach")
        .args(["example.com", "443", "extra"])
        .assert()
        .code(2);
    let output = assertion.get_output();
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("× COMMAND IS NOT VALID\n"));
    assert!(stderr.contains("accepts one address and, optionally, one TCP port"));
    assert!(stderr.contains("reach <ADDRESS> [PORT]"));
    assert!(stderr.contains("Exit code          2"));
}
