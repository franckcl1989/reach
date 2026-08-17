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
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "reach: address is not a valid hostname or IP literal\n"
    );
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
fn ordinary_user_loopback_success_is_a_completed_stdout_result() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local TCP success fixture");
    let port = listener.local_addr().expect("local fixture address").port();

    let assertion = cargo_bin_cmd!("reach")
        .args(["127.0.0.1", &port.to_string()])
        .assert()
        .code(0);
    let output = assertion.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("result: all targets satisfied"));
    assert!(stdout.contains(&format!("target 127.0.0.1:{port}: satisfied")));
    assert!(!stdout.contains('\u{1b}'));
    assert!(
        stdout.lines().count() <= 8,
        "success output should stay concise"
    );
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
    assert!(stdout.contains("result: network check not satisfied"));
    assert!(stdout.contains("TCP connection was refused"));
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
    assert!(String::from_utf8_lossy(&stderr).starts_with("reach: cancelled:"));
}
