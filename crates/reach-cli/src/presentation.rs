use std::{fmt::Write as _, io, time::Duration};

use anstyle::{AnsiColor, Effects, Style};
use reach_core::{DiagnosticResult, InputError};
use unicode_general_category::{GeneralCategory, get_general_category};

mod completed;
mod error;
mod name_resolution;

#[derive(Clone, Copy)]
pub struct Theme {
    styled: bool,
    table_width: Option<u16>,
}

impl Theme {
    pub fn terminal() -> Self {
        let table_width = terminal_size::terminal_size()
            .map(|(terminal_size::Width(width), _)| width.clamp(1, 300))
            .unwrap_or(120);
        Self {
            styled: true,
            table_width: Some(table_width),
        }
    }

    #[cfg(test)]
    pub const fn plain() -> Self {
        Self {
            styled: false,
            table_width: Some(100),
        }
    }

    #[cfg(test)]
    pub const fn plain_with_width(width: u16) -> Self {
        Self {
            styled: false,
            table_width: Some(width),
        }
    }

    pub const fn content_width(self) -> usize {
        match self.table_width {
            Some(width) => width as usize,
            None => 120,
        }
    }

    fn paint(self, style: Style, text: &str) -> String {
        if self.styled {
            format!("{style}{text}{style:#}")
        } else {
            text.to_owned()
        }
    }

    pub fn success(self, text: &str) -> String {
        self.paint(AnsiColor::Green.on_default().effects(Effects::BOLD), text)
    }

    pub fn failure(self, text: &str) -> String {
        self.paint(AnsiColor::Red.on_default().effects(Effects::BOLD), text)
    }

    pub fn warning(self, text: &str) -> String {
        self.paint(AnsiColor::Yellow.on_default().effects(Effects::BOLD), text)
    }

    pub fn heading(self, text: &str) -> String {
        self.paint(AnsiColor::Cyan.on_default().effects(Effects::BOLD), text)
    }
}

pub fn write_result(
    result: &DiagnosticResult,
    output: &mut impl io::Write,
    theme: Theme,
) -> io::Result<()> {
    let rendered = match result {
        DiagnosticResult::Completed(completed) => completed::render(completed, theme),
        DiagnosticResult::ExecutionError(error) => error::render_execution(error, theme),
        DiagnosticResult::Cancelled(cancelled) => error::render_cancelled(cancelled, theme),
    };
    output.write_all(rendered.as_bytes())
}

pub fn write_input_error(
    input_error: &InputError,
    address: &str,
    port: Option<&str>,
    output: &mut impl io::Write,
    theme: Theme,
) -> io::Result<()> {
    output.write_all(error::render_input(input_error, address, port, theme).as_bytes())
}

pub fn write_command_error(
    missing_address: bool,
    output: &mut impl io::Write,
    theme: Theme,
) -> io::Result<()> {
    output.write_all(error::render_command(missing_address, theme).as_bytes())
}

pub fn write_startup_error(
    reason: &str,
    output: &mut impl io::Write,
    theme: Theme,
) -> io::Result<()> {
    output.write_all(error::render_startup(reason, theme).as_bytes())
}

pub fn write_output_error(
    reason: &str,
    output: &mut impl io::Write,
    theme: Theme,
) -> io::Result<()> {
    output.write_all(error::render_output_failure(reason, theme).as_bytes())
}

pub(crate) fn section(output: &mut String, theme: Theme, title: &str) {
    let options = textwrap::Options::new(theme.content_width());
    for line in textwrap::wrap(title, options) {
        let _ = writeln!(output, "{}", theme.heading(&line));
    }
}

pub(crate) fn headline(
    output: &mut String,
    theme: Theme,
    title: &str,
    paint: fn(Theme, &str) -> String,
) {
    for line in textwrap::wrap(title, textwrap::Options::new(theme.content_width())) {
        let _ = writeln!(output, "{}", paint(theme, &line));
    }
}

pub(crate) fn field(output: &mut String, theme: Theme, label: &str, value: impl AsRef<str>) {
    let width = theme.content_width();
    if width < 40 {
        let label_options = textwrap::Options::new(width)
            .initial_indent("  ")
            .subsequent_indent("  ");
        let _ = writeln!(output, "{}", textwrap::fill(label, label_options));
        let value_options = textwrap::Options::new(width)
            .initial_indent("    ")
            .subsequent_indent("    ");
        let _ = writeln!(output, "{}", textwrap::fill(value.as_ref(), value_options));
        return;
    }
    let initial = format!("  {label:<18} ");
    let continuation = " ".repeat(initial.len());
    let options = textwrap::Options::new(width)
        .initial_indent(&initial)
        .subsequent_indent(&continuation);
    let _ = writeln!(output, "{}", textwrap::fill(value.as_ref(), options));
}

pub(crate) fn bullets(output: &mut String, theme: Theme, values: impl IntoIterator<Item = String>) {
    for value in values {
        let options = textwrap::Options::new(theme.content_width())
            .initial_indent("  - ")
            .subsequent_indent("    ");
        let _ = writeln!(output, "{}", textwrap::fill(&value, options));
    }
}

pub(crate) fn paragraph(output: &mut String, theme: Theme, value: &str) {
    let options = textwrap::Options::new(theme.content_width())
        .initial_indent("  ")
        .subsequent_indent("  ");
    let _ = writeln!(output, "{}", textwrap::fill(value, options));
}

/// Preserves ordinary Unicode text while encoding terminal controls and all
/// Unicode format characters. The general-category lookup is provided by the
/// Unicode data crate rather than a locally maintained code-point blacklist.
pub fn terminal_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() || get_general_category(character) == GeneralCategory::Format
            {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

/// The single duration formatting used by every section, so DNS, TCP, and
/// ICMP timings never drift apart.
pub(crate) fn human_duration(value: Duration) -> String {
    if value >= Duration::from_secs(1) {
        let seconds = value.as_secs_f64();
        if seconds.fract() == 0.0 {
            format!("{} s", value.as_secs())
        } else {
            format!("{seconds:.1} s")
        }
    } else if value >= Duration::from_millis(1) {
        format!("{} ms", value.as_millis())
    } else {
        "<1 ms".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use reach_core::{Cancelled, DiagnosticResult, ExecutionError, ExecutionErrorKind, InputError};
    use snapbox::assert_data_eq;
    use snapbox::prelude::*;
    use unicode_width::UnicodeWidthStr as _;

    use super::*;

    #[test]
    fn terminal_text_keeps_readable_unicode_but_cannot_inject_terminal_state() {
        assert_eq!(
            terminal_escape("bücher\n\x1b[31m\u{202e}tail"),
            "bücher\\n\\u{1b}[31m\\u{202e}tail"
        );
    }

    #[test]
    fn durations_use_separated_units_shared_by_every_section() {
        assert_eq!(human_duration(Duration::from_secs(5)), "5 s");
        assert_eq!(human_duration(Duration::from_millis(16)), "16 ms");
        assert_eq!(human_duration(Duration::from_millis(1_200)), "1.2 s");
        assert_eq!(human_duration(Duration::from_micros(500)), "<1 ms");
    }

    #[test]
    fn execution_error_explains_failure_action_and_exit_code() {
        let result = DiagnosticResult::ExecutionError(ExecutionError {
            kind: ExecutionErrorKind::ResourceExhausted,
            safe_message: "socket limit reached\n\x1b[2J".into(),
            partial_evidence: Vec::new(),
        });
        let mut output = Vec::new();
        write_result(&result, &mut output, Theme::plain()).expect("render succeeds");
        assert_data_eq!(
            String::from_utf8(output).expect("UTF-8 output"),
            snapbox::str![[r#"
× CHECK COULD NOT FINISH

  This computer ran out of local networking resources before Reach could finish.

WHAT TO DO
  - Close applications that are using many network connections, then run the check again.
  - If the problem continues, send this report to your support team.

TECHNICAL DETAILS
  Error type         Local resources exhausted
  Reason             socket limit reached\n\u{1b}[2J
  Exit code          2

"#]]
            .raw()
        );
    }

    #[test]
    fn cancellation_is_plain_and_actionable() {
        let result = DiagnosticResult::Cancelled(Cancelled {
            safe_message: "interrupted".into(),
        });
        let mut output = Vec::new();
        write_result(&result, &mut output, Theme::plain()).expect("render succeeds");
        assert_data_eq!(
            String::from_utf8(output).expect("UTF-8 output"),
            snapbox::str![[r#"
! CHECK CANCELLED

  Reach stopped because the check was interrupted. No final network result was produced.

TECHNICAL DETAILS
  Reason             interrupted
  Exit code          130

"#]]
            .raw()
        );
    }

    #[test]
    fn invalid_port_error_shows_the_safe_value_and_examples() {
        let mut output = Vec::new();
        write_input_error(
            &InputError::InvalidPortSyntax,
            "example.com",
            Some("eighty\n"),
            &mut output,
            Theme::plain(),
        )
        .expect("render succeeds");
        let output = String::from_utf8(output).expect("UTF-8 output");
        assert!(output.contains("The TCP port must contain digits only"));
        assert!(output.contains("eighty\\n"));
        assert!(output.contains("reach example.com 443"));
        assert!(output.contains("Exit code          2"));
    }

    #[test]
    fn every_execution_error_kind_has_an_explanation_action_reason_and_exit_code() {
        for kind in [
            ExecutionErrorKind::InvalidInput,
            ExecutionErrorKind::ScopedIpv6BindingFailed,
            ExecutionErrorKind::RequiredCapabilityUnavailable,
            ExecutionErrorKind::ResourceExhausted,
            ExecutionErrorKind::InternalFailure,
        ] {
            let result = DiagnosticResult::ExecutionError(ExecutionError {
                kind,
                safe_message: "safe technical reason".into(),
                partial_evidence: Vec::new(),
            });
            let mut output = Vec::new();
            write_result(&result, &mut output, Theme::plain()).expect("render succeeds");
            let output = String::from_utf8(output).expect("UTF-8 output");
            assert!(output.starts_with("× CHECK COULD NOT FINISH\n"));
            assert!(output.contains("WHAT TO DO"));
            assert!(output.contains("safe technical reason"));
            assert!(output.contains("Exit code          2"));
            assert!(!output.contains("ExecutionError"));
        }
    }

    #[test]
    fn every_input_error_has_plain_guidance_usage_and_safe_context() {
        for error in [
            InputError::EmptyAddress,
            InputError::InvalidAddress,
            InputError::InvalidIpv6Scope,
            InputError::InvalidPortSyntax,
            InputError::PortOutOfRange,
        ] {
            let mut output = Vec::new();
            write_input_error(
                &error,
                "value\n",
                Some("port\x1b"),
                &mut output,
                Theme::plain(),
            )
            .expect("render succeeds");
            let output = String::from_utf8(output).expect("UTF-8 output");
            assert!(output.contains("WHAT TO DO"));
            assert!(output.contains("USAGE"));
            assert!(output.contains("reach example.com 443"));
            assert!(output.contains("value\\n"));
            assert!(output.contains("port\\u{1b}"));
            assert!(output.contains("Exit code          2"));
            assert!(!output.contains('\u{1b}'));
        }
    }

    #[test]
    fn error_layouts_from_twenty_to_three_hundred_columns_do_not_overflow() {
        for width in [20_u16, 40, 59, 60, 80, 120, 140, 300] {
            let output = error::render_input(
                &InputError::InvalidPortSyntax,
                "example.com",
                Some("not-a-port"),
                Theme::plain_with_width(width),
            );
            for line in output.lines() {
                assert!(
                    line.width() <= usize::from(width),
                    "width {width}, rendered {} columns: {line:?}\n{output}",
                    line.width()
                );
            }
        }
    }
}
