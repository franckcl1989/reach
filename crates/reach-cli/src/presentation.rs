use std::{fmt::Write as _, io};

use anstyle::{AnsiColor, Effects, Style};
use reach_core::{DiagnosticResult, InputError};
use unicode_general_category::{GeneralCategory, get_general_category};

mod completed;
mod error;

#[derive(Clone, Copy)]
pub struct Theme {
    styled: bool,
    table_width: Option<u16>,
}

impl Theme {
    pub fn terminal() -> Self {
        let table_width = terminal_size::terminal_size()
            .map(|(terminal_size::Width(width), _)| width.clamp(60, 140))
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

    pub const fn table_width(self) -> Option<u16> {
        self.table_width
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

    pub fn strong(self, text: &str) -> String {
        self.paint(Style::new().effects(Effects::BOLD), text)
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
    let _ = writeln!(output, "{}", theme.heading(title));
}

pub(crate) fn field(output: &mut String, label: &str, value: impl AsRef<str>) {
    let width = terminal_size::terminal_size()
        .map(|(terminal_size::Width(width), _)| width.clamp(60, 140) as usize)
        .unwrap_or(120);
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

pub(crate) fn indented_block(output: &mut String, value: &str) {
    for line in value.lines() {
        let _ = writeln!(output, "  {line}");
    }
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

#[cfg(test)]
mod tests {
    use reach_core::{Cancelled, DiagnosticResult, ExecutionError, ExecutionErrorKind, InputError};
    use snapbox::assert_data_eq;
    use snapbox::prelude::*;

    use super::*;

    #[test]
    fn terminal_text_keeps_readable_unicode_but_cannot_inject_terminal_state() {
        assert_eq!(
            terminal_escape("bücher\n\x1b[31m\u{202e}tail"),
            "bücher\\n\\u{1b}[31m\\u{202e}tail"
        );
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
}
