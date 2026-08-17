use std::time::Duration;

use crate::PlatformError;
use tokio_util::sync::CancellationToken;

const CONTINUOUS_DEADLINE_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A monotonic clock that continues to advance while the machine is suspended.
pub trait ContinuousClock {
    fn now(&self) -> Result<Duration, PlatformError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemContinuousClock;

pub(crate) async fn wait_until_continuous_deadline(
    deadline: Duration,
    cancellation: &CancellationToken,
    clock: &impl ContinuousClock,
) -> Result<(), PlatformError> {
    loop {
        let now = clock.now()?;
        if now >= deadline {
            return Ok(());
        }
        let remaining = deadline.saturating_sub(now);
        let delay = remaining.min(CONTINUOUS_DEADLINE_POLL_INTERVAL);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(PlatformError::OperationCancelled),
            () = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(target_os = "linux")]
impl ContinuousClock for SystemContinuousClock {
    fn now(&self) -> Result<Duration, PlatformError> {
        let value = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let seconds = u64::try_from(value.tv_sec).map_err(|_| {
            PlatformError::ClockUnavailable("CLOCK_BOOTTIME returned negative seconds".into())
        })?;
        let nanoseconds = u32::try_from(value.tv_nsec).map_err(|_| {
            PlatformError::ClockUnavailable("CLOCK_BOOTTIME returned invalid nanoseconds".into())
        })?;
        Ok(Duration::new(seconds, nanoseconds))
    }
}

#[cfg(target_os = "macos")]
impl ContinuousClock for SystemContinuousClock {
    fn now(&self) -> Result<Duration, PlatformError> {
        use mach2::mach_time::{
            mach_continuous_time, mach_timebase_info, mach_timebase_info_data_t,
        };

        let mut timebase = mach_timebase_info_data_t::default();
        // SAFETY: `timebase` is a valid, writable value of the exact type required
        // by the generated `mach2` binding, and remains alive for the call.
        let status = unsafe { mach_timebase_info(&mut timebase) };
        if status != 0 || timebase.denom == 0 {
            return Err(PlatformError::ClockUnavailable(format!(
                "mach_timebase_info failed with status {status}"
            )));
        }

        // SAFETY: the generated binding takes no pointers and has no caller-side
        // safety preconditions; it reads the kernel's continuous tick counter.
        let ticks = unsafe { mach_continuous_time() };
        let nanoseconds = u128::from(ticks)
            .checked_mul(u128::from(timebase.numer))
            .and_then(|value| value.checked_div(u128::from(timebase.denom)))
            .ok_or_else(|| PlatformError::ClockUnavailable("clock conversion overflowed".into()))?;
        duration_from_nanoseconds(nanoseconds)
    }
}

#[cfg(windows)]
impl ContinuousClock for SystemContinuousClock {
    fn now(&self) -> Result<Duration, PlatformError> {
        use windows_sys::Win32::System::SystemInformation::GetTickCount64;

        // SAFETY: the generated binding takes no arguments and returns a value;
        // Windows documents no caller-side safety preconditions.
        let milliseconds = unsafe { GetTickCount64() };
        Ok(Duration::from_millis(milliseconds))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl ContinuousClock for SystemContinuousClock {
    fn now(&self) -> Result<Duration, PlatformError> {
        Err(PlatformError::ClockUnavailable(
            "no suspend-aware clock adapter for this target".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn duration_from_nanoseconds(value: u128) -> Result<Duration, PlatformError> {
    let seconds = value / 1_000_000_000;
    let nanoseconds = value % 1_000_000_000;
    Ok(Duration::new(
        u64::try_from(seconds).map_err(|_| {
            PlatformError::ClockUnavailable("converted clock seconds exceed u64".into())
        })?,
        u32::try_from(nanoseconds).expect("nanosecond remainder is always below one billion"),
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn system_clock_is_nondecreasing() {
        let clock = SystemContinuousClock;
        let first = clock.now().expect("platform clock should be available");
        let second = clock.now().expect("platform clock should be available");
        assert!(second >= first);
    }

    struct SuspendJumpClock(Cell<bool>);

    impl ContinuousClock for SuspendJumpClock {
        fn now(&self) -> Result<Duration, PlatformError> {
            if self.0.replace(true) {
                Ok(Duration::from_secs(10))
            } else {
                Ok(Duration::ZERO)
            }
        }
    }

    #[tokio::test]
    async fn deadline_guard_detects_a_suspend_style_continuous_clock_jump() {
        tokio::time::timeout(
            Duration::from_millis(200),
            wait_until_continuous_deadline(
                Duration::from_secs(5),
                &CancellationToken::new(),
                &SuspendJumpClock(Cell::new(false)),
            ),
        )
        .await
        .expect("continuous-clock jump must not leave five seconds on the Tokio timer")
        .expect("fake clock succeeds");
    }
}
