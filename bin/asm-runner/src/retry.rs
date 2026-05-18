//! Retry-with-backoff helpers.
//!
//! Duplicated from `strata_common::retry` in the alpen repo
//! (`alpen/crates/common/src/retry/mod.rs` + `policies.rs`) — combined here
//! into a single file. Kept close to the upstream so it can be deleted in
//! favour of the shared crate once that's promoted out of alpen. Update both
//! sides when changing.
//!
//! TODO(STR-3473): move this to a shared `strata-common` crate and drop the
//! duplicate. Discussed but not actioned in
//! <https://github.com/alpenlabs/asm/pull/62>.
//!
//! Usage matches alpen and strata-bridge: wrap a fallible async call with
//! [`retry_with_backoff_async`], pick a [`Backoff`] implementation, and the
//! helper handles delays, logging, and exhaustion.

use std::{fmt, future::Future, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::time::sleep as async_sleep;
use tracing::{error, warn};

/// Default retry attempts after the initial call.
const DEFAULT_MAX_RETRIES: u16 = 10;
/// Default initial delay before the first retry, in milliseconds.
const DEFAULT_BASE_DELAY_MS: u64 = 1_000;
/// Default backoff multiplier numerator (paired with [`DEFAULT_MULTIPLIER_BASE`]
/// for a 2× growth factor).
const DEFAULT_MULTIPLIER: u64 = 20;
/// Default backoff multiplier denominator.
const DEFAULT_MULTIPLIER_BASE: u64 = 10;
/// Default cap on the delay between retries, in milliseconds.
const DEFAULT_MAX_DELAY_MS: u64 = 60_000;

/// Runs a fallible async operation with a backoff retry.
///
/// Retries the given async `operation` up to `max_retries` times with delays
/// increasing according to the provided [`Backoff`] implementation.
///
/// Logs a warning on each failure and an error if all retries are exhausted.
///
/// # Parameters
///
/// - `name`: Identifier used in logs for the operation.
/// - `max_retries`: Maximum number of retry attempts (not counting the initial attempt).
/// - `backoff`: Backoff configuration for computing delay.
/// - `operation`: Closure returning a Future that resolves to `Result`; retried on `Err`.
pub(crate) async fn retry_with_backoff_async<R, E, F, Fut>(
    name: &str,
    max_retries: u16,
    backoff: &impl Backoff,
    operation: F,
) -> Result<R, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, E>>,
    E: fmt::Debug,
{
    let mut delay = backoff.base_delay_ms();

    for attempt in 0..=max_retries {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < max_retries => {
                warn!(
                    "Attempt {} failed with {err:?} while running {name}. Retrying in {delay:?}ms",
                    attempt + 1,
                );
                async_sleep(Duration::from_millis(delay)).await;
                delay = backoff.next_delay_ms(delay);
            }
            Err(err) => {
                error!("Max retries exceeded while running {name}, returning with the last error");
                return Err(err);
            }
        }
    }

    // Loop above always returns inside the match.
    unreachable!()
}

/// Backoff schedule: each implementation decides how the delay grows.
pub(crate) trait Backoff {
    /// Base delay in ms.
    fn base_delay_ms(&self) -> u64;

    /// Generates next delay given current delay.
    fn next_delay_ms(&self, curr_delay_ms: u64) -> u64;
}

/// Configuration for exponential retry backoff.
///
/// Uses a fixed-point multiplier (`multiplier / multiplier_base`) to avoid
/// floating-point math. For example, `multiplier = 150` with
/// `multiplier_base = 100` represents a 1.5× multiplier.
///
/// **Extension over the alpen upstream:** carries an optional `max_delay_ms`
/// cap so delays don't explode when retrying for long durations. Without a
/// cap, a 2× multiplier starting at 1 s reaches ~17 minutes by attempt 11 and
/// overflows `u64` not long after; for resilience-oriented retry budgets the
/// cap is essential.
#[derive(Debug, Clone)]
pub(crate) struct ExponentialBackoff {
    base_delay_ms: u64,
    multiplier: u64,
    multiplier_base: u64,
    max_delay_ms: Option<u64>,
}

impl ExponentialBackoff {
    pub(crate) fn new(
        base_delay_ms: u64,
        multiplier: u64,
        multiplier_base: u64,
        max_delay_ms: Option<u64>,
    ) -> Self {
        assert!(multiplier_base != 0, "multiplier_base must be non-zero");
        Self {
            base_delay_ms,
            multiplier,
            multiplier_base,
            max_delay_ms,
        }
    }
}

impl Backoff for ExponentialBackoff {
    fn base_delay_ms(&self) -> u64 {
        self.base_delay_ms
    }

    fn next_delay_ms(&self, curr_delay_ms: u64) -> u64 {
        let next = curr_delay_ms.saturating_mul(self.multiplier) / self.multiplier_base;
        match self.max_delay_ms {
            Some(cap) => next.min(cap),
            None => next,
        }
    }
}

/// Serde-friendly configuration for [`retry_with_backoff_async`] +
/// [`ExponentialBackoff`]. Mirrors `ExponentialBackoff`'s fields (so it can
/// build one) and adds the `max_retries` count consumed by the retry helper.
///
/// See the `DEFAULT_*` consts at the top of this module for the default
/// values; together they give roughly 17 minutes of patience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RetryConfig {
    /// Maximum number of retry attempts after the initial call.
    #[serde(default = "RetryConfig::default_max_retries")]
    pub max_retries: u16,
    /// Initial delay before the first retry, in milliseconds.
    #[serde(default = "RetryConfig::default_base_delay_ms")]
    pub base_delay_ms: u64,
    /// Numerator of the backoff multiplier (paired with `multiplier_base`).
    #[serde(default = "RetryConfig::default_multiplier")]
    pub multiplier: u64,
    /// Denominator of the backoff multiplier.
    #[serde(default = "RetryConfig::default_multiplier_base")]
    pub multiplier_base: u64,
    /// Maximum delay between retries, in milliseconds. Caps the exponential
    /// growth so long retry sequences don't produce absurd waits or overflow.
    #[serde(default = "RetryConfig::default_max_delay_ms")]
    pub max_delay_ms: u64,
}

impl RetryConfig {
    fn default_max_retries() -> u16 {
        DEFAULT_MAX_RETRIES
    }
    fn default_base_delay_ms() -> u64 {
        DEFAULT_BASE_DELAY_MS
    }
    fn default_multiplier() -> u64 {
        DEFAULT_MULTIPLIER
    }
    fn default_multiplier_base() -> u64 {
        DEFAULT_MULTIPLIER_BASE
    }
    fn default_max_delay_ms() -> u64 {
        DEFAULT_MAX_DELAY_MS
    }

    /// Build an [`ExponentialBackoff`] from this config.
    pub(crate) fn backoff(&self) -> ExponentialBackoff {
        ExponentialBackoff::new(
            self.base_delay_ms,
            self.multiplier,
            self.multiplier_base,
            Some(self.max_delay_ms),
        )
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: Self::default_max_retries(),
            base_delay_ms: Self::default_base_delay_ms(),
            multiplier: Self::default_multiplier(),
            multiplier_base: Self::default_multiplier_base(),
            max_delay_ms: Self::default_max_delay_ms(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[test]
    fn exponential_grows_then_caps() {
        let b = ExponentialBackoff::new(1000, 20, 10, Some(60_000));
        let d1 = b.next_delay_ms(b.base_delay_ms());
        assert_eq!(d1, 2000);
        let d2 = b.next_delay_ms(d1);
        assert_eq!(d2, 4000);
        // Saturates at the cap.
        let mut d = d2;
        for _ in 0..20 {
            d = b.next_delay_ms(d);
        }
        assert_eq!(d, 60_000);
    }

    #[test]
    fn exponential_without_cap_matches_alpen() {
        let b = ExponentialBackoff::new(1000, 20, 10, None);
        assert_eq!(b.next_delay_ms(1000), 2000);
        assert_eq!(b.next_delay_ms(2000), 4000);
    }

    #[test]
    #[should_panic]
    fn zero_multiplier_base_panics() {
        let _ = ExponentialBackoff::new(1000, 20, 0, None);
    }

    #[tokio::test]
    async fn retries_until_success() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let backoff = ExponentialBackoff::new(1, 10, 10, Some(10));
        let attempts_clone = attempts.clone();
        let result: Result<&'static str, &'static str> =
            retry_with_backoff_async("test", 5, &backoff, || {
                let attempts = attempts_clone.clone();
                async move {
                    let n = attempts.fetch_add(1, Ordering::SeqCst);
                    if n == 2 { Ok("ok") } else { Err("not yet") }
                }
            })
            .await;
        assert_eq!(result, Ok("ok"));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn exhausts_and_returns_last_error() {
        let backoff = ExponentialBackoff::new(1, 10, 10, Some(10));
        let result: Result<(), &'static str> =
            retry_with_backoff_async("test", 2, &backoff, || async { Err("nope") }).await;
        assert_eq!(result, Err("nope"));
    }
}
