//! Retrying wrapper around the Bitcoin RPC client.
//!
//! Every runner Bitcoin read goes through [`RetryingBitcoinClient`], so the
//! configured retry policy is a property of the client rather than something
//! each call site has to remember to apply.
//!
//! This is the *outer* retry layer. See
//! [`BitcoinConfig::retry_config`](crate::config::BitcoinConfig::retry_config)
//! for how it composes with the client's own narrow transport retry.
//!
//! The wrapper deliberately does not implement [`Reader`] and does not
//! implement `Deref` to the inner client. Either one would let an unwrapped
//! method resolve through to the raw client and silently skip the retry, which
//! is the failure this type exists to prevent. With an inherent impl, a read we
//! have not routed through the retry is a compile error instead. Add methods
//! here as callers need them.
//!
//! The methods are async and never block. [`AsmProverContext`] is driven from a
//! single-threaded runtime, so blocking in here would deadlock it; the
//! synchronous worker contexts keep doing their own `block_on` at the call site.
//!
//! [`AsmProverContext`]: crate::prover_context::AsmProverContext

use bitcoin::{Block, BlockHash, Network, Txid, block::Header};
use bitcoind_async_client::{
    Client, ClientResult,
    corepc_types::model::{GetBlockchainInfo, GetRawTransaction},
    traits::Reader,
};
use strata_retry::{ExponentialBackoff, RetryConfig, retry_with_backoff_async};

/// Bitcoin RPC client that applies the configured backoff retry to every read.
///
/// Construct one per process and share it with [`Arc`](std::sync::Arc); the
/// retry policy is fixed at construction.
#[derive(Debug)]
pub(crate) struct RetryingBitcoinClient {
    inner: Client,
    /// Backoff schedule for Bitcoin RPC calls.
    backoff: ExponentialBackoff,
    /// Maximum retry attempts per Bitcoin RPC call.
    max_retries: u16,
}

/// Defines a read method that forwards to [`Client`] under the retry policy.
///
/// Every method body is the same three moving parts — the log name, the inner
/// call, and the return type — so they are declared rather than written out.
/// Writing them by hand is how call sites drift apart, which is what this
/// module is fixing.
///
/// The `$name` literal is the operation label [`retry_with_backoff_async`] logs
/// on each failed attempt.
macro_rules! retrying_reads {
    ($(
        $(#[$meta:meta])*
        $method:ident($($arg:ident: $arg_ty:ty),*) -> $ret:ty = $name:literal;
    )*) => {
        impl RetryingBitcoinClient {
            $(
                $(#[$meta])*
                ///
                /// Retried under the configured policy.
                pub(crate) async fn $method(&self, $($arg: $arg_ty),*) -> ClientResult<$ret> {
                    retry_with_backoff_async(
                        $name,
                        self.max_retries,
                        &self.backoff,
                        || async { self.inner.$method($($arg),*).await },
                    )
                    .await
                }
            )*
        }
    };
}

retrying_reads! {
    /// Gets the [`Block`] with the given hash.
    get_block(hash: &BlockHash) -> Block = "btc_get_block";

    /// Gets the [`Header`] with the given hash.
    get_block_header(hash: &BlockHash) -> Header = "btc_get_block_header";

    /// Gets the [`BlockHash`] at the given height.
    get_block_hash(height: u64) -> BlockHash = "btc_get_block_hash";

    /// Gets the height of the block with the given hash.
    get_block_height(hash: &BlockHash) -> u64 = "btc_get_block_height";

    /// Gets the raw transaction with the given [`Txid`].
    get_raw_transaction_verbosity_zero(txid: &Txid) -> GetRawTransaction
        = "btc_get_raw_transaction";

    /// Gets the underlying [`Network`].
    network() -> Network = "btc_network";

    /// Gets various state info regarding blockchain processing.
    get_blockchain_info() -> GetBlockchainInfo = "btc_get_blockchain_info";
}

impl RetryingBitcoinClient {
    /// Wraps `inner` so every read above retries under `retry`.
    pub(crate) fn new(inner: Client, retry: &RetryConfig) -> Self {
        Self {
            inner,
            backoff: retry.backoff(),
            max_retries: retry.max_retries,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bitcoin::{BlockHash, hashes::Hash};
    use bitcoind_async_client::{Auth, Client};
    use strata_retry::RetryConfig;

    use super::RetryingBitcoinClient;

    /// Retry config with delays short enough to keep the test fast.
    fn fast_retry(max_retries: u16) -> RetryConfig {
        RetryConfig {
            max_retries,
            base_delay_ms: 1,
            multiplier: 10,
            multiplier_base: 10,
            max_delay_ms: 1,
        }
    }

    /// Client pointed at a closed port, so every RPC fails at the transport.
    fn unreachable_client(retry: &RetryConfig) -> RetryingBitcoinClient {
        // Port 1 is reserved and nothing listens on it, so connections are
        // refused immediately rather than hanging.
        let inner = Client::new(
            "http://127.0.0.1:1".to_string(),
            Auth::UserPass("user".to_string(), "pass".to_string()),
            // Skip the client's own retry loop; this test covers the outer layer.
            Some(0),
            Some(1),
            Some(1),
        )
        .expect("client builds");
        RetryingBitcoinClient::new(inner, retry)
    }

    /// The wrapper retries a failing read and returns the last error rather
    /// than the first. Without the wrapper this returns after one attempt.
    #[tokio::test]
    async fn retries_until_exhausted() {
        let retry = fast_retry(3);
        let client = unreachable_client(&retry);

        let start = Instant::now();
        let result = client
            .get_block_height(&BlockHash::from_raw_hash(Hash::all_zeros()))
            .await;

        assert!(result.is_err(), "unreachable node must fail");
        // 3 retries at 1ms each, so the call cannot have returned instantly
        // after a single attempt.
        assert!(
            start.elapsed() >= Duration::from_millis(3),
            "expected the retry delays to elapse, took {:?}",
            start.elapsed()
        );
    }
}
