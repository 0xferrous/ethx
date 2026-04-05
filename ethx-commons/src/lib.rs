//! Shared wallet and Ethereum CLI support types for `ethx`.
//!
//! This crate mirrors the wallet-facing API shape previously consumed from
//! Foundry so `ethx` can migrate away incrementally while preserving its CLI.

/// ABI and calldata parsing helpers.
pub mod abi;
/// Error types for wallet parsing and signer construction.
pub mod error;
/// Ethereum CLI option wrappers composed from RPC, explorer, and wallet options.
pub mod ethereum;
/// Top-level wallet CLI options and signer resolution helpers.
pub mod opts;
/// Signer abstractions and signer-related helpers.
pub mod signer;
/// Tempo-related compatibility types.
pub mod tempo;
/// Transaction option types used by `ethx`.
pub mod tx;
/// Utility functions for wallet loading and signer creation.
pub mod utils;
/// Raw wallet CLI options such as private keys and mnemonics.
pub mod wallet_raw;

/// ABI and calldata parsing helpers.
pub use abi::parse_function_args;
/// Combined Ethereum CLI options used by `ethx`.
pub use ethereum::{EthereumOpts, EtherscanOpts, RpcOpts};
/// Wallet CLI options and signer resolution entrypoints.
pub use opts::WalletOpts;
/// Signers that require deferred user interaction and the resolved signer type.
pub use signer::{PendingSigner, WalletSigner};
/// Tempo access-key configuration placeholder used for compatibility.
pub use tempo::TempoAccessKeyConfig;
/// Transaction options and authorization-list helpers.
pub use tx::{CliAuthorizationList, TransactionOpts};
/// Raw wallet CLI options used by [`WalletOpts`].
pub use wallet_raw::RawWalletOpts;
