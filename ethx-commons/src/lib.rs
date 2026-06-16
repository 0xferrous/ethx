//! Shared Ethereum CLI support types for `ethx`.
//!
//! Wallet parsing and signer resolution are re-exported from `foundry-wallets`; this crate keeps
//! the remaining `ethx`-specific ABI, RPC/explorer, and transaction option helpers in one place.

/// ABI and calldata parsing helpers.
pub mod abi;
/// Ethereum CLI option wrappers composed from RPC, explorer, and wallet options.
pub mod ethereum;
/// Transaction option types used by `ethx`.
pub mod tx;
/// Small CLI parsing utilities that are not provided by `foundry-wallets`.
pub mod utils;

/// ABI and calldata parsing helpers.
pub use abi::parse_function_args;
/// Combined Ethereum CLI options used by `ethx`.
pub use ethereum::{EthereumOpts, EtherscanOpts, RpcOpts};
/// Tempo access-key configuration compatibility type from `foundry-wallets`.
pub use foundry_wallets::MaybeTempoConfig as TempoAccessKeyConfig;
/// Raw wallet CLI options used by [`WalletOpts`].
pub use foundry_wallets::RawWalletOpts;
/// Wallet CLI options and signer resolution entrypoints provided by `foundry-wallets`.
pub use foundry_wallets::WalletOpts;
/// Signers that require deferred user interaction and the resolved signer type.
pub use foundry_wallets::{PendingSigner, WalletSigner};
/// Transaction options and authorization-list helpers.
pub use tx::{CliAuthorizationList, TransactionOpts};
