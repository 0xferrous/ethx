use alloy_primitives::hex::FromHexError;
use alloy_signer::k256::ecdsa;
use alloy_signer_ledger::LedgerError;
use alloy_signer_local::LocalSignerError;
use alloy_signer_trezor::TrezorError;

/// Errors that can occur while interpreting a user-supplied private key.
#[derive(Debug, thiserror::Error)]
pub enum PrivateKeyError {
    /// The provided private key string was not valid hex.
    #[error("Failed to create wallet from private key. Private key is invalid hex: {0}")]
    InvalidHex(#[from] FromHexError),
    /// The provided string looked like a missing `$ENV_VAR` reference rather than a key.
    #[error(
        "Failed to create wallet from private key. Invalid private key. But env var {0} exists. Is the `$` anchor missing?"
    )]
    ExistsAsEnvVar(String),
}

/// Errors returned while constructing, loading, or using wallet signers.
#[derive(Debug, thiserror::Error)]
pub enum WalletSignerError {
    /// A local signer operation failed.
    #[error(transparent)]
    Local(#[from] LocalSignerError),
    /// A keystore password was supplied but did not decrypt the keystore.
    #[error("Failed to decrypt keystore: incorrect password")]
    IncorrectKeystorePassword,
    /// A Ledger signer operation failed.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// A Trezor signer operation failed.
    #[error(transparent)]
    Trezor(#[from] TrezorError),
    /// An I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Hex decoding failed.
    #[error(transparent)]
    InvalidHex(#[from] FromHexError),
    /// ECDSA signing or parsing failed.
    #[error(transparent)]
    Ecdsa(#[from] ecdsa::Error),
    /// The requested signer backend is not compiled into this crate.
    #[error("ethx-commons was not built with support for {0} signer")]
    UnsupportedSigner(&'static str),
}

impl WalletSignerError {
    /// Returns the standard unsupported error for AWS KMS signer requests.
    pub fn aws_unsupported() -> Self {
        Self::UnsupportedSigner("AWS KMS")
    }

    /// Returns the standard unsupported error for Google Cloud KMS signer requests.
    pub fn gcp_unsupported() -> Self {
        Self::UnsupportedSigner("Google Cloud KMS")
    }

    /// Returns the standard unsupported error for Turnkey signer requests.
    pub fn turnkey_unsupported() -> Self {
        Self::UnsupportedSigner("Turnkey")
    }

    /// Returns the standard unsupported error for browser-wallet signer requests.
    pub fn browser_unsupported() -> Self {
        Self::UnsupportedSigner("Browser Wallet")
    }
}
