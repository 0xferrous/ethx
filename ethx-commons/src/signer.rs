use crate::error::WalletSignerError;
use alloy_consensus::SignableTransaction;
use alloy_dyn_abi::TypedData;
use alloy_network::TxSigner;
use alloy_primitives::{Address, B256, ChainId, Signature, hex};
use alloy_signer::Signer;
use alloy_signer_ledger::{HDPath as LedgerHDPath, LedgerSigner};
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use alloy_signer_trezor::{HDPath as TrezorHDPath, TrezorSigner};
use alloy_sol_types::{Eip712Domain, SolStruct};
use async_trait::async_trait;
use std::{collections::HashSet, path::PathBuf};
use tracing::warn;

/// Result type used by signer construction and wallet helper APIs.
pub type Result<T> = std::result::Result<T, WalletSignerError>;

/// Wrapper enum around different signers.
#[derive(Debug)]
pub enum WalletSigner {
    /// Wrapper around local wallet. e.g. private key, mnemonic
    Local(PrivateKeySigner),
    /// Wrapper around Ledger signer.
    Ledger(LedgerSigner),
    /// Wrapper around Trezor signer.
    Trezor(TrezorSigner),
}

impl WalletSigner {
    /// Creates a signer backed by a Ledger device using the given derivation path.
    pub async fn from_ledger_path(path: LedgerHDPath) -> Result<Self> {
        let ledger = LedgerSigner::new(path, None).await?;
        Ok(Self::Ledger(ledger))
    }

    /// Creates a signer backed by a Trezor device using the given derivation path.
    pub async fn from_trezor_path(path: TrezorHDPath) -> Result<Self> {
        let trezor = TrezorSigner::new(path, None).await?;
        Ok(Self::Trezor(trezor))
    }

    /// Creates a signer backed by AWS KMS.
    ///
    /// This currently returns an unsupported-backend error.
    pub async fn from_aws(key_id: String) -> Result<Self> {
        let _ = key_id;
        Err(WalletSignerError::aws_unsupported())
    }

    /// Creates a signer backed by Google Cloud KMS.
    ///
    /// This currently returns an unsupported-backend error.
    pub async fn from_gcp(
        project_id: String,
        location: String,
        keyring: String,
        key_name: String,
        key_version: u64,
    ) -> Result<Self> {
        let _ = project_id;
        let _ = location;
        let _ = keyring;
        let _ = key_name;
        let _ = key_version;
        Err(WalletSignerError::gcp_unsupported())
    }

    /// Creates a signer backed by Turnkey.
    ///
    /// This currently returns an unsupported-backend error.
    pub fn from_turnkey(
        api_private_key: String,
        organization_id: String,
        address: Address,
    ) -> Result<Self> {
        let _ = api_private_key;
        let _ = organization_id;
        let _ = address;
        Err(WalletSignerError::turnkey_unsupported())
    }

    /// Creates a local signer from a raw private key.
    pub fn from_private_key(private_key: &B256) -> Result<Self> {
        Ok(Self::Local(PrivateKeySigner::from_bytes(private_key)?))
    }

    /// Returns a list of sender addresses available from the current signer.
    ///
    /// For hardware wallets, up to `max` derivation indexes are probed.
    pub async fn available_senders(&self, max: usize) -> Result<Vec<Address>> {
        let mut senders = HashSet::new();

        match self {
            Self::Local(local) => {
                senders.insert(local.address());
            }
            Self::Ledger(ledger) => {
                for i in 0..max {
                    match ledger
                        .get_address_with_path(&LedgerHDPath::LedgerLive(i))
                        .await
                    {
                        Ok(address) => {
                            senders.insert(address);
                        }
                        Err(e) => {
                            warn!("Failed to get Ledger address at index {i} (LedgerLive): {e}");
                        }
                    }
                }
                for i in 0..max {
                    match ledger.get_address_with_path(&LedgerHDPath::Legacy(i)).await {
                        Ok(address) => {
                            senders.insert(address);
                        }
                        Err(e) => {
                            warn!("Failed to get Ledger address at index {i} (Legacy): {e}");
                        }
                    }
                }
            }
            Self::Trezor(trezor) => {
                for i in 0..max {
                    match trezor
                        .get_address_with_path(&TrezorHDPath::TrezorLive(i))
                        .await
                    {
                        Ok(address) => {
                            senders.insert(address);
                        }
                        Err(e) => {
                            warn!("Failed to get Trezor address at index {i} (TrezorLive): {e}");
                        }
                    }
                }
            }
        }
        Ok(senders.into_iter().collect())
    }

    /// Creates a local signer from a mnemonic phrase.
    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: Option<&str>,
        derivation_path: Option<&str>,
        index: u32,
    ) -> Result<Self> {
        let mut builder = MnemonicBuilder::<English>::default().phrase(mnemonic);

        if let Some(passphrase) = passphrase {
            builder = builder.password(passphrase)
        }

        builder = if let Some(hd_path) = derivation_path {
            builder.derivation_path(hd_path)?
        } else {
            builder.index(index)?
        };

        Ok(Self::Local(builder.build()?))
    }
}

macro_rules! delegate {
    ($s:ident, $inner:ident => $e:expr) => {
        match $s {
            Self::Local($inner) => $e,
            Self::Ledger($inner) => $e,
            Self::Trezor($inner) => $e,
        }
    };
}

#[async_trait]
impl Signer for WalletSigner {
    async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<Signature> {
        delegate!(self, inner => inner.sign_hash(hash)).await
    }

    async fn sign_message(&self, message: &[u8]) -> alloy_signer::Result<Signature> {
        delegate!(self, inner => inner.sign_message(message)).await
    }

    fn address(&self) -> Address {
        delegate!(self, inner => alloy_signer::Signer::address(inner))
    }

    fn chain_id(&self) -> Option<ChainId> {
        delegate!(self, inner => inner.chain_id())
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        delegate!(self, inner => inner.set_chain_id(chain_id))
    }

    async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> alloy_signer::Result<Signature>
    where
        Self: Sized,
    {
        delegate!(self, inner => inner.sign_typed_data(payload, domain)).await
    }

    async fn sign_dynamic_typed_data(
        &self,
        payload: &TypedData,
    ) -> alloy_signer::Result<Signature> {
        delegate!(self, inner => inner.sign_dynamic_typed_data(payload)).await
    }
}

#[async_trait]
impl TxSigner<Signature> for WalletSigner {
    fn address(&self) -> Address {
        Signer::address(self)
    }

    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> alloy_signer::Result<Signature> {
        delegate!(self, inner => TxSigner::sign_transaction(inner, tx)).await
    }
}

/// Signers that require user interaction before they can be used.
#[derive(Debug, Clone)]
pub enum PendingSigner {
    /// A keystore file that still needs a password prompt.
    Keystore(PathBuf),
    /// An interactive prompt requesting a raw private key.
    Interactive,
}

impl PendingSigner {
    /// Unlocks the pending signer by prompting the user for the missing secret material.
    pub fn unlock(self) -> Result<WalletSigner> {
        match self {
            Self::Keystore(path) => {
                let password = rpassword::prompt_password("Enter keystore password:")?;
                match PrivateKeySigner::decrypt_keystore(path, password) {
                    Ok(signer) => Ok(WalletSigner::Local(signer)),
                    Err(e) => match e {
                        alloy_signer_local::LocalSignerError::EthKeystoreError(
                            eth_keystore::KeystoreError::MacMismatch,
                        ) => Err(WalletSignerError::IncorrectKeystorePassword),
                        _ => Err(WalletSignerError::Local(e)),
                    },
                }
            }
            Self::Interactive => {
                let private_key = rpassword::prompt_password("Enter private key:")?;
                Ok(WalletSigner::from_private_key(&hex::FromHex::from_hex(
                    private_key,
                )?)?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};

    #[test]
    fn from_private_key_matches_underlying_local_signer() {
        let private_key = b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

        let signer = WalletSigner::from_private_key(&private_key).unwrap();
        let expected = PrivateKeySigner::from_bytes(&private_key).unwrap();

        assert_eq!(Signer::address(&signer), expected.address());
        assert_eq!(
            Signer::address(&signer),
            address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        );
    }

    #[test]
    fn from_mnemonic_matches_underlying_builder() {
        let mnemonic = "test test test test test test test test test test test junk";

        let signer = WalletSigner::from_mnemonic(mnemonic, None, None, 0).unwrap();
        let expected = MnemonicBuilder::<English>::default()
            .phrase(mnemonic)
            .index(0)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(Signer::address(&signer), expected.address());
        assert_eq!(
            Signer::address(&signer),
            address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        );
    }

    #[test]
    fn available_senders_returns_local_address() {
        let private_key = b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let signer = WalletSigner::from_private_key(&private_key).unwrap();

        let senders = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { signer.available_senders(5).await.unwrap() });

        assert_eq!(
            senders,
            vec![address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266")]
        );
    }

    #[tokio::test]
    async fn sign_hash_matches_underlying_local_signer() {
        let private_key = b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let hash = b256!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let signer = WalletSigner::from_private_key(&private_key).unwrap();
        let expected = PrivateKeySigner::from_bytes(&private_key).unwrap();

        assert_eq!(
            signer.sign_hash(&hash).await.unwrap(),
            expected.sign_hash_sync(&hash).unwrap()
        );
    }

    #[test]
    fn chain_id_passthrough_works() {
        let private_key = b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let mut signer = WalletSigner::from_private_key(&private_key).unwrap();

        assert_eq!(signer.chain_id(), None);
        signer.set_chain_id(Some(31337));
        assert_eq!(signer.chain_id(), Some(31337));
    }

    #[tokio::test]
    async fn unsupported_backends_return_expected_errors() {
        assert!(matches!(
            WalletSigner::from_aws("key".into()).await,
            Err(WalletSignerError::UnsupportedSigner("AWS KMS"))
        ));
        assert!(matches!(
            WalletSigner::from_gcp("p".into(), "l".into(), "k".into(), "n".into(), 1).await,
            Err(WalletSignerError::UnsupportedSigner("Google Cloud KMS"))
        ));
        assert!(matches!(
            WalletSigner::from_turnkey(
                "api".into(),
                "org".into(),
                address!("1234567890123456789012345678901234567890")
            ),
            Err(WalletSignerError::UnsupportedSigner("Turnkey"))
        ));
    }
}
