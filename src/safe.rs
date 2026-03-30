use crate::call_encoder::{CallEncoder, RawCall};
use alloy_network::AnyNetwork;
use alloy_primitives::{Address, B256, Bytes, Signature, U256};
use alloy_provider::Provider;
use alloy_signer::Signer;
use alloy_sol_types::{Eip712Domain, SolCall, SolStruct, sol};
use foundry_wallets::WalletSigner;
use std::collections::BTreeSet;
use thiserror::Error;

sol! {
    /// Safe/Gnosis Safe read entrypoints needed by the encoder.
    ///
    /// Hash derivation was verified against the tagged contract sources from:
    /// - `safe-smart-account@v1.0.0: contracts/GnosisSafe.sol`
    /// - `safe-smart-account@v1.1.1: contracts/GnosisSafe.sol`
    /// - `safe-smart-account@v1.2.0: contracts/GnosisSafe.sol`
    /// - `safe-smart-account@v1.3.0: contracts/GnosisSafe.sol`
    /// - `safe-smart-account@v1.4.1: contracts/Safe.sol`
    /// - `safe-smart-account@v1.5.0: contracts/Safe.sol`
    #[sol(rpc)]
    interface SafeReadContract {
        function nonce() external view returns (uint256);

        function VERSION() external view returns (string memory);

        function getThreshold() external view returns (uint256);

        function getOwners() external view returns (address[] memory);
    }

    struct SafeTx {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
        uint256 nonce;
    }

    function execTransaction(
        address to,
        uint256 value,
        bytes data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        bytes signatures
    ) external returns (bool success);
}

/// Safe operation kind used when wrapping an inner call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum SafeOperation {
    /// Execute the wrapped call as a normal `CALL`.
    #[default]
    Call = 0,
    /// Execute the wrapped call as a `DELEGATECALL`.
    DelegateCall = 1,
}

impl From<SafeOperation> for u8 {
    fn from(value: SafeOperation) -> Self {
        value as u8
    }
}

/// Additional Safe-specific metadata used when encoding a wrapped Safe call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SafeCallContext {
    /// The Safe operation mode for the inner execution.
    pub operation: SafeOperation,
    /// Gas limit forwarded to the Safe transaction.
    pub safe_tx_gas: U256,
    /// Base gas used by the Safe refund logic.
    pub base_gas: U256,
    /// Gas price used by the Safe refund logic.
    pub gas_price: U256,
    /// Token used for refunds. Zero address means native ETH semantics in Safe.
    pub gas_token: Address,
    /// Receiver of gas refunds. Zero address keeps Safe default behavior.
    pub refund_receiver: Address,
    /// Prebuilt Safe signatures payload.
    pub signatures: Bytes,
}

/// Safe-specific validation and preparation errors.
#[derive(Debug, Error)]
pub enum SafeEncodeError {
    #[error("unsupported Safe version `{0}`")]
    UnsupportedVersion(String),
    #[error("safe signatures payload must be a concatenation of 65-byte signatures")]
    InvalidSignaturePayloadLength,
    #[error("recovered Safe signature signer {owner} is not an owner of Safe {safe}")]
    NonOwnerRecoveredSignature { owner: Address, safe: Address },
    #[error(
        "insufficient Safe signatures: {provided} unique owner signature(s) provided, below threshold {threshold}, and no local signer is available to add another Safe signature"
    )]
    MissingLocalSigner { provided: usize, threshold: U256 },
    #[error(
        "insufficient Safe signatures: {provided} unique owner signer(s) after including the current signer is below threshold {threshold}"
    )]
    InsufficientSigners { provided: usize, threshold: U256 },
    #[error("current signer {signer} is not an owner of Safe {safe}")]
    NonOwnerCurrentSigner { signer: Address, safe: Address },
}

/// Encodes a plain call into a call to a Safe's `execTransaction` entrypoint.
///
/// The resulting [`RawCall`] targets the Safe contract itself. The inner target/value/calldata are
/// embedded into the encoded `execTransaction(...)` calldata.
///
/// All currently supported Safe versions share a compatible `execTransaction` ABI, so a single
/// encoder implementation can be aliased across versions.
pub struct SafeCallEncoder {
    /// The Safe contract address that should receive the wrapped call.
    pub safe: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SafeHashVersion {
    V1_0_0,
    V1_1_1,
    V1_2_0,
    V1_3_0,
    V1_4_1,
    V1_5_0,
}

impl SafeHashVersion {
    fn parse(version: &str) -> Result<Self, SafeEncodeError> {
        match version {
            "1.0.0" => Ok(Self::V1_0_0),
            "1.1.1" => Ok(Self::V1_1_1),
            "1.2.0" => Ok(Self::V1_2_0),
            "1.3.0" => Ok(Self::V1_3_0),
            "1.4.1" => Ok(Self::V1_4_1),
            "1.5.0" => Ok(Self::V1_5_0),
            other => Err(SafeEncodeError::UnsupportedVersion(other.to_owned())),
        }
    }

    fn domain(self, safe: Address, chain_id: u64) -> Eip712Domain {
        // Safe does not use the common EIP-712 domain shape with `name`/`version`.
        // The tagged contracts derive the domain as either:
        // - `keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, this))`, or
        // - `keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, this))`
        // so `name` and `version` must be omitted here.
        match self {
            Self::V1_0_0 | Self::V1_1_1 | Self::V1_2_0 => {
                Eip712Domain::new(None, None, None, Some(safe), None)
            }
            Self::V1_3_0 | Self::V1_4_1 | Self::V1_5_0 => {
                Eip712Domain::new(None, None, Some(U256::from(chain_id)), Some(safe), None)
            }
        }
    }
}

impl SafeCallEncoder {
    /// Creates a new Safe call encoder.
    pub fn new(safe: Address) -> Self {
        Self { safe }
    }

    async fn load_metadata<P: Provider<AnyNetwork>>(
        &self,
        provider: &P,
    ) -> eyre::Result<(SafeHashVersion, U256, U256, Vec<Address>)> {
        let safe = SafeReadContract::new(self.safe, provider);
        let (version, nonce, threshold, owners) = provider
            .multicall()
            .add(safe.VERSION())
            .add(safe.nonce())
            .add(safe.getThreshold())
            .add(safe.getOwners())
            .aggregate()
            .await?;
        Ok((
            SafeHashVersion::parse(version.as_str())?,
            nonce,
            threshold,
            owners,
        ))
    }

    fn safe_tx_hash(
        &self,
        version: SafeHashVersion,
        chain_id: u64,
        call: &RawCall,
        context: &SafeCallContext,
        nonce: U256,
    ) -> B256 {
        let safe_tx = SafeTx {
            to: call.to,
            value: call.value,
            data: call.data.clone(),
            operation: context.operation.into(),
            safeTxGas: context.safe_tx_gas,
            baseGas: context.base_gas,
            gasPrice: context.gas_price,
            gasToken: context.gas_token,
            refundReceiver: context.refund_receiver,
            nonce,
        };
        safe_tx.eip712_signing_hash(&version.domain(self.safe, chain_id))
    }

    /// Resolves the Safe transaction hash for the provided call/context and sorts any recoverable
    /// EOA signatures by recovered owner address as required by Safe.
    pub async fn prepare_context<P: Provider<AnyNetwork>>(
        &self,
        call: &RawCall,
        context: &SafeCallContext,
        signer: Option<&WalletSigner>,
        provider: &P,
    ) -> eyre::Result<SafeCallContext> {
        if !context.signatures.len().is_multiple_of(65) {
            return Err(SafeEncodeError::InvalidSignaturePayloadLength.into());
        }

        let (version, nonce, threshold, owners) = self.load_metadata(provider).await?;
        let owner_set: BTreeSet<_> = owners.into_iter().collect();
        let chain_id = provider.get_chain_id().await?;
        let safe_tx_hash = self.safe_tx_hash(version, chain_id, call, context, nonce);

        let mut entries = Vec::new();
        let mut recovered_owner_set = BTreeSet::new();
        for chunk in context.signatures.chunks_exact(65) {
            let signature = Signature::try_from(chunk)?;
            let owner = signature.recover_address_from_prehash(&safe_tx_hash)?;
            if !owner_set.contains(&owner) {
                return Err(SafeEncodeError::NonOwnerRecoveredSignature {
                    owner,
                    safe: self.safe,
                }
                .into());
            }
            recovered_owner_set.insert(owner);
            entries.push((owner, chunk.to_vec()));
        }

        if U256::from(recovered_owner_set.len()) < threshold {
            let signer = signer.ok_or(SafeEncodeError::MissingLocalSigner {
                provided: recovered_owner_set.len(),
                threshold,
            })?;
            let signer_address = signer.address();
            if !owner_set.contains(&signer_address) {
                return Err(SafeEncodeError::NonOwnerCurrentSigner {
                    signer: signer_address,
                    safe: self.safe,
                }
                .into());
            }
            if !recovered_owner_set.contains(&signer_address) {
                let signature = signer.sign_hash(&safe_tx_hash).await?;
                entries.push((signer_address, signature.as_bytes().to_vec()));
                recovered_owner_set.insert(signer_address);
            }
        }

        if U256::from(recovered_owner_set.len()) < threshold {
            return Err(SafeEncodeError::InsufficientSigners {
                provided: recovered_owner_set.len(),
                threshold,
            }
            .into());
        }

        entries.sort_by_key(|(owner, _)| *owner);

        let mut signatures = Vec::with_capacity(entries.len() * 65);
        for (_, sig) in entries {
            signatures.extend(sig);
        }

        let mut prepared = context.clone();
        prepared.signatures = Bytes::from(signatures);
        Ok(prepared)
    }
}

impl CallEncoder for SafeCallEncoder {
    type EncodeContext = SafeCallContext;

    fn encode_call(&self, call: RawCall, context: &Self::EncodeContext) -> eyre::Result<RawCall> {
        let data = execTransactionCall {
            to: call.to,
            value: call.value,
            data: call.data,
            operation: context.operation.into(),
            safeTxGas: context.safe_tx_gas,
            baseGas: context.base_gas,
            gasPrice: context.gas_price,
            gasToken: context.gas_token,
            refundReceiver: context.refund_receiver,
            signatures: context.signatures.clone(),
        }
        .abi_encode();

        Ok(RawCall {
            to: self.safe,
            value: U256::ZERO,
            data: data.into(),
        })
    }
}

/// Safe v1.0.0 encoder.
pub type SafeCallEncoderV1_0_0 = SafeCallEncoder;
/// Safe v1.1.1 encoder.
pub type SafeCallEncoderV1_1_1 = SafeCallEncoder;
/// Safe v1.2.0 encoder.
pub type SafeCallEncoderV1_2_0 = SafeCallEncoder;
/// Safe v1.3.0 encoder.
pub type SafeCallEncoderV1_3_0 = SafeCallEncoder;
/// Safe v1.4.1 encoder.
pub type SafeCallEncoderV1_4_1 = SafeCallEncoder;
/// Safe v1.5.0 encoder.
pub type SafeCallEncoderV1_5_0 = SafeCallEncoder;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn sample_call() -> RawCall {
        RawCall {
            to: address!("1111111111111111111111111111111111111111"),
            value: U256::from(42),
            data: Bytes::from_static(b"hello"),
        }
    }

    fn sample_context() -> SafeCallContext {
        SafeCallContext {
            operation: SafeOperation::Call,
            safe_tx_gas: U256::from(100_000),
            base_gas: U256::from(21_000),
            gas_price: U256::from(1_000_000_000u64),
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            signatures: Bytes::new(),
        }
    }

    #[test]
    fn safe_tx_type_hash_matches_contract_constant() {
        let tx = SafeTx {
            to: Address::ZERO,
            value: U256::ZERO,
            data: Bytes::new(),
            operation: 0,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            nonce: U256::ZERO,
        };
        assert_eq!(
            tx.eip712_type_hash(),
            b256!("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8")
        );
    }

    #[test]
    fn legacy_domain_matches_contract_constant() {
        let safe = address!("1234567890123456789012345678901234567890");
        let domain = SafeHashVersion::V1_2_0.domain(safe, 1);
        assert_eq!(
            domain.type_hash(),
            b256!("035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749")
        );
    }

    #[test]
    fn chain_aware_domain_matches_contract_constant() {
        let safe = address!("1234567890123456789012345678901234567890");
        let domain = SafeHashVersion::V1_5_0.domain(safe, 1);
        assert_eq!(
            domain.type_hash(),
            b256!("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218")
        );
    }

    #[test]
    fn safe_hash_derivation_matches_known_runtime_value() {
        let safe = address!("1234567890123456789012345678901234567890");
        let encoder = SafeCallEncoder::new(safe);
        let hash = encoder.safe_tx_hash(
            SafeHashVersion::V1_5_0,
            1,
            &sample_call(),
            &sample_context(),
            U256::from(7),
        );
        assert_eq!(
            hash,
            b256!("6ad3c2d597a14c9cbebd58fa46a4c4dda0287ab66b6b504ced39aee998eeac8e")
        );
    }
}
