use crate::call_encoder::{CallEncoder, RawCall};
use alloy_network::AnyNetwork;
use alloy_primitives::{Address, B256, Bytes, FixedBytes, Signature, U256};
use alloy_provider::Provider;
use alloy_signer::Signer;
use alloy_sol_types::{Eip712Domain, SolCall, SolStruct, SolType, sol};
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

        function approvedHashes(address owner, bytes32 messageHash) external view returns (uint256);
    }

    #[sol(rpc)]
    interface SignatureValidatorContract {
        function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4);
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

const EIP1271_MAGIC_VALUE: FixedBytes<4> = FixedBytes::<4>::new([0x16, 0x26, 0xba, 0x7e]);

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

/// A structured Safe signature input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafeSignature {
    /// A standard recoverable 65-byte EOA signature.
    Eoa(Bytes),
    /// An EIP-1271 contract signature.
    Contract { owner: Address, signature: Bytes },
    /// A Safe approved-hash signature.
    ApprovedHash { owner: Address },
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
    /// Structured Safe signature inputs.
    pub signatures: Vec<SafeSignature>,
    /// Encoded Safe signatures payload prepared for `execTransaction(...)`.
    pub encoded_signatures: Bytes,
}

/// Safe-specific validation and preparation errors.
#[derive(Debug, Error)]
pub enum SafeEncodeError {
    #[error("unsupported Safe version `{0}`")]
    UnsupportedVersion(String),
    #[error("safe EOA signatures must be 65 bytes")]
    InvalidEoaSignatureLength,
    #[error("recovered Safe signature signer {owner} is not an owner of Safe {safe}")]
    NonOwnerRecoveredSignature { owner: Address, safe: Address },
    #[error("contract signature owner {owner} is not an owner of Safe {safe}")]
    NonOwnerContractSignature { owner: Address, safe: Address },
    #[error("approved-hash owner {owner} is not an owner of Safe {safe}")]
    NonOwnerApprovedHash { owner: Address, safe: Address },
    #[error("duplicate signature for Safe owner {owner}")]
    DuplicateOwnerSignature { owner: Address },
    #[error("contract signature for owner {owner} did not return the EIP-1271 magic value")]
    InvalidContractSignature { owner: Address },
    #[error("approved-hash signature for owner {owner} is not currently valid")]
    InvalidApprovedHash { owner: Address },
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

#[derive(Clone, Debug)]
enum PreparedSignature {
    Static { owner: Address, bytes: [u8; 65] },
    Contract { owner: Address, signature: Bytes },
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
        let result = provider
            .multicall()
            .add(safe.VERSION())
            .add(safe.nonce())
            .add(safe.getThreshold())
            .add(safe.getOwners())
            .aggregate()
            .await;
        let (version, nonce, threshold, owners) = match result {
            Ok(values) => values,
            Err(_) => (
                safe.VERSION().call().await?,
                safe.nonce().call().await?,
                safe.getThreshold().call().await?,
                safe.getOwners().call().await?,
            ),
        };
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

    fn encode_static_eoa(signature: &Signature) -> [u8; 65] {
        signature.as_bytes()
    }

    fn encode_static_approved_hash(owner: Address) -> [u8; 65] {
        <sol! { (bytes32,uint256,uint8) }>::abi_encode_packed(&(owner.into_word(), U256::ZERO, 1u8))
            .try_into()
            .expect("approved-hash static signature encoding has fixed length")
    }

    fn encode_signatures(entries: Vec<PreparedSignature>) -> Bytes {
        let static_len = entries.len() * 65;
        let mut dynamic = Vec::new();
        let mut out = Vec::with_capacity(static_len);

        for entry in entries {
            match entry {
                PreparedSignature::Static { bytes, .. } => out.extend_from_slice(&bytes),
                PreparedSignature::Contract { owner, signature } => {
                    let offset = static_len + dynamic.len();
                    let mut static_part = [0u8; 65];
                    static_part[..32].copy_from_slice(owner.into_word().as_slice());
                    let offset_word: B256 = U256::from(offset).into();
                    static_part[32..64].copy_from_slice(offset_word.as_slice());
                    static_part[64] = 0;
                    out.extend_from_slice(&static_part);

                    let len_word: B256 = U256::from(signature.len()).into();
                    dynamic.extend_from_slice(len_word.as_slice());
                    dynamic.extend_from_slice(&signature);
                    let pad = (32 - (signature.len() % 32)) % 32;
                    dynamic.resize(dynamic.len() + pad, 0);
                }
            }
        }

        out.extend_from_slice(&dynamic);
        Bytes::from(out)
    }

    async fn validate_contract_signatures<P: Provider<AnyNetwork>>(
        &self,
        provider: &P,
        safe_tx_hash: B256,
        signatures: &[(Address, Bytes)],
    ) -> eyre::Result<()> {
        if signatures.is_empty() {
            return Ok(());
        }

        let mut multicall = provider
            .multicall()
            .dynamic::<SignatureValidatorContract::isValidSignatureCall>();
        for (owner, signature) in signatures {
            let validator = SignatureValidatorContract::new(*owner, provider);
            multicall =
                multicall.add_dynamic(validator.isValidSignature(safe_tx_hash, signature.clone()));
        }
        let results = match multicall.aggregate().await {
            Ok(results) => results,
            Err(_) => {
                let mut results = Vec::with_capacity(signatures.len());
                for (owner, signature) in signatures {
                    let validator = SignatureValidatorContract::new(*owner, provider);
                    results.push(
                        validator
                            .isValidSignature(safe_tx_hash, signature.clone())
                            .call()
                            .await?,
                    );
                }
                results
            }
        };
        for ((owner, _), result) in signatures.iter().zip(results) {
            if result != EIP1271_MAGIC_VALUE {
                return Err(SafeEncodeError::InvalidContractSignature { owner: *owner }.into());
            }
        }
        Ok(())
    }

    async fn validate_approved_hashes<P: Provider<AnyNetwork>>(
        &self,
        provider: &P,
        executor: Option<Address>,
        safe_tx_hash: B256,
        owners: &[Address],
    ) -> eyre::Result<()> {
        let owners_to_check: Vec<_> = owners
            .iter()
            .copied()
            .filter(|owner| executor != Some(*owner))
            .collect();
        if owners_to_check.is_empty() {
            return Ok(());
        }

        let safe = SafeReadContract::new(self.safe, provider);
        let mut multicall = provider
            .multicall()
            .dynamic::<SafeReadContract::approvedHashesCall>();
        for owner in &owners_to_check {
            multicall = multicall.add_dynamic(safe.approvedHashes(*owner, safe_tx_hash));
        }
        let results = match multicall.aggregate().await {
            Ok(results) => results,
            Err(_) => {
                let mut results = Vec::with_capacity(owners_to_check.len());
                for owner in &owners_to_check {
                    results.push(safe.approvedHashes(*owner, safe_tx_hash).call().await?);
                }
                results
            }
        };
        for (owner, approved) in owners_to_check.into_iter().zip(results) {
            if approved.is_zero() {
                return Err(SafeEncodeError::InvalidApprovedHash { owner }.into());
            }
        }
        Ok(())
    }

    /// Resolves the Safe transaction hash for the provided call/context and sorts signature inputs
    /// by owner address as required by Safe.
    pub async fn prepare_context<P: Provider<AnyNetwork>>(
        &self,
        call: &RawCall,
        context: &SafeCallContext,
        signer: Option<&WalletSigner>,
        executor: Option<Address>,
        provider: &P,
    ) -> eyre::Result<SafeCallContext> {
        let (version, nonce, threshold, owners) = self.load_metadata(provider).await?;
        let owner_set: BTreeSet<_> = owners.into_iter().collect();
        let chain_id = provider.get_chain_id().await?;
        let safe_tx_hash = self.safe_tx_hash(version, chain_id, call, context, nonce);

        let mut entries = Vec::new();
        let mut present_owners = BTreeSet::new();
        let mut contract_signatures = Vec::new();
        let mut approved_hash_owners = Vec::new();

        for signature in &context.signatures {
            match signature {
                SafeSignature::Eoa(bytes) => {
                    if bytes.len() != 65 {
                        return Err(SafeEncodeError::InvalidEoaSignatureLength.into());
                    }
                    let signature = Signature::try_from(bytes.as_ref())?;
                    let owner = signature.recover_address_from_prehash(&safe_tx_hash)?;
                    if !owner_set.contains(&owner) {
                        return Err(SafeEncodeError::NonOwnerRecoveredSignature {
                            owner,
                            safe: self.safe,
                        }
                        .into());
                    }
                    if !present_owners.insert(owner) {
                        return Err(SafeEncodeError::DuplicateOwnerSignature { owner }.into());
                    }
                    entries.push(PreparedSignature::Static {
                        owner,
                        bytes: Self::encode_static_eoa(&signature),
                    });
                }
                SafeSignature::Contract { owner, signature } => {
                    let owner = *owner;
                    if !owner_set.contains(&owner) {
                        return Err(SafeEncodeError::NonOwnerContractSignature {
                            owner,
                            safe: self.safe,
                        }
                        .into());
                    }
                    if !present_owners.insert(owner) {
                        return Err(SafeEncodeError::DuplicateOwnerSignature { owner }.into());
                    }
                    contract_signatures.push((owner, signature.clone()));
                    entries.push(PreparedSignature::Contract {
                        owner,
                        signature: signature.clone(),
                    });
                }
                SafeSignature::ApprovedHash { owner } => {
                    let owner = *owner;
                    if !owner_set.contains(&owner) {
                        return Err(SafeEncodeError::NonOwnerApprovedHash {
                            owner,
                            safe: self.safe,
                        }
                        .into());
                    }
                    if !present_owners.insert(owner) {
                        return Err(SafeEncodeError::DuplicateOwnerSignature { owner }.into());
                    }
                    approved_hash_owners.push(owner);
                    entries.push(PreparedSignature::Static {
                        owner,
                        bytes: Self::encode_static_approved_hash(owner),
                    });
                }
            }
        }

        self.validate_contract_signatures(provider, safe_tx_hash, &contract_signatures)
            .await?;
        self.validate_approved_hashes(provider, executor, safe_tx_hash, &approved_hash_owners)
            .await?;

        if U256::from(present_owners.len()) < threshold {
            let signer = signer.ok_or(SafeEncodeError::MissingLocalSigner {
                provided: present_owners.len(),
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
            if present_owners.insert(signer_address) {
                let signature = signer.sign_hash(&safe_tx_hash).await?;
                entries.push(PreparedSignature::Static {
                    owner: signer_address,
                    bytes: Self::encode_static_eoa(&signature),
                });
            }
        }

        if U256::from(present_owners.len()) < threshold {
            return Err(SafeEncodeError::InsufficientSigners {
                provided: present_owners.len(),
                threshold,
            }
            .into());
        }

        entries.sort_by_key(|entry| match entry {
            PreparedSignature::Static { owner, .. } | PreparedSignature::Contract { owner, .. } => {
                *owner
            }
        });

        let mut prepared = context.clone();
        prepared.encoded_signatures = Self::encode_signatures(entries);
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
            signatures: context.encoded_signatures.clone(),
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
    use alloy_primitives::{address, b256, hex};

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
            signatures: Vec::new(),
            encoded_signatures: Bytes::new(),
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

    #[test]
    fn encode_signatures_sorts_by_owner_address() {
        let owner1 = address!("1111111111111111111111111111111111111111");
        let owner2 = address!("2222222222222222222222222222222222222222");
        let entries = vec![
            PreparedSignature::Contract {
                owner: owner2,
                signature: Bytes::from(vec![0xaa, 0xbb, 0xcc]),
            },
            PreparedSignature::Static {
                owner: owner1,
                bytes: [0x11; 65],
            },
        ];

        let mut sorted = entries.clone();
        sorted.sort_by_key(|entry| match entry {
            PreparedSignature::Static { owner, .. } | PreparedSignature::Contract { owner, .. } => {
                *owner
            }
        });
        let encoded = SafeCallEncoder::encode_signatures(sorted);

        assert_eq!(
            hex::encode(&encoded[..65]),
            "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(
            hex::encode(&encoded[65..97]),
            "0000000000000000000000002222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn encode_signatures_encodes_static_and_dynamic_parts() {
        let owner1 = address!("1111111111111111111111111111111111111111");
        let owner2 = address!("2222222222222222222222222222222222222222");
        let eoa = PreparedSignature::Static {
            owner: owner1,
            bytes: [0x11; 65],
        };
        let contract = PreparedSignature::Contract {
            owner: owner2,
            signature: Bytes::from(vec![0xaa, 0xbb, 0xcc]),
        };

        let encoded = SafeCallEncoder::encode_signatures(vec![eoa, contract]);

        assert_eq!(
            hex::encode(&encoded),
            concat!(
                "1111111111111111111111111111111111111111111111111111111111111111",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "11",
                "0000000000000000000000002222222222222222222222222222222222222222",
                "0000000000000000000000000000000000000000000000000000000000000082",
                "00",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "aabbcc",
                "0000000000000000000000000000000000000000000000000000000000"
            )
        );
    }
}
