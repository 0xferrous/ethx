use crate::safe::{SafeOperation, SafeTxDraft};
use alloy_primitives::{Address, Signature, U256};
use eyre::{Context, Result, bail, eyre};
use serde::{Deserialize, Serialize};

/// Returns the default Safe Transaction Service base URL for common chain IDs.
pub fn default_safe_api_url(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        1 => Some("https://api.safe.global/tx-service/eth"),
        10 => Some("https://api.safe.global/tx-service/oeth"),
        56 => Some("https://api.safe.global/tx-service/bnb"),
        100 => Some("https://api.safe.global/tx-service/gno"),
        130 => Some("https://api.safe.global/tx-service/unichain"),
        137 => Some("https://api.safe.global/tx-service/pol"),
        146 => Some("https://api.safe.global/tx-service/sonic"),
        324 => Some("https://api.safe.global/tx-service/zksync"),
        8453 => Some("https://api.safe.global/tx-service/base"),
        42161 => Some("https://api.safe.global/tx-service/arb1"),
        42220 => Some("https://api.safe.global/tx-service/celo"),
        43114 => Some("https://api.safe.global/tx-service/avax"),
        534352 => Some("https://api.safe.global/tx-service/scr"),
        59144 => Some("https://api.safe.global/tx-service/linea"),
        84532 => Some("https://api.safe.global/tx-service/basesep"),
        11155111 => Some("https://api.safe.global/tx-service/sep"),
        _ => None,
    }
}

/// Returns the next nonce after trusted pending transactions known by the Safe Transaction Service.
pub async fn next_available_nonce(
    base_url: &str,
    safe: Address,
    onchain_nonce: U256,
) -> Result<U256> {
    let url = format!(
        "{}/api/v1/safes/{}/multisig-transactions/?executed=false&trusted=true&ordering=-nonce&limit=1",
        base_url.trim_end_matches('/'),
        checksum(safe)
    );

    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .context("failed to query Safe API pending transactions")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Safe API nonce query failed with status {status}: {body}");
    }

    let pending: MultisigTransactionList = response
        .json()
        .await
        .context("failed to decode Safe API pending transaction response")?;
    let Some(highest_pending) = pending.results.first().map(|tx| tx.nonce) else {
        return Ok(onchain_nonce);
    };
    Ok(onchain_nonce.max(U256::from(highest_pending + 1)))
}

/// Proposes a Safe transaction with a local owner signature to the Safe Transaction Service.
pub async fn propose_transaction(
    base_url: &str,
    safe: Address,
    sender: Address,
    draft: &SafeTxDraft,
    signature: &Signature,
    origin: Option<&str>,
) -> Result<()> {
    let payload = ProposeTransactionPayload::new(sender, draft, signature, origin);
    let url = format!(
        "{}/api/v1/safes/{}/multisig-transactions/",
        base_url.trim_end_matches('/'),
        checksum(safe)
    );

    let detail_url = format!(
        "{}/api/v1/multisig-transactions/{:#x}/",
        base_url.trim_end_matches('/'),
        draft.safe_tx_hash
    );

    let response = reqwest::Client::new()
        .post(url)
        .json(&payload)
        .send()
        .await
        .context("failed to submit Safe API proposal")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Safe API proposal failed with status {status}: {body}");
    }

    println!("{:#x}", draft.safe_tx_hash);
    if let Some(location) = response.headers().get(reqwest::header::LOCATION)
        && let Ok(location) = location.to_str()
    {
        println!("{location}");
    } else {
        println!("{detail_url}");
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct MultisigTransactionList {
    results: Vec<MultisigTransactionSummary>,
}

#[derive(Debug, Deserialize)]
struct MultisigTransactionSummary {
    nonce: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposeTransactionPayload {
    to: String,
    value: String,
    data: String,
    operation: u8,
    safe_tx_gas: u64_string::U256String,
    base_gas: u64_string::U256String,
    gas_price: String,
    gas_token: String,
    refund_receiver: String,
    nonce: u64_string::U256String,
    contract_transaction_hash: String,
    sender: String,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
}

impl ProposeTransactionPayload {
    fn new(
        sender: Address,
        draft: &SafeTxDraft,
        signature: &Signature,
        origin: Option<&str>,
    ) -> Self {
        Self {
            to: checksum(draft.to),
            value: draft.value.to_string(),
            data: format!("0x{}", alloy_primitives::hex::encode(&draft.data)),
            operation: operation_to_u8(draft.operation),
            safe_tx_gas: u64_string::U256String(draft.safe_tx_gas),
            base_gas: u64_string::U256String(draft.base_gas),
            gas_price: draft.gas_price.to_string(),
            gas_token: checksum(draft.gas_token),
            refund_receiver: checksum(draft.refund_receiver),
            nonce: u64_string::U256String(draft.nonce),
            contract_transaction_hash: format!("{:#x}", draft.safe_tx_hash),
            sender: checksum(sender),
            signature: format!("0x{}", alloy_primitives::hex::encode(signature.as_bytes())),
            origin: origin.map(str::to_owned),
        }
    }
}

fn checksum(address: Address) -> String {
    address.to_checksum(None)
}

fn operation_to_u8(operation: SafeOperation) -> u8 {
    operation.into()
}

mod u64_string {
    use alloy_primitives::U256;
    use serde::{Serialize, Serializer};

    #[derive(Debug)]
    pub struct U256String(pub U256);

    impl Serialize for U256String {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&self.0.to_string())
        }
    }
}

/// Resolves a Safe Transaction Service URL from an optional override and chain id.
pub fn resolve_safe_api_url(override_url: Option<&str>, chain_id: u64) -> Result<String> {
    if let Some(url) = override_url {
        return Ok(url.to_owned());
    }
    default_safe_api_url(chain_id)
        .map(str::to_owned)
        .ok_or_else(|| {
            eyre!("no default Safe API URL for chain id {chain_id}; pass --safe-api-url")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_common_chains() {
        assert_eq!(
            default_safe_api_url(1),
            Some("https://api.safe.global/tx-service/eth")
        );
        assert_eq!(
            default_safe_api_url(11155111),
            Some("https://api.safe.global/tx-service/sep")
        );
        assert!(default_safe_api_url(31337).is_none());
    }
}
