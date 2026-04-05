use crate::utils::parse_ether_value;
use alloy_eips::eip7702::SignedAuthorization;
use alloy_network::{Network, TransactionBuilder};
use alloy_primitives::{Address, U64, U256, hex};
use alloy_rlp::Decodable;
use clap::Parser;
use std::str::FromStr;

/// CLI helper to parse an EIP-7702 authorization list entry.
///
/// This can be either a hex-encoded signed authorization or a delegate address.
#[derive(Clone, Debug)]
pub enum CliAuthorizationList {
    /// A delegate address that should be authorized.
    Address(Address),
    /// A fully signed authorization encoded as RLP bytes.
    Signed(SignedAuthorization),
}

impl FromStr for CliAuthorizationList {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = Address::from_str(s) {
            Ok(Self::Address(addr))
        } else if let Ok(auth) = SignedAuthorization::decode(&mut hex::decode(s)?.as_ref()) {
            Ok(Self::Signed(auth))
        } else {
            eyre::bail!("Failed to decode authorization")
        }
    }
}

/// Transaction-related CLI options.
#[derive(Clone, Debug, Parser)]
#[command(next_help_heading = "Transaction options")]
pub struct TransactionOpts {
    /// Gas limit for the transaction.
    #[arg(long, env = "ETH_GAS_LIMIT")]
    pub gas_limit: Option<U256>,

    /// Gas price for legacy transactions, or max fee per gas for EIP-1559 transactions.
    #[arg(long, env = "ETH_GAS_PRICE", value_parser = parse_ether_value, value_name = "PRICE")]
    pub gas_price: Option<U256>,

    /// Max priority fee per gas for EIP-1559 transactions.
    #[arg(long, env = "ETH_PRIORITY_GAS_PRICE", value_parser = parse_ether_value, value_name = "PRICE")]
    pub priority_gas_price: Option<U256>,

    /// Ether to send in the transaction.
    #[arg(long, value_parser = parse_ether_value)]
    pub value: Option<U256>,

    /// Nonce for the transaction.
    #[arg(long)]
    pub nonce: Option<U64>,

    /// Send a legacy transaction instead of an EIP-1559 transaction.
    #[arg(long)]
    pub legacy: bool,

    /// Send a blob transaction using EIP-7594 format.
    #[arg(long, conflicts_with = "legacy")]
    pub blob: bool,

    /// Send a blob transaction using EIP-4844 format instead of EIP-7594.
    #[arg(long, conflicts_with = "legacy", requires = "blob")]
    pub eip4844: bool,

    /// Gas price for EIP-7594/EIP-4844 blob transaction.
    #[arg(long, conflicts_with = "legacy", value_parser = parse_ether_value, env = "ETH_BLOB_GAS_PRICE", value_name = "BLOB_PRICE")]
    pub blob_gas_price: Option<U256>,

    /// EIP-7702 authorization list.
    #[arg(long, conflicts_with_all = &["legacy", "blob"])]
    pub auth: Vec<CliAuthorizationList>,

    /// EIP-2930 access list as JSON.
    #[arg(long)]
    pub access_list: Option<Option<String>>,
}

impl TransactionOpts {
    /// Applies the configured transaction options to a transaction request.
    pub fn apply<N: Network>(&self, tx: &mut N::TransactionRequest, legacy: bool) {
        if let Some(gas_limit) = self.gas_limit {
            tx.set_gas_limit(gas_limit.to());
        }
        if let Some(value) = self.value {
            tx.set_value(value);
        }
        if let Some(gas_price) = self.gas_price {
            if legacy {
                tx.set_gas_price(gas_price.to());
            } else {
                tx.set_max_fee_per_gas(gas_price.to());
            }
        }
        if !legacy && let Some(priority_fee) = self.priority_gas_price {
            tx.set_max_priority_fee_per_gas(priority_fee.to());
        }
        if let Some(_max_blob_fee) = self.blob_gas_price {
            // Blob-gas configuration is currently parsed for CLI compatibility,
            // but not yet applied in the local replacement implementation.
        }
        if let Some(nonce) = self.nonce {
            tx.set_nonce(nonce.to());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_priority_gas_tx_opts() {
        let args: TransactionOpts =
            TransactionOpts::parse_from(["ethx", "--priority-gas-price", "100"]);
        assert!(args.priority_gas_price.is_some());
    }
}
