use crate::WalletOpts;
use alloy_chains::Chain;
use clap::Parser;

/// RPC transport and endpoint options.
#[derive(Clone, Debug, Default, Parser)]
#[command(next_help_heading = "Rpc options")]
pub struct RpcOpts {
    /// The RPC endpoint, defaulting to `http://localhost:8545` when omitted.
    #[arg(short = 'r', long = "rpc-url", env = "ETH_RPC_URL")]
    pub url: Option<String>,
}

/// Explorer and chain-selection options.
#[derive(Clone, Debug, Default, Parser)]
pub struct EtherscanOpts {
    /// The Etherscan-compatible API key.
    #[arg(
        short = 'e',
        long = "etherscan-api-key",
        alias = "api-key",
        env = "ETHERSCAN_API_KEY"
    )]
    pub key: Option<String>,

    /// The chain name or EIP-155 chain id.
    #[arg(short, long, alias = "chain-id", env = "CHAIN")]
    pub chain: Option<Chain>,
}

impl EtherscanOpts {
    /// Returns the configured API key when it is non-empty.
    pub fn key(&self) -> Option<String> {
        self.key
            .as_ref()
            .filter(|key| !key.trim().is_empty())
            .cloned()
    }
}

/// Combined Ethereum-related CLI options used by `ethx`.
#[derive(Clone, Debug, Default, Parser)]
#[command(next_help_heading = "Ethereum options")]
pub struct EthereumOpts {
    /// RPC transport and endpoint options.
    #[command(flatten)]
    pub rpc: RpcOpts,

    /// Explorer and chain-selection options.
    #[command(flatten)]
    pub etherscan: EtherscanOpts,

    /// Wallet and signer selection options.
    #[command(flatten)]
    pub wallet: WalletOpts,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_etherscan_opts() {
        let args: EtherscanOpts =
            EtherscanOpts::parse_from(["ethx", "--etherscan-api-key", "dummykey"]);
        assert_eq!(args.key(), Some("dummykey".to_string()));

        let args: EtherscanOpts = EtherscanOpts::parse_from(["ethx", "--etherscan-api-key", ""]);
        assert_eq!(args.key(), None);
    }

    #[test]
    fn parse_rpc_opts() {
        let args: RpcOpts = RpcOpts::parse_from(["ethx", "--rpc-url", "http://localhost:8545"]);
        assert_eq!(args.url.as_deref(), Some("http://localhost:8545"));
    }
}
