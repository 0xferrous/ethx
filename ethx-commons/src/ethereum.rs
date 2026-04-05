use crate::WalletOpts;
use clap::Parser;
use foundry_cli::opts::{EtherscanOpts, RpcOpts};

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
