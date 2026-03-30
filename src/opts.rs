use clap::{Args, Parser, ValueEnum, ValueHint};
use foundry_cli::{
    opts::{EthereumOpts, TransactionOpts},
    utils::parse_ether_value,
};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum EncoderKind {
    #[default]
    Safe,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum SafeOperationArg {
    #[default]
    Call,
    DelegateCall,
}

#[derive(Debug, Clone, Default, Args)]
#[group(id = "safe-encoder-opts", requires = "encoder", multiple = true)]
#[command(next_help_heading = "Encoding options - safe")]
pub struct SafeEncoderOpts {
    /// Repeatable EOA Safe signatures. Owners are recovered from the Safe tx hash.
    #[arg(
        id = "safe-eoa-signature",
        long = "safe-eoa-signature",
        value_name = "SIG"
    )]
    pub eoa_signatures: Vec<String>,

    /// Repeatable EIP-1271 Safe signatures as `<OWNER>:<SIG>`.
    #[arg(
        id = "safe-contract-signature",
        long = "safe-contract-signature",
        value_name = "OWNER:SIG"
    )]
    pub contract_signatures: Vec<String>,

    /// Repeatable Safe approved-hash signers as `<OWNER>`.
    #[arg(
        id = "safe-approved-hash",
        long = "safe-approved-hash",
        value_name = "OWNER"
    )]
    pub approved_hashes: Vec<String>,

    /// Safe operation for the inner call.
    #[arg(id = "safe-operation", long = "safe-operation", value_enum)]
    pub operation: Option<SafeOperationArg>,

    /// Safe `safeTxGas` value.
    #[arg(id = "safe-tx-gas", long = "safe-tx-gas")]
    pub safe_tx_gas: Option<u128>,

    /// Safe `baseGas` value.
    #[arg(id = "safe-base-gas", long = "safe-base-gas")]
    pub base_gas: Option<u128>,

    /// Safe `gasPrice` value, either in wei or with a unit like `1gwei`.
    #[arg(id = "safe-gas-price", long = "safe-gas-price", value_parser = parse_ether_value, value_name = "PRICE")]
    pub gas_price: Option<alloy_primitives::U256>,

    /// Safe refund token address.
    #[arg(id = "safe-gas-token", long = "safe-gas-token", value_name = "ADDRESS")]
    pub gas_token: Option<String>,

    /// Safe refund receiver address.
    #[arg(
        id = "safe-refund-receiver",
        long = "safe-refund-receiver",
        value_name = "ADDRESS"
    )]
    pub refund_receiver: Option<String>,
}

#[derive(Debug, Clone, Default, Args)]
pub struct EncoderContextOpts {
    #[command(flatten)]
    pub safe: SafeEncoderOpts,
}

#[derive(Debug, Clone, Parser)]
pub struct SendTxOpts {
    /// Only print the transaction hash and exit immediately.
    #[arg(id = "async", long = "async", alias = "cast-async", env = "CAST_ASYNC")]
    pub cast_async: bool,

    /// Wait for transaction receipt synchronously instead of polling.
    #[arg(long, conflicts_with = "async")]
    pub sync: bool,

    /// The number of confirmations until the receipt is fetched.
    #[arg(long, default_value = "1")]
    pub confirmations: u64,

    /// Timeout for sending the transaction.
    #[arg(long, env = "ETH_TIMEOUT")]
    pub timeout: Option<u64>,

    /// Polling interval for transaction receipts (in seconds).
    #[arg(long, alias = "poll-interval", env = "ETH_POLL_INTERVAL")]
    pub poll_interval: Option<u64>,

    /// Wrap the call using a supported encoder.
    #[arg(long, value_enum, help_heading = "Encoding options")]
    pub encoder: Option<EncoderKind>,

    /// The smart-account or wrapper contract address that should receive the wrapped call.
    #[arg(long, value_name = "ADDRESS", help_heading = "Encoding options")]
    pub target: Option<String>,

    #[command(flatten)]
    pub encoder_opts: EncoderContextOpts,

    #[command(flatten)]
    pub eth: EthereumOpts,
}

#[derive(Debug, Parser)]
pub enum SendTxSubcommands {
    /// Use to deploy raw contract bytecode.
    #[command(name = "--create")]
    Create {
        /// The bytecode of the contract to deploy.
        code: String,

        /// The signature of the function to call.
        sig: Option<String>,

        /// The arguments of the function to call.
        #[arg(allow_negative_numbers = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Parser)]
pub struct SendTxArgs {
    /// The destination of the transaction.
    ///
    /// If not provided, you must use cast send --create.
    pub to: Option<String>,

    /// The signature of the function to call.
    pub sig: Option<String>,

    /// The arguments of the function to call.
    #[arg(allow_negative_numbers = true)]
    pub args: Vec<String>,

    #[command(flatten)]
    pub send_tx: SendTxOpts,

    #[command(subcommand)]
    pub command: Option<SendTxSubcommands>,

    /// Send via `eth_sendTransaction` using the `--from` argument or $ETH_FROM as sender.
    #[arg(long, requires = "from")]
    pub unlocked: bool,

    #[command(flatten)]
    pub tx: TransactionOpts,

    /// The path of blob data to be sent.
    #[arg(
        long,
        value_name = "BLOB_DATA_PATH",
        conflicts_with = "legacy",
        requires = "blob",
        help_heading = "Transaction options",
        value_hint = ValueHint::FilePath,
    )]
    pub path: Option<PathBuf>,
}
