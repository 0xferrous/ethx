pub mod call_encoder;
mod opts;
pub mod safe;

use crate::{
    call_encoder::{CallEncoder, RawCall},
    safe::{SafeCallContext, SafeCallEncoder, SafeOperation, SafeSignature},
};
use alloy_network::{AnyNetwork, EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, TxKind, U256, hex};
use alloy_provider::{
    PendingTransactionBuilder, Provider, ProviderBuilder as AlloyProviderBuilder,
};
use alloy_signer::Signer;
use clap::{Parser, Subcommand};
use eyre::{Result, eyre};
use foundry_cli::utils::parse_function_args;
use foundry_common::provider::ProviderBuilder;
use foundry_config::Chain;
use foundry_wallets::WalletSigner;
use opts::{EncoderKind, SafeOperationArg, SendTxArgs};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "ethx",
    about = "Ethereum CLI experiments built on Foundry",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Send a transaction with a cast-like interface.
    Send(SendTxArgs),
}

#[derive(Debug)]
enum PreparedCall {
    Call(RawCall),
    Create { code: Bytes },
}

impl SendTxArgs {
    async fn run(self) -> Result<()> {
        let rpc = self
            .send_tx
            .eth
            .rpc
            .url
            .as_deref()
            .unwrap_or("http://localhost:8545");
        let provider = ProviderBuilder::<AnyNetwork>::new(rpc).build()?;
        if let Some(interval) = self.send_tx.poll_interval {
            provider
                .client()
                .set_poll_interval(Duration::from_secs(interval));
        }

        let signer = self.send_tx.eth.wallet.maybe_signer().await?.0;
        let ens_chain = self
            .send_tx
            .eth
            .etherscan
            .chain
            .unwrap_or_else(Chain::mainnet);

        let prepared = self.prepare_call(&provider, ens_chain).await?;
        let executor = if self.unlocked {
            self.send_tx.eth.wallet.from
        } else {
            signer.as_ref().map(|signer| signer.address())
        };
        let encoded = self
            .apply_encoder(prepared, &provider, signer.as_ref(), executor)
            .await?;
        let mut tx = self
            .build_transaction(encoded, &provider, signer.as_ref())
            .await?;

        if self.unlocked {
            let from = self
                .send_tx
                .eth
                .wallet
                .from
                .ok_or_else(|| eyre!("--unlocked requires --from or ETH_FROM"))?;
            tx.set_from(from);

            let pending = provider.send_transaction(tx).await?;
            return self.handle_pending(pending).await;
        }

        let signer = signer.or_else(|| None).ok_or_else(|| {
            eyre!(
                "No signer available. Pass a Foundry wallet option or use --unlocked with --from."
            )
        })?;
        let from = signer.address();
        if let Some(specified_from) = self.send_tx.eth.wallet.from
            && specified_from != from
        {
            return Err(eyre!(
                "The specified sender via --from does not match the resolved signer address"
            ));
        }

        tx.set_from(from);

        let wallet = EthereumWallet::from(signer);
        let provider = AlloyProviderBuilder::<_, _, AnyNetwork>::default()
            .wallet(wallet)
            .connect_provider(&provider);

        let pending = provider.send_transaction(tx).await?;
        self.handle_pending(pending).await
    }

    async fn prepare_call<P: Provider<AnyNetwork>>(
        &self,
        provider: &P,
        ens_chain: Chain,
    ) -> Result<PreparedCall> {
        let value = self.tx.value.unwrap_or(U256::ZERO);

        if let Some(opts::SendTxSubcommands::Create { code, sig, args }) = &self.command {
            if self.send_tx.encoder.is_some() {
                return Err(eyre!("--encoder is not supported together with --create"));
            }

            let mut init_code = hex::decode(code.trim_start_matches("0x"))?;
            if let Some(sig) = sig {
                let constructor = parse_function_args(
                    sig,
                    args.clone(),
                    None,
                    ens_chain,
                    provider,
                    self.send_tx.eth.etherscan.key.as_deref(),
                )
                .await?
                .0;
                init_code.extend(constructor);
            }

            if !value.is_zero() {
                let _ = value;
            }

            return Ok(PreparedCall::Create {
                code: Bytes::from(init_code),
            });
        }

        let to = self
            .to
            .as_deref()
            .ok_or_else(|| eyre!("missing target address; pass TO or use --create"))?
            .parse::<Address>()?;

        let data = if let Some(sig) = &self.sig {
            Bytes::from(
                parse_function_args(
                    sig,
                    self.args.clone(),
                    Some(to),
                    ens_chain,
                    provider,
                    self.send_tx.eth.etherscan.key.as_deref(),
                )
                .await?
                .0,
            )
        } else {
            Bytes::new()
        };

        Ok(PreparedCall::Call(RawCall { to, value, data }))
    }

    async fn apply_encoder<P: Provider<AnyNetwork>>(
        &self,
        prepared: PreparedCall,
        provider: &P,
        safe_signer: Option<&WalletSigner>,
        safe_executor: Option<Address>,
    ) -> Result<PreparedCall> {
        let Some(kind) = self.send_tx.encoder else {
            return Ok(prepared);
        };

        let raw = match prepared {
            PreparedCall::Call(call) => call,
            PreparedCall::Create { .. } => {
                return Err(eyre!("encoders only support call transactions"));
            }
        };

        let target = self
            .send_tx
            .target
            .as_deref()
            .ok_or_else(|| eyre!("--encoder requires --target <ADDRESS>"))?
            .parse::<Address>()?;

        let encoded = match kind {
            EncoderKind::Safe => {
                let encoder = SafeCallEncoder::new(target);
                let ctx = encoder
                    .prepare_context(
                        &raw,
                        &self.safe_call_context()?,
                        safe_signer,
                        safe_executor,
                        provider,
                    )
                    .await?;
                encoder.encode_call(raw, &ctx)?
            }
        };

        Ok(PreparedCall::Call(encoded))
    }

    fn safe_call_context(&self) -> Result<SafeCallContext> {
        let opts = &self.send_tx.encoder_opts.safe;

        let mut signatures = Vec::new();
        for signature in &opts.eoa_signatures {
            signatures.push(SafeSignature::Eoa(Bytes::from(hex::decode(
                signature.trim_start_matches("0x"),
            )?)));
        }
        for signature in &opts.contract_signatures {
            let (owner, signature) = signature.split_once(':').ok_or_else(|| {
                eyre!("invalid --safe-contract-signature, expected <OWNER>:<SIG>")
            })?;
            signatures.push(SafeSignature::Contract {
                owner: owner.parse()?,
                signature: Bytes::from(hex::decode(signature.trim_start_matches("0x"))?),
            });
        }
        for owner in &opts.approved_hashes {
            signatures.push(SafeSignature::ApprovedHash {
                owner: owner.parse()?,
            });
        }

        let operation = match opts.operation.unwrap_or_default() {
            SafeOperationArg::Call => SafeOperation::Call,
            SafeOperationArg::DelegateCall => SafeOperation::DelegateCall,
        };

        let gas_token = opts
            .gas_token
            .as_deref()
            .map(str::parse)
            .transpose()?
            .unwrap_or(Address::ZERO);
        let refund_receiver = opts
            .refund_receiver
            .as_deref()
            .map(str::parse)
            .transpose()?
            .unwrap_or(Address::ZERO);

        Ok(SafeCallContext {
            operation,
            safe_tx_gas: opts.safe_tx_gas.map(U256::from).unwrap_or(U256::ZERO),
            base_gas: opts.base_gas.map(U256::from).unwrap_or(U256::ZERO),
            gas_price: opts.gas_price.unwrap_or(U256::ZERO),
            gas_token,
            refund_receiver,
            signatures,
            encoded_signatures: Bytes::new(),
        })
    }

    async fn build_transaction<P: Provider<AnyNetwork>>(
        &self,
        prepared: PreparedCall,
        provider: &P,
        signer: Option<&foundry_wallets::WalletSigner>,
    ) -> Result<<AnyNetwork as alloy_network::Network>::TransactionRequest> {
        let legacy = self.tx.legacy;
        let mut tx = <AnyNetwork as alloy_network::Network>::TransactionRequest::default();
        self.tx.apply::<AnyNetwork>(&mut tx, legacy);

        match prepared {
            PreparedCall::Call(call) => {
                tx.set_to(call.to);
                tx.set_input(call.data);
                tx.set_value(call.value);
            }
            PreparedCall::Create { code } => {
                tx.set_kind(TxKind::Create);
                tx.set_input(code);
                tx.set_value(self.tx.value.unwrap_or(U256::ZERO));
            }
        }

        let from = if let Some(from) = self.send_tx.eth.wallet.from {
            from
        } else if let Some(signer) = signer {
            signer.address()
        } else {
            return Err(eyre!(
                "could not determine sender address; pass --from or a signer"
            ));
        };
        tx.set_from(from);

        if tx.chain_id().is_none() {
            tx.set_chain_id(provider.get_chain_id().await?);
        }
        if tx.nonce().is_none() {
            tx.set_nonce(provider.get_transaction_count(from).await?);
        }
        if legacy {
            if tx.gas_price().is_none() {
                tx.set_gas_price(provider.get_gas_price().await?);
            }
        } else if tx.max_fee_per_gas().is_none() || tx.max_priority_fee_per_gas().is_none() {
            let fees = provider.estimate_eip1559_fees().await?;
            if tx.max_fee_per_gas().is_none() {
                tx.set_max_fee_per_gas(fees.max_fee_per_gas);
            }
            if tx.max_priority_fee_per_gas().is_none() {
                tx.set_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
            }
        }
        if tx.gas_limit().is_none() {
            let gas = provider.estimate_gas(tx.clone()).await?;
            tx.set_gas_limit(gas);
        }

        Ok(tx)
    }

    async fn handle_pending(&self, pending: PendingTransactionBuilder<AnyNetwork>) -> Result<()> {
        let tx_hash = *pending.inner().tx_hash();
        if self.send_tx.cast_async {
            println!("{tx_hash:#x}");
            return Ok(());
        }

        let receipt = pending
            .with_required_confirmations(self.send_tx.confirmations)
            .with_timeout(self.send_tx.timeout.map(Duration::from_secs))
            .get_receipt()
            .await?;
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Send(args) => args.run().await,
    }
}
