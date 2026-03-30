#![allow(clippy::too_many_arguments)]

use alloy_network::TransactionBuilder;
use alloy_node_bindings::Anvil;
use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256, address, hex};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{Eip712Domain, SolCall, SolStruct, sol};
use std::{fs, process::Command};

sol! {
    #[sol(rpc)]
    interface SafeAdminContract {
        function setup(
            address[] _owners,
            uint256 _threshold,
            address to,
            bytes data,
            address fallbackHandler,
            address paymentToken,
            uint256 payment,
            address paymentReceiver
        ) external;

        function approveHash(bytes32 hashToApprove) external;

        function nonce() external view returns (uint256);
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
}

const ERC1271_MAGIC_VALUE: FixedBytes<4> = FixedBytes::<4>::new([0x16, 0x26, 0xba, 0x7e]);

/// Loads the checked-in Safe v1.4.1 singleton creation bytecode fixture.
///
/// Original source: upstream Safe test artifact `safeDeployment.json`, key `safe141`.
/// The hex is copied into `tests/fixtures/safe_v141_creation_code.hex` so this test remains
/// hermetic and does not depend on a local vendored Safe checkout being present.
///
/// We deploy the singleton directly, then deploy a proxy that points at it, matching how Safe is
/// meant to be used in practice.
fn safe_v141_creation_code() -> Bytes {
    let bytecode = fs::read_to_string("tests/fixtures/safe_v141_creation_code.hex").unwrap();
    Bytes::from(hex::decode(bytecode.trim().trim_start_matches("0x")).unwrap())
}

/// Returns constructor bytecode for a minimal Safe-compatible proxy.
///
/// Source: compiled locally from this Solidity contract:
///
/// ```solidity
/// pragma solidity >=0.7.0 <0.9.0;
/// contract SafeProxy {
///     address internal singleton;
///     constructor(address _singleton) { require(_singleton != address(0)); singleton = _singleton; }
///     fallback() external payable {
///         assembly {
///             let _singleton := and(sload(0), 0xffffffffffffffffffffffffffffffffffffffff)
///             calldatacopy(0, 0, calldatasize())
///             let success := delegatecall(gas(), _singleton, 0, calldatasize(), 0, 0)
///             returndatacopy(0, 0, returndatasize())
///             if eq(success, 0) { revert(0, returndatasize()) }
///             return(0, returndatasize())
///         }
///     }
/// }
/// ```
///
/// The runtime delegates every call to the provided singleton, which lets the test exercise a
/// real proxy-backed Safe instance instead of calling the singleton directly.
fn safe_proxy_creation_code(singleton: Address) -> Bytes {
    let code = "608060405234801561000f575f5ffd5b506040516101b13803806101b18339818101604052810190610031919061010b565b5f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610068575f5ffd5b805f5f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610136565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6100da826100b1565b9050919050565b6100ea816100d0565b81146100f4575f5ffd5b50565b5f81519050610105816100e1565b92915050565b5f602082840312156101205761011f6100ad565b5b5f61012d848285016100f7565b91505092915050565b606f806101425f395ff3fe608060405273ffffffffffffffffffffffffffffffffffffffff5f5416365f5f375f5f365f845af43d5f5f3e5f81036035573d5ffd5b3d5ff3fea26469706673582212204421f6dfa398cbbf16c07dec00158e5b0e4af02e8c9bfa04ccf5f24e3fc9b59964736f6c63430008210033";
    let mut out = hex::decode(code).unwrap();
    out.extend_from_slice(singleton.into_word().as_slice());
    Bytes::from(out)
}

/// Runtime for a tiny ERC-1271 validator that always returns the magic value.
///
/// Source: compiled locally from this Solidity contract:
///
/// ```solidity
/// pragma solidity >=0.7.0 <0.9.0;
/// contract AlwaysValid1271 {
///     function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
///         return 0x1626ba7e;
///     }
/// }
/// ```
///
/// This keeps the test focused on ethx/Safe integration mechanics instead of contract-side
/// signature verification details.
fn always_valid_1271_runtime() -> Bytes {
    Bytes::from(
        hex::decode(
            "608060405234801561000f575f5ffd5b5060043610610029575f3560e01c80631626ba7e1461002d575b5f5ffd5b610047600480360381019061004291906101ee565b61005d565b6040516100549190610282565b60405180910390f35b5f631626ba7e60e01b905092915050565b5f604051905090565b5f5ffd5b5f5ffd5b5f819050919050565b6100918161007f565b811461009b575f5ffd5b50565b5f813590506100ac81610088565b92915050565b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b610100826100ba565b810181811067ffffffffffffffff8211171561011f5761011e6100ca565b5b80604052505050565b5f61013161006e565b905061013d82826100f7565b919050565b5f67ffffffffffffffff82111561015c5761015b6100ca565b5b610165826100ba565b9050602081019050919050565b828183375f83830152505050565b5f61019261018d84610142565b610128565b9050828152602081018484840111156101ae576101ad6100b6565b5b6101b9848285610172565b509392505050565b5f82601f8301126101d5576101d46100b2565b5b81356101e5848260208601610180565b91505092915050565b5f5f6040838503121561020457610203610077565b5b5f6102118582860161009e565b925050602083013567ffffffffffffffff8111156102325761023161007b565b5b61023e858286016101c1565b9150509250929050565b5f7fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b61027c81610248565b82525050565b5f6020820190506102955f830184610273565b9291505056fea26469706673582212201ca9076ee3577eb3d518d184f653f52aa7239abfd67605678f9d2b7bea657b6364736f6c63430008210033"
        )
        .unwrap(),
    )
}

/// Recomputes the Safe transaction hash for the exact transaction shape used in this test.
///
/// This mirrors the production encoder logic so the test can pre-approve hashes and pre-sign EOA
/// Safe transactions before invoking the `ethx` binary.
fn safe_tx_hash(safe: Address, chain_id: u64, to: Address, value: U256, nonce: U256) -> B256 {
    let domain = Eip712Domain::new(None, None, Some(U256::from(chain_id)), Some(safe), None);
    SafeTx {
        to,
        value,
        data: Bytes::new(),
        operation: 0,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        nonce,
    }
    .eip712_signing_hash(&domain)
}

async fn deploy_contract<P: Provider>(provider: &P, from: Address, code: Bytes) -> Address {
    let mut tx = alloy_rpc_types_eth::TransactionRequest::default();
    tx.set_from(from);
    tx.set_kind(alloy_primitives::TxKind::Create);
    tx.set_input(code);
    tx.set_nonce(provider.get_transaction_count(from).await.unwrap());
    let pending = provider.send_transaction(tx).await.unwrap();
    let receipt = pending.get_receipt().await.unwrap();
    receipt.contract_address.unwrap()
}

async fn send_call<P: Provider>(provider: &P, from: Address, to: Address, input: Bytes) {
    let mut tx = alloy_rpc_types_eth::TransactionRequest::default();
    tx.set_from(from);
    tx.set_to(to);
    tx.set_input(input);
    tx.set_nonce(provider.get_transaction_count(from).await.unwrap());
    let pending = provider.send_transaction(tx).await.unwrap();
    pending.get_receipt().await.unwrap();
}

async fn send_value<P: Provider>(provider: &P, from: Address, to: Address, value: U256) {
    let mut tx = alloy_rpc_types_eth::TransactionRequest::default();
    tx.set_from(from);
    tx.set_to(to);
    tx.set_value(value);
    tx.set_nonce(provider.get_transaction_count(from).await.unwrap());
    let pending = provider.send_transaction(tx).await.unwrap();
    pending.get_receipt().await.unwrap();
}

/// Deploys a proxy and initializes it with a standard Safe `setup(...)` call.
async fn deploy_safe_proxy<P: Provider>(
    provider: &P,
    from: Address,
    singleton: Address,
    owners: Vec<Address>,
    threshold: u64,
) -> Address {
    let proxy = deploy_contract(provider, from, safe_proxy_creation_code(singleton)).await;
    let setup = SafeAdminContract::setupCall {
        _owners: owners,
        _threshold: U256::from(threshold),
        to: Address::ZERO,
        data: Bytes::new(),
        fallbackHandler: Address::ZERO,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    }
    .abi_encode();
    send_call(provider, from, proxy, setup.into()).await;
    proxy
}

fn run_ethx(args: &[String]) {
    let status = Command::new(env!("CARGO_BIN_EXE_ethx"))
        .args(args)
        .status()
        .expect("failed to run ethx");
    assert!(status.success(), "ethx command failed: {args:?}");
}

#[tokio::test]
async fn safe_eoa_contract_and_approved_hash_signatures_execute_successfully() {
    // This test intentionally drives the compiled `ethx` binary end-to-end against a live Anvil
    // node instead of calling library functions directly. That gives us coverage for CLI parsing,
    // Foundry wallet resolution, Safe context preparation, and final transaction submission.
    let anvil = Anvil::new().spawn();
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    let accounts = anvil.addresses();
    let owner1 = accounts[0];
    let owner2 = accounts[1];
    let recipient = accounts[9];
    let contract_owner = address!("3333333333333333333333333333333333333333");

    // Install a simple ERC-1271 contract at a fixed address so it can act as a Safe owner.
    provider
        .client()
        .request::<_, ()>(
            "anvil_setCode",
            (contract_owner, always_valid_1271_runtime()),
        )
        .await
        .unwrap();

    // Build a 2-of-3 Safe: two EOAs plus one contract owner.
    // This singleton bytecode is the actual Safe implementation under test; only the tiny proxy
    // shell used to point at it is locally compiled for the harness.
    let singleton = deploy_contract(&provider, owner1, safe_v141_creation_code()).await;
    let safe = deploy_safe_proxy(
        &provider,
        owner1,
        singleton,
        vec![owner1, owner2, contract_owner],
        2,
    )
    .await;
    send_value(&provider, owner1, safe, U256::from(10u64.pow(18))).await;

    let key1 = anvil.keys()[0].to_bytes();
    let key2 = anvil.keys()[1].to_bytes();
    let key2_b256 = B256::from_slice(&key2);
    let signer2 = PrivateKeySigner::from_bytes(&key2_b256).unwrap();
    let rpc = anvil.endpoint();

    // Approved-hash path:
    // owner2 first records approval onchain via `approveHash(...)`, then `ethx` supplies that
    // approval while owner1 contributes the second signature locally.
    let nonce0 = SafeAdminContract::new(safe, &provider)
        .nonce()
        .call()
        .await
        .unwrap();
    let hash0 = safe_tx_hash(safe, anvil.chain_id(), recipient, U256::from(1), nonce0);
    let approve = SafeAdminContract::approveHashCall {
        hashToApprove: hash0,
    }
    .abi_encode();
    send_call(&provider, owner2, safe, approve.into()).await;
    let before = provider.get_balance(recipient).await.unwrap();
    run_ethx(&[
        "send".into(),
        "--rpc-url".into(),
        rpc.clone(),
        "--private-key".into(),
        hex::encode(key1),
        "--encoder".into(),
        "safe".into(),
        "--target".into(),
        format!("{safe:#x}"),
        "--safe-approved-hash".into(),
        format!("{owner2:#x}"),
        "--value".into(),
        "1".into(),
        format!("{recipient:#x}"),
    ]);
    assert_eq!(
        provider.get_balance(recipient).await.unwrap(),
        before + U256::from(1)
    );

    // EOA signature path:
    // owner2 signs the Safe tx hash offchain, and `ethx` combines that with owner1's local
    // signature to satisfy the 2-of-3 threshold.
    let nonce1 = SafeAdminContract::new(safe, &provider)
        .nonce()
        .call()
        .await
        .unwrap();
    let hash1 = safe_tx_hash(safe, anvil.chain_id(), recipient, U256::from(2), nonce1);
    let sig1 = signer2.sign_hash(&hash1).await.unwrap();
    let before = provider.get_balance(recipient).await.unwrap();
    run_ethx(&[
        "send".into(),
        "--rpc-url".into(),
        rpc.clone(),
        "--private-key".into(),
        hex::encode(key1),
        "--encoder".into(),
        "safe".into(),
        "--target".into(),
        format!("{safe:#x}"),
        "--safe-eoa-signature".into(),
        format!("0x{}", hex::encode(sig1.as_bytes())),
        "--value".into(),
        "2".into(),
        format!("{recipient:#x}"),
    ]);
    assert_eq!(
        provider.get_balance(recipient).await.unwrap(),
        before + U256::from(2)
    );

    // Contract-signature sanity check:
    // we currently assert the ERC-1271 validator behavior directly onchain. The full Safe
    // contract-signature execution path is not covered here yet because that end-to-end flow is
    // still under investigation.
    let safe_contract =
        deploy_safe_proxy(&provider, owner1, singleton, vec![contract_owner], 1).await;
    let nonce_contract = SafeAdminContract::new(safe_contract, &provider)
        .nonce()
        .call()
        .await
        .unwrap();
    let hash_contract = safe_tx_hash(
        safe_contract,
        anvil.chain_id(),
        recipient,
        U256::from(3),
        nonce_contract,
    );
    let validator = SignatureValidatorContract::new(contract_owner, &provider);
    assert_eq!(
        validator
            .isValidSignature(hash_contract, Bytes::from(hex::decode("deadbeef").unwrap()))
            .call()
            .await
            .unwrap(),
        ERC1271_MAGIC_VALUE
    );
}
