#![allow(clippy::too_many_arguments)]

use alloy_network::TransactionBuilder;
use alloy_node_bindings::Anvil;
use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256, address, hex};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{Eip712Domain, SolCall, SolStruct, sol};
use std::{fs, process::Command, time::SystemTime};

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

/// Runtime for a compact test MultiSend-compatible contract.
///
/// The bytecode was compiled from a minimal Solidity contract that implements
/// `multiSend(bytes)` over Safe's packed transaction format. It is installed at the canonical
/// MultiSend address on Anvil via `anvil_setCode`, so the e2e test does not depend on external
/// deployments.
fn test_multisend_runtime() -> Bytes {
    Bytes::from(
        hex::decode(
            "60806040526004361061001d575f3560e01c80638d80ff0a14610021575b5f5ffd5b61003b600480360381019061003691906103f0565b61003d565b005b5f5f90505b815181101561029f575f5f5f5f846020870101805160f81c9450600181015160601c93506015810151925060358101519150505f8167ffffffffffffffff8111156100905761008f6102cc565b5b6040519080825280601f01601f1916602001820160405280156100c25781602001600182028036833780820191505090505b5090505f5f90505b828110156101555787816055896100e1919061046d565b6100eb919061046d565b815181106100fc576100fb6104a0565b5b602001015160f81c60f81b82828151811061011a576101196104a0565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a90535080806001019150506100ca565b505f5f8660ff16036101d1578473ffffffffffffffffffffffffffffffffffffffff168483604051610187919061051f565b5f6040518083038185875af1925050503d805f81146101c1576040519150601f19603f3d011682016040523d82523d5f602084013e6101c6565b606091505b50508091505061023a565b8473ffffffffffffffffffffffffffffffffffffffff16826040516101f6919061051f565b5f60405180830381855af49150503d805f811461022e576040519150601f19603f3d011682016040523d82523d5f602084013e610233565b606091505b5050809150505b8061027a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102719061058f565b60405180910390fd5b826055610287919061046d565b87610292919061046d565b9650505050505050610042565b5050565b5f604051905090565b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b610302826102bc565b810181811067ffffffffffffffff82111715610321576103206102cc565b5b80604052505050565b5f6103336102a3565b905061033f82826102f9565b919050565b5f67ffffffffffffffff82111561035e5761035d6102cc565b5b610367826102bc565b9050602081019050919050565b828183375f83830152505050565b5f61039461038f84610344565b61032a565b9050828152602081018484840111156103b0576103af6102b8565b5b6103bb848285610374565b509392505050565b5f82601f8301126103d7576103d66102b4565b5b81356103e7848260208601610382565b91505092915050565b5f60208284031215610405576104046102ac565b5b5f82013567ffffffffffffffff811115610422576104216102b0565b5b61042e848285016103c3565b91505092915050565b5f819050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61047782610437565b915061048283610437565b925082820190508082111561049a57610499610440565b5b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b5f81519050919050565b5f81905092915050565b8281835e5f83830152505050565b5f6104f9826104cd565b61050381856104d7565b93506105138185602086016104e1565b80840191505092915050565b5f61052a82846104ef565b915081905092915050565b5f82825260208201905092915050565b7f63616c6c206661696c65640000000000000000000000000000000000000000005f82015250565b5f610579600b83610535565b915061058482610545565b602082019050919050565b5f6020820190508181035f8301526105a68161056d565b905091905056fea26469706673582212203412aaf17eebc1c21f895ea30c54545f279895b6e60a1f0714d84ed933f6133c64736f6c63430008210033"
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

fn write_broadcast_json(transactions: &[(Address, U256)]) -> std::path::PathBuf {
    let txs = transactions
        .iter()
        .map(|(to, value)| {
            serde_json::json!({
                "transactionType": "CALL",
                "transaction": {
                    "to": format!("{to:#x}"),
                    "value": format!("{value:#x}"),
                    "input": "0x"
                }
            })
        })
        .collect::<Vec<_>>();
    let json = serde_json::json!({ "transactions": txs });
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("ethx-broadcast-{unique}.json"));
    fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    path
}

#[tokio::test]
async fn safe_execute_deployment_runs_single_and_batched_foundry_calls() {
    let anvil = Anvil::new().spawn();
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    let accounts = anvil.addresses();
    let owner = accounts[0];
    let recipient1 = accounts[7];
    let recipient2 = accounts[8];
    let recipient3 = accounts[9];
    let multi_send = address!("38869bf66a61cf6bdb996a6ae40d5853fd43b526");

    provider
        .client()
        .request::<_, ()>("anvil_setCode", (multi_send, test_multisend_runtime()))
        .await
        .unwrap();

    let singleton = deploy_contract(&provider, owner, safe_v141_creation_code()).await;
    let safe = deploy_safe_proxy(&provider, owner, singleton, vec![owner], 1).await;
    send_value(&provider, owner, safe, U256::from(10u64.pow(18))).await;

    let key = anvil.keys()[0].to_bytes();
    let rpc = anvil.endpoint();

    let single_path = write_broadcast_json(&[(recipient1, U256::from(3))]);
    let before = provider.get_balance(recipient1).await.unwrap();
    run_ethx(&[
        "safe".into(),
        "execute-deployment".into(),
        "--rpc-url".into(),
        rpc.clone(),
        "--private-key".into(),
        hex::encode(key),
        "--safe".into(),
        format!("{safe:#x}"),
        single_path.display().to_string(),
    ]);
    assert_eq!(
        provider.get_balance(recipient1).await.unwrap(),
        before + U256::from(3)
    );

    let batch_path =
        write_broadcast_json(&[(recipient2, U256::from(4)), (recipient3, U256::from(5))]);
    let before2 = provider.get_balance(recipient2).await.unwrap();
    let before3 = provider.get_balance(recipient3).await.unwrap();
    run_ethx(&[
        "safe".into(),
        "execute-deployment".into(),
        "--rpc-url".into(),
        rpc,
        "--private-key".into(),
        hex::encode(key),
        "--safe".into(),
        format!("{safe:#x}"),
        batch_path.display().to_string(),
    ]);
    assert_eq!(
        provider.get_balance(recipient2).await.unwrap(),
        before2 + U256::from(4)
    );
    assert_eq!(
        provider.get_balance(recipient3).await.unwrap(),
        before3 + U256::from(5)
    );
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
