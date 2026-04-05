use alloy_chains::Chain;
use alloy_dyn_abi::{DynSolType, DynSolValue, JsonAbiExt};
use alloy_ens::ProviderEnsExt;
use alloy_json_abi::{Error, Event, Function, Param};
use alloy_primitives::{Address, LogData, hex};
use alloy_provider::{Network, Provider};
use eyre::{Context, ContextCompat, OptionExt, Result};
use foundry_block_explorers::{Client, contract::ContractMetadata, errors::EtherscanError};
use futures::future::join_all;
use std::pin::Pin;

async fn resolve_name_args<N: Network, P: Provider<N>>(
    args: &[String],
    provider: &P,
) -> Vec<String> {
    join_all(args.iter().map(|arg| async {
        if arg.contains('.') {
            match provider.resolve_name(arg).await {
                Ok(addr) => addr.to_string(),
                Err(_) => arg.clone(),
            }
        } else {
            arg.clone()
        }
    }))
    .await
}

/// Encodes a sequence of string arguments against ABI parameters.
pub fn encode_args<I, S>(inputs: &[Param], args: I) -> Result<Vec<DynSolValue>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<S> = args.into_iter().collect();

    if inputs.len() != args.len() {
        eyre::bail!(
            "encode length mismatch: expected {} types, got {}",
            inputs.len(),
            args.len()
        )
    }

    std::iter::zip(inputs, args)
        .map(|(input, arg)| coerce_value(&input.selector_type(), arg.as_ref()))
        .collect()
}

/// ABI-encodes function arguments and prefixes the 4-byte function selector.
pub fn encode_function_args<I, S>(func: &Function, args: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    Ok(func.abi_encode_input(&encode_args(&func.inputs, args)?)?)
}

/// ABI-encodes function arguments without prefixing the 4-byte function selector.
pub fn encode_function_args_raw<I, S>(func: &Function, args: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    Ok(func.abi_encode_input_raw(&encode_args(&func.inputs, args)?)?)
}

/// Parses a function signature string into a [`Function`].
pub fn get_func(sig: &str) -> Result<Function> {
    Function::parse(sig).wrap_err("could not parse function signature")
}

/// Parses an event signature string into an [`Event`].
pub fn get_event(sig: &str) -> Result<Event> {
    Event::parse(sig).wrap_err("could not parse event signature")
}

/// Parses an error signature string into an ABI [`Error`].
pub fn get_error(sig: &str) -> Result<Error> {
    Error::parse(sig).wrap_err("could not parse error signature")
}

/// Marks indexed event parameters heuristically based on the raw log layout.
pub fn get_indexed_event(mut event: Event, raw_log: &LogData) -> Event {
    if !event.anonymous && raw_log.topics().len() > 1 {
        let indexed_params = raw_log.topics().len() - 1;
        let num_inputs = event.inputs.len();
        let num_address_params = event.inputs.iter().filter(|p| p.ty == "address").count();

        event
            .inputs
            .iter_mut()
            .enumerate()
            .for_each(|(index, param)| {
                if param.name.is_empty() {
                    param.name = format!("param{index}");
                }
                if num_inputs == indexed_params
                    || (num_address_params == indexed_params && param.ty == "address")
                {
                    param.indexed = true;
                }
            })
    }
    event
}

/// Fetches ABI metadata from an Etherscan-compatible explorer and resolves a function by name.
pub async fn get_func_etherscan(
    function_name: &str,
    contract: Address,
    args: &[String],
    chain: Chain,
    etherscan_api_key: &str,
) -> Result<Function> {
    let client = Client::new(chain, etherscan_api_key)?;
    let source = find_source(client, contract).await?;
    let metadata = source
        .items
        .first()
        .wrap_err("etherscan returned empty metadata")?;

    let mut abi = metadata.abi()?;
    let funcs = abi.functions.remove(function_name).unwrap_or_default();

    for func in funcs {
        let res = encode_function_args(&func, args);
        if res.is_ok() {
            return Ok(func);
        }
    }

    Err(eyre::eyre!("Function not found in abi"))
}

/// If the code at `address` is a proxy, recurse until the implementation source is found.
pub fn find_source(
    client: Client,
    address: Address,
) -> Pin<Box<dyn Future<Output = Result<ContractMetadata>>>> {
    Box::pin(async move {
        tracing::trace!(%address, "find Etherscan source");
        let source = client.contract_source_code(address).await?;
        let metadata = source
            .items
            .first()
            .wrap_err("Etherscan returned no data")?;
        if metadata.proxy == 0 {
            Ok(source)
        } else {
            let implementation = metadata.implementation.unwrap();
            eprintln!(
                "Contract at {address} is a proxy, trying to fetch source at {implementation}..."
            );
            match find_source(client, implementation).await {
                impl_source @ Ok(_) => impl_source,
                Err(e) => {
                    let err = EtherscanError::ContractCodeNotVerified(address).to_string();
                    if e.to_string() == err {
                        tracing::error!(%err);
                        Ok(source)
                    } else {
                        Err(e)
                    }
                }
            }
        }
    })
}

/// Coerces a single string argument into a dynamic Solidity value of the requested type.
pub fn coerce_value(ty: &str, arg: &str) -> Result<DynSolValue> {
    let ty = DynSolType::parse(ty)?;
    Ok(DynSolType::coerce_str(&ty, arg)?)
}

/// Parses function input as either raw calldata or an ABI signature plus arguments.
///
/// If `to` is `None`, constructor arguments are encoded without a 4-byte selector.
pub async fn parse_function_args<N: Network, P: Provider<N>>(
    sig: &str,
    args: Vec<String>,
    to: Option<Address>,
    chain: Chain,
    provider: &P,
    etherscan_api_key: Option<&str>,
) -> Result<(Vec<u8>, Option<Function>)> {
    if sig.trim().is_empty() {
        eyre::bail!("Function signature or calldata must be provided.")
    }

    let args = resolve_name_args(&args, provider).await;

    if let Ok(data) = hex::decode(sig) {
        return Ok((data, None));
    } else if sig.starts_with("0x") || sig.starts_with("0X") {
        let e = hex::decode(sig).unwrap_err();
        eyre::bail!("Invalid hex calldata '{}': {e}", sig);
    }

    let func = if sig.contains('(') {
        get_func(sig)?
    } else {
        let etherscan_api_key = etherscan_api_key.ok_or_eyre(
            "Function signature does not contain parentheses. If you wish to fetch function data from Etherscan, please provide an API key.",
        )?;
        let to = to.ok_or_eyre("A 'to' address must be provided to fetch function data.")?;
        get_func_etherscan(sig, to, &args, chain, etherscan_api_key).await?
    };

    if to.is_none() {
        Ok((encode_function_args_raw(&func, &args)?, Some(func)))
    } else {
        Ok((encode_function_args(&func, &args)?, Some(func)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_dyn_abi::{DynSolValue, EventExt};
    use alloy_ens::ENS_ADDRESS;
    use alloy_network::AnyNetwork;
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{Address, B256, Bytes, LogData, U256, address, hex};
    use alloy_provider::{Provider, ProviderBuilder};

    fn mock_ens_registry_runtime() -> Bytes {
        Bytes::from(
            hex::decode("608060405234801561000f575f5ffd5b506004361061003f575f3560e01c80630178b8bf1461004357806302571be31461007357806352daf712146100a3575b5f5ffd5b61005d6004803603810190610058919061014e565b6100c1565b60405161006a91906101b8565b60405180910390f35b61008d6004803603810190610088919061014e565b6100ea565b60405161009a91906101b8565b60405180910390f35b6100ab6100f3565b6040516100b891906101b8565b60405180910390f35b5f5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b5f5f9050919050565b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b5f5ffd5b5f819050919050565b61012d8161011b565b8114610137575f5ffd5b50565b5f8135905061014881610124565b92915050565b5f6020828403121561016357610162610117565b5b5f6101708482850161013a565b91505092915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6101a282610179565b9050919050565b6101b281610198565b82525050565b5f6020820190506101cb5f8301846101a9565b9291505056fea264697066735822122087859a4cf15c75ac4d2ed6bb528cd9fcc27cf863463800fceb926e136a1a019c64736f6c63430008210033").unwrap(),
        )
    }

    fn mock_ens_resolver_runtime() -> Bytes {
        Bytes::from(
            hex::decode("608060405234801561000f575f5ffd5b5060043610610034575f3560e01c80633b3b57de146100385780633f6fa65514610068575b5f5ffd5b610052600480360381019061004d919061010a565b610086565b60405161005f9190610174565b60405180910390f35b6100706100af565b60405161007d9190610174565b60405180910390f35b5f5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b5f5ffd5b5f819050919050565b6100e9816100d7565b81146100f3575f5ffd5b50565b5f81359050610104816100e0565b92915050565b5f6020828403121561011f5761011e6100d3565b5b5f61012c848285016100f6565b91505092915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61015e82610135565b9050919050565b61016e81610154565b82525050565b5f6020820190506101875f830184610165565b9291505056fea2646970667358221220bf303891e0d2d989bcc31dba837628069801f585346694dcc131c46fab87b31e64736f6c63430008210033").unwrap(),
        )
    }

    async fn set_code_and_slot<N: Network, P: Provider<N>>(
        provider: &P,
        addr: Address,
        code: Bytes,
        slot0_addr: Address,
    ) {
        let _: serde_json::Value = provider
            .client()
            .request("anvil_setCode", (addr, code))
            .await
            .unwrap();
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(slot0_addr.as_slice());
        let _: serde_json::Value = provider
            .client()
            .request("anvil_setStorageAt", (addr, B256::ZERO, B256::from(word)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn parse_function_args_accepts_raw_hex_calldata() {
        let anvil = Anvil::new().spawn();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        let (data, func) = parse_function_args(
            "0xdeadbeef",
            vec![],
            Some(address!("1111111111111111111111111111111111111111")),
            Chain::mainnet(),
            &provider,
            None,
        )
        .await
        .unwrap();

        assert_eq!(data, hex::decode("deadbeef").unwrap());
        assert!(func.is_none());
    }

    #[tokio::test]
    async fn parse_function_args_encodes_function_inputs() {
        let anvil = Anvil::new().spawn();
        let provider =
            ProviderBuilder::<_, _, AnyNetwork>::default().connect_http(anvil.endpoint_url());
        let to = address!("1111111111111111111111111111111111111111");

        let (data, func) = parse_function_args(
            "transfer(address,uint256)",
            vec![
                "0x2222222222222222222222222222222222222222".into(),
                "7".into(),
            ],
            Some(to),
            Chain::mainnet(),
            &provider,
            None,
        )
        .await
        .unwrap();

        assert!(func.is_some());
        assert_eq!(&data[..4], &hex::decode("a9059cbb").unwrap());
        assert_eq!(data.len(), 4 + 32 + 32);
    }

    #[tokio::test]
    async fn parse_function_args_omits_selector_for_constructor_mode() {
        let anvil = Anvil::new().spawn();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        let (data, func) = parse_function_args(
            "constructor(address,uint256)",
            vec![
                "0x2222222222222222222222222222222222222222".into(),
                "7".into(),
            ],
            None,
            Chain::mainnet(),
            &provider,
            None,
        )
        .await
        .unwrap();

        assert!(func.is_some());
        assert_eq!(data.len(), 32 + 32);
    }

    #[tokio::test]
    async fn parse_function_args_rejects_invalid_hex_calldata() {
        let anvil = Anvil::new().spawn();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        let err = parse_function_args(
            "0xzz",
            vec![],
            Some(address!("1111111111111111111111111111111111111111")),
            Chain::mainnet(),
            &provider,
            None,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("Invalid hex calldata"));
    }

    #[tokio::test]
    async fn parse_function_args_requires_etherscan_key_for_name_only_signatures() {
        let anvil = Anvil::new().spawn();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        let err = parse_function_args(
            "transfer",
            vec![
                "0x2222222222222222222222222222222222222222".into(),
                "7".into(),
            ],
            Some(address!("1111111111111111111111111111111111111111")),
            Chain::mainnet(),
            &provider,
            None,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("please provide an API key"));
    }

    #[tokio::test]
    async fn parse_function_args_requires_to_for_name_only_signatures() {
        let anvil = Anvil::new().spawn();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        let err = parse_function_args(
            "transfer",
            vec![
                "0x2222222222222222222222222222222222222222".into(),
                "7".into(),
            ],
            None,
            Chain::mainnet(),
            &provider,
            Some("dummy"),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("A 'to' address must be provided"));
    }

    #[tokio::test]
    async fn parse_function_args_resolves_ens_names_with_anvil() {
        let anvil = Anvil::new().spawn();
        let provider =
            ProviderBuilder::<_, _, AnyNetwork>::default().connect_http(anvil.endpoint_url());
        let resolved = address!("2222222222222222222222222222222222222222");
        let resolver = address!("1234567890123456789012345678901234567890");
        let to = address!("1111111111111111111111111111111111111111");

        set_code_and_slot(
            &provider,
            ENS_ADDRESS,
            mock_ens_registry_runtime(),
            resolver,
        )
        .await;
        set_code_and_slot(&provider, resolver, mock_ens_resolver_runtime(), resolved).await;

        let (data, func) = parse_function_args(
            "transfer(address,uint256)",
            vec!["vitalik.eth".into(), "7".into()],
            Some(to),
            Chain::mainnet(),
            &provider,
            None,
        )
        .await
        .unwrap();

        assert!(func.is_some());
        assert_eq!(&data[..4], &hex::decode("a9059cbb").unwrap());
        let encoded_addr = &data[4 + 12..4 + 32];
        assert_eq!(encoded_addr, resolved.as_slice());
    }

    #[test]
    fn upstream_common_get_func_behavior_is_covered() {
        let func = get_func("function foo(uint256 a, uint256 b) returns (uint256)").unwrap();
        assert_eq!(func.name, "foo");
        assert_eq!(func.inputs.len(), 2);
        assert_eq!(func.inputs[0].ty, "uint256");
        assert_eq!(func.inputs[1].ty, "uint256");

        let func = get_func("foo(bytes4 a, uint8 b)(bytes4)").unwrap();
        assert_eq!(func.name, "foo");
        assert_eq!(func.inputs.len(), 2);
        assert_eq!(func.inputs[0].ty, "bytes4");
        assert_eq!(func.inputs[1].ty, "uint8");
        assert_eq!(func.outputs[0].ty, "bytes4");
    }

    #[test]
    fn upstream_common_indexed_only_address_behavior_is_covered() {
        let event = get_event("event Ev(address,uint256,address)").unwrap();

        let param0 = B256::repeat_byte(0x11);
        let param1 = vec![3; 32];
        let param2 = B256::repeat_byte(0x22);
        let log = LogData::new_unchecked(vec![event.selector(), param0, param2], param1.into());
        let event = get_indexed_event(event, &log);

        let parsed = event.decode_log(&log).unwrap();
        assert_eq!(event.inputs.iter().filter(|param| param.indexed).count(), 2);
        assert_eq!(
            parsed.indexed[0],
            DynSolValue::Address(Address::from_word(param0))
        );
        assert_eq!(
            parsed.body[0],
            DynSolValue::Uint(U256::from_be_bytes([3; 32]), 256)
        );
        assert_eq!(
            parsed.indexed[1],
            DynSolValue::Address(Address::from_word(param2))
        );
    }

    #[test]
    fn upstream_common_indexed_all_behavior_is_covered() {
        let event = get_event("event Ev(address,uint256,address)").unwrap();

        let param0 = B256::repeat_byte(0x11);
        let param1 = vec![3; 32];
        let param2 = B256::repeat_byte(0x22);
        let log = LogData::new_unchecked(
            vec![event.selector(), param0, B256::from_slice(&param1), param2],
            vec![].into(),
        );
        let event = get_indexed_event(event, &log);

        assert_eq!(event.inputs.iter().filter(|param| param.indexed).count(), 3);
        let parsed = event.decode_log(&log).unwrap();
        assert_eq!(
            parsed.indexed[0],
            DynSolValue::Address(Address::from_word(param0))
        );
        assert_eq!(
            parsed.indexed[1],
            DynSolValue::Uint(U256::from_be_bytes([3; 32]), 256)
        );
        assert_eq!(
            parsed.indexed[2],
            DynSolValue::Address(Address::from_word(param2))
        );
    }

    #[ignore = "TODO: add mocked Etherscan-compatible HTTP test for successful ABI fetch"]
    #[tokio::test]
    async fn parse_function_args_fetches_signature_from_etherscan_todo() {
        // TODO:
        // - start a local mock HTTP server that emulates the Etherscan contract ABI endpoint
        // - return an ABI containing the requested function name with matching overloads
        // - wire `get_func_etherscan` / `parse_function_args` to that mock endpoint
        // - assert the correct overload is selected based on the provided args
        // - assert proxy-resolution behavior if we decide to support testing that path here
        //
        // This test is intentionally left as a skeleton so we preserve the remaining
        // coverage gap explicitly without pretending it is already covered.
        unimplemented!("TODO: mocked Etherscan fetch test");
    }

    #[test]
    fn upstream_common_encode_args_length_validation_is_covered() {
        use alloy_json_abi::Param;

        let params = vec![
            Param {
                name: "a".to_string(),
                ty: "uint256".to_string(),
                internal_type: None,
                components: vec![],
            },
            Param {
                name: "b".to_string(),
                ty: "address".to_string(),
                internal_type: None,
                components: vec![],
            },
        ];

        let args = vec!["1"];
        let res = encode_args(&params, &args);
        assert!(res.is_err());
        assert!(format!("{}", res.unwrap_err()).contains("encode length mismatch"));

        let args = vec!["1", "0x0000000000000000000000000000000000000001"];
        let res = encode_args(&params, &args).unwrap();
        assert_eq!(res.len(), 2);

        let args = vec!["1", "0x0000000000000000000000000000000000000001", "extra"];
        let res = encode_args(&params, &args);
        assert!(res.is_err());
        assert!(format!("{}", res.unwrap_err()).contains("encode length mismatch"));
    }
}
