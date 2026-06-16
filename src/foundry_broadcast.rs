use crate::call_encoder::RawCall;
use alloy_primitives::{Address, Bytes, U256, hex};
use eyre::{Context, Result, bail, eyre};
use serde_json::Value;
use std::{fs, path::Path};

/// Loads executable call transactions from a Foundry broadcast/deployment JSON file.
///
/// The parser intentionally accepts the common Foundry shapes where transaction details live under
/// a nested `transaction` object, while also allowing top-level `to`, `value`, `input`, or `data`
/// fields. Contract creation transactions are rejected because Safe deployment support is outside
/// the scope of this command.
pub fn load_calls(path: impl AsRef<Path>) -> Result<Vec<RawCall>> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read Foundry broadcast JSON `{}`", path.display()))?;
    let json: Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "failed to parse Foundry broadcast JSON `{}`",
            path.display()
        )
    })?;
    parse_calls(&json)
}

/// Parses executable call transactions from a Foundry broadcast/deployment JSON value.
pub fn parse_calls(json: &Value) -> Result<Vec<RawCall>> {
    let transactions = json
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("Foundry JSON does not contain a `transactions` array"))?;

    let mut calls = Vec::with_capacity(transactions.len());
    for (index, entry) in transactions.iter().enumerate() {
        if is_create_transaction(entry) {
            bail!(
                "deployment transactions are not supported yet: found CREATE transaction at index {index}"
            );
        }
        calls.push(parse_call(index, entry)?);
    }

    if calls.is_empty() {
        bail!("Foundry JSON does not contain any transactions to execute");
    }

    Ok(calls)
}

fn parse_call(index: usize, entry: &Value) -> Result<RawCall> {
    let tx = entry.get("transaction").unwrap_or(entry);
    let to = field(tx, entry, &["to"])
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("transaction at index {index} is missing `to`"))?
        .parse::<Address>()
        .with_context(|| format!("transaction at index {index} has invalid `to` address"))?;
    let value = match field(tx, entry, &["value"]) {
        Some(value) => parse_u256(value)
            .with_context(|| format!("transaction at index {index} has invalid `value`"))?,
        None => U256::ZERO,
    };
    let input = field(tx, entry, &["input", "data"])
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("transaction at index {index} is missing calldata `input`/`data`"))?;
    let data = Bytes::from(
        hex::decode(input.trim_start_matches("0x"))
            .with_context(|| format!("transaction at index {index} has invalid calldata hex"))?,
    );

    Ok(RawCall { to, value, data })
}

fn field<'a>(primary: &'a Value, fallback: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names
        .iter()
        .find_map(|name| primary.get(*name).or_else(|| fallback.get(*name)))
}

fn is_create_transaction(entry: &Value) -> bool {
    let ty = entry
        .get("transactionType")
        .or_else(|| entry.get("type"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    ty.eq_ignore_ascii_case("CREATE") || ty.eq_ignore_ascii_case("CREATE2")
}

fn parse_u256(value: &Value) -> Result<U256> {
    match value {
        Value::String(s) => parse_u256_str(s),
        Value::Number(n) => U256::from_str_radix(&n.to_string(), 10).map_err(Into::into),
        other => bail!("expected string or number, got {other}"),
    }
}

fn parse_u256_str(s: &str) -> Result<U256> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        U256::from_str_radix(hex, 16).map_err(Into::into)
    } else {
        U256::from_str_radix(s, 10).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use serde_json::json;

    #[test]
    fn parses_nested_foundry_transactions() {
        let json = json!({
            "transactions": [{
                "transactionType": "CALL",
                "transaction": {
                    "to": "0x0000000000000000000000000000000000000001",
                    "value": "0x2a",
                    "input": "0x1234"
                }
            }]
        });

        let calls = parse_calls(&json).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].to,
            address!("0000000000000000000000000000000000000001")
        );
        assert_eq!(calls[0].value, U256::from(42));
        assert_eq!(calls[0].data, Bytes::from_static(&[0x12, 0x34]));
    }

    #[test]
    fn rejects_create_transactions() {
        let json = json!({ "transactions": [{ "transactionType": "CREATE" }] });
        let err = parse_calls(&json).unwrap_err().to_string();
        assert!(err.contains("deployment transactions are not supported"));
    }
}
