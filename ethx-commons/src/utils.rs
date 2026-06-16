use alloy_dyn_abi::DynSolType;
use alloy_primitives::U256;
use eyre::{ContextCompat, Result};

/// Parses an ether-denominated value from a CLI string.
///
/// Untagged values are interpreted as wei. Hex values with a `0x` prefix are interpreted as raw
/// integers. Unit-suffixed values such as `1gwei` use Alloy's Solidity string coercion.
pub fn parse_ether_value(value: &str) -> Result<U256> {
    Ok(if value.starts_with("0x") {
        U256::from_str_radix(value.trim_start_matches("0x"), 16)?
    } else {
        DynSolType::coerce_str(&DynSolType::Uint(256), value)?
            .as_uint()
            .wrap_err("Could not parse ether value from string")?
            .0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ether_value_works() {
        assert_eq!(parse_ether_value("0x10").unwrap(), U256::from(16));
        assert_eq!(parse_ether_value("100").unwrap(), U256::from(100));
        assert_eq!(
            parse_ether_value("1gwei").unwrap(),
            U256::from(1_000_000_000u64)
        );
    }
}
