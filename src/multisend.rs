use crate::call_encoder::RawCall;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, sol};

sol! {
    function multiSend(bytes transactions) external payable;
}

/// Encodes calls using Safe MultiSend's packed transaction format.
///
/// Each entry is encoded as `operation || to || value || dataLength || data`, where operation is
/// always `0` (`CALL`) because this helper batches normal calls recorded by Foundry.
pub fn encode_multisend_transactions(calls: &[RawCall]) -> Bytes {
    let total_len = calls
        .iter()
        .map(|call| 1 + 20 + 32 + 32 + call.data.len())
        .sum();
    let mut out = Vec::with_capacity(total_len);

    for call in calls {
        out.push(0u8);
        out.extend_from_slice(call.to.as_slice());
        push_u256(&mut out, call.value);
        push_u256(&mut out, U256::from(call.data.len()));
        out.extend_from_slice(&call.data);
    }

    Bytes::from(out)
}

/// Builds the inner Safe call that delegatecalls into MultiSend for a batch of calls.
pub fn multisend_call(calls: &[RawCall], multi_send: Address) -> RawCall {
    let transactions = encode_multisend_transactions(calls);
    let data = multiSendCall { transactions }.abi_encode();
    RawCall {
        to: multi_send,
        value: U256::ZERO,
        data: data.into(),
    }
}

fn push_u256(out: &mut Vec<u8>, value: U256) {
    let word: B256 = value.into();
    out.extend_from_slice(word.as_slice());
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes};

    #[test]
    fn encodes_multisend_packed_transactions() {
        let calls = vec![RawCall {
            to: address!("0000000000000000000000000000000000000001"),
            value: U256::from(2),
            data: bytes!("1234"),
        }];

        let encoded = encode_multisend_transactions(&calls);
        let expected = bytes!(
            "00"
            "0000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "1234"
        );
        assert_eq!(encoded, expected);
    }
}
