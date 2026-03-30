use alloy_primitives::{Address, Bytes, U256};

/// A raw Ethereum call described by its target address, ETH value, and calldata.
///
/// This is the minimal call shape used as both the input and output of [`CallEncoder`].
/// For example, a direct call to a target contract can be transformed into the outer call that
/// must be sent to a smart account contract like a Safe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawCall {
    /// The contract or account the call should be sent to.
    pub to: Address,
    /// The amount of ETH to send alongside the call.
    pub value: U256,
    /// The ABI-encoded calldata for the call.
    pub data: Bytes,
}

/// Transforms a plain call into the actual call that should be submitted on-chain.
///
/// This is intended for wrappers such as smart accounts. For example, an implementation for Safe
/// would take an intended target call and return the corresponding call to the Safe contract that
/// causes the Safe to execute that target call.
pub trait CallEncoder {
    /// Additional encoder-specific metadata required to build the wrapped call.
    ///
    /// Different smart account types can use different context types, e.g. Safe signatures,
    /// gas/refund parameters, module identifiers, or other execution metadata.
    type EncodeContext;

    /// Converts an intended call into its wrapped on-chain representation.
    fn encode_call(&self, call: RawCall, context: &Self::EncodeContext) -> eyre::Result<RawCall>;
}
