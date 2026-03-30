# ethx

[![CI](https://github.com/0xferrous/ethx/actions/workflows/ci.yml/badge.svg)](https://github.com/0xferrous/ethx/actions/workflows/ci.yml)

Experimental Ethereum CLI built on Foundry and Alloy.

Right now the main implemented command is:
- `ethx send` — a `cast send`-like transaction sender

It also supports wrapping calls through a smart-account encoder, currently:
- `safe`

## Encoder abstraction

`ethx send` can either send a transaction directly, or first pass the requested call through an
encoder.

Without an encoder:
- the positional `TO` address is the transaction recipient
- the parsed `sig + args` become the final calldata

With an encoder:
- the positional `TO` address is the inner call destination
- the parsed `sig + args` become the inner calldata
- `--target` is the outer account/contract that actually receives the transaction
- the selected encoder transforms that inner call into the outer calldata expected by the target

This is meant to support smart-account style flows where the final onchain transaction is sent to
an account contract, but still describes some inner call to be executed by that account.

Today the only implemented encoder is `safe`, which wraps the inner call into Safe
`execTransaction(...)` calldata.

From an implementation perspective, the abstraction is centered on:
- `RawCall`: a normalized inner call shape (`to`, `value`, `data`)
- `CallEncoder`: a trait that transforms a `RawCall` into another `RawCall`
- `CallEncoder::EncodeContext`: encoder-specific extra state needed during encoding

That lets each encoder decide:
- how the outer calldata should be built
- whether the outer recipient should differ from the inner recipient
- what extra preparation/validation is needed before encoding

The Safe implementation uses this to attach Safe-specific context such as:
- operation mode
- Safe gas/refund fields
- structured signature inputs
- prepared packed signature bytes

The intent is that other smart-account/account-abstraction styles can be added later by:
- defining their own context type
- implementing `CallEncoder` for their wrapper format
- adding CLI parsing/mapping for their encoder-specific options

## Status

This is an experiment, not a polished replacement for `cast`.

Implemented today:
- Foundry-style function signature + args parsing via `foundry_cli::utils::parse_function_args`
- Foundry wallet resolution via `foundry-wallets`
- regular call sending
- contract creation via `--create`
- unlocked sending via `eth_sendTransaction`
- signer-based sending
- Safe `execTransaction(...)` wrapping
- Safe tx hash derivation for:
  - `1.0.0`
  - `1.1.1`
  - `1.2.0`
  - `1.3.0`
  - `1.4.1`
  - `1.5.0`
- structured Safe signature inputs:
  - EOA signatures
  - EIP-1271 contract signatures
  - approved-hash signatures
- Safe owner/threshold validation and optional auto-add of the current signer signature
- Safe packed signature encoding, including dynamic offsets for contract signatures

## Build

### Nix

```bash
nix-shell -p cargo rustfmt clippy --run 'cargo build'
```

### Cargo

```bash
cargo build
```

## Run

```bash
cargo run -- --help
cargo run -- send --help
```

## Examples

### Send a regular transaction

```bash
ethx send \
  --rpc-url https://rpc.example \
  --private-key <KEY> \
  0xTarget \
  "transfer(address,uint256)" \
  0xRecipient \
  1000000000000000000
```

### Deploy bytecode

```bash
ethx send \
  --rpc-url https://rpc.example \
  --private-key <KEY> \
  --create \
  0x6080...
```

### Send through a Safe

This uses the encoder abstraction to wrap the inner call into Safe `execTransaction(...)` calldata
and send the outer transaction to the Safe itself.

```bash
ethx send \
  --rpc-url https://rpc.example \
  --private-key <OWNER_KEY> \
  --encoder safe \
  --target 0xSafe \
  --safe-eoa-signature 0x<owner_sig> \
  0xInnerTarget \
  "transfer(address,uint256)" \
  0xRecipient \
  1ether
```

You can also supply other Safe signature forms:

```bash
--safe-contract-signature 0xOwnerContract:0x<1271_sig>
--safe-approved-hash 0xOwner
```

Meaning of addresses:
- `TO` positional argument: inner call destination
- `--target`: Safe address

## Safe behavior

For the Safe encoder, `ethx` currently:
- queries Safe metadata:
  - `VERSION()`
  - `nonce()`
  - `getThreshold()`
  - `getOwners()`
  - batching via multicall when available, with fallback to direct calls
- derives the Safe tx signing hash locally
- supports these input forms:
  - `--safe-eoa-signature <SIG>`
  - `--safe-contract-signature <OWNER>:<SIG>`
  - `--safe-approved-hash <OWNER>`
- validates EOA signatures by recovering the owner from the Safe tx hash
- validates EIP-1271 signatures by calling:
  - `owner.isValidSignature(safeTxHash, signature)`
- validates approved-hash signatures by checking:
  - executor is the owner, or
  - `approvedHashes(owner, safeTxHash) != 0`
- verifies referenced/recovered owners are actual Safe owners
- sorts signatures by owner address ascending
- checks threshold early
- if the provided owner signatures are below threshold and a local signer is available, signs the Safe tx hash with the current signer and appends that signature when appropriate
- encodes the final Safe packed signatures payload, including contract-signature offsets and dynamic tails

### Signature support

Supported today:
- standard recoverable 65-byte EOA signatures
- EIP-1271 contract signatures
- approved-hash signatures

Not supported yet:
- Safe `v == 2` P-256 / RIP-7212-style signatures
- additional custom Safe signature encodings beyond the forms above

## Notes

- The local variable named `ens_chain` in the code is currently only used for Foundry parsing / resolution behavior, not as the tx chain id.
- Transaction filling is still mostly explicit/manual at the moment.

## Development

Useful commands:

```bash
cargo fmt --all
cargo test
cargo check
cargo clippy --all-targets --all-features -- -D warnings
```
