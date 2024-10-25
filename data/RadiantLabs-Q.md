### [QA-01] Missing boundary check in EVM transaction decoding

With the `account_contract.cairo`'s `execute_from_outside` function, callers submit a `calldata` blob of `calldata_len` length, out of which the transaction data is extracted by selecting `[call_array].data_len` bytes starting from position `[call_array].data_offset`.

Within the logic that makes this extraction, there is no check that `[call_array].data_offset + [call_array].data_len` fits within `calldata_len`, effectively allowing for the submission of transactions that pass or fail validation depending on what's allocated out of the boundaries of the input data.

Consider adding a boundary check to enforce `[call_array].data_offset + [call_array].data_len < calldata_len`.

Similar lack of validation for non-critical variables can be found in the actual length of the `signature` array vs `signature_len`, the actual length of the `call_array` vs `call_array_len`, as well as in `eth_transactions::parse_access_list()`, where the parsing of `address_item` misses a check that `address_item.data_len = 20`, that the `access_list.data_len = 2` (spec in the python snippet [here](https://eips.ethereum.org/EIPS/eip-2930#parameters)).

### [QA-02] Several of the `stack_size_diff` values defined in `constants.cairo` are off

The `stack_size_diff` constants define, for each opcode, what the expected delta between the stack size before and after the operation is. These values are used by the interpreter to predict EVM stack overflows.

The following values are incorrect:
- `ADDMOD` is `-1`, should be `-2`
- `MULMOD` is `-1`, should be `-2`
- `NOT` is `-1`, should be `0`
- `CALLDATACOPY` is `0`, should be `-3`
- `CODECOPY` is `0`, should be `-3`
- `RETURNDATACOPY` is `0`, should be `-3`

### [QA-03] Inconsistent interfaces used for ERC-20 casing

On Starknet, there are two main ways of defining ERC-20 functions, `camelCase` and `snake_case`. A the time of writing, `camelCase` is being [deprecated](https://community.starknet.io/t/the-great-interface-migration/92107) for `snake_case`, with many tokens supporting both for maximum compatibility.

There is however an inconsistency between Kakarot's native token handling, which uses `camelCase` `balanceOf` and `transferFrom` calls, and the `DualVmToken` contract that instead uses `snake_case` only.

For maximum compatibility, it is recommended to update both Kakarot and `DualVmToken` to support both and accept additional configuration selecting which interface to use.

### [QA-04] After Kakarot's native token is changed, an approval from `account_contract` instances can't be re-triggered

When an `account_contract` instance is created and initialized, it approves the Kakarot's native token to Kakarot, in order to allow it to settle native transfers happening within the EVM:

```cairo
File: library.cairo
083:     func initialize{
084:         syscall_ptr: felt*,
085:         pedersen_ptr: HashBuiltin*,
086:         range_check_ptr,
087:         bitwise_ptr: BitwiseBuiltin*,
088:     }(evm_address: felt) {
---
100:         let infinite = Uint256(Constants.UINT128_MAX, Constants.UINT128_MAX);
101:         IERC20.approve(native_token_address, kakarot_address, infinite);
```

However, Kakarot has a setter that can be called by admins to update the native token used within the EVM:

```cairo
File: kakarot.cairo
102: @external
103: func set_native_token{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
104:     native_token_address: felt
105: ) {
106:     Ownable.assert_only_owner();
107:     return Kakarot.set_native_token(native_token_address);
108: }
```

After this is called, there is no way to re-trigger approval from `account_contract` that were previously initialized.

As this functionality is likely not intended to ever be used after Kakarot has been deployed, consider implementing an initializer pattern.

Alternatively, consider adding the necessary methods in Kakarot and `account_contract` to allow the Kakarot contract to force-approve spending of the native token from the account contracts to itself.

### [QA-05] Some invalid values for the `v` field in Ethereum signatures are accepted

Within the `account_contract`'s `execute_from_outside` function, the validation on `v` is unnecessarily loose: whenever the correct `y_parity` value is `1`, values like `2` or `3` will still be accepted. This is because the `verify_eth_signature_uint256` function calls the `recover_eth_address` Cairo 1 library function to verify the signature, which parses `y_parity` [as a boolean](https://github.com/starkware-libs/cairo/blob/main/corelib/src/starknet/secp256_trait.cairo#L20).
