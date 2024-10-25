## Summary
### Low Risk

|      | Title                                                                         |
| ---- | ----------------------------------------------------------------------------- |
| L-01 | `EVM.charge_gas` revert is not checked in some cases                          |
| L-02 | Unnecessary `EVM.charge_gas` in `CREATE` when executed in a read only context |
| L-03 | Block gas limit is only enforced per transaction                              |
| L-04 | The first `CALL` with value to a precompile will charge a new account gas     |

## Low Risks
### L-01 | `EVM.charge_gas` revert is not checked in some cases

**Issue Description:**

There are some cases where `EVM.charge_gas` is not immediately checked for revert. Although this does not cause any issues due to additional checks being done later, this leads to unnecessary extra computations. Places where this is the case are :
* [CREATE](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/instructions/system_operations.cairo#L132)
* [CALL](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/instructions/system_operations.cairo#L391)
### L-02 | Unnecessary `EVM.charge_gas` in `CREATE` when executed in a read only context

**Issue Description:**

When the `CREATE` opcode is executed in a read only context, it triggers an `EXCEPTIONAL_HALT` error which leads to the consumption of all the remaining gas, so there is no need to charge gas before this error is triggered.

[CREATE](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/instructions/system_operations.cairo#L116)
### L-03 |  Block gas limit is only enforced per transaction

**Issue Description:**

Block gas limit is enforced on every transaction and not per block, this means that it can be exceeded if there are multiple transactions in a given block.

For example, with a block gas limit of 7m, a transaction with a gas limit of 7.1m would fail the check, but multiple transactions with a gas limit of 7m each would each pass the check.

This seems to be by design though and there is no easy solution to achieve this on the Starknet level.

[eth_rpc](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/eth_rpc.cairo#L277-L280)

### L-04 |  The first `CALL` with value to a precompile will charge a new account gas

**Issue Description:**

Since the precompiles are not prefunded, the account will be considered new in the first `CALL` with value as its nonce, balance and code length are all 0, thus charging an additional account creation gas (.i.e 25000).

[CALL](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/instructions/system_operations.cairo#L384)
[is_account_alive](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/state.cairo#L415C1-L432C6)