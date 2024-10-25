### Low-01 EVM tx that calls kakarot-precompile to call a starknet contract that queries or transfers ETH value will likely be reverted or with unexpected result
**Instances(1)**
kakarot allows whitelisted caller evm contract to invokes kakarot precompiles(0x75001), which makes [call](https://github.com/kkrt-labs/kakarot-lib/blob/c2c7cb400f85c3699a6902946bcf4428d5b4fc61/src/CairoLib.sol#L22)/static calls/delegate calls to a starknet contract, allowing EVM contracts to call Cairo contracts. See [doc](https://docs.kakarot.org/starknet/architecture/cairo-precompiles/#cairo-precompile).

In starknet and kakaort, native ETH is represented as an starknet ERC20 contract (native_token_address) and all account balances are stored in the starknet ERC20 contracts, native ETH is represented as an starknet ERC20 contract (native_token_address) and all account balances are stored in the starknet ERC20 contracts

This creates an issue when an EVM contract calls a cairo contract’s function that has logics based on an account’s ETH balance or transfer of ETH balance, because in Kakarot’s `eth_call` flow all the ETH balance changes are only cached in a temporary `state` variable until the final steps of `starknet.commit`.
```rust
//src/kakarot/interpreter.cairo
    func execute{
...
    }(
        env: model.Environment*,
        address: model.Address*,
        is_deploy_tx: felt,
        bytecode_len: felt,
        bytecode: felt*,
        calldata_len: felt,
        calldata: felt*,
        value: Uint256*,
        gas_limit: felt,
        access_list_len: felt,
        access_list: felt*,
    ) -> (model.EVM*, model.Stack*, model.Memory*, model.State*, felt, felt) {
...
            let transfer = model.Transfer(sender.address, address, [value]);
|>          let success = State.add_transfer(transfer);
...
```
(https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/interpreter.cairo#L962-L963)

Example flow: 
eth_rpc::eth_send_raw_unsigned_tx → eth_send_transaction → eth_call → Interpreter::execute → run() → exec_opocode → Precompiles.exec_precompile → KakarotPrecompiles.cairo_precompile → account_contract::execute_starknet_call → call_contract syscall

In account_contract::execute_starknet_call, syscall [call_contract to the target starknet contract with custom calldata](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/accounts/account_contract.cairo#L347) is invoked which executes the external call to a starknet contract.

If the called starknet contract’s function logic require query / transfer of the calling evm account’s [native_token_address(eth)](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/storages.cairo#L12) balance, it will only retrieve the balanceOf from the starknet native_token_address’s storage which doesn’t reflect any eth value transfer that has been made earlier in the same tx.  At this point, native_token_address.balanceOf(calling_account) ≠ state.get_account(calling_account).balance.

POC:

Suppose Kakarot EOA account A has 100 ETH in balance. EVM contract B has 0 ETH in balance.

Kakarot EOA account A invokes a payable EVM contract B::function_B which calls a starknet contract C::function_C which performs logic based on contract B’s native token balance.

The expected behavior: A would invoke a call opocde to B::function_B and passing value 100 ETH. Atomically, function_B invokes C::function_C. 

In starknet, C::function_C should be able to query the current ETH balance of B of 100ETH because A already sent 100 ETH to B before function_C call.

However in current kakarot evm ↔ starknet, C::function_C’s query of B’s ETH balance is still 0 ETH.

In an EVM ↔ Starknet contracts interoperability case, such ETH balance transfers should be common. This means that any starknet contracts that query ETH balance for any purposes might not receive the expected ETH balance due to kakarot state caching.

Impacts: 
Any transactions that involve EVM → Starknet contract calls may have unexpected results or unfairly reverted. Any starknet application that rely on correct ETH balance query may receive an incorrect/outdated balance value.

**Recommendations:**
(1) Either explicitly disallow interactions with starknet contracts that query ETH balance, which limiting use cases;
(2) Or consider transfering eth directly when a call requires so. And if later call reverts during the tx. Kakarot core has to transfer eth back to revert the state.

### Low-02 Invalid check on pendingWordLen might result in malformed byteArray to be converted into incorrect or invalid strings
**Instances(1)**
`byteArray` struct is starknet's special type representing strings.
```rust
//src/CairoLib.sol
    /**
     * pub struct ByteArray {
     *    full_words_len: felt252,
     *    full_words: [<bytes31>],
     *    pending_word: felt252,
     *    pending_word_len: usize,
     *  }
     *  where `full_words` is an array of 31-byte packed words, and `pending_word` word of size `pending_word_len`.
     *  Note that those full words are 32 bytes long, but only 31 bytes are used.
     */
``` 
According to starknet [doc](https://docs.starknet.io/architecture-and-concepts/smart-contracts/serialization-of-cairo-types/#serialization_of_byte_arrays), byteArray’s pendingWordLen should be in range [0,31), maximally 30.
>2. **`pending_word: felt252`**
    The bytes that remain after filling the **`data`** array with full 31-byte chunks. The pending word consists of at most 30 bytes.

The issue is in Cairolib.sol, function `byteArrayToString` has invalid check on pendingWordLen, allowing pendingWordLen to be 31. This allows malformed byteArray to be converted into potentially invalid strings.
```rust
//kakarot/solidity_contracts/lib/kakarot-lib/src/CairoLib.sol
    function byteArrayToString(
        bytes memory data
    ) internal pure returns (string memory) {
        require(data.length >= 96, "Invalid byte array length");
        uint256 fullWordsLength;
        uint256 fullWordsPtr;
        uint256 pendingWord;
        uint256 pendingWordLen;
        assembly {
            fullWordsLength := mload(add(data, 32))
            let fullWordsByteLength := mul(fullWordsLength, 32)
            fullWordsPtr := add(data, 64)
            let pendingWordPtr := add(fullWordsPtr, fullWordsByteLength)
            pendingWord := mload(pendingWordPtr)
            pendingWordLen := mload(add(pendingWordPtr, 32))
        }

 |>     require(pendingWordLen <= 31, "Invalid pending word length");

        uint256 totalLength = fullWordsLength * 31 + pendingWordLen;
        bytes memory result = new bytes(totalLength);
        uint256 resultPtr;
        assembly {
            resultPtr := add(result, 32)
            // Copy full words. Because of the Cairo -> Solidity conversion,
            // each full word is 32 bytes long, but contains 31 bytes of information.
            for {
                let i := 0
            } lt(i, fullWordsLength) {
                i := add(i, 1)
            } {
                let word := mload(fullWordsPtr)
                let storedWord := shl(8, word)
                mstore(resultPtr, storedWord)
                resultPtr := add(resultPtr, 31)
                fullWordsPtr := add(fullWordsPtr, 32)
            }
            // Copy pending word
            if iszero(eq(pendingWordLen, 0)) {
                mstore(
                    resultPtr,
                    shl(mul(sub(32, pendingWordLen), 8), pendingWord)
                )
            }
        }

        return string(result);
```
(https://github.com/kkrt-labs/kakarot-lib/blob/c2c7cb400f85c3699a6902946bcf4428d5b4fc61/src/CairoLib.sol#L220)

Impact: malformed or invalid byteArray can be converted into strings. Since CairoLib.sol is a generic library contract and is expected to be used for all users' custom solidity contracts, depending on the use case this might lead to incorrect /invalid string to be used for downstream tasks.

**Recommendations:**
Change the check into pendingWordLen < 31 .

### Low-03 `helpers::load_word` is vulnerable to out-of-bound , due to missing length check
**Instances(1)**
In kakarot-ssj/crates/utils/src/helpers.cairo, `load_word`  loads a certain length(`mut len: usize`) of bytes(`words: Span<u8>`) into a single u256 in big-endian order.

The issue is there is no check whether `len` is not out-of-bound in `words` byte array.

In case of out-of-bound edge case, entire transaction will throw without proper revert handling. 
```rust
//kakarot-ssj/crates/utils/src/helpers.cairo
pub fn load_word(mut len: usize, words: Span<u8>) -> u256 {
    if len == 0 {
        return 0;
    }
    let mut current: u256 = 0;
    let mut counter = 0

    while len != 0 {
|>      let loaded: u8 = *words[counter];
        let tmp = current * 256;
        current = tmp + loaded.into();
        len -= 1;
        counter += 1;
    };

    current
}
```
(https://github.com/kkrt-labs/kakarot-ssj/blob/d4a7873d6f071813165ca7c7adb2f029287d14ca/crates/utils/src/helpers.cairo#L141)

**Recommendations:**
Consider adding check to ensure input len <= words.length and allow return status, when out-of-bound for downstream handling.

### Low-04 Consider not charging l2 EVM gas from `handle_l1_message`
**Instances(1)**
L1-L2 messaging in kakarot is based on starknet L1-l2 bridge mechanism(e.g. using starknet cores’ starknetMessaging.sendMessageToL2 function). 
In the case of L1 to L2 message, [starknet only charge fees on L1](https://docs.starknet.io/architecture-and-concepts/network-architecture/messaging-mechanism/#l1-l2-message-fees), which already includes L2 starknet gas. Because L2 will be invoked by sequencer or starknet os(`@l1handler`).

The problem is current kakarot's l2 implementation of L1 to L2 flow, i.e.handle_l1_message, will try to charge EVM gas on L2 directly from L1sender's l2 balance. This departs from starknet bridge mechanism's behavior where all fees are charged on L1.

A common use case of an L1 sender that doesn't have any L2 balance who wants to send a message to L2 becomes cumbersome when interacting with kakarot's L1 to L2 flow. As a result, any L1sender who wants to send an L2 message to a kakarot evm contract is also required to have sufficient L2 ETH balance to pay on L2. 
```rust
//src/kakarot/library.cairo
    func handle_l1_message{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        bitwise_ptr: BitwiseBuiltin*,
    }(l1_sender: felt, to_address: felt, value: felt, data_len: felt, data: felt*) -> (
        model.EVM*, model.State*, felt, felt
    ) {
        // TODO: ensure fair gas limits and prices
        let (val_high, val_low) = split_felt(value);
        tempvar value_u256 = new Uint256(low=val_low, high=val_high);
        let to = model.Option(is_some=1, value=to_address);
        let (access_list) = alloc();

        return eth_call(
|>          0, l1_sender, to, 2100000000, 1, value_u256, data_len, data, 0, access_list
        );
    }
```
(https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/library.cairo#L436)

Recommendations:
Consider adding logics L1KakarotMessaging.sol to charge kakarot EVM gas on L1 as well.


