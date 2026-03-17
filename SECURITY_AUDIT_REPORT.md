# Security Audit Report: Celo L2 op-geth (op-testing-bb)

**Audit Date:** 2026-03-17
**Repository:** https://github.com/celo-org/op-geth (audited as clone https://github.com/haxonittech/op-testing-bb)
**Scope:** Full codebase security audit - Celo-specific fork modifications, fee currency system, RPC surfaces, P2P, state transition, precompiles, and cross-cutting concerns.

---

## Executive Summary

After exhaustive analysis of the entire Celo L2 op-geth codebase, including fee currency implementations, state transition logic, RPC surfaces, P2P handlers, precompiles, transaction pool, gas estimation, and miner code, **one confirmed, exploitable security vulnerability** was identified with high confidence.

The codebase is generally well-engineered with proper validation boundaries, appropriate access controls on precompiles, correct dual-balance tracking in the transaction pool, and sound fee currency registration/allowlisting mechanisms. The identified vulnerability is a subtle currency-unit mismatch in the state transition's gas purchase logic that affects fee currency transactions.

---

## FINDING #1: L1 Data Cost and Operator Cost Not Converted to Fee Currency in buyGas Debit Path

### 1. Title
**Currency Unit Mismatch: L1 Cost and Operator Cost Added in Native CELO to Fee-Currency-Denominated Debit Amount**

### 2. Severity
**HIGH** - Affects fee accounting correctness for every fee currency transaction on the Celo L2. Can cause transaction failures or accounting imbalances depending on exchange rates.

### 3. CWE
CWE-704: Incorrect Type Conversion or Cast (specifically, unit/denomination mismatch in financial calculation)

### 4. Affected Components / Files
- **Primary:** `core/state_transition.go` - `buyGas()` function (lines 329-386)
- **Primary:** `core/celo_state_transition.go` - `canPayFee()` function (lines 16-58)
- **Primary:** `core/celo_state_transition.go` - `subFees()` function (lines 61-73)
- **Related:** `contracts/fee_currencies.go` - `DebitFees()` / `CreditFees()` functions
- **Correct Implementation (for reference):** `core/state_transition.go` - credit path in `innerExecute()` (lines 813-815) correctly converts L1 cost

### 5. Exact Root Cause

In `buyGas()` (core/state_transition.go:329-386), the total fee amount `mgval` is computed as:

```go
mgval := new(big.Int).SetUint64(st.msg.GasLimit)
mgval.Mul(mgval, st.msg.GasPrice)    // msg.GasPrice is in FEE CURRENCY for CeloDynamicFeeTxV2
// ...
l1Cost = st.evm.Context.L1CostFunc(st.msg.RollupCostData, st.evm.Context.Time)  // Returns NATIVE CELO
if l1Cost != nil {
    mgval = mgval.Add(mgval, l1Cost)  // BUG: Adding CELO amount to fee-currency amount
}
// ...
operatorCost = st.evm.Context.OperatorCostFunc(st.msg.GasLimit, st.evm.Context.Time)  // Returns NATIVE CELO
mgval = mgval.Add(mgval, operatorCost.ToBig())  // BUG: Adding CELO amount to fee-currency amount
```

This mixed-unit `mgval` is then passed to `subFees()` which calls `contracts.DebitFees(evm, feeCurrency, from, mgval)`, debiting the mixed-unit amount from the fee currency ERC20 contract.

The same mixing occurs in the `balanceCheck` computation (lines 346-355), which is passed to `canPayFee()` for the balance check.

**Contrast with the credit path** (core/state_transition.go:813-815) which CORRECTLY converts l1Cost:
```go
l1Cost := st.evm.Context.L1CostFunc(st.msg.RollupCostData, st.evm.Context.Time)
if l1Cost != nil {
    l1Cost, _ = exchange.ConvertCeloToCurrency(..., feeCurrency, l1Cost)  // CORRECT conversion
}
```

### 6. Exact Attacker Prerequisites
- Attacker can submit CeloDynamicFeeTxV2 transactions (type 0x7b) with a non-nil FeeCurrency on the Celo L2 network
- The exchange rate between CELO and the fee currency must be non-trivial (not 1:1)
- The L1 data cost must be non-zero (true for any data-bearing transaction on the L2)
- No special privileges required - any user can submit fee currency transactions

### 7. Step-by-Step Exploit Path

**Scenario A: Fee currency worth less than CELO (e.g., 1 CELO = 1000 FC)**

1. Attacker crafts a CeloDynamicFeeTxV2 transaction with a fee currency where 1 CELO = 1000 FC
2. Transaction has significant calldata (increasing L1 data cost)
3. L1 data cost = X CELO = 1000X FC (in properly converted terms)
4. `buyGas()` computes: `debit_amount = gasLimit * gasPrice_FC + X` (treating X CELO as X FC)
5. `DebitFees` debits `gasLimit * gasPrice_FC + X` from user's fee currency balance
6. Transaction executes normally
7. `CreditFees` computes: distributes `refund_FC + tip_FC + baseFee_FC + 1000X_FC` (properly converted)
8. **Total credit (1000X FC for L1 portion) > Total debit (X FC for L1 portion)**
9. The fee currency contract attempts to distribute more than it collected
10. If the contract has surplus balance, funds are drained. If not, `CreditFees` reverts and the transaction fails at the state transition level, causing the block to fail

**Scenario B: Fee currency worth more than CELO (e.g., 1 FC = 1000 CELO)**

1. Same setup but reversed exchange rate
2. L1 data cost = X CELO = X/1000 FC (properly converted)
3. `buyGas()` debits `gasLimit * gasPrice_FC + X` FC (treating X CELO as X FC)
4. `CreditFees` distributes `refund_FC + tip_FC + baseFee_FC + X/1000_FC`
5. **Total debit includes X FC for L1 portion, but credit only distributes X/1000 FC**
6. User overpays by `X - X/1000` FC, which stays locked in the fee currency contract

### 8. Why Existing Checks Do Not Stop It

- **Balance check (`canPayFee`)**: Uses the same mixed-unit `balanceCheck`, so it validates against the wrong amount
- **Fee currency registration**: Only checks that the currency is registered, not that amounts are in the correct denomination
- **Transaction pool validation**: The txpool correctly separates native and fee currency costs (via `Cost()` and `FeeCurrencyCost()`), but the state transition does not
- **No unit type system**: Go has no built-in denomination/unit tracking, so the compiler cannot catch this
- **The credit path IS correct**: The conversion at line 815 shows the developers intended to convert, but missed the debit path

### 9. Real-World Impact

1. **Transaction failures**: For fee currencies with significant exchange rate differences from CELO, fee currency transactions may fail during `CreditFees` when the contract cannot distribute more than it collected (Scenario A)
2. **User fund loss**: For the reverse scenario (Scenario B), users systematically overpay L1 data fees in fee currency, with the excess locked in the fee currency contract
3. **Operator cost mishandling**: The Isthmus operator cost has the same mixing bug and is neither properly debited nor credited in the fee currency path
4. **Potential fee currency contract drainage**: If the fee currency contract holds surplus tokens, repeated transactions could drain this surplus through the accounting mismatch
5. **Consensus impact**: This is a consensus-critical code path - all nodes compute the same (incorrect) result, so it doesn't cause a chain split, but it produces economically incorrect state transitions

### 10. Why This Is Exploitable by Unauth/Low-Auth Attacker

Any user who can submit transactions to the Celo L2 network (which is the basic operation of any blockchain user) can trigger this bug by:
1. Using a registered fee currency for their transaction fees
2. Including calldata to maximize L1 data cost
3. No special permissions, admin access, or elevated privileges required

### 11. False-Positive Checks Performed

1. **Verified L1CostFunc returns CELO**: Confirmed in `core/types/rollup_cost.go` - L1 cost functions compute data availability costs in native CELO wei
2. **Verified msg.GasPrice is in fee currency**: For CeloDynamicFeeTxV2, `TransactionToMessage()` converts baseFee to fee currency before computing effectiveGasPrice (line 248-253)
3. **Verified no conversion exists in buyGas**: Exhaustively searched for any `ConvertCeloToCurrency` or `ConvertCurrencyToCelo` calls in the buyGas function - none exist
4. **Verified SkipNonceChecks/SkipTransactionChecks are false for real txs**: These are only set true for RPC simulation calls (eth_call), not real transactions
5. **Verified the credit path DOES convert correctly**: Line 815 explicitly calls `exchange.ConvertCeloToCurrency` for l1Cost in the credit path
6. **Verified this is not intentional**: The comment at contracts/fee_currencies.go:136-141 discusses the l1DataFee workaround for creditGasFees but does not mention the debit-side mismatch
7. **Verified OperatorCostFunc has the same issue**: OperatorCost is in CELO and added without conversion at line 343
8. **Verified the txpool handles this correctly**: `TotalTxCost()` for fee currency txs returns native-only cost, and `FeeCurrencyCost()` returns fee-currency-only cost - the mixing only occurs in the state transition
9. **Verified CeloDynamicFeeTxV2 is the active tx type**: V1 (CeloDynamicFeeTxType) is deprecated at Cel2, V2 is the current accepted type in the txpool
10. **Verified L1CostFunc is non-nil for Celo L2**: Set in `core/evm.go:83` via `types.NewL1CostFunc(config, statedb)` which returns non-nil when `config.Optimism != nil`

### 12. Final Confidence Statement

**100% confident this is a genuine currency-unit mismatch bug in the state transition's fee debit path.** The credit path at line 815 confirms the developers' intent to convert L1 costs to fee currency, but this conversion was not applied in the debit path at lines 337-343. The mathematical inconsistency between debit and credit amounts is provably incorrect.

### 13. Minimal PoC Strategy

1. Deploy a Celo L2 testnet with a registered fee currency that has a significant exchange rate difference from CELO (e.g., 1 CELO = 1000 FC)
2. Submit a CeloDynamicFeeTxV2 transaction with the fee currency and significant calldata (to maximize L1 data cost)
3. Monitor the DebitFees amount vs CreditFees distribution amounts
4. Observe that the CreditFees call either:
   - Reverts (if FC is worth less than CELO and contract lacks surplus)
   - Succeeds but leaves excess tokens in the contract (if FC is worth more than CELO)
5. Compare with a native CELO transaction with identical calldata to show the L1 cost is handled correctly in the native path

### Recommended Fix

In `buyGas()` (core/state_transition.go), convert `l1Cost` and `operatorCost` to fee currency before adding them to `mgval` and `balanceCheck`:

```go
if l1Cost != nil {
    if st.msg.FeeCurrency != nil {
        l1Cost, _ = exchange.ConvertCeloToCurrency(
            st.evm.Context.FeeCurrencyContext.ExchangeRates,
            st.msg.FeeCurrency,
            l1Cost,
        )
    }
    mgval = mgval.Add(mgval, l1Cost)
}
if st.evm.Context.OperatorCostFunc != nil {
    operatorCost = st.evm.Context.OperatorCostFunc(st.msg.GasLimit, st.evm.Context.Time)
    operatorCostBig := operatorCost.ToBig()
    if st.msg.FeeCurrency != nil {
        operatorCostBig, _ = exchange.ConvertCeloToCurrency(
            st.evm.Context.FeeCurrencyContext.ExchangeRates,
            st.msg.FeeCurrency,
            operatorCostBig,
        )
    }
    mgval = mgval.Add(mgval, operatorCostBig)
}
```

The same conversion must be applied to the `balanceCheck` computation.

Additionally, for the Isthmus operator cost refund and operator fee payment, the fee currency path (else branch starting at line 790) should include proper handling of operator costs with currency conversion.

---

## Areas Audited Without Exploitable Findings

The following areas were thoroughly examined and found to be correctly implemented:

### Transfer Precompile (0xfd)
- `core/vm/celo_contracts.go`: Properly checks that only the CELO token contract can call it (`IsCallerCeloToken`), validates input length (96 bytes), checks write protection, and verifies balance before transfer.

### Fee Currency Registration and Validation
- Exchange rates are validated for positive numerator/denominator (`contracts/fee_currencies.go:323-326`)
- Fee currency allowlisting is checked at txpool admission and state transition preCheck
- Intrinsic gas costs are capped at MaxUint64 for overflow protection

### Transaction Pool Dual Balance Tracking
- `core/txpool/validation.go`: Correctly separates native cost (`tx.Cost()` = `tx.Value()` for FC txs) from fee currency cost (`tx.FeeCurrencyCost()`)
- Balance checks are performed against both native and fee currency balances independently
- Replacement transaction cost tracking properly handles mixed-currency accounts

### MultiGasPool
- `core/celo_multi_gaspool.go`: Correctly limits per-currency gas usage in block building
- Disabled during derivation (verifier mode) to prevent local config divergence from consensus

### Currency Blocklist
- `miner/currency_blocklist.go`: Properly thread-safe with RWMutex, correct eviction logic, and manual disable capability for operators

### P2P and Sync
- Standard upstream op-geth message handling with no Celo-specific modifications to protocol handlers
- Message size limits enforced by RLPx transport layer

### RPC Security
- Engine API requires JWT authentication (standard OP-stack)
- Debug/admin APIs require explicit enablement
- Transaction fee cap prevents griefing via expensive RPC calls
- Sequencer API (`SendRawTransactionConditional`) has cost-based rate limiting

### Precompile Gas Accounting
- Fee currency debit/credit gas is tracked separately (`feeCurrencyGasUsed`) and does not affect transaction gas accounting
- Intrinsic gas for fee currencies is properly included in the total intrinsic gas calculation

### State Database Hooks
- `core/state/celo_statedb_hooked.go`: Hooks are disabled during DebitFees/CreditFees to prevent tracing interference, and restored correctly via deferred cleanup
