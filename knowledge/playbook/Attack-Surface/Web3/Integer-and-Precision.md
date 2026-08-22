> Source: https://bugbounty.info/Attack-Surface/Web3/Integer-and-Precision

# Integer and Precision

Solidity's integer arithmetic has two distinct eras: before 0.8, overflow and underflow silently wrap. After 0.8, they revert by default. Neither era is safe  -  post-0.8 contracts use `unchecked {}` blocks to save gas, and the real-world precision bugs (rounding, decimal mismatches, division order) affect both eras equally.

## Overflow and Underflow

Before Solidity 0.8.0, arithmetic wrapped silently:

```solidity
// Pre-0.8 behaviour
uint256 x = 0;
x - 1;  // wraps to 2^256 - 1 = 115792089237316195423570985008687907853269984665640564039457584007913129639935
 
uint8 y = 255;
y + 1;  // wraps to 0
```

The classic exploit: a token balance mapping where `balances[attacker] -= amount` runs before the require check, or where the require check itself is flawed. Subtracting more than you have wraps to a huge number.

Post-0.8, the compiler inserts overflow checks that revert. The attack surface narrows but doesn't disappear because of `unchecked` blocks:

```solidity
// Post-0.8 with unchecked  -  overflow silently wraps again
function calculateFee(uint256 amount, uint256 bps) external pure returns (uint256) {
    unchecked {
        return amount * bps / 10000;  // if amount * bps overflows, result is wrong
    }
}
```

Search for `unchecked` blocks in audited code and verify each arithmetic operation inside them. `unchecked` is legitimate for gas savings in loop counters and known-safe operations  -  the bug is when it wraps around a multiplication that can feasibly overflow.

```bash
# Slither detects overflow in unchecked blocks
slither . --detect tautology,integer-overflow
```

## Rounding Direction

EVM integer division always truncates towards zero (floors for positive numbers). This means every division can silently lose up to `divisor - 1` units. In financial contracts, this matters for:

- **Minting ratios:** if a user deposits 999 wei and the protocol divides by 1000 to compute shares, they get 0 shares but still pay 999 wei
- **Fee calculations:** protocol rounds fees down; attacker makes many small transactions to pay effectively 0 fees
- **Redemption calculations:** always-floor means the protocol systematically pays out slightly less than owed

```solidity
// Who benefits from the rounding?
function sharesToAssets(uint256 shares, uint256 totalShares, uint256 totalAssets)
    public pure returns (uint256)
{
    return shares * totalAssets / totalShares;
    // Always floors. Users get slightly less. Protocol accumulates dust.
    // On redemption this is safe-ish. On deposit it can be exploitable.
}
```

The audit question: does this rounding favour the user or the protocol? Rounding that consistently favours the user is exploitable through repeated small operations.

## Decimal Mismatches

ERC-20 tokens declare their own decimal precision. Most tokens use 18, but USDC and USDT use 6. Chainlink price feeds for USD pairs return 8-decimal values.

```solidity
// VULNERABLE: assumes both tokens are 18-decimal
function depositCollateral(address token, uint256 amount) external {
    uint256 valueUSD = amount * getPrice(token) / 1e18;
    collateral[msg.sender] += valueUSD;
}
 
// If token is USDC (6 decimals) and the price feed returns 8-decimal:
// 1 USDC = 1,000,000 units (6 decimals)
// Price = 1,00000000 (8 decimals)
// valueUSD = 1000000 * 100000000 / 1e18 = 0
// The depositor gets zero collateral credit for their USDC
```

The reverse mismatch (getting too much collateral) is the exploitable direction. If the protocol overestimates the value of a 6-decimal token by treating it as 18-decimal:

```solidity
// Amount deposited: 1 USDC = 1_000_000 (1e6 units)
// Protocol treats as 18-decimal: reads as 1_000_000 / 1e18 = 0.000001 ETH-equivalent
// OR: directly uses the raw value as if it's 1e6 ETH  -  massive overvaluation
```

When auditing any protocol that handles multiple tokens, list all token decimals and trace every arithmetic path that combines prices and amounts.

## Division Before Multiplication

Order of operations matters for precision. Division truncates, so dividing before multiplying amplifies rounding error:

```solidity
// BAD: divides first, loses precision
uint256 fee = amount / 100 * feeRate;
 
// GOOD: multiplies first, divides last
uint256 fee = amount * feeRate / 100;
```

For `amount = 99`, `feeRate = 3`:

- Bad: `99 / 100 * 3 = 0 * 3 = 0`
- Good: `99 * 3 / 100 = 297 / 100 = 2`

Slither's `divide-before-multiply` detector catches this pattern. Review every instance for exploitability  -  some are innocuous (the division result is always large enough), others allow fee-free operation through careful input sizing.

## Share Inflation Attack (First Depositor Attack)

ERC4626 vaults and similar share-based accounting are vulnerable when the first depositor can manipulate the exchange rate between shares and assets.

```solidity
// Standard vault shares calculation
function deposit(uint256 assets) external returns (uint256 shares) {
    shares = assets * totalSupply / totalAssets;
    // If totalSupply == 0 and totalAssets == 0:
    // shares = assets * 0 / 0  -  division by zero, so uses 1:1 default
}
```

Attack sequence:

1. Attacker is first depositor, deposits 1 wei, receives 1 share
2. Attacker donates a large amount (say 1e18) directly to the vault contract (not via `deposit`)
3. `totalAssets` = 1e18 + 1, `totalSupply` = 1 share
4. Next legitimate user deposits 1.9e18 assets
5. `shares = 1.9e18 * 1 / (1e18 + 1) = 1` share
6. Attacker redeems their 1 share: gets `1 * (1e18 + 1 + 1.9e18) / 2 = ~1.45e18` assets
7. Attacker's profit is approximately half the victim's deposit

The fix is either a minimum initial deposit requirement (protocol deposits a large seed amount) or virtual shares/assets that prevent the ratio from ever being extreme.

## Checklist

- Check the Solidity version; if pre-0.8, review all arithmetic for overflow/underflow
- Search for `unchecked` blocks and audit every arithmetic operation inside them
- Identify all division operations and verify the rounding direction favours the protocol, not the user
- List all ERC-20 tokens in scope and their decimal values; trace every price/amount combination
- Check Chainlink feed decimals (8 for USD pairs) against protocol assumptions (often 18)
- Search for division-before-multiplication patterns with Slither
- Identify share-based vaults (ERC4626) and test the first-depositor attack
- Look for fee calculations that round to zero on small inputs
- Test any multiplication that involves both token amounts and prices for overflow potential
- Run Echidna property tests targeting invariants like "total shares never exceed total assets"

## Public Reports

- Share inflation attack on ERC4626 vault - [Trail of Bits](https://blog.trailofbits.com/2022/09/05/the-eip-4626-inflation-attack/)
- Decimal mismatch leading to collateral overvaluation - [Immunefi Disclosure 2023](https://immunefi.com/bug-bounty/angle/disclosed/)
- Division-before-multiply precision loss in fee calculation - [Code4rena 2022-10](https://code4rena.com/reports/2022-10-inverse)
- Integer underflow in pre-0.8 token contract - [Immunefi Disclosure 2022](https://immunefi.com/bug-bounty/sushi/disclosed/)

## See Also

- [Oracle Manipulation](../../Attack-Surface/Web3/Oracle-Manipulation)  -  decimal mismatches amplify oracle price errors
- [Reentrancy](../../Attack-Surface/Web3/Reentrancy)  -  state corruption from reentry interacts with accounting bugs
- [Tooling](../../Attack-Surface/Web3/Tooling)  -  Echidna for property-based testing of arithmetic invariants
- [Smart Contract Basics](../../Attack-Surface/Web3/Smart-Contract-Basics)  -  Solidity types, storage layout
