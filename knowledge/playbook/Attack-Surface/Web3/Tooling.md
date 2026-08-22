> Source: https://bugbounty.info/Attack-Surface/Web3/Tooling

# Web3 Tooling

The standard toolkit for web3 bug hunting is small and mostly free. You need Foundry for PoC development, Slither for static analysis, and Tenderly for transaction tracing. Everything else is situational.

## Foundry

Foundry is the primary toolkit. It has three commands you'll use constantly:

**forge**  -  compiles Solidity, runs tests, manages dependencies

```bash
# Install
curl -L https://foundry.paradigm.xyz | bash && foundryup
 
# Create a new project
forge init my-poc
cd my-poc
 
# Install a dependency (e.g., OpenZeppelin)
forge install OpenZeppelin/openzeppelin-contracts
 
# Run tests verbosely (see console.log and traces)
forge test -vvvv
 
# Run a specific test
forge test --match-test testReentrancyExploit -vvvv
 
# Fork mainnet and run tests against live state
forge test --fork-url https://mainnet.infura.io/v3/KEY -vvvv
```

**cast**  -  interact with live contracts from the command line

```bash
# Read a storage slot
cast storage 0xCONTRACT 0x0 --rpc-url $RPC
 
# Call a view function
cast call 0xCONTRACT "balanceOf(address)(uint256)" 0xADDRESS --rpc-url $RPC
 
# Decode calldata
cast calldata-decode "transfer(address,uint256)" 0xDATA
 
# Compute a function selector
cast sig "initialize(address,uint256)"
 
# Convert between units
cast to-wei 1.5 ether
cast from-wei 1500000000000000000
```

**anvil**  -  local EVM node, optionally forked from mainnet

```bash
# Start a local fork of mainnet
anvil --fork-url https://mainnet.infura.io/v3/KEY
 
# Fork at a specific block (for reproducing historical bugs)
anvil --fork-url $RPC --fork-block-number 18500000
 
# Impersonate an account (no private key needed)
cast rpc anvil_impersonateAccount 0xTARGET_ADDRESS
 
# Send a transaction as the impersonated account
cast send 0xCONTRACT "privilegedFunction()" --from 0xTARGET_ADDRESS --unlocked
```

A minimal Foundry PoC for a reentrancy bug:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
 
import "forge-std/Test.sol";
import "../src/VulnerableBank.sol";
 
contract ReentrancyPoC is Test {
    VulnerableBank bank;
    Attacker attacker;
 
    function setUp() external {
        // Fork mainnet state
        vm.createSelectFork(vm.envString("MAINNET_RPC"));
        bank = VulnerableBank(0xTARGET);
        attacker = new Attacker(address(bank));
    }
 
    function testExploit() external {
        uint256 startBalance = address(attacker).balance;
        attacker.attack{value: 1 ether}();
        uint256 profit = address(attacker).balance - startBalance;
        assertGt(profit, 0, "no profit");
        console.log("Profit:", profit);
    }
}
```

## Slither

Slither is a static analysis framework for Solidity. Run it before manual review to catch low-hanging issues and map call graphs.

```bash
# Install
pip install slither-analyzer
 
# Basic run  -  outputs all detected issues
slither .
 
# Run specific detectors
slither . --detect reentrancy-eth,unprotected-upgrade,arbitrary-send-eth
 
# Output to JSON for programmatic processing
slither . --json slither-report.json
 
# Print the call graph
slither . --print call-graph
 
# Print function summary
slither . --print human-summary
 
# Check a single file
slither contracts/Vault.sol
```

Key detectors for bounty hunting:

| Detector | Catches |
| --- | --- |
| `reentrancy-eth` | ETH-sending reentrancy |
| `reentrancy-no-eth` | State reentrancy without ETH |
| `unprotected-upgrade` | Upgradeable contracts with unguarded upgrade functions |
| `arbitrary-send-eth` | ETH transfer to attacker-controlled address |
| `controlled-delegatecall` | delegatecall to attacker-controlled address |
| `divide-before-multiply` | Precision loss from wrong operation order |
| `tautology` | Always-true/false conditions |

Slither generates false positives. Every finding needs manual validation before reporting.

## Echidna

Echidna is a property-based fuzzer for Solidity. You define invariants and Echidna tries to break them.

```solidity
// Property: total supply should never exceed 1 million tokens
function echidna_total_supply_max() public returns (bool) {
    return token.totalSupply() <= 1_000_000e18;
}
 
// Property: user balance should never exceed their deposits
function echidna_balance_invariant() public returns (bool) {
    return vault.balances(address(this)) <= vault.totalDeposited();
}
```

```bash
# Install via Docker (easiest)
docker pull ghcr.io/crytic/echidna/echidna
 
# Run against a test contract
docker run --rm -v $(pwd):/code ghcr.io/crytic/echidna/echidna echidna /code/contracts/Test.sol --contract TestContract
```

Echidna is most useful for arithmetic invariants (share prices, exchange rates) and access control properties. Less useful than Foundry for multi-step exploits where you know the attack path.

## Tenderly

Tenderly is a web-based transaction simulation and debugging platform. Paste any mainnet transaction hash and get a full execution trace with storage reads/writes, internal calls, and gas costs.

Use cases for bounty hunting:

- Understand a historical exploit by tracing the attacker's transaction
- Simulate a transaction before sending it, to check what state changes it would make
- Debug a failing Foundry test by running it against Tenderly's fork

```text
https://dashboard.tenderly.co/tx/mainnet/0xTRANSACTION_HASH
```

The free tier supports mainnet traces. The simulation API (paid) lets you programmatically simulate transactions and inspect state changes.

## Remix

Remix is a browser-based Solidity IDE at `remix.ethereum.org`. No installation required. Use it for quick PoC sketches and testing simple contracts against Remix's JavaScript VM.

When to use Remix vs Foundry: Remix is faster for throwaway tests on contracts you paste directly. Foundry is required for anything involving mainnet forks, real contract addresses, or multi-transaction exploits.

## Chisel

Chisel is a Solidity REPL included with Foundry. Use it to test Solidity expressions interactively without writing a full contract.

```bash
chisel
 
# Inside the REPL:
> uint256 x = type(uint256).max;
> x
115792089237316195423570985008687907853269984665640564039457584007913129639935
> keccak256(abi.encode(1, 2))
0x...
> address(0x1234).balance
0
```

## Hardhat

Hardhat is an alternative to Foundry using JavaScript/TypeScript. Most older DeFi protocols have Hardhat test suites. If you're reading existing tests to understand a protocol, you may encounter Hardhat.

For new PoC work, Foundry is faster and has better debugging tooling. Use Hardhat only if the target's own tests are in Hardhat and you want to run them locally.

## Checklist

- Install Foundry and confirm `forge`, `cast`, and `anvil` work
- Set up an `.env` file with your RPC URL (Alchemy or Infura free tier is enough)
- Run Slither against the target codebase before starting manual review
- Use `cast storage` to read the implementation address of any proxy contracts
- Use `anvil --fork-url` to create a local mainnet fork for PoC development
- Write Foundry tests for any suspected bug before attempting a live exploit
- Use Tenderly to understand how historical exploits against similar protocols worked
- Verify your PoC produces correct profit/output in the forked environment before reporting
- Do NOT run your PoC against a live mainnet contract  -  the Foundry fork is sufficient proof

## See Also

- [Smart Contract Basics](../../Attack-Surface/Web3/Smart-Contract-Basics)  -  what to look for with these tools
- [Reentrancy](../../Attack-Surface/Web3/Reentrancy)  -  Slither reentrancy detectors in practice
- [Oracle Manipulation](../../Attack-Surface/Web3/Oracle-Manipulation)  -  Tenderly for simulating flash loan sequences
- [Web3 Overview](../../Attack-Surface/Web3/)  -  no-mainnet-exploitation rule
