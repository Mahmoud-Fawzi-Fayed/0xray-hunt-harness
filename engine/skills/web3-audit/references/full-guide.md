---
name: web3-audit
description: Smart contract security audit — DeFi bug classes (accounting desync, access control, incomplete path, off-by-one, oracle, ERC4626, reentrancy, flash loan, signature replay, proxy) plus hooks, Uniswap v4, pull oracles, read-only reentrancy, L2 sequencer, EIP-7702 isEOA, ERC-2771, and cross-chain messaging. Stack router for Solidity, Vyper, Solana, and Move. Detected-vs-proven bar and Foundry fork PoC. Use for any Solidity/Rust/Move contract audit or when prioritizing a DeFi target.
---

# WEB3 SMART CONTRACT AUDIT

Bug classes, stack router, detected-vs-proven bar, Foundry fork PoC.

---

## TRIAGE (order the work — do not refuse an in-scope target)

Assigned in-scope code is in play. Score only decides depth and order. A low score is not a skip.

> Large audited bridges are low hit-rate (ZKsync: huge TVL, OZ audit, ~750K LOC, long review, no finding). Hunt the post-audit diff and the report's exclusion list, then move on. Do not declare "no vuln" without that pass written down.

**Score (higher = deeper pass first):**
- Live value, or the program's own critical ceiling, is large: +2
- No top-tier audit (Halborn, ToB, Cyfrin, OpenZeppelin, Cantina, Spearbit) on this commit: +2
- Deployed, upgraded, or diffed since the last audit within ~30 days: +2
- Oracle, bridge, hook, signature-auth, or upgradeable proxy surface: +1
- Verified source: +1
- Protocol you already know: +1

Where a current top-tier audit exists, read its scope exclusions and the diff since the audited commit. Bugs cluster in what they did not review: new modules, oracle failover, hooks, keeper paths, and the L2 deploy that dropped a sequencer check.

**Payout honesty:** `realistic_ceiling = min(program_cap, the program's own TVL formula)`. Claim only the tokens the PoC moves. A bug in a small pool is not a critical against full protocol TVL. Admin-malice and "centralization risk" follow the program brief — most Immunefi scopes downgrade those; still document a real unprivileged bug.

---

## THE ONE RULE

> "Read ALL sibling functions. If `vote()` has a modifier, check `poke()`, `reset()`, `harvest()`. The missing modifier on the sibling IS the bug."

This single rule explains a large share of critical access-control findings (missing guard on the sibling, not on the function you opened first).

---

## STACK ROUTER

Run the matching checklist. Do not grep Solidity patterns against Rust or Move and call that coverage.

- **Solidity / Vyper (EVM):** classes 1–11 below. On Vyper, record the compiler version. `0.2.15`, `0.2.16`, and `0.3.0` emitted a broken `@nonreentrant` lock (different storage slot per function) — the July 2023 Curve pool drains (~$70M across CRV/ETH, alETH/ETH, msETH/ETH, pETH/ETH). Do not apply that slot bug to `0.3.1+` or `0.4.x`; still confirm siblings share one lock. A lock in the source is not a lock in that bytecode.
- **Solana / Anchor:** prove with `solana-program-test` or a local validator and assert the token-account (or lamport) delta.
  1. Missing `Signer` / `has_one` / owner / mint-authority on every account that is written.
  2. Two mutable accounts of the same type: constrain `a.key() != b.key()` (duplicate mut / type cosplay).
  3. PDA seeds bind the authority and the unique id; `bump` is the canonical `find_program_address` bump.
  4. Remaining accounts used in CPI are still typed and owned by the expected program.
  5. CPI: callee is not attacker-chosen unless intended; `signer_seeds` are not replayable from another instruction.
  6. Token-2022: `transfer` that skips the transfer-hook CPI is a hook bypass; invoking the hook is a reentrancy surface. `permanent_delegate` / freeze / 100% fee → `meme-coin-audit`.
  7. Close: lamport destination is owner-signed; account data is zeroed.
  8. `init_if_needed` where `init` was meant: an attacker pre-creates (or re-creates) the account with their own data and authority before the honest instruction runs.
  9. Sysvar and instruction-introspection accounts passed as raw `AccountInfo`: constrain the address or use the typed `Sysvar` / `Instructions` — a fake `Clock`, `Rent`, or `Instructions` account is attacker-controlled input.
- **Move (Aptos / Sui):** prove with `aptos move test` / `sui move test` and an attacker-address balance delta.
  1. Missing `assert!` on coin value / amount before extract.
  2. `public` / `public(friend)` / `entry` wider than the intended caller set.
  3. Sui: `&` vs `&mut` vs owned; `key`+`store` on a type that should not be transferable; shared-object auth.
  4. `drop` on a resource that must be consumed (value discarded).

---

## 1. ACCOUNTING STATE DESYNCHRONIZATION
> #1 Critical bug class — 28% of all Criticals on Immunefi.

### What It Is
Two state variables supposed to stay in sync. One code path updates A but forgets B. Later code reads both and makes decisions based on stale B.

```
Real Value = A - B
If A updated but B isn't → Real Value appears larger → phantom value
```

### Root Cause Patterns

**Variant 1: Phantom Yield** (Yeet protocol — 35 duplicate reports)
```solidity
function startUnstake(uint256 amount) external {
    totalSupply -= amount;  // decremented BEFORE transfer
    // aToken.balanceOf(this) still reflects old value
    // yieldAmount = aToken.balanceOf - totalSupply = phantom yield
}
```

**Variant 2: Fast Path Skips State Update** (Alchemix V3)
```solidity
function claimRedemption(uint256 tokenId) external {
    if (transmuter.balance >= amount) {
        transmuter.transfer(user, amount);
        _burn(tokenId);
        return;  // EARLY RETURN — cumulativeEarmarked, _redemptionWeight, totalDebt never updated
    }
    // Slow path: updates all state vars correctly
    alchemist.redeem(...);
}
```

**Variant 3: Update Happens in Wrong Order** (Alchemix)
```solidity
function deposit(uint256 amount) external {
    _shares = (amount * totalShares) / totalAssets;  // calculated BEFORE deposit
    totalAssets += amount;   // assets added AFTER shares calculated → wrong rate
}
```

### Grep Patterns
```bash
# Find all accounting variables
grep -rn "totalSupply\|totalShares\|totalAssets\|totalDebt\|cumulativeReward\|rewardPerShare" contracts/

# Find all early returns in claim/redeem functions
grep -rn "\breturn\b" contracts/ -B3 | grep -B3 "if\b"

# For each early return: which state updates in normal path are skipped?
```

---

## 2. ACCESS CONTROL
> #2 Critical — 19% of Criticals. CeFi/key-compromise loss totals (De.Fi ~$946M in 2024, mostly stolen keys) are not the severity of a missing modifier.

### Variant 1: Missing Modifier on Sibling Function
```solidity
function vote(uint256 tokenId) external onlyNewEpoch(tokenId) {  // guarded
function reset(uint256 tokenId) external onlyNewEpoch(tokenId) { // guarded
function poke(uint256 tokenId) external {                         // NO GUARD → infinite FLUX inflation
}
```

### Variant 2: Wrong Check (Existence vs Ownership)
```solidity
function split(uint256 tokenId, uint256 amount) external {
    _requireOwned(tokenId); // OZ: reverts only if owner == address(0). Return value ignored.
    _burn(tokenId);
    _mint(msg.sender, amount); // caller receives a position they do not own
}
// ZeroLend VestedZeroNFT: split() did this (fraction minted to msg.sender, victim lock shrunk).
// Fix: require(msg.sender == _requireOwned(tokenId));
```

### Variant 3: Silent Modifier (the `_` is unconditional)
```solidity
// VULNERABLE — body runs for everyone; the if never reverts:
modifier onlyAdmin() {
    if (msg.sender != admin) { /* empty, or a log */ }
    _;
}
// Also vulnerable: `if (msg.sender == admin) { } _;`
// NOT a bypass: `if (msg.sender == admin) { _; }` — non-admins skip the body
// and get a silent success (no-op). That is not privilege escalation.
// CORRECT: if (msg.sender != admin) revert NotAdmin(); _;
```

### Variant 4: Uninitialized Proxy
```solidity
function initialize(address _owner) public {  // MISSING: initializer modifier
    owner = _owner;  // anyone can call → become owner
}
// Fix: constructor() { _disableInitializers(); }
```

### Variant 5: "Only EOA" (`tx.origin` / `extcodesize`) vs EIP-7702
```solidity
require(tx.origin == msg.sender);       // 7702 delegated EOA still passes; flash-loan "protection" is gone
require(msg.sender.code.length == 0);   // constructors pass (code empty); 7702 has a 23-byte designator so this one rejects them
```
`tx.origin == msg.sender` is not an EOA check after Pectra (May 2025). A signed 7702 authorization runs attacker bytecode as that EOA in the same tx while origin still equals sender. `code.length == 0` is the classic constructor bypass, not a substitute for a real role check. Proof: `evm_version = "prague"`, `vm.signAndAttachDelegation(implementation, attackerPk)`, one call that moves tokens or a privileged slot. A view of `code.length` is detected.

### Variant 6: `_msgSender()` vs `msg.sender` (ERC-2771)
Some paths use `Context._msgSender()` (trusted forwarder), siblings use `msg.sender`. The forwarder is then an alternate caller for one family and not the other. If anyone can set `trustedForwarder`, they impersonate any address. Same shape for `onlyOwner` on `msg.sender` while credits accrue to `_msgSender()`.

### Grep Patterns
```bash
# Find sibling function families — do ALL have the same modifier set?
grep -rn "function vote\|function poke\|function reset\|function update\|function claim\|function harvest" contracts/ -A2

# Ownership check: existence vs ownership?
grep -rn "_requireOwned\|ownerOf\|_isApprovedOrOwner\|_checkAuthorized" contracts/ -B5

# Silent modifiers
grep -rn "modifier\b" contracts/ -A8 | grep -B3 "if (" | grep -v "require\|revert"

# Uninitialized initializer
grep -rn "function initialize\b" contracts/ -A3
grep -rn "_disableInitializers()" contracts/

# isEOA / meta-tx
grep -rn "tx.origin\|code.length\|extcodesize\|_msgSender\|isTrustedForwarder\|trustedForwarder" contracts/
```

### Real Paid Examples

| Protocol | Payout | Bug |
|---|---|---|
| Wormhole | $10M | Uninitialized UUPS proxy → anyone calls initialize() |
| ZeroLend | n/a | split() uses existence check, not ownership check |
| Alchemix | n/a | poke() missing onlyNewEpoch → infinite FLUX inflation |
| Parity | $150M frozen | No access control on initWallet() in library |

---

## 3. INCOMPLETE CODE PATH
> #3 Critical — 17% of Criticals.

### The Function Family Comparison Test
```
1. List all state changes in function A (deposit/place/create)
2. List all state changes in function B (withdraw/update/cancel)
3. For each state change in A: does B have the corresponding reverse?
4. For each token transfer in A: does B have the corresponding refund?
If A does X but B doesn't do the reverse of X → BUG.
```

### Variant 1: Update Function Missing Refund (ThunderNFT)
```solidity
function place_order(OrderInput calldata order) external {
    token.safeTransferFrom(msg.sender, address(this), order.price);  // takes tokens
    orders[orderId] = order;
}
function update_order(OrderInput calldata updatedOrder) external {
    // BUG: NO REFUND for sell orders when price decreases → tokens permanently stuck
    orders[orderId] = updatedOrder;
}
```

### Variant 2: Partial Fill Token Stuck (Plume)
```solidity
function swapForETH(uint256 amountIn) external {
    token.safeTransferFrom(msg.sender, address(this), amountIn);
    uint256 filled = dex.swap(amountIn);  // partial fill possible
    _refundExcessEth(amountIn - filled);  // BUG: refunds ETH only, not ERC20
}
```

### Variant 3: mint() Bypasses Check That deposit() Has (MetaPool)
```solidity
function deposit(uint256 assets, address receiver) public override {
    shares = _deposit(assets, receiver);  // includes receipt validation
}
function mint(uint256 shares, address receiver) public override {
    assets = convertToAssets(shares);
    _mint(receiver, shares);  // MISSING: _deposit() validation → mints without receiving assets
}
```

### Variant 4: `msg.value` reused in multicall
```solidity
function multicall(bytes[] calldata data) external payable {
    for (uint256 i; i < data.length; ++i) {
        (bool ok,) = address(this).delegatecall(data[i]); // every leg sees the SAME msg.value
        require(ok);
    }
}
function deposit() external payable {
    shares[msg.sender] += msg.value; // two legs → two credits, one payment
}
```
`msg.value` is not writable, so every `delegatecall` leg still sees the original value. A fix has to account in storage or transient storage (first leg consumes it, later legs read 0) or take an explicit `amount` instead of `msg.value`. Prove with one call that credits `2 * msg.value` and withdraws both.

### Variant 5: Fee-on-transfer credited at face value
```solidity
uint256 beforeBal = token.balanceOf(address(this));
token.safeTransferFrom(msg.sender, address(this), amount);
_mint(msg.sender, amount); // should be balanceOf(this) - beforeBal
```
Shares or internal credit use the argument, not the tokens received. Second depositor's withdraw reverts, or the attacker withdraws more than the vault holds. Same shape for rebasing tokens and for `safeTransfer` that returns a short amount.

### Variant 6: `try/catch` swallows the revert that should roll back accounting
```solidity
balances[user] -= amount; // effect first
try token.transfer(user, amount) {} catch {
    // continues; user is already debited, tokens never left
}
```
The `catch` is a second code path. List every state write that already ran, and the reverse that the `catch` skips. Same for `try token.transfer(...) returns (bool ok)` when `ok == false` is ignored. Prove: one call, attacker (or victim) balance vs vault inventory desync, then a withdraw that extracts the gap.

### Grep Patterns
```bash
grep -rn "function place_\|function create_\|function add_\|function open_" contracts/ -A5
grep -rn "function update_\|function modify_\|function cancel_" contracts/ -A5
grep -rn "safeApprove\b" contracts/    # safeApprove without zero-reset before
grep -rn "delete\b" contracts/ -B5 -A5  # delete before operation completes
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
grep -rn "function multicall" contracts/ -A12
grep -rn "try \|} catch" contracts/ -B8 -A8
```

---

## 4. OFF-BY-ONE & BOUNDARY CONDITIONS
> #4 High — 22% of Highs. Single character change. Massive impact.

### Root Cause
```solidity
// VeChain Stargate — post-exit reward drain:
function _claimableDelegationPeriods(address delegator) internal view returns (uint256) {
    if (endPeriod > nextClaimablePeriod) {  // BUG: should be >=
        return 0;  // exited users get nothing
    }
    return nextClaimablePeriod - lastClaimedPeriod;  // rewards for period AFTER exit
}
```

### Mental Test for Every Comparison
> For every `if (A > B)`: "What happens when A == B?" Is that correct?

### 6 Boundary Locations to Check
1. Period/Epoch boundaries: `>` vs `>=` at period end
2. Time-based locks: does `block.timestamp == deadline` lock or unlock?
3. Loop break conditions: `break` with `>` vs `>=`
4. Array index boundaries: `i <= array.length` (should be `i < array.length`)
5. Amount/balance boundaries: `>= amount` allows exact full withdrawal?
6. Rounding/precision: can any input produce 0 output that should be non-zero?

### Grep Patterns
```bash
# Boundaries in comparisons
grep -rn "Period\|Epoch\|Round\|Deadline\|period\|epoch\|deadline" contracts/ -A3 | grep "[<>][^=]"

# Loop breaks
grep -rn "\bbreak\b" contracts/ -B10

# Off-by-one in array access
grep -rn "\.length\s*-\s*1\|i\s*<=\s*.*\.length\b" contracts/
```

---

## 5. ORACLE / PRICE MANIPULATION
> Among the largest individual payouts. Mango was ~$117M of thin-market perp price manipulation (Oct 2022). Curve's ~$70M (30 Jul 2023) was Vyper reentrancy, not an oracle bug — section 7.

### Bug A: Missing Staleness Check (most common)
```solidity
// VULNERABLE:
(, int256 price,,,) = priceFeed.latestRoundData();
return uint256(price);  // If Chainlink node goes down, stale price returned indefinitely

// CORRECT:
(, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "Stale price");
require(price > 0, "Invalid price");
```

### Bug B: Pyth / pull oracle used unsafely
`price` is `int64` (can be negative); `conf` is `uint64`; `expo` is `int32`. Casting `uint64(p.price)` on a negative price is not a check.
```solidity
// VULNERABLE: ignores publishTime. Documented as unsafe.
PythStructs.Price memory p = pyth.getPriceUnsafe(id);
return p.price;

// Minimum bar for a state-changing path:
PythStructs.Price memory p = pyth.getPriceNoOlderThan(id, MAX_AGE);
require(p.price > 0, "bad price");
uint64 px = uint64(p.price);
require(p.conf * 10 <= px, "uncertain"); // conf within 10% of price
// Scale by p.expo before comparing to token amounts. A raw int with expo -8 is not a token unit.
// Direction: value collateral at px - conf, debt at px + conf. One mid price for both is the bug.
```
Same family for Redstone and API3: the update is calldata. Check signer threshold, timestamp window, and feed id. A storage fallback used when the payload is missing is a silent stale price. Anyone being able to push the update in the same tx is fine only if those checks hold.

### Bug C: Spot or short window (decision, not a magic duration)
```solidity
// VULNERABLE: spot. slot0 and getReserves move inside one tx.
uint160 sqrtPriceX96 = slot0.sqrtPriceX96;
(uint112 r0, uint112 r1,) = pair.getReserves();
```
A flash loan is one transaction, so any window that fits in one tx (spot, 60s TWAP updated in the same tx, a "TWAP" that reads the current observation twice) is movable with borrowed funds. A 30-minute window blocks single-tx flash loans and still loses to a multi-block push on a thin pool — 1800s is not "safe". Prefer a push oracle with the checks in Bug A/E. If the design is a TWAP, the window has to be long relative to the pool's liquidity, and cardinality must actually be grown (`increaseObservationCardinalityNext`) or the window silently shortens.

### Bug D: Failover is the real target
Primary Chainlink with a Uniswap-spot fallback, or "if stale, use `slot0`", reintroduces Bug C on the path that fires during the incident. Both legs need their own staleness and a disagreement bound. Audit the branch that runs when the primary reverts, not only the happy path.

### Bug E: L2 sequencer uptime (Base, Arbitrum, Optimism, and forks)
Chainlink's own consumer check. `answer == 0` means the sequencer is **up**; `answer == 1` means **down** (easy to invert).
```solidity
(, int256 answer, uint256 startedAt,,) = sequencerUptimeFeed.latestRoundData();
require(answer == 0, "sequencer down");
require(startedAt != 0, "invalid round"); // Arbitrum returns 0 before the feed is initialized
require(block.timestamp - startedAt > GRACE_PERIOD, "grace");
```
Missing grace lets liquidations fire on the stale post-downtime price. Do not hardcode `MAX_PRICE_AGE = 1 hours` for every feed: set it from that feed's heartbeat plus a small grace. A 1h cap on a 24h heartbeat reverts healthy updates; a 24h cap on a 1h heartbeat never catches staleness.

`answeredInRound >= roundId` is a legacy Flux-aggregator check. OCR feeds often set them equal. A missing `answeredInRound` check on a current OCR feed is not, by itself, a finding. `minAnswer` / `maxAnswer` were removed from many feeds — don't report their absence as a bug.

### Bug F: Signed report (Data Streams / Redstone / API3)
The price is calldata in this tx, not `latestRoundData`.
```solidity
// VULNERABLE: decode without verify, or verify then ignore feed id / timestamp
(int192 price,) = abi.decode(unverifiedReport, (int192, uint32));
```
Bar: `VerifierProxy.verify` (Chainlink Data Streams), Redstone `getOracleNumericValueFromTxMsg`, or API3 `fulfill` actually runs; then check **feed id**, **observationsTimestamp / expiration** against `MAX_AGE`, **price > 0**, and that a missing payload does not fall back to an unsanitized storage slot (Bug D). Anyone submitting the report in the same tx is expected — the signature and freshness are the control.

### Proof
Detected: a missing `updatedAt`, a `getPriceUnsafe` call, or a report decoded without `verify`. Proven: on a fork, one sequence moves the price the protocol actually reads, a liquidation or borrow or mint uses that price, and the attacker address is ahead after the loan is repaid (or the position is closed). Log both balances. A view returning a stale number is not impact.

### Grep Patterns
```bash
# Staleness not consulted
grep -rn "latestRoundData" contracts/ -A8 | grep -v "updatedAt\|timestamp"

# Pull oracles
grep -rn "getPriceUnsafe\|getPriceNoOlderThan\|extractPrice\|getPrice\b" contracts/ -A8

# Spot reads
grep -rn "getReserves\|slot0\b\|observe(" contracts/ -A3

# L2 consumer with no sequencer feed
grep -rn "sequencerUptime\|startedAt" contracts/

# Signed-report oracles (not latestRoundData)
grep -rn "VerifierProxy\|verify(.*report\|getOracleNumericValueFromTxMsg\|fulfill(" contracts/ -A10
```

---

## 6. ERC4626 VAULT ATTACKS

### Exchange Rate Manipulation (near-empty vault)
```solidity
// VULNERABLE — first depositor attack:
// 1. Attacker deposits 1 wei → gets 1 share
// 2. Attacker donates large amount directly (transfer, not deposit)
// 3. Exchange rate: 1 share = (1 + donation) assets
// 4. Victim deposits → rounds down to 0 shares → free donation to attacker

// OZ v4.9+: shares = assets * (supply + 10**offset) / (assets + 1)
function _decimalsOffset() internal view virtual override returns (uint8) {
    return 0; // 10**0 = 1 virtual share. This is OZ's default, not "no mitigation".
}
```
OZ's default offset of 0 still adds one virtual share, which blocks the textbook "victim gets 0 shares" case for a normal deposit. A hand-rolled `assets * supply / totalAssets` with no `+ 1` is fully inflatable. Raising the offset makes the donation more expensive; it is not a proof. Confirm on a fork: empty or near-empty vault, direct donation, victim deposits, measure shares. Rounding must favor the vault (`convertToShares` / `previewDeposit` down; `previewMint` / `previewWithdraw` up). The opposite direction is an extractable leak — repeat it in one tx and assert the asset delta. Fee-on-transfer and rebasing assets desync shares when the vault credits the argument instead of the balance delta (variant 5 above).

### ERC4626 Transfer (moves shares but not stake/lock records)
```solidity
// VULNERABLE: shares transferred, but lock records stay with original owner
// → shares stuck, can't redeem → permanent freeze (Belong pattern)
function transfer(address to, uint256 amount) external override {
    _transfer(msg.sender, to, amount);  // moves shares
    // MISSING: transfer lock record from msg.sender to `to`
}
```

### Grep Patterns
```bash
grep -rn "function transfer\|function transferFrom" contracts/ -A15
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```

---

## 7. REENTRANCY
> CEI stops same-contract state re-entry. It does not stop a stale view or a hook into another protocol.

### Variants
- **Single-function**: re-enters the same function before state is updated
- **Cross-function**: re-enters a sibling that trusts the stale state
- **Cross-contract**: callback into another protocol (the other protocol is the one that pays)
- **Read-only**: a view (`getRate`, `convertToAssets`, `getPricePerShare`) is consumed mid-callback while balances and supply are out of sync. CEI does not close this. Curve/Balancer-style share-price reads during ETH transfer are the pattern.
- **Hooks**: ERC-777 `tokensToSend`/`tokensReceived`, ERC-721 `onERC721Received`, ERC-1155 `onERC1155Received`, Uniswap v4, callback vaults. A `nonReentrant` on the outer function does nothing if the hook lands in a different contract that reads stale state.
- **Uniswap v4 (decision tree):** (1) Address LSBs must match implemented callbacks — a missing flag is a **silent skip** (fee, points, slippage never run). (2) Every hook fn must revert unless `msg.sender == poolManager`. (3) `hookData` is the swapper's bytes, not identity — do not `abi.decode` an address and mint points / attribute fees to it. (4) `take` / `settle` / returned delta must net zero per currency or the extra is stolen or stuck. (5) Return-delta flags without the parent action flag are invalid; `BaseHook` checks this, a raw `IHooks` may not. Proof: one swap, attacker token or points delta, or a skipped hook that leaves the pool's accounting wrong.
- **Compiler lock**: Vyper `0.2.15` / `0.2.16` / `0.3.0` `@nonreentrant` used a different slot per function (Curve, ~$70M, 30 Jul 2023). Read the version, not just the decorator.

### Root Cause Pattern
```solidity
// VULNERABLE (effects after interaction):
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");  // INTERACTION first
    require(success);
    balances[msg.sender] -= amount;  // EFFECT after → reentrancy window
}

// CEI stops re-entry into this function's state. It does not fix a view that
// already moved `totalAssets` but not `totalSupply` (or the reverse) before the call.
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}

// Read-only: external protocol calls convertToAssets() inside the callback.
function convertToAssets(uint256 shares) public view returns (uint256) {
    return shares * totalAssets / totalSupply; // stale mid-withdrawal
}
```
Transient-storage guards (`tstore` / OZ `ReentrancyGuardTransient`, EIP-1153) cover one contract for one transaction. They do not make a view consistent for a different protocol. If `tload` is cached before an external call and reused after, treat it as stale state.

### Grep Patterns
```bash
# External calls before state updates
grep -rn "\.call{value\|safeTransfer\|transfer(" contracts/ -B10 | grep -v "require\|revert"

# Missing nonReentrant modifier on critical functions
grep -rn "function withdraw\|function redeem\|function claim" contracts/ -A2 | grep -v "nonReentrant"

# Guard present or not — absence is a lead, not a finding
grep -rn "nonReentrant\|ReentrancyGuard\|_notEntered\|tstore\|tload" contracts/

# Hook surfaces (incl. v4)
grep -rn "onERC721Received\|onERC1155Received\|tokensReceived\|tokensToSend\|beforeSwap\|afterSwap\|hookData\|PoolManager\|take(\|settle(" contracts/
```

**Proof:** one fork sequence. Attacker contract is the receiver. Assert the attacker token delta (or the bad debt left in the lender) after the outer call returns. A revert-free callback, or a view that merely changes mid-tx, is detected. Stop after one profitable path.

---

## 8. FLASH LOAN ATTACKS

### Oracle Manipulation via Flash Loan
```solidity
// Attack flow:
// 1. Borrow $100M from Aave flash loan
// 2. Dump token in Uniswap pool → crash spot price
// 3. Protocol reads Uniswap spot → undercollateralized loans accepted
// 4. Borrow max against cheap collateral
// 5. Repay flash loan, keep profits
```

A flash loan is an amplifier, not a bug class. If the price, share rate, or governance weight cannot be moved inside one transaction, a flash loan does not create impact. Governance that reads `balanceOf` (or current total supply) with no checkpoint is the same primitive: borrow, vote, repay.

### What to look for
```bash
grep -rn "getReserves\|getAmountsOut\|slot0\b" contracts/ -A5
# spot from reserves, or Uniswap V3 slot0, moves inside the loan
grep -rn "balanceOf(msg.sender)" contracts/ | grep -i "vote\|quorum\|propose"
```

**Proof:** attacker profit **after** the loan is repaid, in one tx, on a fork. Log pre and post. Do not loop the attack, and do not touch mainnet.

---

## 9. SIGNATURE REPLAY

### Missing Nonce
```solidity
// VULNERABLE:
function permit(address owner, address spender, uint256 value,
                uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 hash = keccak256(abi.encodePacked(owner, spender, value, deadline));
    // MISSING: nonce not included → same signature usable multiple times
    require(ecrecover(hash, v, r, s) == owner);
}
```

### Missing domain (chain id, contract, malleability, address(0))
```solidity
// VULNERABLE: ecrecover returns address(0) on a malformed signature.
// If owner is unset, signer == owner passes. High-s (malleable) signatures also pass.
address signer = ecrecover(hash, v, r, s);
require(signer == owner);

// Bar: EIP-712. Domain binds name, version, block.chainid, address(this).
// structHash uses abi.encode. encodePacked on dynamic types collides.
// The "\x19\x01" digest itself is encodePacked of fixed-size fields, per the spec.
bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
signer = ECDSA.recover(digest, v, r, s); // OZ rejects address(0) and high s
require(signer == owner);
require(block.timestamp <= deadline);
nonces[owner]++; // before effects. A bitmap nonce (Permit2) must mark the bit, not only read it.
```
`abi.encodePacked` of dynamic types (two strings, or a string beside another dynamic field) is a hash collision, not just a replay. Permit and Permit2: the nonce or unordered-nonce bit must flip, the deadline must be checked, and the spender has to be inside the struct. EIP-1271 (`isValidSignature`) replays when the contract wallet does not bind nonce and chain. A chain id baked into the domain at construction replays after a fork; recompute the separator from `block.chainid` when verifying.

### Grep Patterns
```bash
grep -rn "ecrecover\|ECDSA\.recover\|isValidSignature" contracts/ -B25
# Hash must include nonce + chainId + verifyingContract. Reject address(0).

grep -rn "abi.encodePacked" contracts/ -B5 -A5
grep -rn "nonce\|_nonces\|nonces\[" contracts/
```

**Proof:** same signature (or same digest) succeeds twice, or succeeds on a second chain id / contract address, and the second success moves tokens or changes a privileged slot. A recovered address in a view is detected.

---

## 10. PROXY / UPGRADE ISSUES

### Storage collision
Diff `forge inspect <Contract> storage-layout` between the live implementation and the upgrade. A missing `__gap` on an inherited upgradeable contract shifts every later slot. ERC-7201 namespaced slots (`erc7201:`) and EIP-1967 implementation/admin slots are the layouts to compare. Classic collision: proxy slot 0 is `_owner`, implementation slot 0 is `_initialized`, and writing one overwrites the other.

### Uninitialized implementation, and the front-run
`initialize` without the `initializer` modifier, and no `_disableInitializers()` in the implementation constructor, lets anyone call `initialize` on the implementation. That writes the **implementation's** storage, not the proxy's, unless the upgrade check reads that storage:
- Owner lives in proxy storage (normal UUPS / transparent): you do not become the proxy admin. Don't claim a proxy takeover.
- Upgrade auth is read when `upgradeTo` is invoked **on the implementation** (Wormhole, $10M, Feb 2022): the caller sets the guardian set and submits a new implementation.
- **EIP-6780 (Dencun, March 2024):** `SELFDESTRUCT` deletes code only if the contract was created in the same transaction. On Ethereum and L2s that adopted it, destroying an existing implementation no longer bricks the proxy. The live path is an `upgradeTo` the auth check allows, or a same-transaction metamorphic recreate. "I can selfdestruct it" is not a brick unless you show code size 0 after the call.

If deploy and `initialize` are separate transactions, anyone can initialize in between. A factory that does both in one transaction closes that.

### delegatecall target is chosen by the attacker
```solidity
function execute(address target, bytes calldata data) external {
    target.delegatecall(data); // unprivileged caller picks target and calldata
}
```
`onlyOwner` plus "the owner might be compromised" is centralization risk — read the program brief before grading it. The reportable case is an unprivileged caller choosing `target` or `data`. Also check UUPS `_authorizeUpgrade` is not empty.

### Selector clash (diamond / ERC-2535)
Two facets expose the same 4-byte selector, or a newly added facet `initialize` is callable without `initializer`. Loupe `facetAddress(sel)` vs the actual `delegatecall` target must match. Proof: the attacker-reachable facet runs and a privileged slot or token balance moves.

### Grep Patterns
```bash
grep -rn "function initialize\b\|_disableInitializers\|initializer\|_authorizeUpgrade" contracts/
grep -rn "delegatecall\b" contracts/ -B3 -A5
grep -rn "0x360894\|EIP1967\|_IMPLEMENTATION_SLOT\|erc7201\|diamondCut\|facetAddress" contracts/
```

**Proof:** the attacker address becomes `owner`, or the implementation slot changes to a contract you deployed, in one fork test. A public `initialize` that only sets storage you cannot use is detected.

---

## 11. CROSS-CHAIN / MESSAGING
> Destination mint without a matching source lock, or the same message credited twice.

Walk **both** ends. A destination that accepts a payload without a bound source is the bug. Sequencer censorship or "the relayer might be evil" is not stolen funds unless an unprivileged caller can also deliver.

1. **Who can call the receive path?** `lzReceive` / `_lzReceive` (LayerZero V2), `_ccipReceive` (CCIP), `handle` (Hyperlane), `receiveWormholeMessages` — only the official endpoint/mailbox. An unprivileged `processMessage` is the finding.
2. **Bind the message:** source chain id, source sender (peer / trusted remote), nonce or `guid` **consumed** (not only read), payload hash. Skip any one of those and replay or forge.
3. **Peer / trusted remote / ISM** settable by an unprivileged caller → they point dest at a chain they control.
4. **Amount scaling:** 6-dec vs 18-dec (or shared-decimals vs local-decimals) on the mint path. Off-by-10^n is a drain, not a rounding note.
5. **Unordered nonce / skipped nonce:** an old message still deliverable after a peer or config change.

**Proof:** one Foundry test (fork dest, mock the endpoint `msg.sender`, or fork both ends). Tokens minted or unlocked on dest with no matching lock, or the same `guid`/nonce credited twice. Log the dest attacker balance. A view of the nonce mapping is detected.

```bash
grep -rn "lzReceive\|_lzReceive\|_ccipReceive\|handle(\|receiveWormholeMessages\|trustedRemote\|setPeer\|quoteFee" contracts/ -A12
grep -rn "nonce\|guid\|sourceChain\|srcEid" contracts/ | head
```

---

## DETECTED vs PROVEN

A grep hit, a Slither or Aderyn warning, a revert string, or a view returning an odd number is **detected**. It is not a report.

**Proven** (draft-ready):
- One Foundry test. Pin the fork block in `setUp`, or deploy locally when the bug is in code you control. Do not broadcast. `--fork-url` without a block number follows chain head, so the proof is not reproducible.
- Attacker is a fresh `makeAddr` or an attacker contract. Not the admin, unless the bug is an unauthenticated `initialize`.
- Measured delta: attacker token balance, shares, or a privileged slot (`owner`, implementation) becomes a value you chose. `assertGt(after, before)` and log the difference.
- Control: the same calls from an unrelated address do not receive that delta.
- The impact sentence uses that delta at the fork block. No "could drain TVL". No severity the program table does not support.
- Stop after one profitable path. No loop over users, no mass liquidation, no mainnet call.

HTTP body-diff, n≥10 timing, and DNS callbacks are web2 signals. They do not apply here. The on-chain stand-in is the attacker contract's balance or an event you assert.

### How primitives chain

| Lead | Compose with | What the test has to show |
|---|---|---|
| Stale, spot, fallback, or unverified signed report | a swap or flash loan that moves the price the code reads | borrow, mint, or liquidation profit after the loan is repaid |
| Read-only reentrancy | a lender that prices collateral from that view | borrowed asset kept, bad debt left in the lender |
| Accounting desync or ERC-4626 rounding/donation | a second depositor, or a withdraw | attacker withdraws more assets than they deposited |
| `multicall` + `msg.value` | two legs that both credit `msg.value` | credit of `2 * msg.value` for one payment |
| Missing nonce or domain | a second use of the same signature | a second transfer or a second privileged write |
| Uninitialized implementation | upgrade auth honored on the direct call | implementation slot changes. Post-Dencun, code size still non-zero after `SELFDESTRUCT` is not a brick |
| Sibling missing the modifier | the sibling is callable by the attacker | the state the modifier was meant to protect (Alchemix `poke` mints extra FLUX) |
| `tx.origin == msg.sender` | EIP-7702 delegation in the same tx | protected function runs from a delegated EOA and tokens or a slot move |
| v4 `hookData` as identity | swap with attacker-chosen bytes | points/fees minted to the attacker, or `take` without matching `settle` |
| Dest receive without consumed nonce | replay or mock-endpoint deliver | dest tokens minted twice, or minted with no source lock |

If the chain only works with an admin key the program excludes, leave the severity where the brief puts centralization risk.

---

## FOUNDRY POC TEMPLATE

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

/// Replace the constants. Do not broadcast.
contract ExploitTest is Test {
    address constant TARGET = address(0);
    uint256 constant FORK_BLOCK = 1;
    IERC20 token = IERC20(address(0));
    address attacker;

    function setUp() public {
        vm.createSelectFork(vm.envString("RPC_URL"), FORK_BLOCK);
        attacker = makeAddr("attacker");
    }

    function test_exploit() public {
        uint256 beforeBal = token.balanceOf(attacker);
        vm.startPrank(attacker);
        // one sequence
        vm.stopPrank();
        uint256 afterBal = token.balanceOf(attacker);
        assertGt(afterBal, beforeBal, "no attacker delta");
        console2.log("delta", afterBal - beforeBal);
        // Control: repeat the sequence from an unrelated address.
        // That delta stays 0 unless the bug is intentionally global.
    }
}
```

`deal(token, account, amount)` writes a standard ERC-20 balance slot. It does not work on aTokens, rebasing tokens, or proxies whose balance mapping lives elsewhere. For those, `vm.prank` a whale and transfer. A balance you only created with `deal` is not impact.

### Cheatcodes
```solidity
vm.prank(addr) / vm.startPrank(addr) / vm.stopPrank()
vm.deal(addr, amount)                 // ETH only
deal(token, addr, amount)             // standard ERC-20 slot; see caveat above
vm.warp(ts) / vm.roll(n)
vm.createSelectFork(rpc, blockNumber) // pin the block inside setUp
vm.mockCall(addr, calldata, ret)      // stub an oracle or a sequencer feed
vm.store(addr, slot, value)           // last resort when deal() cannot reach the slot
vm.expectRevert()
vm.assume(cond)                        // fuzz: discard, don't "prove" by filtering the failure away
vm.signAndAttachDelegation(impl, pk)   // EIP-7702; needs evm_version = "prague"
```

### Run
```bash
RPC_URL=... forge test --match-test test_exploit -vvvv
# fuzz: function testFuzz_...(uint256 x). invariants: function invariant_...
forge inspect Target storage-layout
```

---

## Related Skills & Chains

- **`meme-coin-audit`** — Meme coin or SPL token. Rug checks (mint authority, freeze authority, LP lock) are that skill's workflow; use it instead of the DeFi class list.
- **`triage-validation`** — Run the 7Q gate on the fork PoC before writing the draft. STOP at draft — do not submit.
- **`report-writing`** — Draft body: Foundry test, root-cause snippet, and the token amount the test actually moved.
- **`offensive-osint`** — Frontend, admin API, RPC gateway, indexer. On-chain code stays in this skill.
- **`bb-methodology`** — Confirms the engagement is authorized. This skill's triage score orders depth inside that engagement.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream content covers the WHAT;
> this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Easy to mis-file

- A flash loan only amplifies a price, share rate, or vote weight that already moves inside one transaction (section 8).
- Reentrancy that still shows up is the read-only view and the hook into a second protocol, including code that already uses CEI (section 7).
- On a Chainlink primary, the branch that pays is the fallback and the L2 sequencer check (section 5), not the happy-path `latestRoundData`.

### Surfaces the class list underspecifies

- **EIP-7702:** section 2 variant 5. Treat a signed authorization as root on the account.
- **ERC-4337 paymasters:** if `sender` and `callData` are not bound in `validatePaymasterUserOp`, the paymaster sponsors the attacker's userOp and can lose its deposit on the first call. One stolen deposit is the proof. Do not grief the bundler.
- **Bridges:** section 11. Sequencer censorship alone is not stolen funds.
- **LST/LRT:** the oracle hardcodes 1:1 while the market has depegged. Prove a liquidation or a mint that leaves a measured asset delta. "It could depeg" is not a finding.

### Tools

`forge test -vvvv --match-test test_exploit` for the one-shot. Fuzz entrypoints are `testFuzz_*`. Invariants are `invariant_*`. `forge inspect <Contract> storage-layout` for the proxy diff. There is no `forge fuzz` subcommand. Slither or Aderyn is the first pass only. Mythril only on a small single contract. Anvil or Tenderly for state. Solana: a local validator. Move: `aptos move test` / `sui move test`.

### Scope

Read the program brief. A finding that needs the multisig to act maliciously is centralization risk and is usually downgraded or excluded. Prove the unprivileged caller.

### Draft

STOP at draft. Never submit without explicit approval. One `forge test`, the root-cause snippet, and the token amount that test moved. Use the program's severity table for that amount. Do not invent a payout.
