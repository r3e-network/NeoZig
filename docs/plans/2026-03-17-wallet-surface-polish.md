# Wallet Surface Polish Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the wallet module safer and clearer by fixing account ownership hazards and introducing canonical names for the two wallet account models without breaking existing callers.

**Architecture:** Keep the additive namespace-first layout, but tighten the wallet surface so the preferred API exposes distinct names for signer accounts versus stored wallet accounts. Internally, make wallet-owned account storage clone on write and return non-owning views on read so callers do not accidentally double-free shared buffers.

**Tech Stack:** Zig, `std.testing`, existing wallet/runtime modules, `zig build test`

### Task 1: Reproduce the wallet ownership bug

**Files:**
- Modify: `tests/wallet_tests.zig`
- Test: `tests/wallet_tests.zig`

**Step 1: Write the failing test**

Add a test that:
- creates a wallet
- creates a wallet-owned account through `wallet.createAccount(...)`
- deinitializes the returned account copy
- lets `wallet.deinit()` run afterward

This should expose the current shared-ownership bug.

**Step 2: Run test to verify it fails**

Run: `zig build test`
Expected: allocator/double-free failure in wallet account cleanup

### Task 2: Make wallet account storage ownership-safe

**Files:**
- Modify: `src/wallet/neo_wallet.zig`
- Test: `tests/wallet_tests.zig`

**Step 1: Write the minimal implementation**

In `src/wallet/neo_wallet.zig`:
- add explicit ownership flags for account-owned buffers
- add helpers to deep-clone an account for wallet storage
- add helpers to create non-owning account views for read APIs
- clone on `addAccount(...)`
- keep `createAccount(...)` and `importAccount(...)` returning safe caller-owned values
- ensure `getAccount(...)`, `getDefaultAccount(...)`, and `getAccounts(...)` return safe non-owning views instead of shared owning copies

**Step 2: Run tests to verify it passes**

Run: `zig build test`
Expected: green

### Task 3: Clarify the public wallet surface

**Files:**
- Modify: `src/wallet/account_namespace.zig`
- Modify: `src/wallet/mod.zig`
- Modify: `src/neo.zig`
- Modify: `docs/API.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/USAGE.md`
- Modify: `README.md`

**Step 1: Add canonical names**

Add explicit aliases for:
- signer-capable account type
- stored wallet account type

Keep existing `Account` / `WalletAccount` aliases as compatibility exports.

**Step 2: Add coverage**

Add a small namespace assertion test so the preferred and compatibility aliases stay wired correctly.

**Step 3: Update docs**

Document the preferred names and the ownership model for returned wallet accounts.

### Task 4: Verify the refactor end to end

**Files:**
- Test only

**Step 1: Run targeted verification**

Run:
- `zig build wallet-test`
- `zig build test`

Expected: PASS

**Step 2: Run broader regression verification**

Run:
- `zig build rpc-test`
- `zig build examples`

Expected: PASS
