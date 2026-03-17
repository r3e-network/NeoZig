# RPC Extended Responses Split Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split `src/rpc/extended_responses.zig` into smaller category files while preserving the existing import path and top-level exported response names.

**Architecture:** Keep `extended_responses.zig` as the stable façade. Move concrete response definitions into focused category files for account, oracle/naming, network/state, and system/express responses. Re-export the original top-level names unchanged so `rpc.types`, `response_parser.zig`, and downstream callers continue to compile without interface changes.

**Tech Stack:** Zig, existing RPC response parsing layer, `zig build rpc-test`, `zig build test`, `zig build examples`

### Task 1: Reproduce the missing category namespaces

**Files:**
- Modify: `src/rpc/extended_responses.zig`
- Test: `src/rpc/extended_responses.zig`

**Step 1: Write the failing test**

Add a façade test that expects:
- `account`
- `oracle`
- `network`
- `system`

And assert stable mappings:
- `account.NeoAccountState == NeoAccountState`
- `oracle.OracleRequest == OracleRequest`
- `network.NeoGetStateRoot == NeoGetStateRoot`
- `system.NeoListPlugins == NeoListPlugins`

**Step 2: Run test to verify it fails**

Run: `zig build rpc-test --summary all`
Expected: FAIL because the category namespaces do not exist yet

### Task 2: Split the extended response file

**Files:**
- Create: `src/rpc/extended_account_responses.zig`
- Create: `src/rpc/extended_oracle_responses.zig`
- Create: `src/rpc/extended_network_responses.zig`
- Create: `src/rpc/extended_system_responses.zig`
- Modify: `src/rpc/extended_responses.zig`

**Step 1: Move account-oriented responses**

Move:
- `NeoAccountState`
- `NeoAddress`
- `TransactionSendToken`
- `NeoGetUnclaimedGas`
- `NeoValidateAddress`
- `Nep17Contract`

Into `extended_account_responses.zig`.

**Step 2: Move oracle and naming responses**

Move:
- `OracleRequest`
- `OracleResponseCode`
- `ContractMethodToken`
- `NameState`
- `RecordState`

Into `extended_oracle_responses.zig`.

**Step 3: Move network/state responses**

Move:
- `NeoGetNextBlockValidators`
- `NeoGetStateHeight`
- `NeoGetStateRoot`
- `NeoWitness`
- `NeoNetworkFee`
- `PopulatedBlocks`

Into `extended_network_responses.zig`.

**Step 4: Move system/express responses**

Move:
- `NeoListPlugins`
- `NativeContractState`
- `ExpressContractState`
- `ExpressShutdown`
- `Diagnostics`
- `ContractStorageEntry`

Into `extended_system_responses.zig`.

**Step 5: Rebuild the façade**

Make `extended_responses.zig`:
- expose `account`, `oracle`, `network`, `system`
- re-export the original top-level names unchanged
- keep the existing tests

### Task 3: Verify the split

**Files:**
- Test only

**Step 1: Run targeted verification**

Run:
- `zig build rpc-test --summary all`

Expected: PASS

**Step 2: Run broader regression verification**

Run:
- `zig build test`
- `zig build examples`

Expected: PASS
