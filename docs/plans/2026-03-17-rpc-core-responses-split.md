# RPC Core Responses Split Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split `src/rpc/responses.zig` into smaller response-category files while preserving the existing `responses.zig` import path and top-level exported types.

**Architecture:** Keep `responses.zig` as the stable façade. Move concrete response definitions into focused files for blockchain, invocation, token, and contract responses, plus a small shared helper module for JSON/string conversion helpers. Re-export the original top-level names so `response_parser.zig`, `rpc.types`, and downstream callers remain unchanged.

**Tech Stack:** Zig, existing RPC response parser, `zig build rpc-test`, `zig build test`, `zig build examples`

### Task 1: Reproduce the missing category namespaces

**Files:**
- Modify: `src/rpc/responses.zig`
- Test: `src/rpc/responses.zig`

**Step 1: Write the failing test**

Add a façade test that expects:
- `blockchain`
- `invocation`
- `token`
- `contract`

And assert stable mappings:
- `blockchain.NeoBlock == NeoBlock`
- `invocation.InvocationResult == InvocationResult`
- `token.Nep17Balances == Nep17Balances`
- `contract.ContractState == ContractState`

**Step 2: Run test to verify it fails**

Run: `zig build rpc-test --summary all`
Expected: FAIL because the category namespaces do not exist yet

### Task 2: Split the core response file

**Files:**
- Create: `src/rpc/responses_common.zig`
- Create: `src/rpc/responses_blockchain.zig`
- Create: `src/rpc/responses_invocation.zig`
- Create: `src/rpc/responses_token.zig`
- Create: `src/rpc/responses_contract.zig`
- Modify: `src/rpc/responses.zig`

**Step 1: Extract shared helpers**

Move:
- `stringifyJsonValue`
- `jsonValueToOwnedString`
- `parseIntFromJson`

Into `responses_common.zig`.

**Step 2: Move blockchain-oriented responses**

Move:
- `NeoBlock`
- `NeoWitness`
- `Transaction`
- `TransactionSigner`
- `WitnessRule`
- `WitnessCondition`
- `NeoVersion`
- `HardforkInfo`
- `ProtocolConfiguration`
- `NetworkFeeResponse`
- `SendRawTransactionResponse`

Into `responses_blockchain.zig`.

**Step 3: Move invocation/application-log responses**

Move:
- `InvocationResult`
- `NeoApplicationLog`
- `Execution`
- `Notification`

Into `responses_invocation.zig`.

**Step 4: Move token responses**

Move:
- `Nep17Balances`
- `TokenBalance`
- `Nep17Transfers`
- `TokenTransfer`

Into `responses_token.zig`.

**Step 5: Move contract responses**

Move:
- `ContractState`
- `ContractNef`
- `ContractFeatures`
- `ContractManifest`
- `ContractGroup`
- `ContractParameterDefinition`
- `ContractMethod`
- `ContractEvent`
- `ContractABI`
- `ContractPermission`

Into `responses_contract.zig`.

**Step 6: Rebuild the façade**

Make `responses.zig`:
- expose `blockchain`, `invocation`, `token`, `contract`
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
