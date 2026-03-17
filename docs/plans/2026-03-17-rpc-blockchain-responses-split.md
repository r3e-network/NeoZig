# RPC Blockchain Responses Split Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split `src/rpc/responses_blockchain.zig` into smaller submodules while preserving its current import path and exported response names.

**Architecture:** Keep `responses_blockchain.zig` as a stable façade. Move the concrete response definitions into focused submodules for block, transaction, and network responses. Re-export the original top-level names unchanged so `responses.zig` and downstream imports keep compiling without API changes.

**Tech Stack:** Zig, current RPC response layer, `zig build rpc-test`, `zig build test`, `zig build examples`

### Task 1: Reproduce the missing submodule namespaces

**Files:**
- Modify: `src/rpc/responses_blockchain.zig`
- Test: `src/rpc/responses_blockchain.zig`

**Step 1: Write the failing test**

Add a façade test that expects:
- `block`
- `transaction`
- `network`

And assert stable mappings:
- `block.NeoBlock == NeoBlock`
- `transaction.Transaction == Transaction`
- `network.NeoVersion == NeoVersion`

**Step 2: Run test to verify it fails**

Run: `zig build rpc-test --summary all`
Expected: FAIL because the submodule namespaces do not exist yet

### Task 2: Split the blockchain response file

**Files:**
- Create: `src/rpc/responses_blockchain_block.zig`
- Create: `src/rpc/responses_blockchain_transaction.zig`
- Create: `src/rpc/responses_blockchain_network.zig`
- Modify: `src/rpc/responses_blockchain.zig`

**Step 1: Move block responses**

Move:
- `NeoBlock`

Into `responses_blockchain_block.zig`.

**Step 2: Move transaction responses**

Move:
- `NeoWitness`
- `Transaction`
- `TransactionSigner`
- `WitnessRule`
- `WitnessCondition`

Into `responses_blockchain_transaction.zig`.

**Step 3: Move network responses**

Move:
- `NeoVersion`
- `HardforkInfo`
- `ProtocolConfiguration`
- `NetworkFeeResponse`
- `SendRawTransactionResponse`

Into `responses_blockchain_network.zig`.

**Step 4: Rebuild the façade**

Make `responses_blockchain.zig`:
- expose `block`, `transaction`, `network`
- re-export the original top-level names unchanged

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
