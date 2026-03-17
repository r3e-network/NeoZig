# Transaction Surface Polish Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Clarify the transaction public API by introducing canonical names for the two distinct witness models while preserving existing compatibility aliases.

**Architecture:** Keep the additive namespace-first layout and the current module split, but stop forcing users to infer semantics from `Witness`, `CompleteWitness`, and `WitnessScripts`. The preferred API should expose one canonical type name for the transaction-serialized witness and one canonical type name for the richer script-witness helper model, with legacy aliases preserved.

**Tech Stack:** Zig, `std.testing`, existing `transaction` module layout, `zig build transaction-test`, `zig build test`

### Task 1: Reproduce the missing canonical aliases

**Files:**
- Modify: `src/transaction/mod.zig`
- Test: `src/transaction/mod.zig`

**Step 1: Write the failing test**

Add a transaction module test that expects:
- `ScriptWitness` to exist and map to the rich witness helper type
- `TransactionWitness` to exist and map to the serialized transaction witness type
- compatibility aliases `CompleteWitness`, `WitnessScripts`, and `Witness` to still resolve

**Step 2: Run test to verify it fails**

Run: `zig build transaction-test --summary all`
Expected: FAIL because the new canonical aliases do not exist yet

### Task 2: Add canonical transaction aliases

**Files:**
- Modify: `src/transaction/witness_namespace.zig`
- Modify: `src/transaction/mod.zig`
- Modify: `src/neo.zig`

**Step 1: Write the minimal implementation**

Add:
- `ScriptWitness` for the richer `witness.zig` witness model
- `TransactionWitness` for the transaction-serialized `transaction_builder.zig` witness model

Keep:
- `Witness` as the existing compatibility alias
- `CompleteWitness` and `WitnessScripts` as compatibility aliases to `ScriptWitness`

**Step 2: Add namespace assertions**

Extend existing namespace tests so the top-level and runtime surfaces keep the preferred aliases wired correctly.

### Task 3: Update docs to prefer the canonical surface

**Files:**
- Modify: `README.md`
- Modify: `docs/API.md`
- Modify: `docs/USAGE.md`
- Modify: `docs/ARCHITECTURE.md`

**Step 1: Update docs**

Document that:
- `neo.transaction.TransactionWitness` is the serialized transaction witness
- `neo.transaction.ScriptWitness` is the helper model with script-building helpers
- `CompleteWitness` / `WitnessScripts` remain compatibility aliases

### Task 4: Verify end to end

**Files:**
- Test only

**Step 1: Run targeted verification**

Run:
- `zig build transaction-test --summary all`
- `zig build test`

Expected: PASS

**Step 2: Run broader regression verification**

Run:
- `zig build rpc-test`
- `zig build examples`

Expected: PASS
