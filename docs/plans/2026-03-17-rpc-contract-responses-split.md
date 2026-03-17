# RPC Contract Responses Split Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split `src/rpc/responses_contract.zig` into smaller submodules while preserving its current import path and exported response names.

**Architecture:** Keep `responses_contract.zig` as a stable façade. Move the concrete response definitions into focused submodules for contract state, manifest, and ABI-related types. Re-export the original top-level names unchanged so `responses.zig`, `extended_system_responses.zig`, and downstream imports keep compiling without API changes.

**Tech Stack:** Zig, current RPC response layer, `zig build rpc-test`, `zig build test`, `zig build examples`

### Task 1: Reproduce the missing submodule namespaces

**Files:**
- Modify: `src/rpc/responses_contract.zig`
- Test: `src/rpc/responses_contract.zig`

**Step 1: Write the failing test**

Add a façade test that expects:
- `state`
- `manifest`
- `abi`

And assert stable mappings:
- `state.ContractState == ContractState`
- `manifest.ContractManifest == ContractManifest`
- `abi.ContractABI == ContractABI`

**Step 2: Run test to verify it fails**

Run: `zig build rpc-test --summary all`
Expected: FAIL because the submodule namespaces do not exist yet

### Task 2: Split the contract response file

**Files:**
- Create: `src/rpc/responses_contract_state.zig`
- Create: `src/rpc/responses_contract_manifest.zig`
- Create: `src/rpc/responses_contract_abi.zig`
- Modify: `src/rpc/responses_contract.zig`

**Step 1: Move state-oriented responses**

Move:
- `ContractState`
- `ContractNef`
- `ContractFeatures`

Into `responses_contract_state.zig`.

**Step 2: Move manifest-oriented responses**

Move:
- `ContractManifest`
- `ContractGroup`
- `TrueFlag`

Into `responses_contract_manifest.zig`.

**Step 3: Move ABI-oriented responses**

Move:
- `ContractParameterDefinition`
- `ContractMethod`
- `ContractEvent`
- `ContractABI`
- `ContractPermission`

Into `responses_contract_abi.zig`.

**Step 4: Rebuild the façade**

Make `responses_contract.zig`:
- expose `state`, `manifest`, `abi`
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
