# RPC Types Catalog Polish Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `neo.rpc.types` the complete response-model catalog and extend `neo.rpc` with the remaining unique response aliases without introducing duplicate ambiguous names.

**Architecture:** Keep `rpc.types` as the canonical type catalog. Add stable family namespaces (`core`, `extended`, `protocol`, `remaining`) that point at the existing façade modules, then re-export the remaining unique response types at the `rpc.types` level. Mirror the same unique types through `rpc/mod.zig` for convenience, while leaving ambiguous duplicates scoped under the family namespaces only.

**Tech Stack:** Zig, current RPC façade modules, `zig build rpc-test`, `zig build test`, `zig build examples`

### Task 1: Reproduce the missing catalog coverage

**Files:**
- Modify: `src/rpc/types.zig`
- Test: `src/rpc/types.zig`

**Step 1: Write the failing test**

Add a test that expects:
- `core`, `extended`, `protocol`, `remaining` namespaces to exist
- `NeoGetClaimable`, `NeoFindStates`, and `DiagnosticsResponse` to be exported from `rpc.types`

**Step 2: Run test to verify it fails**

Run: `zig build rpc-test --summary all`
Expected: FAIL because the namespaces and additional exports do not exist yet

### Task 2: Build the complete `rpc.types` catalog

**Files:**
- Modify: `src/rpc/types.zig`

**Step 1: Add family namespaces**

Expose:
- `core = @import("responses.zig")`
- `extended = @import("extended_responses.zig")`
- `protocol = @import("protocol_responses.zig")`
- `remaining = @import("remaining_responses.zig")`

**Step 2: Add remaining unique top-level exports**

Add the missing unique response-model exports from the extended, protocol, and remaining façades, including state, wallet, diagnostics, and utility types.

### Task 3: Mirror the unique types through `neo.rpc`

**Files:**
- Modify: `src/rpc/mod.zig`

**Step 1: Add additive aliases**

Re-export the newly cataloged unique types from `types` through `neo.rpc`, while keeping ambiguous duplicate names scoped under `neo.rpc.types.*`.

### Task 4: Update docs

**Files:**
- Modify: `README.md`
- Modify: `docs/API.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/USAGE.md`

**Step 1: Document the catalog**

Explain that:
- `neo.rpc.types` is the complete response-model catalog
- `neo.rpc.types.core`, `extended`, `protocol`, and `remaining` expose the full organized model surface
- `neo.rpc` mirrors the unique common response aliases for convenience

### Task 5: Verify the polish pass

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
