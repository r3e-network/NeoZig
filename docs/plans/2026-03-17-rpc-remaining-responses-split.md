# RPC Remaining Responses Split Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split `src/rpc/remaining_responses.zig` into smaller category files while preserving the existing import path and response aliases.

**Architecture:** Keep `src/rpc/remaining_responses.zig` as the stable façade that existing code imports. Move the concrete response definitions into focused category files (`token`, `node`, `state`, `misc`) and have the façade re-export them so `response_parser.zig`, `neo_protocol.zig`, and any external callers continue to compile unchanged.

**Tech Stack:** Zig, existing RPC response parsing layer, `zig build rpc-test`, `zig build test`

### Task 1: Reproduce the missing category layout

**Files:**
- Modify: `src/rpc/remaining_responses.zig`
- Test: `src/rpc/remaining_responses.zig`

**Step 1: Write the failing test**

Add a test that expects the façade module to expose category namespaces:
- `token`
- `node`
- `state`
- `misc`

And assert a few stable mappings such as:
- `token.NeoGetTokenTransfers == NeoGetTokenTransfers`
- `node.NeoGetVersion == NeoGetVersion`
- `state.NeoFindStates == NeoFindStates`
- `misc.DiagnosticsResponse == DiagnosticsResponse`

**Step 2: Run test to verify it fails**

Run: `zig build rpc-test --summary all`
Expected: FAIL because the category namespaces do not exist yet

### Task 2: Split the file into focused modules

**Files:**
- Create: `src/rpc/remaining_token_responses.zig`
- Create: `src/rpc/remaining_node_responses.zig`
- Create: `src/rpc/remaining_state_responses.zig`
- Create: `src/rpc/remaining_misc_responses.zig`
- Modify: `src/rpc/remaining_responses.zig`

**Step 1: Move token-related helpers**

Move:
- `NeoGetTokenBalances`
- `TokenBalances`
- `TokenBalance`
- `NeoGetTokenTransfers`

Into `remaining_token_responses.zig`.

**Step 2: Move node/diagnostic protocol objects**

Move:
- `NeoGetVersion`
- `NeoSendRawTransaction`

Into `remaining_node_responses.zig`.

**Step 3: Move state-service responses**

Move:
- `NeoFindStates`
- `NeoGetUnspents`

Into `remaining_state_responses.zig`.

**Step 4: Move misc aliases and utility responses**

Move:
- `TransactionAttributeResponse`
- `NotificationResponse`
- `ResponseAliases`
- `ExpressShutdownResponse`
- `DiagnosticsResponse`

Into `remaining_misc_responses.zig`.

**Step 5: Rebuild the façade**

Make `remaining_responses.zig`:
- expose `token`, `node`, `state`, `misc`
- re-export the original top-level names unchanged
- keep existing tests

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
