# RPC Protocol Responses Split Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split `src/rpc/protocol_responses.zig` into smaller category files while preserving the existing import path and top-level exported response names.

**Architecture:** Keep `protocol_responses.zig` as the stable façade. Move concrete response definitions into focused category files for contract, network, and wallet/state responses. Re-export the original top-level names unchanged so `rpc.types`, `protocol_responses` imports, and downstream callers keep compiling without interface changes.

**Tech Stack:** Zig, existing RPC/protocol response layer, `zig build rpc-test`, `zig build test`, `zig build examples`

### Task 1: Reproduce the missing category namespaces

**Files:**
- Modify: `src/rpc/protocol_responses.zig`
- Test: `src/rpc/protocol_responses.zig`

**Step 1: Write the failing test**

Add a façade test that expects:
- `contract`
- `network`
- `wallet`

And assert stable mappings:
- `contract.ContractManifest == ContractManifest`
- `network.NeoGetPeers == NeoGetPeers`
- `wallet.NeoGetClaimable == NeoGetClaimable`

**Step 2: Run test to verify it fails**

Run: `zig build rpc-test --summary all`
Expected: FAIL because the category namespaces do not exist yet

### Task 2: Split the protocol response file

**Files:**
- Create: `src/rpc/protocol_contract_responses.zig`
- Create: `src/rpc/protocol_network_responses.zig`
- Create: `src/rpc/protocol_wallet_responses.zig`
- Modify: `src/rpc/protocol_responses.zig`

**Step 1: Move contract-oriented responses**

Move:
- `ContractNef`
- `ContractManifest`
- `ContractGroup`
- `ContractABI`
- `ContractMethodInfo`
- `ContractParameterDefinition`
- `ContractEventInfo`
- `ContractPermission`
- `ContractStorageEntry`

Into `protocol_contract_responses.zig`.

**Step 2: Move network responses**

Move:
- `NeoGetMemPool`
- `NeoGetPeers`
- `Peer`

Into `protocol_network_responses.zig`.

**Step 3: Move wallet/state responses**

Move:
- `NeoGetWalletBalance`
- `NeoGetClaimable`
- `ClaimableTransaction`

Into `protocol_wallet_responses.zig`.

**Step 4: Keep helpers near the contract module**

Move contract-specific helpers such as contract hash script/signing support into the contract response file.

**Step 5: Rebuild the façade**

Make `protocol_responses.zig`:
- expose `contract`, `network`, `wallet`
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
