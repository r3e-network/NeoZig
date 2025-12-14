# Usage Guide

This document focuses on practical usage patterns for the Neo Zig SDK:

- allocator + ownership expectations
- safe key handling
- common RPC flows
- transaction building/signing

## Importing

The package exports both `neo-zig` and `neo_zig` module names:

```zig
const neo = @import("neo-zig");
// or: const neo = @import("neo_zig");
```

## Allocators and Ownership

Most APIs that allocate memory take an explicit `std.mem.Allocator`. Follow these rules:

- If a function returns an allocated `[]u8`/`[]T`, free it with the allocator you passed in.
- If a type has `deinit(allocator)` or `deinit()`, call it exactly once when you’re done.
- Treat `std.heap.page_allocator` as a convenience for short-lived tools/demos; prefer a real allocator for applications.

## RPC Client

Create a service and a client:

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const config = neo.rpc.NeoSwiftConfig.init();
    var service = neo.rpc.NeoSwiftService.init("https://mainnet1.neo.coz.io:443");

    var client = neo.rpc.NeoSwift.build(allocator, &service, config);
    defer client.deinit();

    const count_request = try client.getBlockCount();
    const block_count = try count_request.send();
    std.log.info("Block count: {}", .{block_count});
}
```

### Network Magic (Best Practice)

When signing transactions, use the network magic for the connected chain. The SDK can fetch it from the node:

```zig
const magic = try client.getNetworkMagicNumber();
// Use `magic` when signing transactions.
```

## Keys and Secret Handling

- Always `zeroize()` private keys / keypairs after use.
- Avoid logging private keys, WIF strings, NEP-2 intermediate material, etc.

Example:

```zig
const kp = try neo.crypto.generateKeyPair(true);
defer {
    var mutable = kp;
    mutable.zeroize();
}
```

## Transactions

Typical flow:

1. Build script (NEP-17 transfer, contract call, etc.)
2. Add signers
3. Build transaction
4. Sign with the correct network magic
5. Send (`sendrawtransaction`)

See `examples/complete_demo.zig` for an end-to-end offline build and validation flow.

## JSON Value Memory

The SDK uses dynamically-owned `std.json.Value` in some APIs. When you clone/own a value, free it via `src/utils/json_utils.zig`:

- `json_utils.cloneValue(value, allocator)`
- `json_utils.freeValue(value, allocator)`

This avoids relying on `.deinit()` semantics that changed across Zig versions.

