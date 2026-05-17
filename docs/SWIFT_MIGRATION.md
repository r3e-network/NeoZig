# Swift → Zig Migration Guide

This SDK aims to stay API-compatible with the original Swift **NeoSwift**
library, while adopting Zig conventions around:

- explicit memory management (`deinit`, allocators)
- explicit error propagation (`try`)
- synchronous calls (no `async/await`)

Most types live under the `neo` root module:

```zig
const neo = @import("neo-zig");
// or: const neo = @import("neo_zig");
```

In v2.0+ the recommended layout is flat — everything you need is directly on
`neo`:

- `neo.Client` for RPC (AWS-style: fluent builder, direct operation methods)
- `neo.Hash160`, `neo.Hash256`, `neo.Address`, `neo.ContractParameter` for value types
- `neo.crypto`, `neo.transaction`, `neo.wallet`, `neo.contract`, `neo.script`, `neo.serialization`

The deprecated v1.x paths (`neo.model`, `neo.security`, `neo.io`, `neo.runtime`,
`neo.vm`, `neo.core`) still resolve through compatibility shims and are
scheduled for removal in v3.0. See [MIGRATION_V2.md](MIGRATION_V2.md) for the
side-by-side mapping.

## RPC client

Swift:

```swift
let neoSwift = NeoSwift.build(HttpService(URL(string: "https://testnet1.neo.coz.io:443")!))
let response = try await neoSwift.getBlockCount().send()
```

Zig:

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var client = try neo.Client.builder(allocator)
        .endpoint("https://testnet1.neo.coz.io:443")  // or .network(.testnet)
        .timeoutMs(30_000)
        .retryPolicy(.{ .max_attempts = 5 })
        .build();
    defer client.deinit();

    // Operations return their values directly — no .send() step.
    const block_count = try client.getBlockCount();
    std.log.info("Block count: {}", .{block_count});
}
```

Notes:

- The Zig `Client` collapses the Swift two-step `getX().send()` into a single
  method call. Operations that return owned data require `defer response.deinit(allocator)`.
- For RPC methods not yet wrapped on `neo.Client`, drop down to the legacy
  `neo.rpc.NeoClient` (still exposed) which has the full pre-v2 method set.
- Transient failures are retried automatically using
  `RetryPolicy.{ initial_backoff_ms, multiplier, max_backoff_ms, jitter }`.

## Keys, addresses, WIF

Swift:

```swift
let keyPair = try ECKeyPair.create()
let address = keyPair.getAddress()
let wif = try keyPair.exportAsWIF()
```

Zig:

```zig
const key_pair = try neo.crypto.generateKeyPair(true);
defer {
    var kp = key_pair;
    kp.zeroize();
}

const address = try key_pair.public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
const wif = try key_pair.exportAsWIF(allocator);
defer allocator.free(wif);
```

Notes:

- Sensitive buffers (private keys, NEP-2 intermediate material) are explicitly zeroized.
- When a function returns an allocated string/slice, it must be freed with the allocator you passed in.

## Transactions / scripts

Transaction building follows the same high-level flow as NeoSwift, but in Zig
you'll typically:

- pass an allocator to builders/utilities
- `deinit()` transactions/builders that own heap data

See [`examples/complete_demo.zig`](../examples/complete_demo.zig) for an
end-to-end transaction build and signing flow.

## Errors

Per-module error sets (`neo.CryptoError`, `neo.TransactionError`,
`neo.WalletError`, …) are direct mirrors of NeoSwift's typed exceptions. The
umbrella `neo.Error` covers every operation if you just want a single return
type.

For JSON-RPC server errors specifically: a `neo.Client` operation returns
`error.ServerError` and stashes the structured `{ code, message, data }` for
inspection via `Client.takeLastServerError()`.
