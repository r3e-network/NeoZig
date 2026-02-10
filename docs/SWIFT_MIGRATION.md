# Swift → Zig Migration Guide

This SDK aims to stay API-compatible with the original Swift **NeoClient** library, while adopting Zig conventions around:

- explicit memory management (`deinit`, allocators)
- explicit error propagation (`try`)
- synchronous calls (no `async/await`)

Most types live under the `neo` root module:

```zig
const neo = @import("neo-zig");
// or: const neo = @import("neo_zig");
```

## RPC client (NeoClient.build)

Swift:

```swift
let neoSwift = NeoClient.build(HttpService(URL(string: "https://testnet1.neo.coz.io:443")!))
let response = try await neoSwift.getBlockCount().send()
```

Zig:

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("https://testnet1.neo.coz.io:443");

    // `NeoClient.build` takes `*NeoService` and moves ownership into the client.
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    const request = try client.getBlockCount();
    const block_count = try request.send();

    std.log.info("Block count: {}", .{block_count});
}
```

Notes:

- The client owns the service after `build`; do not call `service.deinit()` afterwards.
- Most RPC methods return a request object; call `.send()` to perform the network call.
- For allocator-controlled service setup (no `page_allocator` fallback), use `neo.rpc.ServiceFactory.*` helpers.

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

- Sensitive buffers (private keys, NEP-2 intermediate material, etc.) are explicitly zeroized.
- When a function returns an allocated string/slice, it must be freed with the allocator you passed in.

## Transactions / scripts

Transaction building follows the same high-level flow as NeoClient, but in Zig you’ll typically:

- pass an allocator to builders/utilities
- `deinit()` transactions/builders that own heap data

See `examples/complete_demo.zig` for an end-to-end transaction build and signing flow.
