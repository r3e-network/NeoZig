# Migration Guide: v1.x → v2.0

`v2.0` reshapes the public API around a single `neo.Client` modeled on the AWS SDK pattern. Most existing code keeps compiling via back-compat aliases, but the new surface is significantly simpler.

## TL;DR

| Old (v1.x) | New (v2.0) |
| --- | --- |
| `neo.rpc.Client.builder(alloc)…build()` | `neo.Client.builder(alloc)…build()` |
| `neo.NeoZig.Factory.createMainNet(…)` | `neo.Client.builder(alloc).network(.mainnet).build()` |
| `try (try client.getBlockCount()).send()` | `try client.getBlockCount()` |
| `neo.model.Hash160` | `neo.Hash160` |
| `neo.security.crypto.generateKeyPair(…)` | `neo.crypto.generateKeyPair(…)` |
| `neo.runtime.transaction.TransactionBuilder` | `neo.transaction.TransactionBuilder` |
| `neo.errors.CryptoError` | `neo.CryptoError` (or `neo.errors.CryptoError`) |
| (server JSON-RPC error info was discarded) | `client.takeLastServerError()` after `error.ServerError` |

Old paths still resolve through deprecated aliases — they will be removed in v3.0.

## 1. The `Client` is now one struct, not two

v1.x had two parallel client structs:

- `neo.NeoZig` — "convenience" wrapper around a service
- `neo.rpc.NeoClient` — operation methods returning lazy `RpcRequest` handles

In v2.0 both are superseded by **`neo.Client`**. Operations return their response values directly. Construct with the builder:

```zig
var client = try neo.Client.builder(allocator)
    .endpoint("http://localhost:20332")   // OR .network(.testnet)
    .timeoutMs(30_000)
    .retryPolicy(.{ .max_attempts = 5 })
    .build();
defer client.deinit();
```

Builder methods (all chainable, all return a new builder by value):

| Method | Effect |
| --- | --- |
| `.endpoint(url)` | Sets the JSON-RPC endpoint URL |
| `.network(.mainnet \| .testnet \| .private)` | Selects a default endpoint preset |
| `.timeoutMs(u32)` | Per-request timeout (best-effort) |
| `.retryPolicy(RetryPolicy{…})` | Retries on transient failures |
| `.nnsResolver(Hash160)` | Overrides the NNS resolver contract hash |
| `.blockIntervalMs(u32)` | Block production interval |
| `.pollingIntervalMs(u32)` | Block polling interval |
| `.allowTransmissionOnFault(bool)` | Broadcast even when test-invoke faults |
| `.includeRawResponses(bool)` | Capture raw response strings |
| `.maxResponseBytes(usize)` | Cap response body size |

The old `NeoZig.Factory.createMainNet/createTestNet/createDev/createProduction` factories are still present but no longer the recommended path; replace with `.network(.mainnet|.testnet|.private)`.

## 2. Operations return values, not request handles

**Old:**

```zig
var request = try client.getBlockCount();   // RpcRequest(u32)
const count = try request.send();            // u32 (or call .deinit() if not sending)
```

**New:**

```zig
const count = try client.getBlockCount();    // u32 directly
```

Operations that return owned data still need `.deinit(allocator)`:

```zig
var version = try client.getVersion();
defer version.deinit(allocator);

var block = try client.getBlockByIndex(12345, .{ .full_transactions = true });
defer block.deinit(allocator);
```

Complex operations take an option struct rather than a long positional list:

```zig
const result = try client.invokeFunction(
    contract_hash,
    "transfer",
    params,
    .{ .signers = signers },
);

const transfers = try client.getNep17Transfers(
    script_hash,
    .{ .from_time = 1700_000_000_000, .to_time = 1710_000_000_000 },
);
```

Operations available in v2.0:

- Blockchain: `getBestBlockHash`, `getBlockHash`, `getBlock`, `getBlockByIndex`, `getBlockCount`, `getConnectionCount`, `getVersion`, `getTransaction`
- Contracts: `getContractState`, `invokeFunction`, `invokeScript`, `sendRawTransaction`, `calculateNetworkFee`
- NEP-17: `getNep17Balances`, `getNep17Transfers`
- Wallet: `validateAddress`
- Network: `getNetworkMagic`

Additional operations from the legacy `neo.rpc.NeoClient` are still reachable through `client.service` for advanced use cases.

## 3. Flat top-level surface

v1.4 organized the API into a five-level namespace hierarchy: `neo.runtime.contract.naming.NeoNameService`. v2.0 also exposes everything flat on `neo`:

```zig
// v1.x preferred path
const hash = try neo.model.Hash160.initWithString("…");
const kp = try neo.security.crypto.generateKeyPair(true);
var b = neo.runtime.transaction.TransactionBuilder.init(allocator);

// v2.0 preferred path
const hash = try neo.Hash160.initWithString("…");
const kp = try neo.crypto.generateKeyPair(true);
var b = neo.transaction.TransactionBuilder.init(allocator);
```

The old paths still resolve — `neo.model`, `neo.runtime`, `neo.security`, `neo.core`, `neo.io`, `neo.vm`, `neo.compat` are kept as deprecated aliases through v2.x. They will be removed in v3.0.

## 4. Errors

Per-module error sets (`CryptoError`, `RpcError`, `TransactionError`, …) are re-exposed on `neo` directly and also still under `neo.errors`. A new umbrella `neo.Error` unions all of them:

```zig
fn doWork() neo.Error!void {
    // any module error fits into neo.Error
}
```

### Structured JSON-RPC server errors

Previously, when a node returned a JSON-RPC `error` object the SDK only surfaced `error.ServerError` and discarded the `code`/`message`/`data`. v2.0 captures the structured payload on the client; inspect it with `takeLastServerError`:

```zig
client.getBlock(missing_hash, .{}) catch |err| switch (err) {
    error.ServerError => {
        var info = client.takeLastServerError() orelse return err;
        defer info.deinit(allocator);
        std.log.warn("server error {d}: {s}", .{ info.code, info.message });
    },
    else => return err,
};
```

## 5. RPC robustness changes

- **Exponential backoff with jitter.** The retry loop now sleeps `initial_backoff_ms * multiplier^attempt` (capped at `max_backoff_ms`), with ±`jitter` randomization. The v1.x retry loop spun without delay.
- **Auto-incrementing JSON-RPC ids.** `HttpClient.jsonRpcRequest` assigns sequential ids when `request_id == null`. The previous default of `id = 1` for every request is preserved if you pass `1` explicitly.
- **`HttpClient.jsonRpcRequest` is now `*Self`.** If you held an `HttpClient` by value and called `jsonRpcRequest` on it, switch to a pointer. Most callers go through the `Client` and are unaffected.

## 6. Cleanup that may show up in your diffs

These are gone in v2.0 (none were referenced from a non-orphan file):

- `NeoSwift/` and `neo_csharp/` — upstream reference sources, removed from the working tree (they were already `.gitignore`d)
- `.hive-mind/` — tool cache that should not have been tracked
- 33 files in `src/protocol/response/*.zig` that were duplicate definitions of the live `src/rpc/responses_*.zig` set
- 5 abandoned modules in `src/protocol/` (`service.zig`, `protocol_error.zig`, `neo_express*.zig`, the `polling/` split)
- 4 orphan test files in `tests/` that no `build.zig` step referenced (`advanced_test_suite.zig`, `complete_test_suite.zig`, `complete_test_conversion.zig`, `final_comprehensive_tests.zig`)

If your code imported any of these directly, see the working `src/rpc/responses_*.zig` set or the consolidated test suites referenced from `build.zig`.

## 7. Known caveats

- **Timeouts are still best-effort.** `std.http` does not expose socket-level deadlines, so the per-request `timeoutMs` is enforced as an elapsed-time check after a fetch completes, not as a hard deadline. A request that hangs at the kernel level cannot be interrupted by the SDK.
- **The deep internal layout of `src/rpc/`** still has redundant umbrella files (`responses.zig`, `extended_responses.zig`, `protocol_responses.zig`, `remaining_responses.zig`) routing to ~25 fragment files. These are scheduled for collapse in a subsequent point release; the public `neo.Client` API will not change.
