# Neo Zig SDK 🚀

[![Zig](https://img.shields.io/badge/Zig-0.14.0+-orange)](https://ziglang.org/)
[![Neo](https://img.shields.io/badge/Neo-N3-brightgreen)](https://neo.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)](https://github.com/r3e-network/neo-zig-sdk)
[![Release](https://img.shields.io/github/v/release/r3e-network/neo-zig-sdk?sort=semver&display_name=tag)](https://github.com/r3e-network/neo-zig-sdk/releases/latest)

A Neo N3 blockchain SDK in Zig, modeled on the AWS SDK ergonomics: one `Client`, fluent builder, direct operation methods, explicit ownership, structured errors.

## ✨ Features

- **🧭 AWS-style `Client`** — single `neo.Client.builder(allocator)...build()` entry point; operations return values directly (no intermediate request handles to send)
- **🔐 Cryptographic Suite** — secp256r1, ECDSA, RIPEMD160, NEP-2, BIP32, WIF with allocator-aware APIs
- **🏗️ Type-Safe Core Types** — Hash160, Hash256, Address, ContractParameter, StackItem
- **📝 Smart Contract Support** — NEP-17/NEP-11 tokens, contract deployment, native contracts (NEO, GAS, Policy, Role, CryptoLib, Notary, …)
- **🔧 Transaction System** — multi-sig, witness rules, builder, broadcast
- **🌐 RPC Client** — exponential backoff with jitter, auto-incrementing request ids, structured JSON-RPC error capture
- **💼 Wallet System** — NEP-6, BIP-39 mnemonics, HD wallets
- **🧪 Testing** — 13 named test suites, all green

## ✅ Status

- **Zig**: `0.14.0+` (see `build.zig.zon`)
- **Neo protocol**: aligned with Neo N3 v3.9.1 (VM opcodes, interop pricing, native contract hashes, `getversion` metadata)
- **Test coverage**: 13 named test suites, all green (`zig build test`, plus 12 domain suites)
- **Networking**: `std.http` transport with exponential backoff + jitter on transient failures; timeouts are still best-effort (no socket deadlines in stdlib)
- **Contracts**: some high-level helpers return stub values when no RPC client is attached; attach `neo.Client` for live calls

## 📖 Documentation

- **[Quick Start](#-quick-start)** — 5-minute walkthrough
- **[Usage Guide](docs/USAGE.md)** — comprehensive patterns with examples
- **[Architecture](docs/ARCHITECTURE.md)** — module organization
- **[API Reference](docs/API.md)** — full API surface
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** — common issues
- **[Migration v1 → v2](docs/MIGRATION_V2.md)** — what changed and how to update
- **[Swift Migration](docs/SWIFT_MIGRATION.md)** — transition from the NeoSwift SDK
- **[Contributing](CONTRIBUTING.md)** — development guidelines
- **[Security](SECURITY.md)** — security best practices

## 🆕 v2.0.0 Release

`v2.0.0` reshapes the public API around a single AWS-SDK-style `Client`:

- 🧭 **One `neo.Client`** — fluent builder, direct operation methods (no `RpcRequest` → `.send()` two-step)
- ⚡ **RPC robustness** — real exponential backoff with jitter, auto-incrementing request ids, structured server-error capture (`Client.takeLastServerError()`)
- 🧱 **Flat top-level surface** — `neo.Hash160`, `neo.Client`, `neo.Error`, etc. directly on `neo` — no namespace pyramid
- 🧹 **8,000 LOC of dead code removed** — orphan duplicate response modules and abandoned protocol splits deleted
- 🔁 **Back-compat shims kept** — deprecated paths (`neo.runtime.*`, `neo.model.*`, …) still resolve, scheduled for removal in v3.0

See [CHANGELOG.md](CHANGELOG.md) and [docs/MIGRATION_V2.md](docs/MIGRATION_V2.md) for details.

```bash
git clone --branch v2.0.0 https://github.com/r3e-network/neo-zig-sdk.git
cd neo-zig-sdk
zig build test
```

If you hit cache errors (e.g. `failed to check cache: invalid manifest file format`) when switching Zig versions, use a repo-local global cache:

```bash
zig build test --global-cache-dir .zig-global-cache
```

Run the offline demos (no node required):

```bash
zig build demo
zig build examples
zig build complete-demo
```

Add as a package dependency (recommended: use `zig fetch --save` so the required `.hash` is recorded):

```zig
.dependencies = .{
    // Added via: `zig fetch --save https://github.com/r3e-network/neo-zig-sdk/archive/refs/tags/v2.0.0.tar.gz`
    .neo_zig = .{
        .url = "https://github.com/r3e-network/neo-zig-sdk/archive/refs/tags/v2.0.0.tar.gz",
        .hash = "...",
    },
};
```

## 🏗️ Architecture

```
src/
├── neo.zig             Public surface: Client, types, errors, domain modules
├── client.zig          The neo.Client struct + Builder + operation methods
├── core/               Shared constants and per-module error sets
├── types/              Hash160, Hash256, Address, ContractParameter, StackItem,
│                       CallFlags, Role, RecordType, NeoVmStateType, …
├── crypto/             secp256r1, ECDSA, hashing, NEP-2, BIP-32, WIF, base58
├── serialization/      BinaryReader/Writer, varint, NeoSerializable
├── script/             ScriptBuilder, OpCode, InteropService, ScriptReader
├── contract/           SmartContract, NEP-17/NEP-11, native contracts (NEO,
│                       GAS, Policy, Role, CryptoLib, Notary, Treasury,
│                       ContractManagement), NEF, NNS, NEP-9 URIs
├── transaction/        TransactionBuilder, NeoTransaction, AccountSigner,
│                       ContractSigner, Witness/WitnessRule, broadcast
├── wallet/             Wallet, Account, NEP-6, BIP-39 mnemonics
├── rpc/                Low-level RPC transport, request/response model,
│                       structured-error capture, retry/backoff policy
├── protocol/           Internal JSON-RPC service helpers
└── utils/              base58, bytes/string/array/numeric helpers, JSON utils
```

**Public entry point** is `src/neo.zig`. Most consumers only need:

- `neo.Client` + `neo.Client.builder(alloc)…build()` (in `src/client.zig`)
- `neo.Hash160`, `neo.Hash256`, `neo.Address`, `neo.ContractParameter`
- `neo.Error` (and the per-module `neo.CryptoError`, `neo.RpcError`, …)
- Domain modules: `neo.crypto`, `neo.transaction`, `neo.wallet`, `neo.contract`, `neo.script`, `neo.serialization`
- `neo.rpc` only when reaching past `Client` is necessary

## 🚀 Quick Start

### Installation

Add to your `build.zig.zon`:

```bash
zig fetch --save https://github.com/r3e-network/neo-zig-sdk/archive/refs/tags/v2.0.0.tar.gz
```

Then add to your `build.zig`:

```zig
const neo_zig = b.dependency("neo_zig", .{});
// Module names exported by this package: "neo-zig" and "neo_zig" (alias).
exe.root_module.addImport("neo-zig", neo_zig.module("neo-zig"));
```

### Your First Transaction

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // 1. Generate a key pair
    var key_pair = try neo.crypto.generateKeyPair(true);
    defer key_pair.zeroize();

    // 2. Create address
    const address = try key_pair.public_key.toAddress(
        neo.constants.AddressConstants.ADDRESS_VERSION,
    );
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("Your address: {s}", .{address_str});

    // 3. Build a client (AWS-SDK style — fluent builder, one entry point)
    var client = try neo.Client.builder(allocator)
        .network(.testnet)
        .timeoutMs(30_000)
        .retryPolicy(.{ .max_attempts = 5, .initial_backoff_ms = 500 })
        .build();
    defer client.deinit();

    // 4. Query the chain. Operations return values directly — no
    //    intermediate request handle to .send().
    const count = try client.getBlockCount();
    std.log.info("Current block: {}", .{count});

    var version = try client.getVersion();
    defer version.deinit(allocator);
    std.log.info("Node version: {s}", .{version.user_agent});

    // 5. Structured server errors are captured on the client and accessible
    //    after a method returns error.ServerError:
    //
    //   const bad = client.getBlock(missing_hash, .{}) catch |err| switch (err) {
    //       error.ServerError => {
    //           var info = client.takeLastServerError() orelse return err;
    //           defer info.deinit(allocator);
    //           std.log.warn("server error {d}: {s}", .{ info.code, info.message });
    //           return err;
    //       },
    //       else => return err,
    //   };
    //   _ = bad;
}
```

### Complete Workflow Example

See [`examples/complete_demo.zig`](examples/complete_demo.zig) for a full example covering:

- Key generation and address creation
- Transaction building and signing
- Wallet management
- RPC client usage

### Basic Usage

```zig
const std = @import("std");
const neo = @import("neo-zig");
const security = neo.security;
const rpc = neo.rpc;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Generate key pair
    const key_pair = try security.crypto.generateKeyPair(true);
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    // Create address
    const address = try key_pair.public_key.toAddress(neo.core.constants.AddressConstants.ADDRESS_VERSION);
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);

    std.log.info("Generated address: {s}", .{address_str});

    // Create RPC client
    const config = try rpc.Config.builder()
        .blockInterval(3000)
        .pollingInterval(3000)
        .build();
    var client = try rpc.Client.builder(allocator)
        .endpoint("https://testnet1.neo.coz.io:443")
        .config(config)
        .build();
    defer client.deinit();

    // Query blockchain
    const block_count_request = try client.getBlockCount();
    // Note: Actual network call would require proper error handling

    std.log.info("Neo Zig SDK initialized successfully!");
}
```

### Smart Contract Interaction

```zig
// Deploy contract
const contract_mgmt = neo.contract.ContractManagement.init(allocator, null);
const nef_file = [_]u8{ 0x4E, 0x45, 0x46, 0x33 }; // NEF3 magic
const manifest = "{}"; // Contract manifest JSON

var deploy_tx = try contract_mgmt.deploy(&nef_file, manifest, null);
defer deploy_tx.deinit();

// Transfer NEP-17 tokens
const gas_token = neo.contract.GasToken.init(allocator, null);
var transfer_tx = try gas_token.transfer(
    from_address.toHash160(),
    to_address.toHash160(),
    100000000, // 1 GAS (8 decimals)
    null
);
defer transfer_tx.deinit();

// Build and broadcast transaction
var final_tx = try transfer_tx.build();
defer final_tx.deinit(allocator);

// Broadcasting requires a live node endpoint.
var broadcaster = neo.transaction.BroadcastUtils.testnet(allocator);
defer broadcaster.deinit();
const tx_hash = try broadcaster.broadcastTransaction(final_tx);
```

### Wallet Management

```zig
// Create BIP-39 wallet
var bip39_account = try neo.wallet.Bip39Account.create(allocator, "secure_password");
defer bip39_account.deinit();

const mnemonic = bip39_account.getMnemonic();
std.log.info("Mnemonic words: {}", .{std.mem.count(u8, mnemonic, " ") + 1});

// BIP-39 fully supports Unicode mnemonics and passphrases with NFKD normalization.
// Both the mnemonic and passphrase are normalized using NFKD (Normalization Form
// Compatibility Decomposition) as required by the BIP-39 specification.
// Supported Unicode scripts include Latin (é, ü, ñ, etc.), Greek (α, β, γ), CJK (中文, 日本語), and more.

// Create NEP-6 wallet
var nep6_wallet = neo.wallet.CompleteNEP6Wallet.init(allocator, "My Neo Wallet");
defer nep6_wallet.deinit();

const account = try nep6_wallet.createAccount("wallet_password", "Main Account");

// Save wallet to file
try nep6_wallet.saveToFile("my_wallet.json");

// Load wallet from file
var loaded_wallet = try neo.wallet.CompleteNEP6Wallet.loadFromFile("my_wallet.json", allocator);
defer loaded_wallet.deinit();
```

Preferred wallet account names are `neo.wallet.StoredAccount` for wallet-managed records and
`neo.wallet.SignerAccount` for standalone signer-capable accounts. Compatibility aliases
`neo.wallet.WalletAccount` and `neo.wallet.Account` still work.

For transactions, prefer `neo.transaction.TransactionWitness` for serialized transaction witnesses
`neo.transaction.ScriptWitness` for the richer witness helper model, and
`neo.transaction.WitnessScopeSet` for the richer scope enum helpers. Compatibility aliases
`neo.transaction.Witness`, `neo.transaction.CompleteWitness`, and `neo.transaction.WitnessScripts`
still work, and `neo.transaction.CompleteWitnessScope` also remains available.

## 🔧 Building

```bash
# Build the library
zig build

# Run all tests
zig build test

# Run examples (includes complete_demo)
zig build examples

# Generate HTML documentation
zig build docs

# Run benchmarks
zig build bench
```

## 📊 Swift Migration

The Neo Zig SDK aims for NeoClient API familiarity and broad parity coverage. Some higher-level helpers are still evolving; see **Known Limitations** below.

### Migration Examples

**Swift:**

```swift
let keyPair = try ECKeyPair.create()
let address = keyPair.getAddress()
let neoSwift = NeoClient.build(HttpService(URL(string: "https://testnet1.neo.coz.io:443")!))
let response = try await neoSwift.getBlockCount().send()
```

**Zig:**

```zig
const key_pair = try neo.security.crypto.generateKeyPair(true);
const address = try key_pair.public_key.toAddress(neo.core.constants.AddressConstants.ADDRESS_VERSION);
var client = try neo.rpc.Client.builder(allocator)
    .endpoint("https://testnet1.neo.coz.io:443")
    .config(try neo.rpc.Config.builder().build())
    .build();
defer client.deinit();
const request = try client.getBlockCount();
const response = try request.send();
```

## 🛡️ Security

- **Memory Safety**: Zig safety plus explicit zeroization in key/NEP-2/WIF paths
- **Cryptographic Security**: RFC 6979, ISO RIPEMD160, NEP standards
- **Input Validation**: Comprehensive validation of external inputs
- **Secure Defaults**: Safe configurations throughout

## ⚡ Performance

- **Allocator-aware APIs**: explicit ownership and predictable memory use
- **Low overhead**: idiomatic Zig, compile-time specialization, and minimal hidden work
- **Benchmarkable**: use `zig build bench` to measure on your target and optimize mode

## 🎯 Use Cases

- **DApp Development**: Build complete decentralized applications
- **Wallet Applications**: Professional wallet software with all standards
- **Token Platforms**: Create and manage NEP-17/NEP-11 ecosystems
- **Enterprise Integration**: Mission-critical blockchain operations
- **Developer Tools**: Neo blockchain development utilities
- **Educational Platforms**: Teaching and learning Neo development

## 📚 Documentation

### Generated Documentation

```bash
zig build docs
# Open zig-out/docs/index.html in your browser
```

### Guides

| Guide                                      | Description                      |
| ------------------------------------------ | -------------------------------- |
| [Usage Guide](docs/USAGE.md)               | Comprehensive practical patterns |
| [API Reference](docs/API.md)               | Complete API documentation       |
| [Architecture](docs/ARCHITECTURE.md)       | Module organization and design   |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions      |
| [Swift Migration](docs/SWIFT_MIGRATION.md) | Transition from Swift SDK        |
| [Examples](examples/)                      | Working code examples            |

### Security & Contributing

- **[Security](SECURITY.md)** - Security best practices
- **[Contributing](CONTRIBUTING.md)** - Development guidelines

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Install [Zig 0.14.0+](https://ziglang.org/download/)
2. Clone the repository: `git clone git@github.com:r3e-network/neo-zig-sdk.git`
3. Build: `zig build`
4. Test: `zig build test`

### Code Quality

- Follow Zig style guidelines
- Add tests for new functionality
- Update documentation for API changes
- Ensure memory safety throughout
- Validate security implications

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Neo Project**: For the innovative Neo blockchain platform
- **Zig Community**: For the excellent systems programming language
- **R3E Network**: For supporting advanced blockchain infrastructure development
- **Contributors**: All developers advancing Neo blockchain technology

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/r3e-network/neo-zig-sdk/issues)
- **Discussions**: [GitHub Discussions](https://github.com/r3e-network/neo-zig-sdk/discussions)
- **Email**: jimmy@r3e.network
- **Documentation**: run `zig build docs` and open `zig-out/docs/index.html`

## 📝 Known Limitations

The SDK aims for NeoClient parity, but a few higher-level surfaces are still in progress:

- Contract iterator helpers (`ContractIterator`, `TokenIterator`) now support RPC traversal via `traverseiterator`, but remain experimental; remember to call `deinit()` to terminate remote iterator sessions.
- Transaction tracking (`NeoTransaction.getApplicationLog`) is still stubbed; use the `rpc` client directly for application logs.
- Some response models in `src/protocol/response/*` omit rarely-used fields and will be completed as nodes evolve.

Allocator notes:

- Most public APIs accept an allocator. A small number of convenience constructors still fall back to `std.heap.page_allocator`; allocator-taking variants are available (for example `NefFile.initWithAllocator` and `TokenProperties.initWithAllocator`).
- Prefer allocator-aware constructors in long-running processes (for example `NeoService.initWithAllocator`) to avoid relying on `std.heap.page_allocator`.

Networking notes:

- HTTP timeouts are best-effort. `std.http` does not expose per-request socket deadlines, so the SDK relies on elapsed-time checks and retry limits.
- HTTP response bodies captured into memory are capped by default (32 MiB) to avoid unbounded growth. Override via `NeoService.setMaxResponseBytes()` / `HttpService.setMaxResponseBytes()` / `HttpClient.setMaxResponseBytes()` (pass `0` to reset to the default cap).

## 🎖️ Project Status

- **Status**: Core modules implemented; some helper APIs experimental
- **Version**: 1.4.0
- **Maintenance**: Actively maintained

---

## 🔍 Technical Notes

### Requirements

- **Zig**: 0.14.0 or later
- **Platform**: Cross-platform (Linux, macOS, Windows)
- **Dependencies**: Zero external dependencies (self-contained)

### Performance

- Benchmark on your target with `zig build bench` and the desired `-Doptimize=` mode.
- Most APIs are allocator-aware so you can control allocation strategies in hot paths.

### Security

- Avoid logging secrets (private keys, mnemonics, WIF, NEP-2 intermediate data).
- Prefer HTTPS endpoints for RPC; timeouts are best-effort (see Networking notes above).

### Compatibility

- **Neo Protocol**: N3 (latest)
- **Standards**: NEP-6, NEP-17, NEP-11, BIP-39, BIP-32
- **Networks**: MainNet, TestNet, private networks
