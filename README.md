# Neo Zig SDK 🚀

[![Zig](https://img.shields.io/badge/Zig-0.14.0+-orange)](https://ziglang.org/)
[![Neo](https://img.shields.io/badge/Neo-N3-brightgreen)](https://neo.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)](https://github.com/r3e-network/neo-zig-sdk)
[![Release](https://img.shields.io/github/v/release/r3e-network/neo-zig-sdk?sort=semver&display_name=tag)](https://github.com/r3e-network/neo-zig-sdk/releases/latest)

A Neo N3 blockchain SDK implemented in Zig, focused on explicit memory management, clear error handling, and NeoSwift API familiarity.

## ✨ Features

- **🔐 Cryptographic Suite**: secp256r1, ECDSA, RIPEMD160, NEP-2, BIP32, WIF encoding with allocator-aware APIs
- **🏗️ Type-Safe Core Types**: Hash160, Hash256, Neo addresses with comprehensive validation
- **📝 Smart Contract Support**: NEP-17/NEP-11 tokens, contract deployment and interaction helpers
- **🔧 Transaction System**: Multi-signature, witness rules, transaction building
- **🌐 RPC Client**: HTTP client with parsing and best-effort retries/timeouts
- **💼 Wallet System**: NEP-6, BIP-39, HD wallets with secure storage helpers
- **🧪 Testing**: Broad validation coverage mirroring Swift SDK behavior
- **📚 Documentation**: Examples, API docs, and migration notes

## ✅ Status

- **Zig**: `0.14.0+` (see `build.zig.zon`)
- **Test coverage**: `zig build test` runs unit + parity suites
- **Networking**: RPC transport uses `std.http.Client`; timeouts are best-effort (no socket deadlines in stdlib)
- **Contracts**: Some high-level helpers return stub values when no RPC client is attached; attach `neo.rpc.NeoSwift` for live calls

## 📖 Docs

- `docs/SWIFT_MIGRATION.md`
- `docs/USAGE.md`
- `docs/ARCHITECTURE.md`

## 🆕 v1.0.1 Release

`v1.0.1` is a patch release focused on correctness, safer ownership patterns, and docs polish. Highlights:

- ✅ **Cryptography + addresses** – Base58/Base58Check, `Hash160` helpers, NEP-2, WIF, and RIPEMD160 validated against reference vectors.
- 🧾 **Transactions + wallets** – Builders, account abstractions, and witness handling mirror Swift semantics.
- 🌐 **RPC client** – JSON-RPC payload builders and response parsing cover the published Neo node APIs (HTTP timeouts are best-effort; no socket deadlines).
- 🧪 **Regression coverage** – Broad parity tests for contracts, RPC, wallets, serialization, and transactions.
- 📘 **Docs + examples** – README, demos, and migration notes track the shipped surface.

Grab the release straight from GitHub:

```bash
git clone --branch v1.0.1 https://github.com/r3e-network/neo-zig-sdk.git
cd neo-zig-sdk
zig build test
# Individual suites:
zig build parity-test
zig build rpc-test
zig build integration-test
zig build crypto-test
zig build contract-test
zig build transaction-test
zig build wallet-test
zig build protocol-test
zig build serialization-test
zig build script-test
zig build types-test
zig build witnessrule-test
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

or add it as a package dependency (recommended: use `zig fetch --save` so the
required `.hash` is recorded in your `build.zig.zon`):

```zig
.dependencies = .{
    // Added via: `zig fetch --save https://github.com/r3e-network/neo-zig-sdk/archive/refs/tags/v1.0.1.tar.gz`
    .neo_zig = .{
        .url = "https://github.com/r3e-network/neo-zig-sdk/archive/refs/tags/v1.0.1.tar.gz",
        .hash = "...",
    },
};
```

## 🏗️ Architecture

```
src/
├── neo.zig                     # Main SDK entry point
├── core/
│   ├── constants.zig          # Neo blockchain constants
│   └── errors.zig             # Comprehensive error system
├── types/
│   ├── hash160.zig            # 160-bit hashes (addresses, contracts)
│   ├── hash256.zig            # 256-bit hashes (blocks, transactions)
│   ├── address.zig            # Neo address with Base58Check
│   └── contract_parameter.zig # Neo VM parameter types
├── crypto/
│   ├── keys.zig               # Private/public key management
│   ├── signatures.zig         # ECDSA signature operations
│   ├── secp256r1.zig          # Elliptic curve implementation
│   ├── ripemd160.zig          # RIPEMD160 hash function
│   ├── nep2.zig               # Password-protected keys
│   ├── bip32.zig              # HD wallet derivation
│   └── wif.zig                # Wallet Import Format
├── transaction/
│   ├── transaction_builder.zig # Transaction construction
│   ├── neo_transaction.zig    # Complete transaction implementation
│   ├── account_signer.zig     # Account-based signing
│   ├── witness_rule.zig       # Witness validation rules
│   └── transaction_broadcast.zig # Network broadcasting
├── contract/
│   ├── smart_contract.zig     # Contract interaction
│   ├── contract_management.zig # Contract deployment
│   ├── fungible_token.zig     # NEP-17 tokens
│   ├── non_fungible_token.zig # NEP-11 NFTs
│   ├── gas_token.zig          # Native GAS token
│   ├── neo_token.zig          # Native NEO token
│   ├── policy_contract.zig    # Network policy
│   ├── role_management.zig    # Node roles
│   ├── nef_file.zig           # NEF3 format
│   ├── neo_uri.zig            # NEP-9 URI scheme
│   └── nns_name.zig           # Neo Name Service
├── rpc/
│   ├── neo_client.zig         # Main RPC client
│   ├── http_client.zig        # HTTP networking
│   ├── responses.zig          # Response types
│   └── response_parser.zig    # JSON parsing
├── wallet/
│   ├── neo_wallet.zig         # Core wallet management
│   ├── nep6_wallet.zig        # NEP-6 standard
│   ├── nep6_complete.zig      # Complete NEP-6 implementation
│   └── bip39_account.zig      # BIP-39 mnemonic accounts
├── script/
│   ├── script_builder.zig     # Neo VM script construction
│   └── op_code.zig            # VM opcodes
├── serialization/
│   ├── binary_writer.zig      # Binary serialization
│   ├── binary_reader.zig      # Binary deserialization
│   └── neo_serializable.zig   # Serialization framework
└── utils/
    ├── base58.zig             # Base58 encoding
    ├── string_extensions.zig  # String utilities
    ├── array_extensions.zig   # Array utilities
    ├── logging.zig            # Production logging
    └── validation.zig         # Input validation
```

## 🚀 Quick Start

### Installation

Add to your `build.zig`:

```zig
const neo_zig = b.dependency("neo_zig", .{});
// Module names exported by this package: "neo-zig" and "neo_zig" (alias).
exe.root_module.addImport("neo-zig", neo_zig.module("neo-zig"));
```

### Basic Usage

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    // Initialize logging
    neo.utils.initGlobalLogger(.Info);
    
    // Generate key pair
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }
    
    // Create address
    const address = try key_pair.public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    
    std.log.info("Generated address: {s}", .{address_str});
    
    // Create RPC client
    const config = neo.rpc.NeoSwiftConfig.init();
    var service = neo.rpc.NeoSwiftService.init("https://testnet1.neo.coz.io:443");
    var client = neo.rpc.NeoSwift.build(allocator, &service, config);
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

// Note: For now, BIP-39 seed derivation supports ASCII mnemonics/passphrases only.
// Non-ASCII requires Unicode NFKD normalization (not yet implemented in this SDK).

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

## 🔧 Building

```bash
# Build the library
zig build

# Run all tests
zig build test

# Run examples
zig build examples

# Generate documentation
zig build docs

# Run benchmarks
zig build bench
```

## 📊 Swift Migration

The Neo Zig SDK aims for NeoSwift API familiarity and broad parity coverage. Some higher-level helpers are still evolving; see **Known Limitations** below.

### Migration Examples

**Swift:**
```swift
let keyPair = try ECKeyPair.create()
let address = keyPair.getAddress()
let neoSwift = NeoSwift.build(HttpService(URL(string: "https://testnet1.neo.coz.io:443")!))
let response = try await neoSwift.getBlockCount().send()
```

**Zig:**
```zig
const key_pair = try neo.crypto.generateKeyPair(true);
const address = try key_pair.public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
var service = neo.rpc.NeoSwiftService.init("https://testnet1.neo.coz.io:443");
var client = neo.rpc.NeoSwift.build(allocator, &service, neo.rpc.NeoSwiftConfig.init());
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

- **API Documentation**: run `zig build docs` and open `zig-out/docs/index.html`
- [**Examples**](examples/) - Working code examples
- [**Swift Migration Guide**](docs/SWIFT_MIGRATION.md) - Transition from Swift SDK
- [**Security Guide**](SECURITY.md) - Security best practices
- [**Contributing**](CONTRIBUTING.md) - Development guidelines

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

The SDK aims for NeoSwift parity, but a few higher-level surfaces are still in progress:

- Contract iterator helpers (`ContractIterator`, `TokenIterator`) now support RPC traversal via `traverseiterator`, but remain experimental; remember to call `deinit()` to terminate remote iterator sessions.
- Transaction tracking (`NeoTransaction.getApplicationLog`) is still stubbed; use the `rpc` client directly for application logs.
- Some response models in `src/protocol/response/*` omit rarely-used fields and will be completed as nodes evolve.

Allocator notes:

- Most public APIs accept an allocator. A small number of convenience constructors still fall back to `std.heap.page_allocator`; allocator-taking variants are available (for example `NefFile.initWithAllocator` and `TokenProperties.initWithAllocator`).
- Prefer allocator-aware constructors in long-running processes (for example `NeoSwiftService.initWithAllocator`) to avoid relying on `std.heap.page_allocator`.

Networking notes:

- HTTP timeouts are best-effort. `std.http` does not expose per-request socket deadlines, so the SDK relies on elapsed-time checks and retry limits.
- HTTP response bodies captured into memory are capped by default (32 MiB) to avoid unbounded growth. Override via `NeoSwiftService.setMaxResponseBytes()` / `HttpService.setMaxResponseBytes()` / `HttpClient.setMaxResponseBytes()` (pass `0` to reset to the default cap).

## 🎖️ Project Status

- **Status**: Core modules implemented; some helper APIs experimental
- **Version**: 1.0.1
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
