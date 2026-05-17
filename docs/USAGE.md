# Usage Guide

This comprehensive guide covers practical usage patterns for the Neo Zig SDK, including memory management, common workflows, and best practices.

## Table of Contents

- [Importing the SDK](#importing-the-sdk)
- [Allocators and Memory Management](#allocators-and-memory-management)
- [Quick Start Examples](#quick-start-examples)
- [Key Management](#key-management)
- [Address Operations](#address-operations)
- [RPC Client Usage](#rpc-client-usage)
- [Transaction Building](#transaction-building)
- [Smart Contract Interaction](#smart-contract-interaction)
- [Wallet Management](#wallet-management)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Importing the SDK

The package exports both `neo-zig` and `neo_zig` module names:

```zig
const neo = @import("neo-zig");
// or: const neo = @import("neo_zig");
```

The recommended v2.0 layout is flat — everything you need is directly on `neo`:

- `neo.Client` — the AWS-style client with `Client.builder(allocator)…build()`
- `neo.Hash160`, `neo.Hash256`, `neo.Address`, `neo.ContractParameter`, `neo.StackItem` — value types
- `neo.Error` — umbrella error set; plus per-module: `neo.CryptoError`, `neo.TransactionError`, etc.
- `neo.crypto`, `neo.transaction`, `neo.wallet`, `neo.contract`, `neo.script`, `neo.serialization`
- `neo.constants`, `neo.utils`
- `neo.rpc` — low-level transport (escape hatch; most code does not need it)

The deprecated v1.x paths `neo.runtime`, `neo.model`, `neo.security`, `neo.core`,
`neo.io`, and `neo.vm` still resolve through compatibility shims and will be
removed in v3.0; see [MIGRATION_V2.md](MIGRATION_V2.md).

For RPC response models, prefer `neo.rpc.types` for the full catalog; the
common types (`NeoBlock`, `NeoVersion`, `InvocationResult`, `Nep17Balances`,
etc.) are also re-exported directly on `neo` via the `Client` module.

## Allocators and Memory Management

### Allocator Guidelines

Most APIs that allocate memory take an explicit `std.mem.Allocator`. Follow these rules:

- If a function returns an allocated `[]u8` or `[]T`, free it with the allocator you passed in
- If a type has `deinit(allocator)` or `deinit()`, call it exactly once when done
- Treat `std.heap.page_allocator` as a convenience for short-lived tools/demos; prefer a real allocator for applications

### Allocator Selection

```zig
const std = @import("std");

pub fn main() !void {
    // OPTION 1: Page allocator (for simple scripts and demos)
    const allocator = std.heap.page_allocator;

    // OPTION 2: General Purpose Allocator (for applications)
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer gpa.deinit();
    const allocator = gpa.allocator();

    // OPTION 3: Fixed buffer allocator (for known upper bounds)
    var buffer: [1024 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();
}
```

### Memory Cleanup Patterns

```zig
// Pattern 1: defer for automatic cleanup
var wallet = neo.wallet.Wallet.init(allocator);
defer wallet.deinit();

const account = try wallet.createAccount("My Account");

// Pattern 2: Immediate cleanup for large objects in loops
while (processing) {
    var client = try neo.Client.builder(allocator)
        .endpoint("https://testnet1.neo.coz.io:443")
        .build();
    defer client.deinit();
    // ... use client ...
}

// Pattern 3: Allocated strings require explicit free
const address_str = try address.toString(allocator);
defer allocator.free(address_str);

// Pattern 4: Zeroize sensitive data
var key_pair = try neo.crypto.generateKeyPair(true);
defer {
    var kp = key_pair;
    kp.zeroize();
}

// Pattern 5: Nested cleanup with mutable copy
const wif_result = try neo.crypto.decodeWIF(wif_string, allocator);
defer {
    var mutable = wif_result;
    mutable.deinit();
}
```

## Quick Start Examples

### Example 1: Generate Keys and Address

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Generate a new key pair
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var kp = key_pair;
        kp.zeroize();
    }

    // Create address from public key
    const address = try key_pair.public_key.toAddress(
        neo.constants.AddressConstants.ADDRESS_VERSION,
    );

    // Convert to string for display
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);

    std.log.info("Generated address: {s}", .{address_str});
}
```

### Example 2: Connect to RPC and Query Blockchain

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn queryBlockchain() !void {
    const allocator = std.heap.page_allocator;

    var client = try neo.Client.builder(allocator)
        .network(.testnet)
        .blockIntervalMs(3000)
        .pollingIntervalMs(3000)
        .build();
    defer client.deinit();

    // Operations return their values directly — no .send() step.
    const block_count = try client.getBlockCount();
    std.log.info("Current block count: {}", .{block_count});

    // Get network magic (required for signing); cached after first call.
    const magic = try client.getNetworkMagic();
    std.log.info("Network magic: {}", .{magic});
}
```

### Example 3: Transfer NEP-17 Tokens

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn transferGas(from_private_key: []const u8, to_address_str: []const u8) !void {
    const allocator = std.heap.page_allocator;

    // Load key pair from private key
    const private_key = neo.crypto.generatePrivateKeyFromBytes(from_private_key);
    const key_pair = try private_key.getKeyPair(true);
    defer {
        var kp = key_pair;
        kp.zeroize();
    }

    // Build a client (the AWS-style way)
    var client = try neo.Client.builder(allocator)
        .network(.testnet)
        .timeoutMs(30_000)
        .retryPolicy(.{ .max_attempts = 5 })
        .build();
    defer client.deinit();

    const magic = try client.getNetworkMagic();

    // Parse addresses
    const from_address = try neo.Address.fromHash160(key_pair.public_key.toHash160());
    const to_address = try neo.Address.fromString(allocator, to_address_str);
    defer allocator.free(to_address);

    // GAS token wrapper still uses the legacy client surface; pass through
    // `client.getService()` or wrap directly. For most use cases prefer
    // calling `client.invokeFunction` / `client.sendRawTransaction` directly.
    const gas_token = neo.contract.GasToken.init(allocator, &client);

    var transfer_tx = try gas_token.transfer(
        from_address.toHash160(),
        to_address.toHash160(),
        100000000, // 1 GAS (8 decimals)
        null,
    );
    defer transfer_tx.deinit();

    const signed_tx = try transfer_tx.sign(key_pair, magic);
    const send_response = try client.sendRawTransaction(signed_tx);
    std.log.info("Transfer sent: {s}", .{send_response.hash});
}
```

## Key Management

### Generating Keys

```zig
// Generate a new key pair
const key_pair = try neo.crypto.generateKeyPair(true); // true = compressed
defer {
    var kp = key_pair;
    kp.zeroize();
}

// Generate private key only
const private_key = neo.crypto.generatePrivateKey();
defer private_key.zeroize();

// Get public key from private key
const public_key = try private_key.getPublicKey(true);
```

### Working with WIF (Wallet Import Format)

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn demonstrateWIF() !void {
    const allocator = std.heap.page_allocator;

    // Generate key pair
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var kp = key_pair;
        kp.zeroize();
    }

    // Export to WIF (MainNet)
    const wif = try neo.crypto.encodeWIF(
        key_pair.private_key,
        true,           // compressed
        .mainnet,
        allocator,
    );
    defer allocator.free(wif);
    std.log.info("WIF: {s}", .{wif});

    // Import from WIF
    var decoded = try neo.crypto.decodeWIF(wif, allocator);
    defer decoded.deinit();

    // Verify the key matches
    if (decoded.private_key.eql(key_pair.private_key)) {
        std.log.info("WIF round-trip successful", .{});
    }
}
```

### NEP-2 Encrypted Keys

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn demonstrateNEP2() !void {
    const allocator = std.heap.page_allocator;
    const password = "my_secure_password";

    // Generate key pair
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var kp = key_pair;
        kp.zeroize();
    }

    // Encrypt to NEP-2 format
    const encrypted = try neo.crypto.encryptNEP2(
        key_pair.private_key,
        password,
        allocator,
    );
    defer allocator.free(encrypted);
    std.log.info("NEP-2: {s}", .{encrypted});

    // Decrypt NEP-2
    const decrypted = try neo.crypto.decryptNEP2(
        encrypted,
        password,
        allocator,
    );
    defer decrypted.zeroize();
    std.log.info("Decrypted successfully", .{});
}
```

### BIP-32 HD Wallets

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn demonstrateBIP32() !void {
    const allocator = std.heap.page_allocator;

    // Generate random seed
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);

    // Create master key from seed
    const master = try neo.crypto.BIP32.masterKey(&seed, allocator);
    defer master.deinit();

    // Derive path for Neo (NEO uses coin type 888)
    // m/44'/888'/0'/0/0 - first account
    const account = try master.derivePath("m/44'/888'/0'/0/0", allocator);
    defer account.deinit();

    // Get the private key
    const private_key = account.getPrivateKey();
    defer private_key.zeroize();

    std.log.info("HD wallet derived", .{});
}
```

## Address Operations

### Creating Addresses

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn demonstrateAddresses() !void {
    const allocator = std.heap.page_allocator;

    // Generate new key pair
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var kp = key_pair;
        kp.zeroize();
    }

    // Create address from public key
    const address = try key_pair.public_key.toAddress(
        neo.constants.AddressConstants.ADDRESS_VERSION,
    );

    // Convert to string
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("Address: {s}", .{address_str});

    // Validate address
    if (address.isValid()) {
        std.log.info("Address is valid", .{});
    }

    if (address.isStandard()) {
        std.log.info("Standard single-signature address", .{});
    }
}
```

### Working with Script Hashes

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn demonstrateScriptHashes() !void {
    const allocator = std.heap.page_allocator;

    // Parse address to get script hash
    const address_str = "NX5v2MtKixV3mPJPfbJdc7f3oGyM2eE9CQ";
    const address = try neo.Address.fromString(allocator, address_str);
    defer allocator.free(address);

    const script_hash = address.toHash160();

    // Round-trip: Hash160 -> Address
    const recovered = neo.Address.fromHash160(script_hash);
    if (address.eql(recovered)) {
        std.log.info("Address round-trip successful", .{});
    }

    // Create Hash160 from string directly
    const hash_from_str = try neo.Hash160.fromAddress(address_str, allocator);
    defer allocator.free(hash_from_str);
}
```

## RPC Client Usage

### Basic Client Setup

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn demonstrateRPC() !void {
    const allocator = std.heap.page_allocator;

    var client = try neo.Client.builder(allocator)
        .endpoint("https://testnet1.neo.coz.io:443")  // or .network(.testnet)
        .timeoutMs(30_000)
        .retryPolicy(.{
            .max_attempts = 3,
            .initial_backoff_ms = 500,
            .multiplier = 2.0,
            .max_backoff_ms = 30_000,
            .jitter = 0.25,
        })
        .blockIntervalMs(3000)
        .pollingIntervalMs(3000)
        .maxResponseBytes(64 * 1024 * 1024)
        .build();
    defer client.deinit();

    // Use client...
}
```

### Query Methods

Operations return their response values directly:

```zig
// Blockchain queries
const block_count = try client.getBlockCount();             // u32
const best_hash = try client.getBestBlockHash();            // Hash256
var block = try client.getBlock(block_hash, .{});           // NeoBlock
defer block.deinit(allocator);

// Network queries
const magic = try client.getNetworkMagic();                 // u32 (cached)
var version = try client.getVersion();                      // NeoVersion
defer version.deinit(allocator);

// Token balances
var balances = try client.getNep17Balances(script_hash);    // Nep17Balances
defer balances.deinit(allocator);

var transfers = try client.getNep17Transfers(
    script_hash,
    .{ .from_time = 1700_000_000_000 },
);
defer transfers.deinit(allocator);
```

### Contract Invocation

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn invokeContract(client: *neo.Client, script_hash: neo.Hash160) !void {
    const allocator = std.heap.page_allocator;

    const params = [_]neo.ContractParameter{
        neo.ContractParameter.integer(1000),
    };

    var result = try client.invokeFunction(
        script_hash,
        "balanceOf",
        &params,
        .{ .signers = &.{} },
    );
    defer result.deinit(allocator);

    std.log.info("Invocation state: {}", .{result.state});
}
```

### Handling Structured Server Errors

When a node returns a JSON-RPC `error` object, `Client` returns
`error.ServerError` and stashes the parsed `code`/`message`/`data` for
inspection:

```zig
const result = client.getBlock(unknown_hash, .{}) catch |err| switch (err) {
    error.ServerError => {
        var info = client.takeLastServerError() orelse return err;
        defer info.deinit(allocator);
        std.log.warn("RPC error {d}: {s}", .{ info.code, info.message });
        return err;
    },
    else => return err,
};
defer result.deinit(allocator);
```

## Transaction Building

Preferred transaction witness names:

- `neo.transaction.TransactionWitness` for serialized witnesses inside transactions
- `neo.transaction.ScriptWitness` for the richer witness helper model
- `neo.transaction.WitnessScopeSet` for the richer scope enum with combination helpers
- `neo.transaction.Witness`, `neo.transaction.CompleteWitness`, and `neo.transaction.WitnessScripts` remain as compatibility aliases
- `neo.transaction.CompleteWitnessScope` remains as a compatibility alias

### Basic Transaction

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn buildBasicTransaction(
    allocator: std.mem.Allocator,
    client: *neo.Client,
    from_hash: neo.Hash160,
    to_hash: neo.Hash160,
) !neo.transaction.NeoTransaction {
    // Create builder
    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();

    // Configure
    _ = builder.version(0)
        .additionalNetworkFee(500000)   // 0.005 NEO
        .additionalSystemFee(1000000);  // 0.01 NEO

    // Add signer
    const signer = neo.transaction.Signer.init(
        from_hash,
        neo.transaction.WitnessScope.CalledByEntry,
    );
    try builder.signer(signer);

    // Add GAS transfer
    try builder.transferToken(
        neo.contract.GasToken.GAS_HASH,
        from_hash,
        to_hash,
        100000000, // 1 GAS
    );

    // Build
    var transaction = try builder.build();
    errdefer transaction.deinit(allocator);

    // Validate
    try transaction.validate();

    return transaction;
}
```

### Transaction with Multiple Signers

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn buildMultiSigTransaction(
    allocator: std.mem.Allocator,
    client: *neo.Client,
    signers: []const neo.transaction.Signer,
    key_pairs: []const neo.crypto.KeyPair,
) !neo.transaction.NeoTransaction {
    const allocator = std.heap.page_allocator;
    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();

    // Add all signers
    for (signers) |signer| {
        try builder.signer(signer);
    }

    // Configure fees
    _ = builder.version(0)
        .additionalNetworkFee(500000)
        .additionalSystemFee(1000000);

    // Build transaction
    var transaction = try builder.build();
    errdefer transaction.deinit(allocator);

    // Get network magic
    const magic = try client.getNetworkMagic();

    // Sign with each key
    for (key_pairs) |key_pair| {
        var mutable_tx = transaction;
        transaction = try mutable_tx.sign(key_pair, magic);
        mutable_tx.deinit(allocator);
    }

    try transaction.validate();
    return transaction;
}
```

### Sending a Transaction

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn sendTransaction(
    client: *neo.Client,
    transaction: *neo.transaction.NeoTransaction,
) ![]const u8 {
    const allocator = std.heap.page_allocator;

    // Serialize transaction
    const tx_bytes = try transaction.serialize(allocator);
    defer allocator.free(tx_bytes);

    // Send to network
    const tx_hash = try client.sendRawTransaction(tx_bytes);

    std.log.info("Transaction sent: {s}", .{tx_hash});

    // Wait for confirmation (optional) — drop down to the legacy
    // neo.rpc.NeoClient for methods not yet on neo.Client:
    //   var req = try neo.rpc.NeoClient.builder(...).build().getApplicationLog(tx_hash);
    //   const log = try req.send();

    return tx_hash;
}
```

## Smart Contract Interaction

### NEP-17 Token Operations

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn nep17Operations(
    allocator: std.mem.Allocator,
    client: *neo.Client,
    wallet_hash: neo.Hash160,
) !void {
    // Create token wrapper
    const gas_token = neo.contract.GasToken.init(allocator, client);

    // Check balance
    const balance = try gas_token.balanceOf(wallet_hash);
    std.log.info("GAS balance: {}", .{balance});

    // Get decimals
    const decimals = try gas_token.decimals();
    std.log.info("GAS decimals: {}", .{decimals});

    // Get symbol
    const symbol = try gas_token.symbol();
    defer allocator.free(symbol);
    std.log.info("Token symbol: {s}", .{symbol});

    // Get total supply
    const supply = try gas_token.getTotalSupply();
    std.log.info("Total supply: {}", .{supply});
}
```

### NEP-11 NFT Operations

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn nep11Operations(
    allocator: std.mem.Allocator,
    client: *neo.Client,
    owner_hash: neo.Hash160,
    nft_hash: neo.Hash160,
) !void {
    const nft = neo.contract.NonFungibleToken.init(allocator, client, nft_hash);

    // Get balance (number of NFTs owned)
    const count = try nft.balanceOf(owner_hash);
    std.log.info("NFTs owned: {}", .{count});

    // Get all tokens owned (iterating)
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const token_id = try nft.tokenOfOwnerByIndex(owner_hash, i);
        std.log.info("Token ID: {s}", .{token_id});
        allocator.free(token_id);
    }

    // Get token properties
    const token_id = "token123";
    const properties = try nft.properties(token_id);
    if (properties) |props| {
        std.log.info("Name: {s}", .{props.name});
        allocator.free(props.name);
    }
}
```

### Contract Deployment

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn deployContract(
    allocator: std.mem.Allocator,
    client: *neo.Client,
    nef_bytes: []const u8,
    manifest_json: []const u8,
    sender_hash: neo.Hash160,
) !neo.transaction.NeoTransaction {
    // Create contract management wrapper
    const contract_mgmt = neo.contract.ContractManagement.init(allocator, client);

    // Build deploy transaction
    var deploy_tx = try contract_mgmt.deploy(
        nef_bytes,
        manifest_json,
        sender_hash,
    );

    return deploy_tx;
}
```

## Wallet Management

Preferred wallet account names:

- `neo.wallet.StoredAccount` for wallet-managed records returned by `neo.wallet.Wallet`
- `neo.wallet.SignerAccount` for standalone signer-capable accounts
- `neo.wallet.WalletAccount` / `neo.wallet.Account` remain as compatibility aliases

### NEP-6 Wallet

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn demonstrateNEP6Wallet() !void {
    const allocator = std.heap.page_allocator;

    // Create new wallet
    var wallet = neo.wallet.CompleteNEP6Wallet.init(allocator, "My Wallet");
    defer wallet.deinit();

    // Create account with password
    const account = try wallet.createAccount("secure_password", "Main Account");

    // Get account address
    const address = account.getAddress();
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("Account address: {s}", .{address_str});

    // Save wallet to file
    try wallet.saveToFile("wallet.json");

    // Load wallet from file
    var loaded = try neo.wallet.CompleteNEP6Wallet.loadFromFile("wallet.json", allocator);
    defer loaded.deinit();
    std.log.info("Wallet loaded", .{});
}
```

`neo.wallet.Wallet` lookup APIs return borrowed `StoredAccount` views. The wallet owns those
records, so callers should not deinitialize them separately.

### BIP-39 Mnemonic Wallet

```zig
const std = @import("std");
const neo = @import("neo-zig");

pub fn demonstrateBIP39() !void {
    const allocator = std.heap.page_allocator;

    // Create new BIP-39 account
    var bip39 = try neo.wallet.Bip39Account.create(allocator, "password");
    defer bip39.deinit();

    // Get mnemonic phrase (24 words by default)
    const mnemonic = bip39.getMnemonic();
    std.log.info("Mnemonic: {s}", .{mnemonic});

    // IMPORTANT: Save this mnemonic safely!
    // It can recover all accounts.

    // Derive first account (m/44'/888'/0'/0'/0')
    const account = try bip39.deriveAccount(0);
    const private_key = try account.getPrivateKey(allocator);
    defer private_key.zeroize();
    defer allocator.free(private_key);

    // Derive second account (m/44'/888'/0'/1'/0')
    const account2 = try bip39.deriveAccount(1);
    std.log.info("Second account derived", .{});
}

// Loading from mnemonic
pub fn loadFromMnemonic(mnemonic: []const u8) !void {
    const allocator = std.heap.page_allocator;

    var bip39 = try neo.wallet.Bip39Account.loadFromMnemonic(
        allocator,
        mnemonic,
        "password", // optional passphrase
    );
    defer bip39.deinit();

    const account = try bip39.deriveAccount(0);
    std.log.info("Loaded account", .{});
}
```

## Error Handling

### Basic Error Handling

```zig
const address = neo.Address.fromString(allocator, str) catch |err| {
    switch (err) {
        error.InvalidAddress => {
            std.log.err("Invalid Neo address format", .{});
            return error.InvalidAddress;
        },
        error.OutOfMemory => {
            std.log.err("Out of memory", .{});
            return error.OutOfMemory;
        },
        else => {
            std.log.err("Unknown error: {}", .{err});
            return err;
        }
    }
};
```

### Propagating Errors

```zig
pub fn complexOperation() !void {
    // Multiple operations that can fail
    const key_pair = try generateKey();
    defer key_pair.zeroize();

    const address = try key_pair.public_key.toAddress(VERSION);
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);

    const transaction = try buildTransaction();
    defer transaction.deinit(allocator);

    // All errors will propagate up
}
```

### Recoverable Errors

Operations return values directly. The client's `RetryPolicy` already handles
transport-level transients with exponential backoff and jitter, so most retry
loops don't need to be written by hand:

```zig
pub fn robustRPCRequest(client: *neo.Client) !u32 {
    return client.getBlockCount() catch |err| switch (err) {
        // Transient — client.retry already retried `max_attempts` times.
        // Surface to caller or escalate.
        error.NetworkTimeout, error.ConnectionFailed => {
            std.log.err("transport failed after retries: {s}", .{@errorName(err)});
            return err;
        },
        // JSON-RPC error from the server — inspect the structured payload.
        error.ServerError => {
            var info = client.takeLastServerError() orelse return err;
            defer info.deinit(client.allocator);
            std.log.warn("rpc error {d}: {s}", .{ info.code, info.message });
            return err;
        },
        else => return err,
    };
}
```

## Best Practices

### Security

1. **Always zeroize sensitive data:**

```zig
var key_pair = try neo.crypto.generateKeyPair(true);
defer {
    var kp = key_pair;
    kp.zeroize();
}
```

2. **Never log private keys, WIF, or mnemonics:**

```zig
// BAD
std.log.info("Private key: {s}", .{private_key});

// GOOD
std.log.info("Key generated successfully", .{});
```

3. **Use secure connections (HTTPS):**

```zig
// Use HTTPS for production
var client = try neo.Client.builder(allocator)
    .endpoint("https://mainnet1.neo.coz.io:443")
    .build();
defer client.deinit();
```

### Performance

1. **Reuse allocators:**

```zig
// For batch operations, reuse the allocator
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer gpa.deinit();
const allocator = gpa.allocator();
```

2. **Pre-allocate when size is known:**

```zig
// Use FixedBufferAllocator for known limits
var buffer: [4096]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&buffer);
const allocator = fba.allocator();
```

3. **Minimize allocations in hot paths:**

```zig
// Prefer stack allocation for small fixed-size data
var address_buffer: [35]u8 = undefined; // Max Neo address length
const address_str = try address.toStringBuffer(&address_buffer);
```

### Memory

1. **Match allocation with deallocation:**

```zig
// Allocate with allocator, free with same allocator
const str = try someFunction(allocator);
defer allocator.free(str);
```

2. **Use defer for cleanup:**

```zig
var wallet = neo.wallet.Wallet.init(allocator);
defer wallet.deinit(); // Always runs, even on error
```

3. **Handle optional values:**

```zig
if (account.getLabel()) |label| {
    std.log.info("Label: {s}", .{label});
}
```

## Network Magic Values

When signing transactions, use the correct network magic:

| Network | Magic |
|---------|-------|
| MainNet | 860400102 |
| TestNet | 894300462 |

Get from node:

```zig
const magic = try client.getNetworkMagic();
```

## Related Documentation

- [API Reference](API.md) - Detailed API documentation
- [Architecture](ARCHITECTURE.md) - SDK architecture overview
- [Swift Migration](SWIFT_MIGRATION.md) - Migration from Swift SDK
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions
- [Examples](../examples/) - Working code examples
