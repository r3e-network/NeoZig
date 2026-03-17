# Troubleshooting Guide

This guide covers common issues, error messages, and their solutions when using the Neo Zig SDK.

## Table of Contents

- [Build Issues](#build-issues)
- [Memory and Allocator Errors](#memory-and-allocator-errors)
- [Cryptography Errors](#cryptography-errors)
- [RPC and Network Errors](#rpc-and-network-errors)
- [Transaction Errors](#transaction-errors)
- [Wallet Errors](#wallet-errors)
- [Address and Hash Validation](#address-and-hash-validation)
- [Common Error Codes](#common-error-codes)

## Build Issues

### "error: unable to find 'neo-zig' dependency"

**Problem**: The SDK cannot be found as a dependency.

**Solution**: Ensure your `build.zig.zon` contains the correct dependency:

```zig
.dependencies = .{
    .neo_zig = .{
        .url = "https://github.com/r3e-network/neo-zig-sdk/archive/refs/tags/v1.4.0.tar.gz",
        .hash = "...",
    },
};
```

Then add it to your `build.zig`:

```zig
const neo_zig = b.dependency("neo_zig", .{});
exe.root_module.addImport("neo-zig", neo_zig.module("neo-zig"));
```

Run `zig build` after updating dependencies.

### "error: invalid manifest file format" during cache errors

**Problem**: Switching Zig versions causes cache corruption.

**Solution**: Use a repo-local global cache:

```bash
zig build test --global-cache-dir .zig-global-cache
```

Or clear the cache:

```bash
rm -rf .zig-cache ~/.cache/zig
```

### " Zig 0.x.x is too old, expected 0.14.0+"

**Problem**: Your Zig version is below the minimum required version.

**Solution**: Install Zig 0.14.0 or later from [ziglang.org](https://ziglang.org/download/).

## Memory and Allocator Errors

### Memory leaks detected during tests

**Problem**: Tests report memory leaks.

**Solution**: Ensure all types with `deinit()` are properly cleaned up:

```zig
var wallet = neo.wallet.Wallet.init(allocator);
defer wallet.deinit();  // Always defer deinit

const account = try wallet.createAccount("My Account");
// ... use account ...
```

For types with allocator parameter:

```zig
var client = try neo.rpc.Client.builder(allocator)
    .endpoint("https://testnet1.neo.coz.io:443")
    .config(config)
    .build();
defer client.deinit();
```

### "out of memory" during allocation

**Problem**: Allocation fails due to memory pressure or incorrect allocator.

**Solution**: Use an appropriate allocator for your use case:

```zig
// For short-lived tools, page_allocator is fine
const allocator = std.heap.page_allocator;

// For long-running applications, use a general purpose allocator
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();
defer gpa.deinit();
```

### Double-free or use-after-free

**Problem**: Program crashes with memory corruption.

**Solution**: Follow the ownership model strictly:

```zig
// GOOD: Clear ownership
var client = try neo.rpc.Client.builder(allocator)
    .endpoint("https://testnet1.neo.coz.io:443")
    .config(config)
    .build();
defer client.deinit();

// BAD: Double ownership
var client = try neo.rpc.Client.builder(allocator)
    .endpoint("https://testnet1.neo.coz.io:443")
    .config(config)
    .build();
client.deinit();
client.deinit();  // CRASH!
```

## Cryptography Errors

### "invalid key" or "invalid private key format"

**Problem**: Private key validation fails.

**Solution**: Ensure the key is in the correct format:

```zig
// Generate a valid key
const private_key = neo.crypto.generatePrivateKey();

// Or decode from WIF
const wif = try neo.crypto.decodeWIF(wif_string, allocator);
defer wif.deinit();
```

Private keys must be 32 bytes for secp256r1.

### "signature verification failed"

**Problem**: ECDSA signature verification fails.

**Solution**:

1. Ensure you're using the correct network magic when signing:

```zig
const magic = try client.getNetworkMagicNumber();
// Use magic when building the transaction
```

2. Verify the public key matches the signature:

```zig
const is_valid = try neo.crypto.verifySignature(
    message,
    signature,
    public_key,
);
```

3. Check that the signature wasn't tampered with during transmission.

### "NEP-2 decryption failed"

**Problem**: Decrypting a NEP-2 encrypted key fails.

**Solution**:

1. Verify the password is correct:

```zig
var nep2_key = try neo.crypto.NEP2.fromEncryptedString(encrypted_nep2, allocator);
defer nep2_key.deinit();

const private_key = try nep2_key.decrypt(allocator, "correct_password");
// Wrong password returns an error
```

2. Ensure the NEP-2 string is correctly formatted.

### "BIP-39 mnemonic validation failed"

**Problem**: BIP-39 mnemonic word validation fails.

**Solution**:

```zig
// Validate mnemonic before use
const is_valid = neo.wallet.Bip39Account.isValidMnemonic(mnemonic);

// BIP-39 now supports Unicode mnemonics and passphrases with NFKD normalization.
// Both the mnemonic and passphrase are normalized using NFKD as required by BIP-39.
// Supported Unicode scripts include Latin (é, ü, ñ), Greek (α, β), CJK (中文, 日本語), and more.
```

## RPC and Network Errors

### "connection refused" or "timeout"

**Problem**: Cannot connect to Neo node.

**Solution**:

1. Verify the endpoint URL:

```zig
// TestNet
var service = neo.rpc.service.Service.init("https://testnet1.neo.coz.io:443");

// MainNet
var service = neo.rpc.service.Service.init("https://mainnet1.neo.coz.io:443");
```

2. Check network connectivity:

```bash
curl -X POST https://testnet1.neo.coz.io:443 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getversion","params":[],"id":1}'
```

3. Configure timeout:

```zig
var client = try neo.rpc.Client.builder(allocator)
    .endpoint("https://testnet1.neo.coz.io:443")
    .config(try neo.rpc.Config.builder().build())
    .timeoutMs(30000)
    .build();
defer client.deinit();
```

### "invalid response format"

**Problem**: RPC response cannot be parsed.

**Solution**:

1. Check if the node is responding correctly:

```zig
const version = try client.getVersion();
std.log.info("Node version: {}", .{version});
```

2. Ensure you're using a compatible Neo node version (v3.9+).

3. Enable debug logging:

```zig
std.log.debug("Enable additional RPC diagnostics in your application", .{});
```

### "HTTP response too large"

**Problem**: Response body exceeds the 32 MiB default limit.

**Solution**:

```zig
// Increase or disable the limit
var client = try neo.rpc.Client.builder(allocator)
    .endpoint(endpoint)
    .config(try neo.rpc.Config.builder().build())
    .maxResponseBytes(64 * 1024 * 1024)
    .build();
defer client.deinit();

// Or keep the transport-level path when you already own a service:
var service = neo.rpc.service.Service.init(endpoint);
service.setMaxResponseBytes(64 * 1024 * 1024);
```

### "max retries exceeded"

**Problem**: RPC request failed after maximum retries.

**Solution**:

```zig
var client = try neo.rpc.Client.builder(allocator)
    .endpoint("https://testnet1.neo.coz.io:443")
    .config(try neo.rpc.Config.builder().build())
    .maxRetries(5)
    .timeoutMs(30000)
    .build();
defer client.deinit();
```

Check the node status and consider using a different endpoint.

## Transaction Errors

### "invalid signer scope"

**Problem**: Witness scope is invalid for the operation.

**Solution**: Use appropriate scopes:

```zig
const signer = neo.transaction.Signer.init(
    script_hash,
    neo.transaction.WitnessScope.CalledByEntry,  // Most common
);

// For contracts that need broader access:
neo.transaction.WitnessScope.Global,
// Or combine scopes:
neo.transaction.WitnessScope.CalledByEntry | neo.transaction.WitnessScope.CustomContracts;
```

### "insufficient funds"

**Problem**: Account doesn't have enough tokens for the transaction.

**Solution**:

1. Check balance before building:

```zig
const balance = try client.getNep17Balance(
    account_hash,
    neo.contract.NeoToken.NEO_HASH,
);
std.log.info("NEO balance: {}", .{balance});
```

2. Account for system and network fees:

```zig
var builder = neo.transaction.TransactionBuilder.init(allocator);
_ = builder.additionalSystemFee(1000000)  // 0.01 NEO
    .additionalNetworkFee(500000);  // 0.005 NEO
```

### "invalid transaction signature"

**Problem**: Transaction signature verification fails.

**Solution**:

1. Ensure correct network magic:

```zig
const magic = try client.getNetworkMagicNumber();
const signed_tx = try transaction.sign(key_pair, magic);
```

2. Verify signer order matches script hashes:

```zig
// Signers must be in the order their scripts will be executed
for (signers) |signer| {
    // Add signers from most restrictive to least restrictive
}
```

### "transaction already exists"

**Problem**: Transaction with the same hash was already broadcast.

**Solution**: The transaction was already sent. Check the blockchain:

```zig
const tx_hash = try transaction.getHash(allocator);
const application_log = try client.getApplicationLog(tx_hash);
```

Do not attempt to resend the same transaction.

## Wallet Errors

### "wallet file corrupted"

**Problem**: NEP-6 wallet file is invalid or corrupted.

**Solution**:

1. Verify the JSON structure:

```json
{
  "name": "My Wallet",
  "version": "3.0",
  "scrypt": {
    "cost": 16384,
    "blockSize": 8,
    "parallel": 8,
    "size": 64
  },
  "accounts": [...],
  "extra": null
}
```

2. Try loading with a backup:

```zig
var wallet = try neo.wallet.CompleteNEP6Wallet.loadFromFile("backup.json", allocator);
defer wallet.deinit();
```

### "wrong password for wallet"

**Problem**: Decrypting wallet fails due to incorrect password.

**Solution**: Use the correct password or restore from mnemonic:

```zig
var bip39 = try neo.wallet.Bip39Account.loadFromMnemonic(
    allocator,
    mnemonic,
    "password_if_applied",
);
```

### "account not found in wallet"

**Problem**: Looking up an account fails.

**Solution**:

```zig
const account = wallet.getAccount(script_hash);
if (account == null) {
    // Account doesn't exist
    // Check if you meant to add it
}
```

## Address and Hash Validation

### "invalid address format"

**Problem**: Neo address validation fails.

**Solution**:

1. Validate the address format:

```zig
const address = neo.Address.fromString(allocator, address_str);
if (address.isValid()) {
    // Address is valid
}
```

2. Ensure you're using the correct address version:

```zig
// MainNet: ADDRESS_VERSION (0x35 = 53)
// TestNet: ADDRESS_VERSION_TESTNET (0x35 = 53) - Same for N3
const address = try public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
```

### "address doesn't match network"

**Problem**: Address is for the wrong network.

**Solution**: Addresses are network-agnostic in N3, but ensure consistency:

```zig
// All operations should use the same network endpoint
// MainNet addresses work on MainNet, TestNet on TestNet
```

### "hash length invalid"

**Problem**: Hash160 or Hash256 length is incorrect.

**Solution**:

```zig
// Hash160 must be 20 bytes
const hash160 = neo.Hash160.fromString("abc");

// Hash256 must be 32 bytes
const hash256 = neo.Hash256.fromString("abc");
```

## Common Error Codes

### Error Set Reference

The SDK uses comprehensive error sets. Common errors include:

```zig
// From neo.core.errors
error.OutOfMemory              // Allocation failed
error.InvalidInput             // Invalid function parameter
error.InvalidAddress           // Malformed Neo address
error.InvalidPublicKey         // Invalid ECDSA public key
error.InvalidPrivateKey        // Invalid ECDSA private key
error.InvalidSignature         // Signature verification failed
error.InvalidFormat            // Parsing failed (WIF, NEP-2, etc.)
error.WrongPassword            // Decryption with wrong password

// From neo.rpc.errors
error.ConnectionFailed         // Network connection failed
error.RequestTimeout           // RPC request timed out
error.InvalidResponse          // Malformed RPC response
error.ServerError              // RPC server returned error
```

### Handling Errors

```zig
const result = client.getBlockCount() catch |err| {
    switch (err) {
        error.ConnectionFailed => {
            std.log.err("Cannot connect to node", .{});
            return err;
        },
        error.RequestTimeout => {
            std.log.warn("Request timed out, retrying...", .{});
            return try client.getBlockCount();
        },
        else => {
            std.log.err("Unexpected error: {}", .{err});
            return err;
        }
    }
};
```

## Getting Help

If your issue isn't covered here:

1. Check [existing issues](https://github.com/r3e-network/neo-zig-sdk/issues)
2. Search [GitHub Discussions](https://github.com/r3e-network/neo-zig-sdk/discussions)
3. Create a new issue with:
   - Clear description of the problem
   - Minimal reproduction code
   - Zig version (`zig version`)
   - OS and environment details
