# API Reference

This document provides a high-level overview of the Neo Zig SDK API, organized by functional area.

## Table of Contents

- [Module Organization](#module-organization)
- [Core Types](#core-types)
- [Cryptography](#cryptography)
- [RPC Client](#rpc-client)
- [Transactions](#transactions)
- [Smart Contracts](#smart-contracts)
- [Wallet](#wallet)
- [Utilities](#utilities)

## Module Organization

The SDK is organized under the `neo` root module:

```zig
const neo = @import("neo-zig");
```

Available submodules:

| Module              | Purpose                                                        |
| ------------------- | -------------------------------------------------------------- |
| `neo.core`          | Constants, errors, and core types                              |
| `neo.types`         | Hash160, Hash256, Address, ContractParameter                   |
| `neo.crypto`        | Cryptographic operations (keys, signatures, NEP-2, WIF, BIP32) |
| `neo.rpc`           | JSON-RPC client (NeoClient, HTTP transport)                    |
| `neo.transaction`   | Transaction building and signing                               |
| `neo.contract`      | Smart contract wrappers (NEP-17, NEP-11, native contracts)     |
| `neo.wallet`        | NEP-6 wallets, BIP-39 accounts                                 |
| `neo.script`        | Neo VM script construction                                     |
| `neo.serialization` | Binary serialization framework                                 |
| `neo.utils`         | Logging, validation, string/array utilities                    |

## Core Types

### Hash160

Represents a 160-bit hash (20 bytes), used for addresses and contract scripts.

```zig
// Create from string
const hash = try neo.Hash160.fromAddress("NX5v2MtKixV3mPJPfbJdc7f3oGyM2eE9CQ", allocator);

// Create from bytes
const bytes: [20]u8 = .{0}**20;
const hash = neo.Hash160.fromBytes(bytes);

// Create zero hash
const zero = neo.Hash160.ZERO;

// Convert to string
const str = try hash.string(allocator);
defer allocator.free(str);

// Compare
if (hash.eql(other_hash)) { /* equal */ }

// Get script hash for address
const script_hash = address.toHash160();
```

### Hash256

Represents a 256-bit hash (32 bytes), used for blocks and transactions.

```zig
// Create from string
const hash = try neo.Hash256.fromString("abc123...", allocator);

// SHA256 operation
const data = "Hello, Neo!";
const sha_hash = neo.Hash256.sha256(data);

// Convert to hex string
const hex_str = try hash.string(allocator);
defer allocator.free(hex_str);
```

### Address

Represents a Neo N3 address with Base58Check encoding.

```zig
// Create from public key
const address = try public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);

// Create from string
const address = try neo.Address.fromString(allocator, "NX5v2MtKixV3mPJPfbJdc7f3oGyM2eE9CQ");

// Validate
if (address.isValid()) { /* valid format */ }
if (address.isStandard()) { /* single-signature */ }

// Convert to script hash
const script_hash = address.toHash160();

// Round-trip conversion
const recovered = neo.Address.fromHash160(script_hash);
if (address.eql(recovered)) { /* same address */ }
```

### ContractParameter

Represents Neo VM contract parameters.

```zig
// Integer parameter
const int_param = neo.ContractParameter.integer(42);

// String parameter
const str_param = neo.ContractParameter.string("hello", allocator);
defer allocator.free(str_param.value.?);

// Byte array parameter
const bytes_param = neo.ContractParameter.byteArray(&[_]u8{0x01, 0x02, 0x03});

// Boolean parameter
const bool_param = neo.ContractParameter.boolean(true);

// Array parameter
const arr_param = neo.ContractParameter.array(&[_]neo.ContractParameter{
    neo.ContractParameter.integer(1),
    neo.ContractParameter.integer(2),
});

// Hash160 parameter
const hash_param = neo.ContractParameter.hash160(script_hash);
```

## Cryptography

### Key Generation

```zig
// Generate a new key pair
const key_pair = try neo.crypto.generateKeyPair(true);  // true = compressed
defer {
    var kp = key_pair;
    kp.zeroize();
}

// Generate private key only
const private_key = neo.crypto.generatePrivateKey();
defer private_key.zeroize();

// Get public key from private key
const public_key = try private_key.getPublicKey(true);  // true = compressed
```

### WIF (Wallet Import Format)

```zig
// Export private key to WIF
const wif = try neo.crypto.encodeWIF(
    private_key,
    true,               // compressed
    .mainnet,           // or .testnet
    allocator,
);
defer allocator.free(wif);

// Import WIF
var decoded = try neo.crypto.decodeWIF(wif, allocator);
defer decoded.deinit();
// decoded.private_key contains the key
```

### NEP-2 (Encrypted Private Key)

```zig
// Encrypt private key
const encrypted = try neo.crypto.encryptNEP2(
    private_key,
    "my_secure_password",
    allocator,
);
defer allocator.free(encrypted);

// Decrypt NEP-2
const decrypted_key = try neo.crypto.decryptNEP2(
    encrypted,
    "my_secure_password",
    allocator,
);
defer decrypted_key.zeroize();
```

### BIP-32 HD Wallets

```zig
// Create master key from seed
const master = try neo.crypto.BIP32.masterKey(seed, allocator);
defer master.deinit();

// Derive child key
const child = try master.derivePath("m/44'/888'/0'/0/0", allocator);
defer child.deinit();
```

### Signatures

```zig
// Sign a message
const signature = try neo.crypto.sign(
    message,      // []const u8
    private_key,
);

// Verify signature
const is_valid = try neo.crypto.verifySignature(
    message,
    signature,
    public_key,
);
```

### RIPEMD160 and Hash160

```zig
// RIPEMD160 hash
const ripemd = try neo.crypto.ripemd160Hash(data);
const hex = try ripemd.string(allocator);
defer allocator.free(hex);

// Hash160 (RIPEMD160 of SHA256)
const hash160 = try neo.crypto.hash160(data);
```

## RPC Client

### NeoClient Service

```zig
// Create service
var service = neo.rpc.NeoService.init("https://testnet1.neo.coz.io:443");

// Configure
service.setMaxResponseBytes(32 * 1024 * 1024);  // 32 MiB default
const config = service.getConfiguration();
```

### NeoClient Client

```zig
// Build client
const config = neo.rpc.NeoConfig.init();
var client = neo.rpc.NeoClient.build(allocator, &service, config);
defer client.deinit();

// Or with custom config
var custom_config = neo.rpc.NeoConfig.init();
custom_config.timeout_ms = 30000;
custom_config.max_retries = 3;
var client = neo.rpc.NeoClient.build(allocator, &service, custom_config);
```

### RPC Methods

**Blockchain Info:**

```zig
// Get current block count
const block_count_request = try client.getBlockCount();
const block_count = try block_count_request.send();

// Get best block hash
const best_hash_request = try client.getBestBlockHash();
const best_hash = try best_hash_request.send();

// Get block by hash or index
const block_request = try client.getBlock(block_hash);
const block = try block_request.send();

// Get block header
const header_request = try client.getBlockHeader(block_hash);
const header = try header_request.send();
```

**Network Info:**

```zig
// Get network magic (for signing)
const magic_request = try client.getNetworkMagicNumber();
const magic = try magic_request.send();

// Get node version
const version_request = try client.getVersion();
const version = try version_request.send();

// Getpeers (network connectivity)
const peers_request = try client.getPeers();
const peers = try peers_request.send();
```

**Token Balances:**

```zig
// Get NEP-17 balances
const balances_request = try client.getNep17Balances(script_hash);
const balances = try balances_request.send();

// Get specific token balance
const balance_request = try client.getNep17Balance(
    script_hash,
    neo.contract.GasToken.GAS_HASH,
);
const balance = try balance_request.send();
```

**Smart Contract:**

```zig
// Invoke read-only contract method
const params = [_]neo.ContractParameter{
    neo.ContractParameter.hash160(holder_address),
};
const invoke_request = try client.invokeFunction(
    contract_hash,
    "balanceOf",
    &params,
    &signers,
);
const result = try invoke_request.send();

// Get contract state
const state_request = try client.getContractState(contract_hash);
const state = try state_request.send();
```

**Transaction:**

```zig
// Send raw transaction
const result = try client.sendRawTransaction(transaction_bytes);

// Get application log
const log_request = try client.getApplicationLog(tx_hash);
const log = try log_request.send();

// Get transaction info
const tx_request = try client.getTransaction(tx_hash);
const tx = try tx_request.send();
```

## Transactions

### Transaction Builder

```zig
// Create builder
var builder = neo.transaction.TransactionBuilder.init(allocator);
defer builder.deinit();

// Configure
_ = builder.version(0)
    .additionalNetworkFee(500000)   // 0.005 NEO
    .additionalSystemFee(1000000);  // 0.01 NEO

// Add signer
const signer = neo.transaction.Signer.init(
    script_hash,
    neo.transaction.WitnessScope.CalledByEntry,
);
try builder.signer(signer);

// Add token transfer (NEP-17)
try builder.transferToken(
    neo.contract.GasToken.GAS_HASH,
    from_hash,
    to_hash,
    100000000,  // 1 GAS (8 decimals)
);

// Add custom script
try builder.script(script_bytes);

// Build transaction
var transaction = try builder.build();
defer transaction.deinit(allocator);

// Validate
try transaction.validate();

// Get transaction hash
const tx_hash = try transaction.getHash(allocator);
const hash_hex = try tx_hash.string(allocator);
defer allocator.free(hash_hex);
```

### Transaction Signing

```zig
// Get network magic (required for correct signing)
const magic = try client.getNetworkMagicNumber();

// Sign with key pair
const signed_tx = try transaction.sign(key_pair, magic);

// For multi-signature
const multi_tx = try transaction.signMulti(signer1, signature1, magic);
const final_tx = try multi_tx.signMulti(signer2, signature2, magic);
```

### Witness Rules

```zig
// Create witness rule for specific action
const rule = neo.transaction.WitnessRule.init(
    .Action,
    .Boolean,
);

// Example: Allow only specific contract calls
const contract_rule = neo.transaction.WitnessRule.forContract(contract_hash);
```

## Smart Contracts

### Native Contracts

```zig
// NEO Token
const neo_token = neo.contract.NeoToken.init(allocator, client);
const neo_balance = try neo_token.balanceOf(holder_address);
const neo_supply = try neo_token.getTotalSupply();

// GAS Token
const gas_token = neo.contract.GasToken.init(allocator, client);
const gas_balance = try gas_token.balanceOf(holder_address);

// Transfer
var transfer_tx = try gas_token.transfer(
    from_hash,
    to_hash,
    100000000,  // 1 GAS
    null,       // no data
);
defer transfer_tx.deinit();
```

### NEP-17 Tokens

```zig
// Generic NEP-17 interface
const token = neo.contract.FungibleToken.init(
    allocator,
    client,
    token_hash,
);

// Balance
const balance = try token.balanceOf(holder_address);

// Transfer
var transfer_tx = try token.transfer(
    from_hash,
    to_hash,
    amount,
    null,
);
```

### NEP-11 NFTs

```zig
// NFT token
const nft = neo.contract.NonFungibleToken.init(
    allocator,
    client,
    nft_hash,
);

// Get balance (number of NFTs owned)
const count = try nft.balanceOf(holder_address);

// Get specific token
const token_id = try nft.tokenOfOwnerByIndex(holder_address, 0);

// Transfer NFT
try nft.transfer(
    from_hash,
    to_hash,
    token_id,
);
```

### Contract Deployment

```zig
// Deploy new contract
const contract_mgmt = neo.contract.ContractManagement.init(allocator, client);

var nef_file: []const u8 = // ... NEF3 bytes;
const manifest = // ... contract manifest JSON;

var deploy_tx = try contract_mgmt.deploy(&nef_file, manifest, null);
defer deploy_tx.deinit();
```

### Contract Management

```zig
// Get contract state
const state = try contract_mgmt.getContract(contract_hash);

// Update contract
var update_tx = try contract_mgmt.update(&new_nef, new_manifest, null);
defer update_tx.deinit();

// Destroy contract
var destroy_tx = try contract_mgmt.destroy(null);
defer destroy_tx.deinit();
```

## Wallet

### NEP-6 Wallet

```zig
// Create new wallet
var wallet = neo.wallet.CompleteNEP6Wallet.init(allocator, "My Wallet");
defer wallet.deinit();

// Create account
const account = try wallet.createAccount("password", "Main Account");
const address = account.getAddress();

// Save wallet
try wallet.saveToFile("wallet.json");

// Load wallet
var loaded = try neo.wallet.CompleteNEP6Wallet.loadFromFile("wallet.json", allocator);
defer loaded.deinit();

// Unlock account
const unlocked = try wallet.getAccountUnlocked("password", account_address);
defer unlocked.deinit();
```

### BIP-39 Account

```zig
// Create new BIP-39 account
var bip39 = try neo.wallet.Bip39Account.create(allocator, "password");
defer bip39.deinit();

// Get mnemonic (24 words)
const mnemonic = bip39.getMnemonic();
std.log.info("Mnemonic: {s}", .{mnemonic});

// Derive accounts
const account = try bip39.deriveAccount(0);  // m/44'/888'/0'/0/0

// Load from mnemonic
var loaded = try neo.wallet.Bip39Account.loadFromMnemonic(
    allocator,
    mnemonic,
    "password",  // optional passphrase
);
defer loaded.deinit();

// Get private key
const private_key = try loaded.getPrivateKey(allocator);
defer private_key.zeroize();
```

### Wallet Operations

```zig
// Get account by address
const account = wallet.getAccount(address.toHash160());
if (account) |acc| {
    std.log.info("Found account: {s}", .{acc.getLabel().?});
}

// Check if default account
if (wallet.isDefault(account.?)) {
    std.log.info("Is default account");
}

// Get all accounts
const count = wallet.getAccountCount();
std.log.info("Total accounts: {}", .{count});
```

## Utilities

### Logging

```zig
// Use std.log directly (configure level/output in your application build options)

// Log messages
std.log.debug("Debug message: {}", .{value});
std.log.info("Info message: {}", .{value});
std.log.warn("Warning message: {}", .{value});
std.log.err("Error message: {}", .{value});
```

### Validation

```zig
// Validate Neo address
const is_valid = neo.utils.StringUtils.isValidAddress(address_str, allocator);

// Validate hex payload
const is_valid_hex = neo.utils.StringUtils.isValidHex(hex_str);
```

### String Extensions

```zig
// Hex decoding
const bytes = try neo.utils.StringUtils.bytesFromHex(hex_str, allocator);
defer allocator.free(bytes);

// Base58 encoding/decoding
const base58 = try neo.utils.StringUtils.base58Encoded(bytes, allocator);
defer allocator.free(base58);

const maybe_decoded = try neo.utils.StringUtils.base58Decoded(base58, allocator);
if (maybe_decoded) |decoded| allocator.free(decoded);
```

## Error Handling

The SDK uses Zig's error union types for explicit error handling:

```zig
// Basic error handling
const result = someNeoFunction() catch |err| {
    switch (err) {
        error.OutOfMemory => {
            std.log.err("Memory allocation failed", .{});
            return err;
        },
        error.InvalidInput => {
            std.log.err("Invalid input parameter", .{});
            return err;
        },
        else => {
            std.log.err("Unexpected error: {}", .{err});
            return err;
        }
    }
};

// Propagate errors
const address = try neo.Address.fromString(allocator, str);
```

## Memory Management Summary

| Type                 | Ownership   | Cleanup                         |
| -------------------- | ----------- | ------------------------------- |
| `KeyPair`            | Caller owns | `key_pair.zeroize()`            |
| `PrivateKey`         | Caller owns | `private_key.zeroize()`         |
| `WifResult`          | Caller owns | `result.deinit()`               |
| `Address`            | Caller owns | `address.deinit(allocator)`     |
| `Hash160`            | Caller owns | `hash.deinit(allocator)`        |
| `Hash256`            | Caller owns | `hash.deinit(allocator)`        |
| `Transaction`        | Caller owns | `transaction.deinit(allocator)` |
| `TransactionBuilder` | Caller owns | `builder.deinit()`              |
| `NeoClient`          | Caller owns | `client.deinit()`               |
| `Wallet`             | Caller owns | `wallet.deinit()`               |
| `Bip39Account`       | Caller owns | `account.deinit()`              |
| `NEP6Wallet`         | Caller owns | `wallet.deinit()`               |
| `Allocated strings`  | Caller owns | `allocator.free(str)`           |
| `JSON Values`        | Caller owns | Use `json_utils.freeValue()`    |
