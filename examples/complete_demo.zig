//! Complete Neo Zig SDK demonstration
//!
//! Comprehensive Neo Zig SDK demo.

const std = @import("std");

const neo = @import("neo-zig");

fn ensure(ok: bool) !void {
    if (!ok) return error.DemoInvariantFailed;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.log.info("🚀 Neo Zig SDK - Complete Demo", .{});
    std.log.info("================================================", .{});

    // Demonstrate all SDK functionality
    try demonstrateKeyManagement(allocator);
    try demonstrateHashOperations(allocator);
    try demonstrateAddressOperations(allocator);
    try demonstrateTransactionBuilding(allocator);
    try demonstrateWalletManagement(allocator);
    try demonstrateRpcClient(allocator);

    std.log.info("✅ All functionality successfully demonstrated!", .{});
}

/// Demonstrates key management
fn demonstrateKeyManagement(allocator: std.mem.Allocator) !void {
    std.log.info("\n🔑 Key Management ", .{});

    // Generate key pair
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    std.log.info("  ✅ Generated key pair with compressed public key", .{});

    // Test WIF encoding
    const wif_mainnet = try neo.crypto.encodeWIF(key_pair.private_key, true, .mainnet, allocator);
    defer allocator.free(wif_mainnet);

    std.log.info("  📝 WIF encoded: {s}...", .{wif_mainnet[0..10]});

    // Decode WIF and verify
    var decoded = try neo.crypto.decodeWIF(wif_mainnet, allocator);
    defer decoded.deinit();
    try ensure(decoded.private_key.eql(key_pair.private_key));
    std.log.info("  ✅ WIF round-trip successful", .{});

    std.log.info("  🌐 Network: {}, Compressed: {}", .{ decoded.network, decoded.compressed });
}

/// Demonstrates hash operations
fn demonstrateHashOperations(allocator: std.mem.Allocator) !void {
    std.log.info("\n🔐 Hash Operations ", .{});

    const test_data = "Neo Zig SDK hash test data";

    // SHA256
    const sha_hash = neo.Hash256.sha256(test_data);
    const sha_hex = try sha_hash.string(allocator);
    defer allocator.free(sha_hex);
    std.log.info("  📊 SHA256: {s}...", .{sha_hex[0..16]});

    // RIPEMD160
    const ripemd_hash = try neo.crypto.ripemd160Hash(test_data);
    const ripemd_hex = try ripemd_hash.string(allocator);
    defer allocator.free(ripemd_hex);
    std.log.info("  🔍 RIPEMD160: {s}...", .{ripemd_hex[0..16]});

    // Hash160
    const hash160_result = try neo.crypto.hash160(test_data);
    const hash160_hex = try hash160_result.string(allocator);
    defer allocator.free(hash160_hex);
    std.log.info("  📋 Hash160: {s}...", .{hash160_hex[0..16]});

    // Test hash comparison and operations
    const same_sha = neo.Hash256.sha256(test_data);
    if (sha_hash.eql(same_sha)) {
        std.log.info("  ✅ Hash consistency verified", .{});
    }
}

/// Demonstrates address operations
fn demonstrateAddressOperations(allocator: std.mem.Allocator) !void {
    std.log.info("\n🏠 Address Operations ", .{});

    // Create address from public key
    var private_key = neo.crypto.generatePrivateKey();
    defer private_key.zeroize();
    const public_key = try private_key.getPublicKey(true);
    const address = try public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);

    // Convert to string
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);

    std.log.info("  📍 Generated address: {s}", .{address_str});

    // Validate address properties
    if (address.isValid()) {
        std.log.info("  ✅ Address is valid", .{});
    }

    if (address.isStandard()) {
        std.log.info("  📝 Standard single-signature address", .{});
    }

    // Test address conversion back to Hash160
    const script_hash = address.toHash160();
    const recovered_address = neo.Address.fromHash160(script_hash);

    if (address.eql(recovered_address)) {
        std.log.info("  ✅ Address round-trip successful", .{});
    }

    // Test Hash160 from address
    const hash_from_address = try neo.Hash160.fromAddress(address_str, allocator);
    if (script_hash.eql(hash_from_address)) {
        std.log.info("  ✅ Hash160 from address conversion successful", .{});
    }
}

/// Demonstrates transaction building
fn demonstrateTransactionBuilding(allocator: std.mem.Allocator) !void {
    std.log.info("\n💰 Transaction Building ", .{});

    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();

    // Configure transaction
    _ = builder.version(0)
        .additionalNetworkFee(500000)
        .additionalSystemFee(1000000);

    std.log.info("  ⚙️ Transaction configured - Version: 0, Network Fee: 500000, System Fee: 1000000", .{});

    // Add signer
    const signer = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry);
    _ = try builder.signer(signer);

    std.log.info("  👤 Signer added with CalledByEntry scope", .{});

    // Build GAS transfer
    _ = try builder.transferToken(
        neo.transaction.TransactionBuilder.GAS_TOKEN_HASH,
        neo.Hash160.ZERO, // from
        neo.Hash160.ZERO, // to
        100000000, // 1 GAS
    );

    std.log.info("  💸 GAS transfer script built (1.00000000 GAS)", .{});

    // Add high priority)
    _ = try builder.highPriority();

    if (builder.isHighPriority()) {
        std.log.info("  ⚡ High priority attribute added", .{});
    }

    // Build final transaction)
    var transaction = try builder.build();
    defer transaction.deinit(allocator);

    try transaction.validate();
    std.log.info("  ✅ Transaction built and validated successfully", .{});

    // Calculate transaction hash)
    const tx_hash = try transaction.getHash(allocator);
    const hash_hex = try tx_hash.string(allocator);
    defer allocator.free(hash_hex);

    std.log.info("  🔗 Transaction hash: {s}...", .{hash_hex[0..16]});
}

/// Demonstrates wallet management
fn demonstrateWalletManagement(allocator: std.mem.Allocator) !void {
    std.log.info("\n💼 Wallet Management ", .{});

    // Create wallet
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();

    _ = wallet.name("Demo Wallet").version("3.0");
    std.log.info("  📁 Created wallet: {s} v{s}", .{ wallet.getName(), wallet.getVersion() });

    // Create account
    const account = try wallet.createAccount("Demo Account");
    std.log.info("  👤 Created account with label: {s}", .{account.getLabel().?});

    // Verify default account
    if (wallet.isDefault(account)) {
        std.log.info("  🎯 Account set as default", .{});
    }

    std.log.info("  📊 Wallet has {} accounts", .{wallet.getAccountCount()});

    // Get account address
    const account_address = account.getAddress();
    const address_str = try account_address.toString(allocator);
    defer allocator.free(address_str);

    std.log.info("  📍 Account address: {s}", .{address_str});

    // Test account lookup
    const script_hash = account.getScriptHash();
    const found_account = wallet.getAccount(script_hash);

    if (found_account != null) {
        std.log.info("  ✅ Account lookup successful", .{});
    }
}

/// Demonstrates RPC client
fn demonstrateRpcClient(allocator: std.mem.Allocator) !void {
    std.log.info("\n🌐 RPC Client ", .{});

    // Create RPC client
    const config = neo.rpc.NeoConfig.init();
    var service = neo.rpc.NeoService.init("http://localhost:20332");
    const service_config = service.getConfiguration();
    var client = neo.rpc.NeoClient.build(allocator, &service, config);
    defer client.deinit();

    std.log.info("  🔗 RPC client created for endpoint: {s}", .{service_config.endpoint});
    std.log.info("  ⏱️ Timeout: {}ms", .{service_config.timeout_ms});

    // Test RPC request creation
    const best_block_request = try client.getBestBlockHash();
    std.log.info("  📊 Created request: {s}", .{best_block_request.method});

    const block_count_request = try client.getBlockCount();
    std.log.info("  📊 Created request: {s}", .{block_count_request.method});

    const version_request = try client.getVersion();
    std.log.info("  📊 Created request: {s}", .{version_request.method});

    // Test contract invocation request
    const contract_hash = neo.Hash160.ZERO;
    const params = [_]neo.ContractParameter{neo.ContractParameter.integer(42)};
    const signers = [_]neo.transaction.Signer{};

    const invoke_request = try client.invokeFunction(contract_hash, "balanceOf", &params, &signers);
    std.log.info("  📝 Created contract invocation: {s}", .{invoke_request.method});

    // Test wallet RPC methods
    const test_script_hash = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const balances_request = try client.getNep17Balances(test_script_hash);
    std.log.info("  💰 Created balance request: {s}", .{balances_request.method});

    std.log.info("  ✅ All RPC requests created successfully", .{});
}
