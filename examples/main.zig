//! Neo Zig SDK Examples
//!
//! Comprehensive, self-contained examples demonstrating key SDK features.
//! Each example is compilable and can be run independently.

const std = @import("std");
const neo = @import("neo-zig");
const tx = neo.transaction;
const wallet = neo.wallet;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.log.info("Neo Zig SDK Examples", .{});
    std.log.info("====================", .{});

    try demonstrateHashes(allocator);
    try demonstrateKeysAndAddresses(allocator);
    try demonstrateWifRoundtrip(allocator);
    try demonstrateAddressValidation(allocator);
    try demonstrateTransactionBuilding(allocator);
    try demonstrateWalletOperations(allocator);
    try demonstrateContractParameters(allocator);
    try demonstrateRpcRequests(allocator);

    std.log.info("\nAll examples completed successfully.", .{});
}

fn ensure(ok: bool) !void {
    if (!ok) return error.ExampleInvariantFailed;
}

fn demonstrateHashes(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Hash Operations ---", .{});

    const message = "Neo Zig SDK hash example";

    const sha = neo.Hash256.sha256(message);
    const sha_hex = try sha.string(allocator);
    defer allocator.free(sha_hex);
    std.log.info("SHA256(\"{s}\") = {s}...", .{ message, sha_hex[0..16] });

    const double_sha = neo.crypto.BytesHashUtils.hash256(message);
    const double_sha_hex = try double_sha.string(allocator);
    defer allocator.free(double_sha_hex);
    std.log.info("Double SHA256 = {s}...", .{double_sha_hex[0..16]});

    const hash160 = try neo.crypto.hash160(message);
    const hash160_hex = try hash160.string(allocator);
    defer allocator.free(hash160_hex);
    std.log.info("Hash160 = {s}...", .{hash160_hex[0..16]});

    const ripemd = try neo.crypto.ripemd160Hash(message);
    const ripemd_hex = try ripemd.string(allocator);
    defer allocator.free(ripemd_hex);
    std.log.info("RIPEMD160 = {s}...", .{ripemd_hex[0..16]});
}

fn demonstrateKeysAndAddresses(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Key Generation & Address Creation ---", .{});

    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var mutable = key_pair;
        mutable.zeroize();
    }

    const address = try key_pair.public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("Generated address: {s}", .{address_str});

    const parsed = try neo.Address.fromString(address_str, allocator);
    try ensure(parsed.eql(address));

    const script_hash = address.toHash160();
    const hash_hex = try script_hash.toHex(allocator);
    defer allocator.free(hash_hex);
    std.log.info("Script hash: {s}", .{hash_hex});

    if (address.isValid()) {
        std.log.info("Address is valid", .{});
    }
    if (address.isStandard()) {
        std.log.info("Address is standard (single signature)", .{});
    }
}

fn demonstrateWifRoundtrip(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- WIF Key Format ---", .{});

    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var mutable = key_pair;
        mutable.zeroize();
    }

    const wif_mainnet = try neo.crypto.encodeWIF(key_pair.private_key, true, .mainnet, allocator);
    defer allocator.free(wif_mainnet);
    std.log.info("Mainnet WIF: {s}...", .{wif_mainnet[0..10]});

    const wif_testnet = try neo.crypto.encodeWIF(key_pair.private_key, true, .testnet, allocator);
    defer allocator.free(wif_testnet);
    std.log.info("Testnet WIF: {s}...", .{wif_testnet[0..10]});

    var decoded = try neo.crypto.decodeWIF(wif_mainnet, allocator);
    defer decoded.deinit();

    try ensure(decoded.private_key.eql(key_pair.private_key));
    try ensure(decoded.compressed);
    try ensure(decoded.network == .mainnet);
    std.log.info("WIF round-trip successful", .{});
}

fn demonstrateAddressValidation(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Address Validation ---", .{});

    const test_address = "Nj6QRk4G1UcCqSF9QWxxwwfzgfttFsqvGh";
    const address = try neo.Address.fromString(test_address, allocator);

    if (address.isValid()) {
        std.log.info("Address '{s}' is valid", .{test_address});
    }

    if (address.isStandard()) {
        std.log.info("Address is standard single-signature", .{});
    }

    const script_hash = address.toHash160();
    const hash_hex = try script_hash.toHex(allocator);
    defer allocator.free(hash_hex);
    std.log.info("Script hash: {s}", .{hash_hex});

    const reconstructed = neo.Address.fromHash160(script_hash);
    try ensure(address.eql(reconstructed));
    std.log.info("Address round-trip from hash successful", .{});
}

fn demonstrateTransactionBuilding(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Transaction Building ---", .{});

    var builder = tx.TransactionBuilder.init(allocator);
    defer builder.deinit();

    _ = builder.version(0)
        .additionalNetworkFee(500000)
        .additionalSystemFee(1000000);

    const signer = tx.Signer.init(neo.Hash160.ZERO, tx.WitnessScope.CalledByEntry);
    _ = try builder.signer(signer);

    _ = try builder.transferToken(
        tx.TransactionBuilder.GAS_TOKEN_HASH,
        neo.Hash160.ZERO,
        neo.Hash160.ZERO,
        100000000,
    );

    var transaction = try builder.build();
    defer transaction.deinit(allocator);

    try transaction.validate();
    std.log.info("Transaction built and validated successfully", .{});

    const tx_hash = try transaction.getHash(allocator);
    const hash_hex = try tx_hash.string(allocator);
    defer allocator.free(hash_hex);
    std.log.info("Transaction hash: {s}...", .{hash_hex[0..16]});
}

fn demonstrateWalletOperations(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Wallet Operations ---", .{});

    var wallet_instance = wallet.Wallet.init(allocator);
    defer wallet_instance.deinit();

    _ = wallet_instance.name("Example Wallet").version("3.0");
    std.log.info("Created wallet: {s} v{s}", .{ wallet_instance.getName(), wallet_instance.getVersion() });

    const account = try wallet_instance.createAccount("Primary Account");
    std.log.info("Created account: {s}", .{account.getLabel().?});

    if (wallet_instance.isDefault(account)) {
        std.log.info("Account is default", .{});
    }

    std.log.info("Wallet has {} accounts", .{wallet_instance.getAccountCount()});

    const account_address = account.getAddress();
    const address_str = try account_address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("Account address: {s}", .{address_str});
}

fn demonstrateContractParameters(_: std.mem.Allocator) !void {
    std.log.info("\n--- Contract Parameters ---", .{});

    const param_string = neo.ContractParameter.string("hello");
    std.log.info("String parameter: {s}", .{param_string.String});

    const param_integer = neo.ContractParameter.integer(42);
    std.log.info("Integer parameter: {}", .{param_integer.Integer});

    const param_bool = neo.ContractParameter.boolean(true);
    std.log.info("Boolean parameter: {}", .{param_bool.Boolean});

    const param_hash160 = neo.ContractParameter.hash160(neo.Hash160.ZERO);
    _ = param_hash160;
    std.log.info("Hash160 parameter created", .{});

    const param_array = neo.ContractParameter.array(&[_]neo.ContractParameter{
        neo.ContractParameter.string("item1"),
        neo.ContractParameter.integer(123),
    });
    std.log.info("Array parameter with {} items", .{param_array.Array.len});
}

fn demonstrateRpcRequests(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- RPC Client (AWS-style) ---", .{});

    var client = try neo.Client.builder(allocator)
        .endpoint("http://localhost:20332")
        .timeoutMs(15_000)
        .retryPolicy(.{ .max_attempts = 3 })
        .build();
    defer client.deinit();

    std.log.info("Client built (endpoint=http://localhost:20332, timeout=15s, retries=3)", .{});

    // Each operation is a direct method on the client.
    // Note: these only complete with a live Neo N3 node listening on the endpoint.
    // We comment the actual network calls to keep this example offline-safe.
    //
    //   const count = try client.getBlockCount();
    //   var version = try client.getVersion();
    //   defer version.deinit(allocator);
    //   var balances = try client.getNep17Balances(some_hash);
    //   defer balances.deinit(allocator);
    //
    // The builder also accepts a network preset:
    //   var mainnet = try neo.Client.builder(allocator).network(.mainnet).build();
    //   defer mainnet.deinit();

    std.log.info("RPC client surface verified offline", .{});
}
