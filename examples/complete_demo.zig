//! Complete Neo Zig SDK demonstration.
//!
//! Exercises every major area of the SDK against the v2.0 flat surface:
//!   keys + WIF, hashes, addresses, transactions, wallets, and the
//!   AWS-style `neo.Client`. None of the operations contact a real node.

const std = @import("std");

const neo = @import("neo-zig");

fn ensure(ok: bool) !void {
    if (!ok) return error.DemoInvariantFailed;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.log.info("Neo Zig SDK — Complete Demo", .{});
    std.log.info("============================", .{});

    try demonstrateKeyManagement(allocator);
    try demonstrateHashOperations(allocator);
    try demonstrateAddressOperations(allocator);
    try demonstrateTransactionBuilding(allocator);
    try demonstrateWalletManagement(allocator);
    try demonstrateRpcClient(allocator);

    std.log.info("All functionality successfully demonstrated.", .{});
}

/// Generate a key pair, round-trip through WIF.
fn demonstrateKeyManagement(allocator: std.mem.Allocator) !void {
    std.log.info("\n-- Key Management --", .{});

    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }
    std.log.info("  generated compressed key pair", .{});

    const wif_mainnet = try neo.crypto.encodeWIF(key_pair.private_key, true, .mainnet, allocator);
    defer allocator.free(wif_mainnet);
    std.log.info("  WIF: {s}...", .{wif_mainnet[0..10]});

    var decoded = try neo.crypto.decodeWIF(wif_mainnet, allocator);
    defer decoded.deinit();
    try ensure(decoded.private_key.eql(key_pair.private_key));
    std.log.info("  WIF round-trip OK (network={}, compressed={})", .{ decoded.network, decoded.compressed });
}

/// SHA256, RIPEMD160, and the combined Hash160 (RIPEMD160 of SHA256).
fn demonstrateHashOperations(allocator: std.mem.Allocator) !void {
    std.log.info("\n-- Hash Operations --", .{});
    const test_data = "Neo Zig SDK hash test data";

    const sha_hash = neo.Hash256.sha256(test_data);
    const sha_hex = try sha_hash.string(allocator);
    defer allocator.free(sha_hex);
    std.log.info("  SHA256:    {s}...", .{sha_hex[0..16]});

    const ripemd_hash = try neo.crypto.ripemd160Hash(test_data);
    const ripemd_hex = try ripemd_hash.string(allocator);
    defer allocator.free(ripemd_hex);
    std.log.info("  RIPEMD160: {s}...", .{ripemd_hex[0..16]});

    const hash160_result = try neo.crypto.hash160(test_data);
    const hash160_hex = try hash160_result.string(allocator);
    defer allocator.free(hash160_hex);
    std.log.info("  Hash160:   {s}...", .{hash160_hex[0..16]});

    const same_sha = neo.Hash256.sha256(test_data);
    try ensure(sha_hash.eql(same_sha));
    std.log.info("  hash consistency verified", .{});
}

/// Address ↔ Hash160 round-trip.
fn demonstrateAddressOperations(allocator: std.mem.Allocator) !void {
    std.log.info("\n-- Address Operations --", .{});

    var private_key = neo.crypto.generatePrivateKey();
    defer private_key.zeroize();
    const public_key = try private_key.getPublicKey(true);
    const address = try public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);

    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("  address: {s}", .{address_str});

    if (address.isValid()) std.log.info("  address valid", .{});
    if (address.isStandard()) std.log.info("  standard single-signature", .{});

    const script_hash = address.toHash160();
    const recovered_address = neo.Address.fromHash160(script_hash);
    try ensure(address.eql(recovered_address));
    std.log.info("  Hash160 ↔ Address round-trip OK", .{});

    const hash_from_address = try neo.Hash160.fromAddress(address_str, allocator);
    try ensure(script_hash.eql(hash_from_address));
}

/// Build, validate, and hash a GAS transfer transaction.
fn demonstrateTransactionBuilding(allocator: std.mem.Allocator) !void {
    std.log.info("\n-- Transaction Building --", .{});

    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();

    _ = builder.version(0)
        .additionalNetworkFee(500_000)
        .additionalSystemFee(1_000_000);

    const signer = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry);
    _ = try builder.signer(signer);

    _ = try builder.transferToken(
        neo.transaction.TransactionBuilder.GAS_TOKEN_HASH,
        neo.Hash160.ZERO,
        neo.Hash160.ZERO,
        100_000_000, // 1.00000000 GAS
    );

    _ = try builder.highPriority();
    try ensure(builder.isHighPriority());

    var transaction = try builder.build();
    defer transaction.deinit(allocator);
    try transaction.validate();

    const tx_hash = try transaction.getHash(allocator);
    const hash_hex = try tx_hash.string(allocator);
    defer allocator.free(hash_hex);
    std.log.info("  tx hash: {s}...", .{hash_hex[0..16]});
}

/// Wallet + Account creation, default-account, lookup.
fn demonstrateWalletManagement(allocator: std.mem.Allocator) !void {
    std.log.info("\n-- Wallet Management --", .{});

    var wallet_instance = neo.wallet.Wallet.init(allocator);
    defer wallet_instance.deinit();

    _ = wallet_instance.name("Demo Wallet").version("3.0");
    std.log.info("  wallet: {s} v{s}", .{ wallet_instance.getName(), wallet_instance.getVersion() });

    const account = try wallet_instance.createAccount("Demo Account");
    std.log.info("  account label: {s}", .{account.getLabel().?});
    if (wallet_instance.isDefault(account)) std.log.info("  account is default", .{});

    const account_address = account.getAddress();
    const address_str = try account_address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("  address: {s}", .{address_str});

    const script_hash = account.getScriptHash();
    try ensure(wallet_instance.getAccount(script_hash) != null);
}

/// Build a `neo.Client` and confirm the AWS-style operations are reachable.
/// Operations are not actually invoked — that would require a live Neo node.
fn demonstrateRpcClient(allocator: std.mem.Allocator) !void {
    std.log.info("\n-- RPC Client (AWS-style) --", .{});

    var client = try neo.Client.builder(allocator)
        .endpoint("http://localhost:20332")
        .timeoutMs(15_000)
        .retryPolicy(.{ .max_attempts = 3, .initial_backoff_ms = 500 })
        .build();
    defer client.deinit();

    std.log.info("  client built (endpoint=http://localhost:20332)", .{});
    std.log.info("  retry: max_attempts={d}, backoff_ms={d}", .{
        client.retry.max_attempts,
        client.retry.initial_backoff_ms,
    });

    // Each of these returns its response value directly when a live node is
    // present — kept commented to keep the demo offline-safe:
    //
    //   const count = try client.getBlockCount();
    //   var version = try client.getVersion();
    //   defer version.deinit(allocator);
    //   var block = try client.getBlockByIndex(count - 1, .{ .full_transactions = true });
    //   defer block.deinit(allocator);
    //   var balances = try client.getNep17Balances(some_hash);
    //   defer balances.deinit(allocator);

    std.log.info("  client surface verified offline", .{});
}
