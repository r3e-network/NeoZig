//! Neo Zig SDK Benchmarks
//!
//! Performance benchmarks for key Neo SDK operations

const std = @import("std");
const ArrayList = std.ArrayList;


const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.log.info("🚀 Neo Zig SDK Benchmarks", .{});
    std.log.info("========================", .{});
    
    try benchmarkKeyGeneration();
    try benchmarkHashOperations();
    try benchmarkSignatures(allocator);
    try benchmarkAddressGeneration();
    try benchmarkTransactionBuilding(allocator);
    
    std.log.info("✅ All benchmarks completed!", .{});
}

/// Benchmark key generation operations
fn benchmarkKeyGeneration() !void {
    std.log.info("\n🔑 Key Generation Benchmark:", .{});
    
    const iterations = 1000;
    const start = std.time.nanoTimestamp();
    
    for (0..iterations) |_| {
        const private_key = neo.crypto.generatePrivateKey();
        _ = private_key; // Suppress unused variable warning
    }
    
    const end = std.time.nanoTimestamp();
    const duration_ns = end - start;
    const avg_ns = @as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(iterations));
    
    std.log.info("  Generated {} keys in {d}ms", .{ iterations, @as(f64, @floatFromInt(duration_ns)) / 1_000_000.0 });
    std.log.info("  Average: {d}μs per key", .{ avg_ns / 1000.0 });
}

/// Benchmark hash operations
fn benchmarkHashOperations() !void {
    std.log.info("\n🔐 Hash Operations Benchmark:", .{});
    
    const test_data = "Neo Zig SDK benchmark test data for hashing operations";
    const iterations = 10000;
    
    // SHA256 benchmark
    const start_sha = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const hash = neo.crypto.sha256(test_data);
        _ = hash;
    }
    const end_sha = std.time.nanoTimestamp();
    const sha_duration = end_sha - start_sha;
    
    std.log.info("  SHA256: {} hashes in {d}ms ({d}μs avg)", .{ 
        iterations, 
        @as(f64, @floatFromInt(sha_duration)) / 1_000_000.0,
        @as(f64, @floatFromInt(sha_duration)) / @as(f64, @floatFromInt(iterations)) / 1000.0
    });
    
    // Hash160 benchmark
    const start_h160 = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const hash = neo.crypto.hash160(test_data) catch continue;
        _ = hash;
    }
    const end_h160 = std.time.nanoTimestamp();
    const h160_duration = end_h160 - start_h160;
    
    std.log.info("  Hash160: {} hashes in {d}ms ({d}μs avg)", .{ 
        iterations, 
        @as(f64, @floatFromInt(h160_duration)) / 1_000_000.0,
        @as(f64, @floatFromInt(h160_duration)) / @as(f64, @floatFromInt(iterations)) / 1000.0
    });
}

/// Benchmark signature operations
fn benchmarkSignatures(allocator: std.mem.Allocator) !void {
    std.log.info("\n✍️  Signature Operations Benchmark:", .{});
    
    const message = "Neo Zig SDK signature benchmark message";
    const iterations = 100;
    
    // Generate test key
    const private_key = neo.crypto.generatePrivateKey();
    const public_key = try private_key.getPublicKey(true);
    
    // Signing benchmark
    const start_sign = std.time.nanoTimestamp();
    var signatures = ArrayList(neo.crypto.Signature).init(allocator);
    defer signatures.deinit();
    
    for (0..iterations) |_| {
        const signature = try neo.crypto.signMessage(message, private_key);
        try signatures.append(signature);
    }
    
    const end_sign = std.time.nanoTimestamp();
    const sign_duration = end_sign - start_sign;
    
    std.log.info("  Signing: {} signatures in {d}ms ({d}μs avg)", .{ 
        iterations, 
        @as(f64, @floatFromInt(sign_duration)) / 1_000_000.0,
        @as(f64, @floatFromInt(sign_duration)) / @as(f64, @floatFromInt(iterations)) / 1000.0
    });
    
    // Verification benchmark
    const start_verify = std.time.nanoTimestamp();
    var valid_count: u32 = 0;
    
    for (signatures.items) |signature| {
        const valid = try neo.crypto.verifyMessage(signature, message, public_key);
        if (valid) valid_count += 1;
    }
    
    const end_verify = std.time.nanoTimestamp();
    const verify_duration = end_verify - start_verify;
    
    std.log.info("  Verification: {} verifications in {d}ms ({d}μs avg)", .{ 
        iterations, 
        @as(f64, @floatFromInt(verify_duration)) / 1_000_000.0,
        @as(f64, @floatFromInt(verify_duration)) / @as(f64, @floatFromInt(iterations)) / 1000.0
    });
    std.log.info("  Valid signatures: {}/{}", .{ valid_count, iterations });
}

/// Benchmark address generation
fn benchmarkAddressGeneration() !void {
    std.log.info("\n🏠 Address Generation Benchmark:", .{});
    
    const iterations = 1000;
    const start = std.time.nanoTimestamp();
    
    for (0..iterations) |_| {
        const private_key = neo.crypto.generatePrivateKey();
        const public_key = try private_key.getPublicKey(true);
        const address = try public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
        _ = address;
    }
    
    const end = std.time.nanoTimestamp();
    const duration = end - start;
    
    std.log.info("  Generated {} addresses in {d}ms ({d}μs avg)", .{ 
        iterations, 
        @as(f64, @floatFromInt(duration)) / 1_000_000.0,
        @as(f64, @floatFromInt(duration)) / @as(f64, @floatFromInt(iterations)) / 1000.0
    });
}

/// Benchmark transaction building
fn benchmarkTransactionBuilding(allocator: std.mem.Allocator) !void {
    std.log.info("\n💰 Transaction Building Benchmark:", .{});
    
    const iterations = 100;
    const start = std.time.nanoTimestamp();
    
    for (0..iterations) |_| {
        var builder = neo.transaction.TransactionBuilder.init(allocator);
        defer builder.deinit();
        
        // Configure transaction
        _ = builder.version(0)
            .additionalNetworkFee(500000)
            .additionalSystemFee(1000000);

        _ = try builder.validUntilBlock(100000);
        
        // Add signer
        const signer = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry);
        _ = try builder.signer(signer);
        
        // Add transfer
        _ = try builder.transferToken(
            neo.transaction.TransactionBuilder.GAS_TOKEN_HASH,
            neo.Hash160.ZERO,
            neo.Hash160.ZERO,
            100000000,
        );
        
        // Build transaction
        var transaction = try builder.build();
        defer transaction.deinit(allocator);
    }
    
    const end = std.time.nanoTimestamp();
    const duration = end - start;
    
    std.log.info("  Built {} transactions in {d}ms ({d}μs avg)", .{ 
        iterations, 
        @as(f64, @floatFromInt(duration)) / 1_000_000.0,
        @as(f64, @floatFromInt(duration)) / @as(f64, @floatFromInt(iterations)) / 1000.0
    });
}
