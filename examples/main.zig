//! Neo Zig SDK Examples
//!
//! This file demonstrates the core functionality of the Neo Zig SDK,
//! including hash operations, address management, and contract parameters.

const std = @import("std");
const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.log.info("🚀 Neo Zig SDK Examples");
    std.log.info("========================");
    
    // Hash160 Examples
    try demonstrateHash160(allocator);
    
    // Hash256 Examples
    try demonstrateHash256(allocator);
    
    // Address Examples
    try demonstrateAddresses(allocator);
    
    // Contract Parameter Examples
    try demonstrateContractParameters(allocator);
    
    std.log.info("✅ All examples completed successfully!");
}

/// Demonstrates Hash160 operations
fn demonstrateHash160(allocator: std.mem.Allocator) !void {
    std.log.info("\n📋 Hash160 Examples:");
    
    // Create from hex string
    const hex_hash = try neo.Hash160.fromHex("0x1234567890abcdef1234567890abcdef12345678");
    const hex_str = try hex_hash.toHex(allocator);
    defer allocator.free(hex_str);
    std.log.info("  Hash160 from hex: {s}", .{hex_str});
    
    // Create zero hash
    const zero_hash = neo.Hash160.zero();
    std.log.info("  Zero hash: {}", .{zero_hash});
    
    // Hash some data
    const data = "Hello Neo Blockchain";
    const computed_hash = try neo.Hash160.ripemd160(data);
    std.log.info("  RIPEMD160('{}') = {}", .{ data, computed_hash });
    
    // Compare hashes
    if (hex_hash.eql(zero_hash)) {
        std.log.info("  Hashes are equal");
    } else {
        std.log.info("  Hashes are different");
    }
}

/// Demonstrates Hash256 operations
fn demonstrateHash256(allocator: std.mem.Allocator) !void {
    std.log.info("\n🔐 Hash256 Examples:");
    
    // Create from integer
    const int_hash = neo.Hash256.fromInt(0x123456789ABCDEF);
    std.log.info("  Hash256 from int: {}", .{int_hash});
    
    // SHA256 hashing
    const data = "Neo Blockchain Platform";
    const sha_hash = neo.Hash256.sha256(data);
    std.log.info("  SHA256('{}') = {}", .{ data, sha_hash });
    
    // Double SHA256 (Bitcoin-style)
    const double_sha = neo.Hash256.doubleSha256(data);
    std.log.info("  Double SHA256('{}') = {}", .{ data, double_sha });
    
    // Arithmetic operations
    const hash1 = neo.Hash256.fromInt(100);
    const hash2 = neo.Hash256.fromInt(50);
    const sum = hash1.add(hash2);
    std.log.info("  {} + {} = {}", .{ hash1.toInt(), hash2.toInt(), sum.toInt() });
    
    // Bitwise operations
    const and_result = hash1.bitwiseAnd(hash2);
    std.log.info("  Bitwise AND result: {}", .{and_result.toInt()});
    
    // Mining difficulty check
    const target = neo.Hash256.fromInt(0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    const mining_hash = neo.Hash256.fromInt(0x00001234567890ABCDEF);
    if (mining_hash.meetsDifficulty(target)) {
        std.log.info("  Mining hash meets difficulty target! ⛏️");
    }
}

/// Demonstrates Neo address operations
fn demonstrateAddresses(allocator: std.mem.Allocator) !void {
    std.log.info("\n🏠 Address Examples:");
    
    // Create address from Hash160
    var script_bytes: [20]u8 = undefined;
    for (&script_bytes, 0..) |*byte, i| {
        byte.* = @intCast((i * 17 + 42) % 256);
    }
    const script_hash = neo.Hash160.init(script_bytes);
    const address = neo.Address.fromHash160(script_hash);
    
    // Convert to string
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("  Address string: {s}", .{address_str});
    
    // Check address properties
    if (address.isValid()) {
        std.log.info("  ✅ Address is valid");
    }
    
    if (address.isStandard()) {
        std.log.info("  📝 Standard single-signature address");
    } else if (address.isMultiSig()) {
        std.log.info("  👥 Multi-signature address");
    }
    
    std.log.info("  Network: {}", .{address.getNetwork()});
    
    // Convert back to Hash160
    const recovered_hash = address.toHash160();
    if (script_hash.eql(recovered_hash)) {
        std.log.info("  ✅ Hash160 round-trip successful");
    }
}

/// Demonstrates contract parameter operations
fn demonstrateContractParameters(allocator: std.mem.Allocator) !void {
    std.log.info("\n📝 Contract Parameter Examples:");
    
    // Create various parameter types
    const bool_param = neo.ContractParameter.boolean(true);
    const int_param = neo.ContractParameter.integer(12345);
    const str_param = neo.ContractParameter.string("Hello Neo Smart Contract");
    
    const data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const bytes_param = neo.ContractParameter.byteArray(&data);
    
    const hash_param = neo.ContractParameter.hash160(neo.Hash160.zero());
    
    // Display parameter information
    const params = [_]neo.ContractParameter{ bool_param, int_param, str_param, bytes_param, hash_param };
    
    for (params, 0..) |param, i| {
        const param_str = try param.toString(allocator);
        defer allocator.free(param_str);
        const type_str = param.getType().toString();
        
        std.log.info("  Param {}: {} = {s}", .{ i + 1, type_str, param_str });
        
        // Validate parameter
        param.validate() catch |err| {
            std.log.warn("    ⚠️ Validation error: {}", .{err});
        };
        
        // Show estimated size
        const size = param.estimateSize();
        std.log.info("    Estimated size: {} bytes", .{size});
    }
    
    // Create transfer parameters example
    const from_hash = neo.Hash160.zero();
    const to_hash = neo.Hash160.zero();
    const transfer_params = try neo.types.ParameterUtils.transferParams(from_hash, to_hash, 1000, allocator);
    defer allocator.free(transfer_params);
    
    std.log.info("  Transfer parameters created: {} params", .{transfer_params.len});
    const total_size = neo.types.ParameterUtils.estimateArraySize(transfer_params);
    std.log.info("  Total estimated size: {} bytes", .{total_size});
    
    // Validate all parameters
    neo.types.ParameterUtils.validateArray(transfer_params) catch |err| {
        std.log.warn("  ⚠️ Parameter validation error: {}", .{err});
    };
    
    std.log.info("  ✅ All parameters valid");
}

/// Demonstrates error handling
fn demonstrateErrorHandling() !void {
    std.log.info("\n⚠️ Error Handling Examples:");
    
    // Invalid hex hash
    const invalid_result = neo.Hash160.fromHex("invalid_hex");
    if (invalid_result) |_| {
        std.log.info("  Unexpected success");
    } else |err| {
        std.log.info("  Expected error: {}", .{err});
    }
    
    // Invalid address
    if (neo.Address.validateString("invalid_address", std.heap.page_allocator)) {
        std.log.info("  Unexpected valid address");
    } else {
        std.log.info("  ✅ Invalid address correctly rejected");
    }
}