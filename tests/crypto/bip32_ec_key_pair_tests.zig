//! BIP32 EC Key Pair Tests
//!
//! Complete conversion from NeoSwift Bip32ECKeyPairTests.swift
//! Tests hierarchical deterministic key derivation functionality.

const std = @import("std");
const testing = std.testing;
const Bip32ECKeyPair = @import("../../src/crypto/bip32.zig").Bip32ECKeyPair;

test "BIP32 key pair creation" {
    const allocator = testing.allocator;
    
    const test_seed = [_]u8{0x12} ** 64;
    
    var master_key = try Bip32ECKeyPair.generateKeyPair(&test_seed, allocator);
    defer master_key.deinit(allocator);
    
    try testing.expect(master_key.isValid());
    try testing.expectEqual(@as(i32, 0), master_key.depth);
    try testing.expectEqual(@as(i32, 0), master_key.child_number);
}

test "BIP32 key derivation" {
    const allocator = testing.allocator;
    
    const test_seed = [_]u8{0xAB} ** 64;
    
    var master_key = try Bip32ECKeyPair.generateKeyPair(&test_seed, allocator);
    defer master_key.deinit(allocator);
    
    const derivation_path = [_]i32{ 44, 888, 0, 0, 0 }; // Neo derivation path
    
    var derived_key = try Bip32ECKeyPair.deriveKeyPair(master_key, &derivation_path, allocator);
    defer derived_key.deinit(allocator);
    
    try testing.expect(derived_key.isValid());
    try testing.expectEqual(@as(i32, 5), derived_key.depth);
    try testing.expect(derived_key.child_number == 0);
}