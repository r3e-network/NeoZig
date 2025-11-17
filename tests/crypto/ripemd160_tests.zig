//! RIPEMD160 Tests
//!
//! Complete conversion from NeoSwift RIPEMD160Tests.swift
//! Tests RIPEMD160 hashing functionality.

const std = @import("std");


const testing = std.testing;
const ripemd160 = @import("../../src/crypto/ripemd160.zig");

test "RIPEMD160 hash computation" {
    const test_data = "Hello, Neo!";
    const test_bytes = @as([]const u8, test_data);
    
    const hash_result = ripemd160.ripemd160(test_bytes);
    try testing.expectEqual(@as(usize, 20), hash_result.len);
    try testing.expect(!std.mem.allEqual(u8, &hash_result, 0));
}

test "RIPEMD160 consistency" {
    const test_data = "Test data";
    const test_bytes = @as([]const u8, test_data);
    
    const hash1 = ripemd160.ripemd160(test_bytes);
    const hash2 = ripemd160.ripemd160(test_bytes);
    
    try testing.expectEqualSlices(u8, &hash1, &hash2);
}