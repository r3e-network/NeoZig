const std = @import("std");


const neo = @import("src/neo.zig");

test "Neo SDK main module functionality" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test that our main module exports work
    _ = neo.constants;
    _ = neo.errors;
    _ = neo.types;
    _ = neo.crypto;
    _ = neo.utils;
    
    // Test constants are accessible
    try testing.expectEqual(@as(usize, 20), neo.constants.HASH160_SIZE);
    try testing.expectEqual(@as(usize, 32), neo.constants.HASH256_SIZE);
    
    // Test error types are accessible
    const neo_error: type = neo.errors.NeoError;
    const crypto_error: type = neo.errors.CryptoError;
    _ = neo_error;
    _ = crypto_error;
    
    // Test basic functionality compiles
    try testing.expect(true);
}

test "Neo SDK type aliases" {
    const testing = std.testing;
    
    // Test that our type aliases work
    _ = neo.Hash160;
    _ = neo.Hash256;
    _ = neo.Address;
    _ = neo.ContractParameter;
    
    // These should all be accessible
    try testing.expect(true);
}