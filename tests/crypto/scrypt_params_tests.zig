//! Scrypt Parameters Tests
//!
//! Complete conversion from NeoSwift ScryptParamsTests.swift
//! Tests scrypt parameter validation and configuration.

const std = @import("std");
const testing = std.testing;
const ScryptParams = @import("../../src/crypto/scrypt_params.zig").ScryptParams;

test "Scrypt parameters creation and validation" {
    const testing = std.testing;
    
    // Test default parameters
    const default_params = ScryptParams.default();
    try testing.expectEqual(@as(u32, ScryptParams.N_STANDARD), default_params.n);
    try testing.expectEqual(@as(u32, ScryptParams.R_STANDARD), default_params.r);
    try testing.expectEqual(@as(u32, ScryptParams.P_STANDARD), default_params.p);
    
    try default_params.validate();
    
    // Test custom parameters
    const custom_params = ScryptParams.init(1024, 4, 2);
    try testing.expectEqual(@as(u32, 1024), custom_params.n);
    try testing.expectEqual(@as(u32, 4), custom_params.r);
    try testing.expectEqual(@as(u32, 2), custom_params.p);
    
    try custom_params.validate();
}

test "Scrypt parameters equality and hashing" {
    const testing = std.testing;
    
    const params1 = ScryptParams.init(1024, 8, 8);
    const params2 = ScryptParams.init(1024, 8, 8);
    const params3 = ScryptParams.init(2048, 8, 8);
    
    try testing.expect(params1.eql(params2));
    try testing.expect(!params1.eql(params3));
    
    const hash1 = params1.hash();
    const hash2 = params2.hash();
    const hash3 = params3.hash();
    
    try testing.expectEqual(hash1, hash2);
    try testing.expectNotEqual(hash1, hash3);
}

test "Scrypt parameters validation errors" {
    const testing = std.testing;
    
    // Test invalid N (not power of 2)
    const invalid_n = ScryptParams.init(1023, 8, 8);
    try testing.expectError(error.InvalidScryptN, invalid_n.validate());
    
    // Test invalid r
    const invalid_r = ScryptParams.init(1024, 0, 8);
    try testing.expectError(error.InvalidScryptR, invalid_r.validate());
    
    // Test invalid p
    const invalid_p = ScryptParams.init(1024, 8, 0);
    try testing.expectError(error.InvalidScryptP, invalid_p.validate());
}