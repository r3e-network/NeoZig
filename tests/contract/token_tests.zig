//! Token Tests
//!
//! Complete conversion from NeoSwift TokenTests.swift
//! Tests base token functionality shared by NEP-17 and NEP-11.

const std = @import("std");
const testing = std.testing;
const Token = @import("../../src/contract/token.zig").Token;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;

test "Token base functionality" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = @import("../../src/rpc/neo_client.zig").NeoSwift.build(allocator, mock_service, mock_config);
    
    const token_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const token = Token.init(token_hash, neo_swift);
    
    try testing.expect(token.getScriptHash().eql(token_hash));
    try token.validate();
}

test "Token fraction calculations" {
    const testing = std.testing;
    
    // Test amount to fractions conversion
    const decimals: u32 = 8;
    const amount: f64 = 1.5;
    const expected_fractions: u64 = 150000000; // 1.5 * 10^8
    
    const calculated_fractions = Token.toFractions(amount, decimals);
    try testing.expectEqual(expected_fractions, calculated_fractions);
    
    // Test fractions to amount conversion
    const calculated_amount = Token.fromFractions(expected_fractions, decimals);
    try testing.expectEqual(amount, calculated_amount);
}