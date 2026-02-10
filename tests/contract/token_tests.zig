//! Token Tests
//!
//!
//! Tests base token functionality shared by NEP-17 and NEP-11.

const std = @import("std");

const testing = std.testing;
const Token = @import("../../src/contract/token.zig").Token;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const TestUtils = @import("../helpers/test_utilities.zig");

test "Token base functionality" {
    const allocator = testing.allocator;

    var client = try TestUtils.makeClientStub(allocator);
    defer TestUtils.destroyClientStub(&client);

    const token_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const token = Token.init(allocator, token_hash, &client);

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
