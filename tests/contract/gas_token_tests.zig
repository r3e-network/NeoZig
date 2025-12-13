//! GAS Token Tests
//!
//! Complete conversion from NeoSwift GasTokenTests.swift
//! Tests GAS token functionality and operations.

const std = @import("std");


const testing = std.testing;
const GasToken = @import("../../src/contract/gas_token.zig").GasToken;
const constants = @import("../../src/core/constants.zig");
const TestUtils = @import("../helpers/test_utilities.zig");

test "GAS token constants and properties" {
    const allocator = testing.allocator;
    
    var neo_swift = try TestUtils.makeNeoSwiftStub(allocator);
    defer TestUtils.destroyNeoSwiftStub(&neo_swift);
    
    const gas_token = GasToken.init(neo_swift);
    
    const gas_hash_string = try gas_token.getScriptHash().toString(allocator);
    defer allocator.free(gas_hash_string);
    
    try testing.expect(gas_hash_string.len > 0);
    try gas_token.validate();
    try testing.expect(gas_token.isNativeContract());
}
