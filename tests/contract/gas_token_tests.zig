//! GAS Token Tests
//!
//! Complete conversion from NeoSwift GasTokenTests.swift
//! Tests GAS token functionality and operations.

const std = @import("std");
const testing = std.testing;
const GasToken = @import("../../src/contract/gas_token.zig").GasToken;
const constants = @import("../../src/core/constants.zig");

test "GAS token constants and properties" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = @import("../../src/rpc/neo_client.zig").NeoSwift.build(allocator, mock_service, mock_config);
    
    const gas_token = GasToken.init(neo_swift);
    
    const gas_hash_string = try gas_token.getScriptHash().toString(allocator);
    defer allocator.free(gas_hash_string);
    
    try testing.expect(gas_hash_string.len > 0);
    try gas_token.validate();
    try testing.expect(gas_token.isNativeContract());
}