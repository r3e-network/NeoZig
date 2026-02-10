//! GAS Token Tests
//!
//!
//! Tests GAS token functionality and operations.

const std = @import("std");

const testing = std.testing;
const GasToken = @import("../../src/contract/gas_token.zig").GasToken;
const TestUtils = @import("../helpers/test_utilities.zig");

test "GAS token constants and properties" {
    const allocator = testing.allocator;

    var client = try TestUtils.makeClientStub(allocator);
    defer TestUtils.destroyClientStub(&client);

    const gas_token = GasToken.init(allocator, &client);

    const gas_hash_string = try gas_token.getScriptHash().toString(allocator);
    defer allocator.free(gas_hash_string);

    try testing.expect(gas_hash_string.len > 0);
    try gas_token.validate();
    try testing.expect(gas_token.isNativeContract());
}
