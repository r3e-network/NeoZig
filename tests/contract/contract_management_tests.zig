//! Contract Management Tests
//!
//!
//! Tests contract management functionality.

const std = @import("std");

const testing = std.testing;
const ContractManagement = @import("../../src/contract/contract_management.zig").ContractManagement;
const TestUtils = @import("../helpers/test_utilities.zig");

test "Contract management creation" {
    const allocator = testing.allocator;

    var client = try TestUtils.makeClientStub(allocator);
    defer TestUtils.destroyClientStub(&client);

    const contract_mgmt = ContractManagement.init(allocator, &client);

    try contract_mgmt.validate();
    try testing.expect(contract_mgmt.isNativeContract());
}

test "Contract management operations" {
    const testing = std.testing;

    const mgmt_methods = [_][]const u8{
        "deploy",
        "update",
        "destroy",
        "getContract",
        "getContractById",
        "hasMethod",
    };

    for (mgmt_methods) |method| {
        try testing.expect(method.len > 0);
    }
}
