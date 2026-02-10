//! Role Management Tests
//!
//!
//! Tests role management contract functionality.

const std = @import("std");

const testing = std.testing;
const RoleManagement = @import("../../src/contract/role_management.zig").RoleManagement;
const Role = @import("../../src/types/role.zig").Role;
const TestUtils = @import("../helpers/test_utilities.zig");

test "Role management contract creation" {
    const allocator = testing.allocator;

    var client = try TestUtils.makeClientStub(allocator);
    defer TestUtils.destroyClientStub(&client);

    const role_management = RoleManagement.init(allocator, &client);

    try role_management.validate();
    try testing.expect(role_management.isNativeContract());
}

test "Role management operations" {
    const testing = std.testing;

    // Test role types
    try testing.expect(Role.StateValidator.isConsensusRole());
    try testing.expect(!Role.Oracle.isConsensusRole());
    try testing.expect(Role.Oracle.isDataServiceRole());
    try testing.expect(!Role.StateValidator.isDataServiceRole());
}
