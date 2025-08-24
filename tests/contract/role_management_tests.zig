//! Role Management Tests
//!
//! Complete conversion from NeoSwift RoleManagementTests.swift
//! Tests role management contract functionality.

const std = @import("std");
const testing = std.testing;
const RoleManagement = @import("../../src/contract/role_management.zig").RoleManagement;
const Role = @import("../../src/types/role.zig").Role;

test "Role management contract creation" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = @import("../../src/rpc/neo_client.zig").NeoSwift.build(allocator, mock_service, mock_config);
    
    const role_management = RoleManagement.init(neo_swift);
    
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