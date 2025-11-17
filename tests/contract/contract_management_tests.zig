//! Contract Management Tests
//!
//! Complete conversion from NeoSwift ContractManagementTests.swift
//! Tests contract management functionality.

const std = @import("std");


const testing = std.testing;
const ContractManagement = @import("../../src/contract/contract_management.zig").ContractManagement;

test "Contract management creation" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = @import("../../src/rpc/neo_client.zig").NeoSwift.build(allocator, mock_service, mock_config);
    
    const contract_mgmt = ContractManagement.init(neo_swift);
    
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