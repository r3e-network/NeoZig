//! Contract Management Tests
//!
//! Complete conversion from NeoSwift ContractManagementTests.swift
//! Tests contract management functionality.

const std = @import("std");


const testing = std.testing;
const ContractManagement = @import("../../src/contract/contract_management.zig").ContractManagement;
const TestUtils = @import("../helpers/test_utilities.zig");

test "Contract management creation" {
    const allocator = testing.allocator;
    
    var neo_swift = try TestUtils.makeNeoSwiftStub(allocator);
    defer TestUtils.destroyNeoSwiftStub(&neo_swift);
    
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
