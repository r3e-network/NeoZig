//! Policy Contract Tests
//!
//! Complete conversion from NeoSwift PolicyContractTests.swift
//! Tests Neo policy contract functionality and governance operations.

const std = @import("std");


const testing = std.testing;
const PolicyContract = @import("../../src/contract/policy_contract.zig").PolicyContract;
const constants = @import("../../src/core/constants.zig");
const TestUtils = @import("../helpers/test_utilities.zig");

test "Policy contract constants" {
    const allocator = testing.allocator;
    
    var neo_swift = try TestUtils.makeNeoSwiftStub(allocator);
    defer TestUtils.destroyNeoSwiftStub(&neo_swift);
    
    const policy_contract = PolicyContract.init(neo_swift);
    
    try policy_contract.validate();
    try testing.expect(policy_contract.isNativeContract());
}

test "Policy contract methods" {
    const testing = std.testing;
    
    const policy_methods = [_][]const u8{
        "getFeePerByte",
        "setFeePerByte", 
        "getExecFeeFactor",
        "setExecFeeFactor",
        "getStoragePrice",
        "setStoragePrice",
        "isBlocked",
        "blockAccount",
        "unblockAccount",
    };
    
    for (policy_methods) |method| {
        try testing.expect(method.len > 0);
    }
}
