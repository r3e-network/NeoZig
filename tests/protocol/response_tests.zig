//! Response Tests
//!
//! Complete conversion from NeoSwift ResponseTests.swift
//! Tests JSON-RPC response parsing and handling.

const std = @import("std");
const testing = std.testing;
const Response = @import("../../src/rpc/response.zig").Response;

test "JSON-RPC response creation" {
    const allocator = testing.allocator;
    
    const test_result = "test_result";
    const response_id: u32 = 1;
    
    var response = Response([]u8).init(test_result, null, response_id, null);
    
    try testing.expectEqualStrings("2.0", response.jsonrpc);
    try testing.expectEqualStrings(test_result, response.result.?);
    try testing.expect(response.error == null);
    try testing.expectEqual(response_id, response.id);
}

test "Response error handling" {
    const allocator = testing.allocator;
    
    const error_code: i32 = -32601;
    const error_message = "Method not found";
    
    const rpc_error = @import("../../src/protocol/service.zig").JsonRpcError.init(
        error_code,
        try allocator.dupe(u8, error_message),
        null,
    );
    
    var error_response = Response([]u8).init(null, rpc_error, 1, null);
    defer error_response.deinit(allocator);
    
    try testing.expect(error_response.result == null);
    try testing.expect(error_response.error != null);
    try testing.expectEqual(error_code, error_response.error.?.code);
}