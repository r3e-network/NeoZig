//! Response Tests
//!
//! Complete conversion from NeoSwift ResponseTests.swift
//! Tests JSON-RPC response parsing and handling.

const std = @import("std");

const testing = std.testing;
const neo = @import("neo-zig");
const Response = neo.rpc.Response;
const ResponseError = neo.rpc.ResponseError;

test "JSON-RPC response creation" {
    const allocator = testing.allocator;
    const test_result = "test_result";
    var response = Response([]const u8).init(allocator, test_result);
    defer response.deinit();

    try testing.expectEqualStrings("2.0", response.jsonrpc);
    try testing.expectEqualStrings(test_result, response.result.?);
    try testing.expect(response.response_error == null);
    try testing.expectEqual(@as(u32, 1), response.id);
}

test "Response error handling" {
    const allocator = testing.allocator;

    const error_code: i32 = -32601;
    const error_message = "Method not found";

    const message_copy = try allocator.dupe(u8, error_message);
    var error_response = Response([]const u8).initWithError(allocator, ResponseError.init(error_code, message_copy, null));
    defer error_response.deinit();

    try testing.expect(error_response.result == null);
    try testing.expect(error_response.response_error != null);
    try testing.expectEqual(error_code, error_response.response_error.?.code);
}
