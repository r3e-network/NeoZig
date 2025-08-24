//! Request Tests
//!
//! Complete conversion from NeoSwift RequestTests.swift
//! Tests JSON-RPC request creation and handling.

const std = @import("std");
const testing = std.testing;
const Request = @import("../../src/rpc/request.zig").Request;

test "JSON-RPC request creation" {
    const allocator = testing.allocator;
    
    const method = "getversion";
    const params = "[]";
    const request_id: u32 = 1;
    
    var request = Request([]u8, []u8).init(method, params, request_id);
    
    try testing.expectEqualStrings("2.0", request.jsonrpc);
    try testing.expectEqualStrings(method, request.method);
    try testing.expectEqualStrings(params, request.params);
    try testing.expectEqual(request_id, request.id);
}

test "Request JSON encoding" {
    const allocator = testing.allocator;
    
    var request = Request([]u8, []u8).init("getblockcount", "[]", 42);
    
    const json_string = try request.encodeToJson(allocator);
    defer allocator.free(json_string);
    
    try testing.expect(std.mem.indexOf(u8, json_string, "getblockcount") != null);
    try testing.expect(std.mem.indexOf(u8, json_string, "\"id\":42") != null);
    try testing.expect(std.mem.indexOf(u8, json_string, "\"jsonrpc\":\"2.0\"") != null);
}