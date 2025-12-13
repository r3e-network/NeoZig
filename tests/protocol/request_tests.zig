//! Request Tests
//!
//! Complete conversion from NeoSwift RequestTests.swift
//! Tests JSON-RPC request creation and handling.

const std = @import("std");


const testing = std.testing;
const neo = @import("neo-zig");
const Request = neo.rpc.Request;

test "JSON-RPC request creation" {
    const allocator = testing.allocator;
    
    const method = "getversion";
    const TestResponse = struct {
        result: ?u32 = null,

        pub fn init() @This() {
            return .{ .result = null };
        }
    };
    const TestRequest = Request(TestResponse, u32);

    var request = try TestRequest.withNoParams(allocator, method);
    defer request.deinit();
    
    try testing.expectEqualStrings("2.0", request.jsonrpc);
    try testing.expectEqualStrings(method, request.method);
    try testing.expectEqual(@as(usize, 0), request.getParams().len);
    try testing.expect(request.id > 0);
}

test "Request JSON encoding" {
    const allocator = testing.allocator;
    
    const TestResponse = struct {
        result: ?u32 = null,

        pub fn init() @This() {
            return .{ .result = null };
        }
    };
    const TestRequest = Request(TestResponse, u32);

    var request = try TestRequest.withNoParams(allocator, "getblockcount");
    defer request.deinit();

    const json_value = try request.toJson();
    defer neo.utils.json_utils.freeValue(json_value, allocator);

    const json_string = try std.json.stringifyAlloc(allocator, json_value, .{});
    defer allocator.free(json_string);

    const id_fragment = try std.fmt.allocPrint(allocator, "\"id\":{d}", .{request.id});
    defer allocator.free(id_fragment);
    
    try testing.expect(std.mem.indexOf(u8, json_string, "getblockcount") != null);
    try testing.expect(std.mem.indexOf(u8, json_string, "\"jsonrpc\":\"2.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_string, "\"params\":[]") != null);
    try testing.expect(std.mem.indexOf(u8, json_string, id_fragment) != null);
}
