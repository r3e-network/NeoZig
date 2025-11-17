//! Response Parser
//!
//! Production response parsing for all Neo RPC responses
//! Handles type-safe conversion from JSON to Zig types.

const std = @import("std");
const builtin = @import("builtin");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const StackItem = @import("../types/stack_item.zig").StackItem;
const json_utils = @import("../utils/json_utils.zig");

/// Parses RPC response result based on expected type
pub fn parseResponseResult(comptime T: type, result: std.json.Value, allocator: std.mem.Allocator) !T {
    return switch (T) {
        // Basic types
        Hash256 => try Hash256.initWithString(result.string),
        Hash160 => try Hash160.initWithString(result.string),
        u32 => @as(u32, @intCast(result.integer)),
        i64 => result.integer,
        bool => result.bool,
        []const u8 => try allocator.dupe(u8, result.string),

        // Complex response types
        @import("responses.zig").NeoBlock => try @import("responses.zig").NeoBlock.fromJson(result, allocator),
        @import("responses.zig").NeoVersion => try @import("responses.zig").NeoVersion.fromJson(result, allocator),
        @import("responses.zig").InvocationResult => try @import("responses.zig").InvocationResult.fromJson(result, allocator),
        @import("responses.zig").Nep17Balances => try @import("responses.zig").Nep17Balances.fromJson(result, allocator),
        @import("responses.zig").Nep17Transfers => try @import("responses.zig").Nep17Transfers.fromJson(result, allocator),
        @import("response_aliases.zig").NeoGetRawMemPool => try @import("response_aliases.zig").NeoGetRawMemPool.fromJson(result, allocator),
        @import("response_aliases.zig").NeoGetRawTransaction => try @import("response_aliases.zig").NeoGetRawTransaction.fromJson(result, allocator),
        @import("responses.zig").NetworkFeeResponse => try @import("responses.zig").NetworkFeeResponse.fromJson(result, allocator),
        @import("token_responses.zig").NeoGetNep17Balances => try @import("token_responses.zig").NeoGetNep17Balances.fromJson(result, allocator),
        @import("token_responses.zig").NeoGetNep11Balances => try @import("token_responses.zig").NeoGetNep11Balances.fromJson(result, allocator),
        @import("complete_responses.zig").NeoAccountState => try @import("complete_responses.zig").NeoAccountState.fromJson(result, allocator),
        @import("protocol_responses.zig").NeoGetPeers => try @import("protocol_responses.zig").NeoGetPeers.fromJson(result, allocator),
        @import("complete_responses.zig").NeoListPlugins => try @import("complete_responses.zig").NeoListPlugins.fromJson(result, allocator),
        @import("remaining_responses.zig").NeoGetVersion => try @import("remaining_responses.zig").NeoGetVersion.fromJson(result, allocator),

        else => blk: {
            if (@hasDecl(T, "fromJson")) break :blk try T.fromJson(result, allocator);
            if (T == std.json.Value) break :blk try json_utils.cloneValue(result, allocator);
            @compileError("Unsupported RPC response type: " ++ @typeName(T));
        },
    };
}

/// Validates RPC response structure
pub fn validateRpcResponse(allocator: std.mem.Allocator, response_body: []const u8) !std.json.Value {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, response_body, .{});
    defer parsed.deinit();

    try validateResponseValue(parsed.value);

    return try json_utils.cloneValue(parsed.value, allocator);
}

/// Batch response parser for multiple RPC calls
pub fn parseBatchResponse(response_body: []const u8, allocator: std.mem.Allocator) ![]std.json.Value {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, response_body, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidResponse;

    const response_array = parsed.value.array;
    var results = try allocator.alloc(std.json.Value, response_array.items.len);
    errdefer allocator.free(results);

    for (response_array.items, 0..) |item, i| {
        try validateResponseValue(item);
        results[i] = try json_utils.cloneValue(item, allocator);
    }

    return results;
}

fn validateResponseValue(value: std.json.Value) !void {
    const response_obj = value.object;

    const jsonrpc = response_obj.get("jsonrpc") orelse return error.InvalidResponse;
    if (jsonrpc != .string or !std.mem.eql(u8, jsonrpc.string, "2.0")) {
        return error.InvalidResponse;
    }

    const has_result = response_obj.get("result") != null;
    const has_error = response_obj.get("error") != null;

    if (!has_result and !has_error) {
        return error.InvalidResponse;
    }

    if (has_error) {
        const error_obj = response_obj.get("error").?.object;
        const error_code = error_obj.get("code").?.integer;
        const error_message = error_obj.get("message").?.string;

        if (!builtin.is_test) {
            std.log.err("RPC Error {d}: {s}", .{ error_code, error_message });
        }
        return error.RPCError;
    }
}

/// Stack item parsing utilities
pub const StackItemParser = struct {
    /// Parses stack item as string
    pub fn parseAsString(stack_item: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
        var decoded = try StackItem.decodeFromJson(stack_item, allocator);
        defer decoded.deinit(allocator);
        return try decoded.getString(allocator);
    }

    /// Parses stack item as integer
    pub fn parseAsInteger(stack_item: std.json.Value, allocator: std.mem.Allocator) !i64 {
        var decoded = try StackItem.decodeFromJson(stack_item, allocator);
        defer decoded.deinit(allocator);
        return decoded.getInteger();
    }

    /// Parses stack item as boolean
    pub fn parseAsBoolean(stack_item: std.json.Value, allocator: std.mem.Allocator) !bool {
        var decoded = try StackItem.decodeFromJson(stack_item, allocator);
        defer decoded.deinit(allocator);
        return decoded.getBoolean();
    }

    /// Parses stack item as byte array
    pub fn parseAsByteArray(stack_item: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
        var decoded = try StackItem.decodeFromJson(stack_item, allocator);
        defer decoded.deinit(allocator);
        return try decoded.getByteArray(allocator);
    }
};

// Tests
test "Response parsing for basic types" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test Hash256 parsing
    const hash_json = std.json.Value{ .string = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" };
    const parsed_hash = try parseResponseResult(Hash256, hash_json, allocator);
    const expected_hash = try Hash256.initWithString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    try testing.expect(parsed_hash.eql(expected_hash));

    // Test integer parsing
    const int_json = std.json.Value{ .integer = 12345 };
    const parsed_int = try parseResponseResult(u32, int_json, allocator);
    try testing.expectEqual(@as(u32, 12345), parsed_int);

    // Test boolean parsing
    const bool_json = std.json.Value{ .bool = true };
    const parsed_bool = try parseResponseResult(bool, bool_json, allocator);
    try testing.expect(parsed_bool);
}

test "Stack item parsing utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create test stack item JSON
    var item_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&item_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "ByteString") });
    try json_utils.putOwnedKey(&item_obj, allocator, "value", std.json.Value{ .string = try allocator.dupe(u8, "SGVsbG8gTmVv") }); // "Hello Neo" in base64

    const stack_item = std.json.Value{ .object = item_obj };
    defer json_utils.freeValue(stack_item, allocator);

    // Test string parsing
    const parsed_string = try StackItemParser.parseAsString(stack_item, allocator);
    defer allocator.free(parsed_string);
    try testing.expectEqualStrings("Hello Neo", parsed_string);

    // Test integer stack item
    var int_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&int_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Integer") });
    try json_utils.putOwnedKey(&int_obj, allocator, "value", std.json.Value{ .string = try allocator.dupe(u8, "42") });

    const int_stack_item = std.json.Value{ .object = int_obj };
    defer json_utils.freeValue(int_stack_item, allocator);
    const parsed_int = try StackItemParser.parseAsInteger(int_stack_item, allocator);
    try testing.expectEqual(@as(i64, 42), parsed_int);

    // Test boolean stack item
    var bool_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&bool_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Boolean") });
    try json_utils.putOwnedKey(&bool_obj, allocator, "value", std.json.Value{ .string = try allocator.dupe(u8, "true") });

    const bool_stack_item = std.json.Value{ .object = bool_obj };
    defer json_utils.freeValue(bool_stack_item, allocator);
    const parsed_bool = try StackItemParser.parseAsBoolean(bool_stack_item, allocator);
    try testing.expect(parsed_bool);

    // Test byte array stack item
    var bytes_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&bytes_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "ByteString") });
    try json_utils.putOwnedKey(&bytes_obj, allocator, "value", std.json.Value{ .string = try allocator.dupe(u8, "U29tZUJ5dGVz") });

    const bytes_stack_item = std.json.Value{ .object = bytes_obj };
    defer json_utils.freeValue(bytes_stack_item, allocator);
    const parsed_bytes = try StackItemParser.parseAsByteArray(bytes_stack_item, allocator);
    defer allocator.free(parsed_bytes);
    try testing.expectEqualStrings("SomeBytes", parsed_bytes);
}

test "RPC response validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test valid JSON-RPC response
    const valid_response =
        \\{"jsonrpc":"2.0","result":"test_result","id":1}
    ;

    const validated = try validateRpcResponse(allocator, valid_response);
    defer json_utils.freeValue(validated, allocator);

    const response_obj = validated.object;
    try testing.expectEqualStrings("2.0", response_obj.get("jsonrpc").?.string);
    try testing.expectEqualStrings("test_result", response_obj.get("result").?.string);

    // Test error response
    const error_response =
        \\{"jsonrpc":"2.0","error":{"code":-1,"message":"Test error"},"id":1}
    ;

    try testing.expectError(error.RPCError, validateRpcResponse(allocator, error_response));
}
