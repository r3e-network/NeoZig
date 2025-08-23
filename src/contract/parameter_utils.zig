//! Contract Parameter Utilities
//!
//! Production utilities for contract parameter conversion and JSON handling.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;

/// Converts ContractParameter to JSON for RPC calls
pub fn parameterToJson(param: ContractParameter, allocator: std.mem.Allocator) !std.json.Value {
    var param_obj = std.json.ObjectMap.init(allocator);
    
    switch (param) {
        .Boolean => |value| {
            try param_obj.put("type", std.json.Value{ .string = "Boolean" });
            try param_obj.put("value", std.json.Value{ .bool = value });
        },
        .Integer => |value| {
            try param_obj.put("type", std.json.Value{ .string = "Integer" });
            try param_obj.put("value", std.json.Value{ .integer = value });
        },
        .String => |value| {
            try param_obj.put("type", std.json.Value{ .string = "String" });
            const base64_value = try @import("../utils/string_extensions.zig").StringUtils.base64Encoded(value, allocator);
            defer allocator.free(base64_value);
            try param_obj.put("value", std.json.Value{ .string = base64_value });
        },
        .ByteArray => |value| {
            try param_obj.put("type", std.json.Value{ .string = "ByteArray" });
            const base64_value = try @import("../utils/string_extensions.zig").StringUtils.base64Encoded(value, allocator);
            defer allocator.free(base64_value);
            try param_obj.put("value", std.json.Value{ .string = base64_value });
        },
        .Hash160 => |value| {
            try param_obj.put("type", std.json.Value{ .string = "Hash160" });
            const hash_hex = try value.string(allocator);
            defer allocator.free(hash_hex);
            try param_obj.put("value", std.json.Value{ .string = hash_hex });
        },
        .Hash256 => |value| {
            try param_obj.put("type", std.json.Value{ .string = "Hash256" });
            const hash_hex = try value.string(allocator);
            defer allocator.free(hash_hex);
            try param_obj.put("value", std.json.Value{ .string = hash_hex });
        },
        .PublicKey => |value| {
            try param_obj.put("type", std.json.Value{ .string = "PublicKey" });
            const key_hex = try @import("../utils/bytes.zig").toHex(&value, allocator);
            defer allocator.free(key_hex);
            try param_obj.put("value", std.json.Value{ .string = key_hex });
        },
        .Signature => |value| {
            try param_obj.put("type", std.json.Value{ .string = "Signature" });
            const sig_hex = try @import("../utils/bytes.zig").toHex(&value, allocator);
            defer allocator.free(sig_hex);
            try param_obj.put("value", std.json.Value{ .string = sig_hex });
        },
        .Array => |items| {
            try param_obj.put("type", std.json.Value{ .string = "Array" });
            
            var array_values = std.ArrayList(std.json.Value).init(allocator);
            defer array_values.deinit();
            
            for (items) |item| {
                try array_values.append(try parameterToJson(item, allocator));
            }
            
            try param_obj.put("value", std.json.Value{ .array = try array_values.toOwnedSlice() });
        },
        else => {
            return errors.ContractError.InvalidParameters;
        },
    }
    
    return std.json.Value{ .object = param_obj };
}

/// Parses stack item value based on type
pub fn parseStackItemValue(stack_item: std.json.Value, expected_type: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const item_obj = stack_item.object;
    const item_type = item_obj.get("type").?.string;
    const item_value = item_obj.get("value").?.string;
    
    if (!std.mem.eql(u8, item_type, expected_type)) {
        return errors.ContractError.InvalidParameters;
    }
    
    return switch (std.hash_map.hashString(item_type)) {
        std.hash_map.hashString("ByteString") => try @import("../utils/string_extensions.zig").StringUtils.base64Decoded(item_value, allocator),
        std.hash_map.hashString("Integer") => try allocator.dupe(u8, item_value),
        std.hash_map.hashString("Boolean") => try allocator.dupe(u8, item_value),
        else => try allocator.dupe(u8, item_value),
    };
}

/// Parses integer from stack item
pub fn parseStackItemInteger(stack_item: std.json.Value) !i64 {
    const item_obj = stack_item.object;
    const item_type = item_obj.get("type").?.string;
    const item_value = item_obj.get("value").?.string;
    
    if (std.mem.eql(u8, item_type, "Integer")) {
        return std.fmt.parseInt(i64, item_value, 10) catch {
            return errors.ContractError.InvalidParameters;
        };
    }
    
    return errors.ContractError.InvalidParameters;
}

/// Parses boolean from stack item
pub fn parseStackItemBoolean(stack_item: std.json.Value) !bool {
    const item_obj = stack_item.object;
    const item_type = item_obj.get("type").?.string;
    const item_value = item_obj.get("value").?.string;
    
    if (std.mem.eql(u8, item_type, "Boolean")) {
        return std.mem.eql(u8, item_value, "true") or std.mem.eql(u8, item_value, "1");
    }
    
    if (std.mem.eql(u8, item_type, "Integer")) {
        const int_val = std.fmt.parseInt(i64, item_value, 10) catch 0;
        return int_val != 0;
    }
    
    return false;
}

// Tests
test "parameterToJson conversion" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test boolean parameter
    const bool_param = ContractParameter.boolean(true);
    const bool_json = try parameterToJson(bool_param, allocator);
    defer bool_json.deinit();
    
    const bool_obj = bool_json.object;
    try testing.expectEqualStrings("Boolean", bool_obj.get("type").?.string);
    try testing.expect(bool_obj.get("value").?.bool);
    
    // Test integer parameter
    const int_param = ContractParameter.integer(12345);
    const int_json = try parameterToJson(int_param, allocator);
    defer int_json.deinit();
    
    const int_obj = int_json.object;
    try testing.expectEqualStrings("Integer", int_obj.get("type").?.string);
    try testing.expectEqual(@as(i64, 12345), int_obj.get("value").?.integer);
    
    // Test string parameter
    const string_param = ContractParameter.string("Hello Neo");
    const string_json = try parameterToJson(string_param, allocator);
    defer string_json.deinit();
    
    const string_obj = string_json.object;
    try testing.expectEqualStrings("String", string_obj.get("type").?.string);
    // Value should be base64 encoded
    try testing.expect(string_obj.get("value").?.string.len > 0);
}