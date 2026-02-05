//! Contract Parameter Utilities
//!
//! Production utilities for contract parameter conversion and JSON handling.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const ContractParameterContext = @import("../types/contract_parameter.zig").ContractParameterContext;
const json_utils = @import("../utils/json_utils.zig");

/// Converts ContractParameter to JSON for RPC calls
pub fn parameterToJson(param: ContractParameter, allocator: std.mem.Allocator) !std.json.Value {
    var param_obj = std.json.ObjectMap.init(allocator);

    switch (param) {
        .Boolean => |value| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Boolean") });
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .bool = value });
        },
        .Integer => |value| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Integer") });
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .integer = value });
        },
        .String => |value| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "String") });
            const base64_value = try @import("../utils/string_extensions.zig").StringUtils.base64Encoded(value, allocator);
            var base64_owned = false;
            errdefer if (!base64_owned) allocator.free(base64_value);
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .string = base64_value });
            base64_owned = true;
        },
        .ByteArray => |value| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "ByteArray") });
            const base64_value = try @import("../utils/string_extensions.zig").StringUtils.base64Encoded(value, allocator);
            var base64_owned = false;
            errdefer if (!base64_owned) allocator.free(base64_value);
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .string = base64_value });
            base64_owned = true;
        },
        .Hash160 => |value| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Hash160") });
            const hash_hex = try value.string(allocator);
            var hash_owned = false;
            errdefer if (!hash_owned) allocator.free(hash_hex);
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .string = hash_hex });
            hash_owned = true;
        },
        .Hash256 => |value| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Hash256") });
            const hash_hex = try value.string(allocator);
            var hash_owned = false;
            errdefer if (!hash_owned) allocator.free(hash_hex);
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .string = hash_hex });
            hash_owned = true;
        },
        .PublicKey => |value| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "PublicKey") });
            const key_hex = try @import("../utils/bytes.zig").toHex(&value, allocator);
            var key_owned = false;
            errdefer if (!key_owned) allocator.free(key_hex);
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .string = key_hex });
            key_owned = true;
        },
        .Signature => |value| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Signature") });
            const sig_hex = try @import("../utils/bytes.zig").toHex(&value, allocator);
            var sig_owned = false;
            errdefer if (!sig_owned) allocator.free(sig_hex);
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .string = sig_hex });
            sig_owned = true;
        },
        .Array => |items| {
            try json_utils.putOwnedKey(&param_obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, "Array") });

            var array_values = std.json.Array.init(allocator);
            var cleanup_needed = true;
            errdefer if (cleanup_needed) array_values.deinit();

            try array_values.ensureTotalCapacity(items.len);
            for (items) |item| {
                const item_json = try parameterToJson(item, allocator);
                array_values.appendAssumeCapacity(item_json);
            }

            cleanup_needed = false;
            try json_utils.putOwnedKey(&param_obj, allocator, "value", std.json.Value{ .array = array_values });
        },
        else => {
            return errors.ContractError.InvalidParameters;
        },
    }

    return std.json.Value{ .object = param_obj };
}

/// Parses ContractParameter from JSON (inverse of parameterToJson for supported types).
pub fn parameterFromJson(param_json: std.json.Value, allocator: std.mem.Allocator) !ContractParameter {
    if (param_json != .object) return errors.SerializationError.InvalidFormat;

    const obj = param_json.object;
    const type_value = obj.get("type") orelse return errors.SerializationError.InvalidFormat;
    if (type_value != .string) return errors.SerializationError.InvalidFormat;

    const type_str = type_value.string;
    const value = obj.get("value") orelse std.json.Value{ .null = {} };

    if (std.mem.eql(u8, type_str, "Any")) return ContractParameter{ .Any = {} };
    if (std.mem.eql(u8, type_str, "Void")) return ContractParameter{ .Void = {} };

    if (std.mem.eql(u8, type_str, "Boolean")) {
        return switch (value) {
            .bool => |b| ContractParameter.boolean(b),
            .integer => |i| ContractParameter.boolean(i != 0),
            .string => |s| ContractParameter.boolean(std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "1")),
            else => errors.SerializationError.InvalidFormat,
        };
    }

    if (std.mem.eql(u8, type_str, "Integer")) {
        return switch (value) {
            .integer => |i| ContractParameter.integer(i),
            .string => |s| ContractParameter.integer(std.fmt.parseInt(i64, s, 10) catch return errors.SerializationError.InvalidFormat),
            else => errors.SerializationError.InvalidFormat,
        };
    }

    if (std.mem.eql(u8, type_str, "String")) {
        if (value != .string) return errors.SerializationError.InvalidFormat;
        const raw = value.string;

        const decoded = @import("../utils/string_extensions.zig").StringUtils.base64Decoded(raw, allocator) catch {
            return ContractParameter.string(try allocator.dupe(u8, raw));
        };
        return ContractParameter.string(decoded);
    }

    if (std.mem.eql(u8, type_str, "ByteArray")) {
        if (value != .string) return errors.SerializationError.InvalidFormat;
        const raw = value.string;

        const decoded = @import("../utils/string_extensions.zig").StringUtils.base64Decoded(raw, allocator) catch blk: {
            const bytes = @import("../utils/string_extensions.zig").StringUtils.bytesFromHex(raw, allocator) catch return errors.SerializationError.InvalidFormat;
            break :blk bytes;
        };
        return ContractParameter.byteArray(decoded);
    }

    if (std.mem.eql(u8, type_str, "Hash160")) {
        if (value != .string) return errors.SerializationError.InvalidFormat;
        return ContractParameter.hash160(try Hash160.initWithString(value.string));
    }

    if (std.mem.eql(u8, type_str, "Hash256")) {
        if (value != .string) return errors.SerializationError.InvalidFormat;
        return ContractParameter.hash256(try Hash256.initWithString(value.string));
    }

    if (std.mem.eql(u8, type_str, "PublicKey")) {
        if (value != .string) return errors.SerializationError.InvalidFormat;
        var key_buf: [constants.PUBLIC_KEY_SIZE_COMPRESSED]u8 = undefined;
        const bytes = std.fmt.hexToBytes(&key_buf, value.string) catch return errors.SerializationError.InvalidFormat;
        return try ContractParameter.publicKeyChecked(bytes);
    }

    if (std.mem.eql(u8, type_str, "Signature")) {
        if (value != .string) return errors.SerializationError.InvalidFormat;
        var sig_buf: [constants.SIGNATURE_SIZE]u8 = undefined;
        const bytes = std.fmt.hexToBytes(&sig_buf, value.string) catch return errors.SerializationError.InvalidFormat;
        return try ContractParameter.signatureChecked(bytes);
    }

    if (std.mem.eql(u8, type_str, "Array")) {
        if (value != .array) return errors.SerializationError.InvalidFormat;
        var items = ArrayList(ContractParameter).init(allocator);
        errdefer {
            for (items.items) |item| {
                item.deinit(allocator);
            }
            items.deinit();
        }
        for (value.array.items) |item_json| {
            try items.append(try parameterFromJson(item_json, allocator));
        }
        return ContractParameter.array(try items.toOwnedSlice());
    }

    if (std.mem.eql(u8, type_str, "Map")) {
        var map = std.HashMap(ContractParameter, ContractParameter, ContractParameterContext, std.hash_map.default_max_load_percentage).init(allocator);
        errdefer {
            var it = map.iterator();
            while (it.next()) |entry| {
                entry.key_ptr.*.deinit(allocator);
                entry.value_ptr.*.deinit(allocator);
            }
            map.deinit();
        }

        switch (value) {
            .array => |arr| {
                for (arr.items) |entry| {
                    if (entry != .object) return errors.SerializationError.InvalidFormat;
                    const entry_obj = entry.object;
                    const key_json = entry_obj.get("key") orelse return errors.SerializationError.InvalidFormat;
                    const value_json = entry_obj.get("value") orelse return errors.SerializationError.InvalidFormat;
                    const key_param = try parameterFromJson(key_json, allocator);
                    const value_param = try parameterFromJson(value_json, allocator);
                    try map.put(key_param, value_param);
                }
            },
            .object => |obj_val| {
                var it = obj_val.iterator();
                while (it.next()) |entry| {
                    const key_param = ContractParameter.string(try allocator.dupe(u8, entry.key_ptr.*));
                    const value_param = if (entry.value_ptr.* == .object and entry.value_ptr.object.get("type") != null) blk: {
                        break :blk try parameterFromJson(entry.value_ptr.*, allocator);
                    } else blk: {
                        const value_str = switch (entry.value_ptr.*) {
                            .string => |s| try allocator.dupe(u8, s),
                            .integer => |i| try std.fmt.allocPrint(allocator, "{d}", .{i}),
                            .bool => |b| try allocator.dupe(u8, if (b) "true" else "false"),
                            .number_string => |s| try allocator.dupe(u8, s),
                            else => return errors.SerializationError.InvalidFormat,
                        };
                        break :blk ContractParameter.string(value_str);
                    };
                    try map.put(key_param, value_param);
                }
            },
            else => return errors.SerializationError.InvalidFormat,
        }

        return ContractParameter{ .Map = map };
    }

    return errors.SerializationError.InvalidFormat;
}

/// Frees any allocator-owned memory within a ContractParameter.
/// Call this only for parameters whose contents were allocated by this allocator.
pub fn freeParameter(param: ContractParameter, allocator: std.mem.Allocator) void {
    param.deinit(allocator);
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
    defer @import("../utils/json_utils.zig").freeValue(bool_json, allocator);

    const bool_obj = bool_json.object;
    try testing.expectEqualStrings("Boolean", bool_obj.get("type").?.string);
    try testing.expect(bool_obj.get("value").?.bool);

    // Test integer parameter
    const int_param = ContractParameter.integer(12345);
    const int_json = try parameterToJson(int_param, allocator);
    defer @import("../utils/json_utils.zig").freeValue(int_json, allocator);

    const int_obj = int_json.object;
    try testing.expectEqualStrings("Integer", int_obj.get("type").?.string);
    try testing.expectEqual(@as(i64, 12345), int_obj.get("value").?.integer);

    // Test string parameter
    const string_param = ContractParameter.string("Hello Neo");
    const string_json = try parameterToJson(string_param, allocator);
    defer @import("../utils/json_utils.zig").freeValue(string_json, allocator);

    const string_obj = string_json.object;
    try testing.expectEqualStrings("String", string_obj.get("type").?.string);
    // Value should be base64 encoded
    try testing.expect(string_obj.get("value").?.string.len > 0);
}
