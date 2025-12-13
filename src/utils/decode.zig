//! Decode utilities and protocols
//!
//! Complete conversion from NeoSwift Decode.swift
//! Provides safe decoding and string conversion protocols.

const std = @import("std");
const ArrayList = std.ArrayList;


const errors = @import("../core/errors.zig");

/// String decodable trait (converted from Swift StringDecodable protocol)
pub fn StringDecodable(comptime T: type) type {
    return struct {
        /// Creates instance from string (equivalent to Swift init(string:))
        pub fn initFromString(string: []const u8) !T {
            return T.initFromString(string);
        }
        
        /// Gets string representation (equivalent to Swift .string property)
        pub fn toString(self: T, allocator: std.mem.Allocator) ![]u8 {
            return T.toString(self, allocator);
        }
        
        /// Encodes to JSON string (equivalent to Swift encode(to:))
        pub fn encodeToJson(self: T, allocator: std.mem.Allocator) !std.json.Value {
            const string_value = try self.toString(allocator);
            return std.json.Value{ .string = string_value };
        }
        
        /// Decodes from JSON string (equivalent to Swift init(from:))
        pub fn decodeFromJson(json_value: std.json.Value) !T {
            const string_value = switch (json_value) {
                .string => |s| s,
                else => return errors.ValidationError.InvalidFormat,
            };
            
            return try T.initFromString(string_value);
        }
    };
}

/// Safe decoder wrapper (converted from Swift SafeDecode)
pub fn SafeDecode(comptime T: type) type {
    return struct {
        value: T,
        
        const Self = @This();
        
        pub fn init(value: T) Self {
            return Self{ .value = value };
        }
        
        /// Safe decoding from JSON (equivalent to Swift SafeDecode init(from:))
        pub fn decodeFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            _ = allocator;
            // Try direct decoding first
            if (T.decodeFromJson) |decode_fn| {
                if (decode_fn(json_value)) |decoded_value| {
                    return Self.init(decoded_value);
                } else |_| {
                    // Fall back to string decoding
                    const string_value = switch (json_value) {
                        .string => |s| s,
                        else => return errors.ValidationError.InvalidFormat,
                    };
                    
                    const decoded_value = try T.initFromString(string_value);
                    return Self.init(decoded_value);
                }
            } else {
                return errors.ValidationError.UnsupportedOperation;
            }
        }
        
        /// Encodes to JSON (equivalent to Swift encode(to:))
        pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
            return try self.value.encodeToJson(allocator);
        }
    };
}

/// JSON decoding utilities (converted from Swift JSON handling)
pub const JsonDecodeUtils = struct {
    /// Safely decodes string from JSON value
    pub fn decodeString(json_value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
        return switch (json_value) {
            .string => |s| try allocator.dupe(u8, s),
            .integer => |i| try std.fmt.allocPrint(allocator, "{d}", .{i}),
            .float => |f| try std.fmt.allocPrint(allocator, "{d}", .{f}),
            else => errors.ValidationError.InvalidFormat,
        };
    }
    
    /// Safely decodes integer from JSON value
    pub fn decodeInteger(json_value: std.json.Value) !i64 {
        return switch (json_value) {
            .integer => |i| i,
            .string => |s| std.fmt.parseInt(i64, s, 10) catch return errors.ValidationError.InvalidFormat,
            else => errors.ValidationError.InvalidFormat,
        };
    }
    
    /// Safely decodes boolean from JSON value
    pub fn decodeBoolean(json_value: std.json.Value) !bool {
        return switch (json_value) {
            .bool => |b| b,
            .string => |s| std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "1"),
            .integer => |i| i != 0,
            else => errors.ValidationError.InvalidFormat,
        };
    }
    
    /// Safely decodes array from JSON value
    pub fn decodeArray(json_value: std.json.Value) ![]const std.json.Value {
        return switch (json_value) {
            .array => |a| a.items,
            else => errors.ValidationError.InvalidFormat,
        };
    }
    
    /// Safely decodes object from JSON value
    pub fn decodeObject(json_value: std.json.Value) !std.json.ObjectMap {
        return switch (json_value) {
            .object => |o| o,
            else => errors.ValidationError.InvalidFormat,
        };
    }
    
    /// Converts any value to string safely
    pub fn valueToString(json_value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
        return switch (json_value) {
            .string => |s| try allocator.dupe(u8, s),
            .integer => |i| try std.fmt.allocPrint(allocator, "{d}", .{i}),
            .float => |f| try std.fmt.allocPrint(allocator, "{d}", .{f}),
            .bool => |b| try allocator.dupe(u8, if (b) "true" else "false"),
            .null => try allocator.dupe(u8, "null"),
            .array => try allocator.dupe(u8, "[array]"),
            .object => try allocator.dupe(u8, "{object}"),
        };
    }
};

/// Nullable decoding utilities (converted from Swift nullable handling)
pub const NullableDecodeUtils = struct {
    /// Decodes nullable string
    pub fn decodeNullableString(json_value: std.json.Value, allocator: std.mem.Allocator) !?[]u8 {
        return switch (json_value) {
            .string => |s| try allocator.dupe(u8, s),
            .null => null,
            else => null,
        };
    }
    
    /// Decodes nullable integer
    pub fn decodeNullableInteger(json_value: std.json.Value) ?i64 {
        return switch (json_value) {
            .integer => |i| i,
            .string => |s| std.fmt.parseInt(i64, s, 10) catch null,
            else => null,
        };
    }
    
    /// Decodes nullable boolean
    pub fn decodeNullableBoolean(json_value: std.json.Value) ?bool {
        return switch (json_value) {
            .bool => |b| b,
            .string => |s| if (std.mem.eql(u8, s, "true")) true else if (std.mem.eql(u8, s, "false")) false else null,
            else => null,
        };
    }
};

/// Array decoding utilities (converted from Swift array handling)
pub const ArrayDecodeUtils = struct {
    /// Decodes array or single value as array (equivalent to Swift @SingleValueOrNilArray)
    pub fn decodeSingleValueOrArray(
        comptime T: type,
        json_value: std.json.Value,
        decode_fn: *const fn (std.json.Value, std.mem.Allocator) anyerror!T,
        allocator: std.mem.Allocator,
    ) ![]T {
        return switch (json_value) {
            .array => |array| {
                var result = ArrayList(T).init(allocator);
                for (array.items) |item| {
                    try result.append(try decode_fn(item, allocator));
                }
                return try result.toOwnedSlice();
            },
            .null => try allocator.alloc(T, 0),
            else => {
                // Single value - wrap in array
                var result = try allocator.alloc(T, 1);
                result[0] = try decode_fn(json_value, allocator);
                return result;
            },
        };
    }
    
    /// Decodes array of strings
    pub fn decodeStringArray(json_value: std.json.Value, allocator: std.mem.Allocator) ![][]u8 {
        const decode_string = struct {
            fn decode(value: std.json.Value, alloc: std.mem.Allocator) ![]u8 {
                return try JsonDecodeUtils.decodeString(value, alloc);
            }
        }.decode;
        
        return try decodeSingleValueOrArray([]u8, json_value, decode_string, allocator);
    }
    
    /// Decodes array of integers
    pub fn decodeIntegerArray(json_value: std.json.Value, allocator: std.mem.Allocator) ![]i64 {
        const decode_integer = struct {
            fn decode(value: std.json.Value, alloc: std.mem.Allocator) !i64 {
                _ = alloc;
                return try JsonDecodeUtils.decodeInteger(value);
            }
        }.decode;
        
        return try decodeSingleValueOrArray(i64, json_value, decode_integer, allocator);
    }
};

// Tests (converted from Swift Decode tests)
test "StringDecodable protocol" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test string decodable implementation with Hash160
    const Hash160 = @import("../types/hash160.zig").Hash160;
    
    // Test creation from string (equivalent to Swift StringDecodable tests)
    const hash_string = "1234567890abcdef1234567890abcdef12345678";
    const hash = try Hash160.initWithString(hash_string);
    
    const converted_string = try hash.string(allocator);
    defer allocator.free(converted_string);
    
    try testing.expectEqualStrings(hash_string, converted_string);
}

test "Safe decoding operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test safe string decoding (equivalent to Swift SafeDecode tests)
    const string_json = std.json.Value{ .string = "test_string" };
    const decoded_string = try JsonDecodeUtils.decodeString(string_json, allocator);
    defer allocator.free(decoded_string);
    
    try testing.expectEqualStrings("test_string", decoded_string);
    
    // Test integer from string (equivalent to Swift safe integer decoding)
    const int_string_json = std.json.Value{ .string = "42" };
    const decoded_int = try JsonDecodeUtils.decodeInteger(int_string_json);
    try testing.expectEqual(@as(i64, 42), decoded_int);
    
    // Test boolean from string
    const bool_string_json = std.json.Value{ .string = "true" };
    const decoded_bool = try JsonDecodeUtils.decodeBoolean(bool_string_json);
    try testing.expect(decoded_bool);
}

test "Array decoding utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test string array decoding (equivalent to Swift array decoding tests)
    var string_array = ArrayList(std.json.Value).init(allocator);
    defer string_array.deinit();
    
    try string_array.append(std.json.Value{ .string = "first" });
    try string_array.append(std.json.Value{ .string = "second" });
    
    const array_json = std.json.Value{ .array = string_array };
    const decoded_array = try ArrayDecodeUtils.decodeStringArray(array_json, allocator);
    defer {
        for (decoded_array) |str| {
            allocator.free(str);
        }
        allocator.free(decoded_array);
    }
    
    try testing.expectEqual(@as(usize, 2), decoded_array.len);
    try testing.expectEqualStrings("first", decoded_array[0]);
    try testing.expectEqualStrings("second", decoded_array[1]);
    
    // Test single value as array (equivalent to Swift @SingleValueOrNilArray)
    const single_value_json = std.json.Value{ .string = "single" };
    const single_as_array = try ArrayDecodeUtils.decodeStringArray(single_value_json, allocator);
    defer {
        for (single_as_array) |str| {
            allocator.free(str);
        }
        allocator.free(single_as_array);
    }
    
    try testing.expectEqual(@as(usize, 1), single_as_array.len);
    try testing.expectEqualStrings("single", single_as_array[0]);
}

test "Nullable decoding operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test nullable string decoding (equivalent to Swift nullable tests)
    const null_json = std.json.Value{ .null = {} };
    const null_string = try NullableDecodeUtils.decodeNullableString(null_json, allocator);
    try testing.expectEqual(@as(?[]u8, null), null_string);
    
    const string_json = std.json.Value{ .string = "not_null" };
    const some_string = try NullableDecodeUtils.decodeNullableString(string_json, allocator);
    defer if (some_string) |s| allocator.free(s);
    
    try testing.expect(some_string != null);
    try testing.expectEqualStrings("not_null", some_string.?);
    
    // Test nullable integer
    const null_int = NullableDecodeUtils.decodeNullableInteger(null_json);
    try testing.expectEqual(@as(?i64, null), null_int);
    
    const int_json = std.json.Value{ .integer = 42 };
    const some_int = NullableDecodeUtils.decodeNullableInteger(int_json);
    try testing.expectEqual(@as(i64, 42), some_int.?);
}
