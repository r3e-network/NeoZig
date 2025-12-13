//! Complete Stack Item implementation
//!
//! Complete conversion from NeoSwift StackItem.swift
//! Provides comprehensive Neo VM stack item handling with all types.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const json_utils = @import("../utils/json_utils.zig");

/// Complete stack item (converted from Swift StackItem)
pub const CompleteStackItem = union(enum) {
    Any: ?[]const u8,
    Pointer: u256,
    Boolean: bool,
    Integer: i64,
    ByteString: []const u8,
    Buffer: []const u8,
    Array: []const CompleteStackItem,
    Struct: []const CompleteStackItem,
    Map: std.HashMap(CompleteStackItem, CompleteStackItem, StackItemContext, std.hash_map.default_max_load_percentage),
    InteropInterface: u64,
    
    const Self = @This();
    
    // Type constants (match Swift constants)
    pub const ANY_VALUE = "Any";
    pub const POINTER_VALUE = "Pointer";
    pub const BOOLEAN_VALUE = "Boolean";
    pub const INTEGER_VALUE = "Integer";
    pub const BYTE_STRING_VALUE = "ByteString";
    pub const BUFFER_VALUE = "Buffer";
    pub const ARRAY_VALUE = "Array";
    pub const STRUCT_VALUE = "Struct";
    pub const MAP_VALUE = "Map";
    pub const INTEROP_INTERFACE_VALUE = "InteropInterface";
    
    // Byte constants (match Swift byte constants)
    pub const ANY_BYTE: u8 = 0x00;
    pub const POINTER_BYTE: u8 = 0x10;
    pub const BOOLEAN_BYTE: u8 = 0x20;
    pub const INTEGER_BYTE: u8 = 0x21;
    pub const BYTE_STRING_BYTE: u8 = 0x28;
    pub const BUFFER_BYTE: u8 = 0x30;
    pub const ARRAY_BYTE: u8 = 0x40;
    pub const STRUCT_BYTE: u8 = 0x41;
    pub const MAP_BYTE: u8 = 0x48;
    pub const INTEROP_INTERFACE_BYTE: u8 = 0x60;
    
    /// Creates stack items (equivalent to Swift case constructors)
    pub fn any(value: ?[]const u8) Self {
        return Self{ .Any = value };
    }
    
    pub fn pointer(value: u256) Self {
        return Self{ .Pointer = value };
    }
    
    pub fn boolean(value: bool) Self {
        return Self{ .Boolean = value };
    }
    
    pub fn integer(value: i64) Self {
        return Self{ .Integer = value };
    }
    
    pub fn byteString(value: []const u8) Self {
        return Self{ .ByteString = value };
    }
    
    pub fn buffer(value: []const u8) Self {
        return Self{ .Buffer = value };
    }
    
    pub fn array(value: []const CompleteStackItem) Self {
        return Self{ .Array = value };
    }
    
    pub fn struct_item(value: []const CompleteStackItem) Self {
        return Self{ .Struct = value };
    }
    
    pub fn map(value: std.HashMap(CompleteStackItem, CompleteStackItem, StackItemContext, std.hash_map.default_max_load_percentage)) Self {
        return Self{ .Map = value };
    }
    
    pub fn interopInterface(value: u64) Self {
        return Self{ .InteropInterface = value };
    }
    
    /// Gets JSON value (equivalent to Swift .jsonValue property)
    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .Any => ANY_VALUE,
            .Pointer => POINTER_VALUE,
            .Boolean => BOOLEAN_VALUE,
            .Integer => INTEGER_VALUE,
            .ByteString => BYTE_STRING_VALUE,
            .Buffer => BUFFER_VALUE,
            .Array => ARRAY_VALUE,
            .Struct => STRUCT_VALUE,
            .Map => MAP_VALUE,
            .InteropInterface => INTEROP_INTERFACE_VALUE,
        };
    }
    
    /// Gets byte value (equivalent to Swift .byte property)
    pub fn getByte(self: Self) u8 {
        return switch (self) {
            .Any => ANY_BYTE,
            .Pointer => POINTER_BYTE,
            .Boolean => BOOLEAN_BYTE,
            .Integer => INTEGER_BYTE,
            .ByteString => BYTE_STRING_BYTE,
            .Buffer => BUFFER_BYTE,
            .Array => ARRAY_BYTE,
            .Struct => STRUCT_BYTE,
            .Map => MAP_BYTE,
            .InteropInterface => INTEROP_INTERFACE_BYTE,
        };
    }
    
    /// Gets as string (equivalent to Swift string conversion)
    pub fn getString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .ByteString => |value| try allocator.dupe(u8, value),
            .Integer => |value| try std.fmt.allocPrint(allocator, "{d}", .{value}),
            .Boolean => |value| try allocator.dupe(u8, if (value) "true" else "false"),
            .Buffer => |value| try allocator.dupe(u8, value),
            else => errors.ContractError.UnexpectedReturnType,
        };
    }
    
    /// Gets as integer (equivalent to Swift integer conversion)
    pub fn getInteger(self: Self) !i64 {
        return switch (self) {
            .Integer => |value| value,
            .Boolean => |value| if (value) @as(i64, 1) else @as(i64, 0),
            .ByteString => |value| std.fmt.parseInt(i64, value, 10) catch {
                return errors.ContractError.UnexpectedReturnType;
            },
            else => errors.ContractError.UnexpectedReturnType,
        };
    }
    
    /// Gets as boolean (equivalent to Swift boolean conversion)
    pub fn getBoolean(self: Self) !bool {
        return switch (self) {
            .Boolean => |value| value,
            .Integer => |value| value != 0,
            .ByteString => |value| std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1"),
            else => errors.ContractError.UnexpectedReturnType,
        };
    }
    
    /// Gets as byte array (equivalent to Swift byte array conversion)
    pub fn getByteArray(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .ByteString => |value| try allocator.dupe(u8, value),
            .Buffer => |value| try allocator.dupe(u8, value),
            .Integer => |value| {
                const bytes = std.mem.toBytes(std.mem.nativeToLittle(i64, value));
                return try allocator.dupe(u8, &bytes);
            },
            else => errors.ContractError.UnexpectedReturnType,
        };
    }
    
    /// Gets as array (equivalent to Swift array conversion)
    pub fn getArray(self: Self) ![]const CompleteStackItem {
        return switch (self) {
            .Array => |value| value,
            .Struct => |value| value,
            else => errors.ContractError.UnexpectedReturnType,
        };
    }
    
    /// Gets as Hash160 (utility method)
    pub fn getHash160(self: Self, allocator: std.mem.Allocator) !Hash160 {
        const bytes = try self.getByteArray(allocator);
        defer allocator.free(bytes);
        
        if (bytes.len != 20) {
            return errors.ValidationError.InvalidHash;
        }
        
        var hash_bytes: [20]u8 = undefined;
        @memcpy(&hash_bytes, bytes);
        return Hash160.fromArray(hash_bytes);
    }
    
    /// Gets as Hash256 (utility method)
    pub fn getHash256(self: Self, allocator: std.mem.Allocator) !Hash256 {
        const bytes = try self.getByteArray(allocator);
        defer allocator.free(bytes);
        
        if (bytes.len != 32) {
            return errors.ValidationError.InvalidHash;
        }
        
        var hash_bytes: [32]u8 = undefined;
        @memcpy(&hash_bytes, bytes);
        return Hash256.init(hash_bytes);
    }
    
    /// Validates stack item type
    pub fn validate(self: Self) !void {
        switch (self) {
            .Array => |items| {
                for (items) |item| {
                    try item.validate();
                }
            },
            .Struct => |items| {
                for (items) |item| {
                    try item.validate();
                }
            },
            .Map => |map| {
                var iterator = map.iterator();
                while (iterator.next()) |entry| {
                    try entry.key_ptr.validate();
                    try entry.value_ptr.validate();
                }
            },
            else => {}, // Other types are always valid
        }
    }
    
    /// Compares stack items for equality
    pub fn eql(self: Self, other: Self) bool {
        const self_type = @as(u8, @intFromEnum(self));
        const other_type = @as(u8, @intFromEnum(other));
        
        if (self_type != other_type) return false;
        
        return switch (self) {
            .Any => |a| {
                if (a == null and other.Any == null) return true;
                if (a == null or other.Any == null) return false;
                return std.mem.eql(u8, a.?, other.Any.?);
            },
            .Pointer => |a| a == other.Pointer,
            .Boolean => |a| a == other.Boolean,
            .Integer => |a| a == other.Integer,
            .ByteString => |a| std.mem.eql(u8, a, other.ByteString),
            .Buffer => |a| std.mem.eql(u8, a, other.Buffer),
            .Array => |a| {
                if (a.len != other.Array.len) return false;
                for (a, other.Array) |item_a, item_b| {
                    if (!item_a.eql(item_b)) return false;
                }
                return true;
            },
            .Struct => |a| {
                if (a.len != other.Struct.len) return false;
                for (a, other.Struct) |item_a, item_b| {
                    if (!item_a.eql(item_b)) return false;
                }
                return true;
            },
            .Map => |a| {
                if (a.count() != other.Map.count()) return false;
                var iter = a.iterator();
                while (iter.next()) |entry| {
                    const other_value = other.Map.get(entry.key_ptr.*) orelse return false;
                    if (!entry.value_ptr.eql(other_value)) return false;
                }
                return true;
            },
            .InteropInterface => |a| a == other.InteropInterface,
        };
    }
    
    /// Hash function for HashMap usage
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        // Hash the type first
        hasher.update(&[_]u8{self.getByte()});
        
        switch (self) {
            .Any => |value| {
                if (value) |v| hasher.update(v);
            },
            .Pointer => |value| {
                const bytes = std.mem.toBytes(value);
                hasher.update(&bytes);
            },
            .Boolean => |value| hasher.update(&[_]u8{if (value) 1 else 0}),
            .Integer => |value| {
                const bytes = std.mem.toBytes(value);
                hasher.update(&bytes);
            },
            .ByteString => |value| hasher.update(value),
            .Buffer => |value| hasher.update(value),
            .Array => |items| {
                for (items) |item| {
                    const item_hash = item.hash();
                    const item_bytes = std.mem.toBytes(item_hash);
                    hasher.update(&item_bytes);
                }
            },
            .Struct => |items| {
                for (items) |item| {
                    const item_hash = item.hash();
                    const item_bytes = std.mem.toBytes(item_hash);
                    hasher.update(&item_bytes);
                }
            },
            .Map => |map| {
                var iter = map.iterator();
                while (iter.next()) |entry| {
                    const key_hash = entry.key_ptr.hash();
                    const value_hash = entry.value_ptr.hash();
                    hasher.update(&std.mem.toBytes(key_hash));
                    hasher.update(&std.mem.toBytes(value_hash));
                }
            },
            .InteropInterface => |value| {
                const bytes = std.mem.toBytes(value);
                hasher.update(&bytes);
            },
        }
        
        return hasher.final();
    }
};

/// Stack item context for HashMap
pub const StackItemContext = struct {
    pub fn hash(self: @This(), item: CompleteStackItem) u64 {
        _ = self;
        return item.hash();
    }
    
    pub fn eql(self: @This(), a: CompleteStackItem, b: CompleteStackItem) bool {
        _ = self;
        return a.eql(b);
    }
};

/// Stack item utilities
pub const StackItemUtils = struct {
    /// Creates stack item from JSON (utility method)
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !CompleteStackItem {
        const obj = json_value.object;
        const item_type = obj.get("type").?.string;
        
        if (std.mem.eql(u8, item_type, "Boolean")) {
            const value = obj.get("value").?.bool;
            return CompleteStackItem.boolean(value);
        }
        
        if (std.mem.eql(u8, item_type, "Integer")) {
            const value = obj.get("value").?.integer;
            return CompleteStackItem.integer(value);
        }
        
        if (std.mem.eql(u8, item_type, "ByteString")) {
            const base64_value = obj.get("value").?.string;
            const decoded = try @import("../utils/string_extensions.zig").StringUtils.base64Decoded(base64_value, allocator);
            return CompleteStackItem.byteString(decoded);
        }
        
        if (std.mem.eql(u8, item_type, "Array")) {
            const array_value = obj.get("value").?.array;
            var items = try allocator.alloc(CompleteStackItem, array_value.len);
            
            for (array_value, 0..) |item_json, i| {
                items[i] = try fromJson(item_json, allocator);
            }
            
            return CompleteStackItem.array(items);
        }
        
        // Default to Any for unknown types
        return CompleteStackItem.any(null);
    }
    
    /// Converts stack item to JSON (utility method)
    pub fn toJson(item: CompleteStackItem, allocator: std.mem.Allocator) !std.json.Value {
        var obj = std.json.ObjectMap.init(allocator);
        
        try json_utils.putOwnedKey(&obj, allocator, "type", std.json.Value{ .string = try allocator.dupe(u8, item.getJsonValue()) });
        
        switch (item) {
            .Boolean => |value| {
                try json_utils.putOwnedKey(&obj, allocator, "value", std.json.Value{ .bool = value });
            },
            .Integer => |value| {
                try json_utils.putOwnedKey(&obj, allocator, "value", std.json.Value{ .integer = value });
            },
            .ByteString => |value| {
                const base64_value = try @import("../utils/string_extensions.zig").StringUtils.base64Encoded(value, allocator);
                defer allocator.free(base64_value);
                try json_utils.putOwnedKey(&obj, allocator, "value", std.json.Value{ .string = base64_value });
            },
            .Array => |items| {
                var array_json = ArrayList(std.json.Value).init(allocator);
                for (items) |array_item| {
                    try array_json.append(try toJson(array_item, allocator));
                }
                try json_utils.putOwnedKey(&obj, allocator, "value", std.json.Value{ .array = array_json });
            },
            else => {
                try json_utils.putOwnedKey(&obj, allocator, "value", std.json.Value{ .null = {} });
            },
        }
        
        return std.json.Value{ .object = obj };
    }
    
    /// Creates stack item from contract parameter
    pub fn fromContractParameter(param: @import("../types/contract_parameter.zig").ContractParameter, allocator: std.mem.Allocator) !CompleteStackItem {
        return switch (param) {
            .Boolean => |value| CompleteStackItem.boolean(value),
            .Integer => |value| CompleteStackItem.integer(value),
            .String => |value| CompleteStackItem.byteString(try allocator.dupe(u8, value)),
            .ByteArray => |value| CompleteStackItem.byteString(try allocator.dupe(u8, value)),
            .Hash160 => |value| CompleteStackItem.byteString(try allocator.dupe(u8, &value.toArray())),
            .Hash256 => |value| CompleteStackItem.byteString(try allocator.dupe(u8, &value.toArray())),
            .Array => |items| {
                var stack_items = try allocator.alloc(CompleteStackItem, items.len);
                for (items, 0..) |item, i| {
                    stack_items[i] = try fromContractParameter(item, allocator);
                }
                return CompleteStackItem.array(stack_items);
            },
            else => CompleteStackItem.any(null),
        };
    }
    
    /// Validates stack item size limits
    pub fn validateSizeLimits(item: CompleteStackItem) !void {
        switch (item) {
            .ByteString => |value| {
                if (value.len > 65535) {
                    return errors.ValidationError.DataTooLarge;
                }
            },
            .Buffer => |value| {
                if (value.len > 65535) {
                    return errors.ValidationError.DataTooLarge;
                }
            },
            .Array => |items| {
                if (items.len > 2048) {
                    return errors.ValidationError.DataTooLarge;
                }
                for (items) |array_item| {
                    try validateSizeLimits(array_item);
                }
            },
            .Struct => |items| {
                if (items.len > 2048) {
                    return errors.ValidationError.DataTooLarge;
                }
                for (items) |struct_item| {
                    try validateSizeLimits(struct_item);
                }
            },
            else => {}, // Other types have inherent size limits
        }
    }
};

// Tests (converted from Swift StackItem tests)
test "CompleteStackItem creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test basic stack item creation (equivalent to Swift StackItem tests)
    const bool_item = CompleteStackItem.boolean(true);
    const int_item = CompleteStackItem.integer(12345);
    const string_item = CompleteStackItem.byteString("Hello Neo");
    
    try testing.expectEqualStrings("Boolean", bool_item.getJsonValue());
    try testing.expectEqualStrings("Integer", int_item.getJsonValue());
    try testing.expectEqualStrings("ByteString", string_item.getJsonValue());
    
    try testing.expectEqual(CompleteStackItem.BOOLEAN_BYTE, bool_item.getByte());
    try testing.expectEqual(CompleteStackItem.INTEGER_BYTE, int_item.getByte());
    try testing.expectEqual(CompleteStackItem.BYTE_STRING_BYTE, string_item.getByte());
}

test "CompleteStackItem type conversion operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test string conversion (equivalent to Swift string conversion tests)
    const string_item = CompleteStackItem.byteString("Test String");
    const string_value = try string_item.getString(allocator);
    defer allocator.free(string_value);
    
    try testing.expectEqualStrings("Test String", string_value);
    
    // Test integer conversion
    const int_item = CompleteStackItem.integer(42);
    const int_value = try int_item.getInteger();
    try testing.expectEqual(@as(i64, 42), int_value);
    
    const int_as_string = try int_item.getString(allocator);
    defer allocator.free(int_as_string);
    try testing.expectEqualStrings("42", int_as_string);
    
    // Test boolean conversion
    const bool_item = CompleteStackItem.boolean(true);
    const bool_value = try bool_item.getBoolean();
    try testing.expect(bool_value);
    
    const bool_as_int = try bool_item.getInteger();
    try testing.expectEqual(@as(i64, 1), bool_as_int);
}

test "CompleteStackItem complex types" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test array stack item (equivalent to Swift array tests)
    const array_items = try allocator.alloc(CompleteStackItem, 3);
    defer allocator.free(array_items);
    
    array_items[0] = CompleteStackItem.integer(1);
    array_items[1] = CompleteStackItem.integer(2);
    array_items[2] = CompleteStackItem.integer(3);
    
    const array_item = CompleteStackItem.array(array_items);
    
    try testing.expectEqualStrings("Array", array_item.getJsonValue());
    
    const retrieved_array = try array_item.getArray();
    try testing.expectEqual(@as(usize, 3), retrieved_array.len);
    
    // Test validation
    try array_item.validate();
    
    // Test struct stack item
    const struct_items = try allocator.alloc(CompleteStackItem, 2);
    defer allocator.free(struct_items);
    
    struct_items[0] = CompleteStackItem.byteString("field1");
    struct_items[1] = CompleteStackItem.byteString("field2");
    
    const struct_item = CompleteStackItem.struct_item(struct_items);
    try testing.expectEqualStrings("Struct", struct_item.getJsonValue());
    
    try struct_item.validate();
}

test "CompleteStackItem JSON operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON conversion (equivalent to Swift Codable tests)
    const original_item = CompleteStackItem.integer(54321);
    
    const json_value = try StackItemUtils.toJson(original_item, allocator);
    defer json_utils.freeValue(json_value, allocator);
    
    const obj = json_value.object;
    try testing.expectEqualStrings("Integer", obj.get("type").?.string);
    try testing.expectEqual(@as(i64, 54321), obj.get("value").?.integer);
    
    // Test round-trip conversion
    const parsed_item = try StackItemUtils.fromJson(json_value, allocator);
    try testing.expect(original_item.eql(parsed_item));
}

test "CompleteStackItem hash operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Hash160 conversion
    const hash160_bytes = [_]u8{0x01} ** 20;
    const hash160_item = CompleteStackItem.byteString(&hash160_bytes);
    
    const hash160_value = try hash160_item.getHash160(allocator);
    try testing.expect(std.mem.eql(u8, &hash160_bytes, &hash160_value.toArray()));
    
    // Test Hash256 conversion
    const hash256_bytes = [_]u8{0x02} ** 32;
    const hash256_item = CompleteStackItem.byteString(&hash256_bytes);
    
    const hash256_value = try hash256_item.getHash256(allocator);
    try testing.expect(std.mem.eql(u8, &hash256_bytes, &hash256_value.toArray()));
    
    // Test invalid hash conversion
    const invalid_hash_item = CompleteStackItem.byteString("invalid_length");
    try testing.expectError(
        errors.ValidationError.InvalidHash,
        invalid_hash_item.getHash160(allocator)
    );
}
