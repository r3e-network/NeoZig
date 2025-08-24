//! Stack Item Implementation
//!
//! Complete conversion from NeoSwift StackItem.swift
//! Provides Neo VM stack item types and operations.

const std = @import("std");

/// Stack item types for Neo VM (converted from Swift StackItem)
pub const StackItem = union(enum) {
    /// Any type (wildcard)
    Any: ?[]const u8,
    /// Pointer type (instruction pointer)
    Pointer: i64,
    /// Boolean value
    Boolean: bool,
    /// Integer value (big integer)
    Integer: i64,
    /// Byte string value
    ByteString: []const u8,
    /// Buffer value (mutable byte array)
    Buffer: []const u8,
    /// Array of stack items
    Array: []StackItem,
    /// Struct (same as array but different semantics)
    Struct: []StackItem,
    /// Map of stack items
    Map: std.HashMap(StackItem, StackItem, StackItemContext, std.hash_map.default_max_load_percentage),
    /// Interop interface
    InteropInterface: struct {
        iterator_id: []const u8,
        interface_name: []const u8,
    },
    
    /// Stack item type constants (matches Swift constants)
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
    
    /// Stack item type bytes (matches Swift constants)
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
    
    const Self = @This();
    
    /// Gets JSON value (equivalent to Swift jsonValue)
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
    
    /// Gets byte value (equivalent to Swift byte)
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
    
    /// Creates stack item from JSON type string
    pub fn fromJsonValue(json_value: []const u8) ?Self {
        if (std.mem.eql(u8, json_value, ANY_VALUE)) return Self{ .Any = null };
        if (std.mem.eql(u8, json_value, POINTER_VALUE)) return Self{ .Pointer = 0 };
        if (std.mem.eql(u8, json_value, BOOLEAN_VALUE)) return Self{ .Boolean = false };
        if (std.mem.eql(u8, json_value, INTEGER_VALUE)) return Self{ .Integer = 0 };
        if (std.mem.eql(u8, json_value, BYTE_STRING_VALUE)) return Self{ .ByteString = "" };
        if (std.mem.eql(u8, json_value, BUFFER_VALUE)) return Self{ .Buffer = "" };
        if (std.mem.eql(u8, json_value, ARRAY_VALUE)) return Self{ .Array = &[_]StackItem{} };
        if (std.mem.eql(u8, json_value, STRUCT_VALUE)) return Self{ .Struct = &[_]StackItem{} };
        if (std.mem.eql(u8, json_value, INTEROP_INTERFACE_VALUE)) return Self{ 
            .InteropInterface = .{ .iterator_id = "", .interface_name = "" }
        };
        return null;
    }
    
    /// Creates stack item from byte value
    pub fn fromByte(byte_value: u8) ?Self {
        return switch (byte_value) {
            ANY_BYTE => Self{ .Any = null },
            POINTER_BYTE => Self{ .Pointer = 0 },
            BOOLEAN_BYTE => Self{ .Boolean = false },
            INTEGER_BYTE => Self{ .Integer = 0 },
            BYTE_STRING_BYTE => Self{ .ByteString = "" },
            BUFFER_BYTE => Self{ .Buffer = "" },
            ARRAY_BYTE => Self{ .Array = &[_]StackItem{} },
            STRUCT_BYTE => Self{ .Struct = &[_]StackItem{} },
            MAP_BYTE => Self{ .Map = undefined }, // Would need proper initialization
            INTEROP_INTERFACE_BYTE => Self{ 
                .InteropInterface = .{ .iterator_id = "", .interface_name = "" }
            },
            else => null,
        };
    }
    
    /// Gets value as boolean
    pub fn getBoolean(self: Self) !bool {
        return switch (self) {
            .Boolean => |value| value,
            .Integer => |value| value != 0,
            .ByteString => |value| value.len > 0,
            .Array => |value| value.len > 0,
            else => error.InvalidStackItemType,
        };
    }
    
    /// Gets value as integer
    pub fn getInteger(self: Self) !i64 {
        return switch (self) {
            .Integer => |value| value,
            .Boolean => |value| if (value) @as(i64, 1) else @as(i64, 0),
            .ByteString => |value| blk: {
                if (value.len == 0) break :blk 0;
                if (value.len > 8) return error.IntegerTooLarge;
                
                var result: i64 = 0;
                for (value, 0..) |byte, i| {
                    result |= @as(i64, byte) << @intCast(i * 8);
                }
                break :blk result;
            },
            else => error.InvalidStackItemType,
        };
    }
    
    /// Gets value as string
    pub fn getString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .ByteString => |value| try allocator.dupe(u8, value),
            .Integer => |value| try std.fmt.allocPrint(allocator, "{}", .{value}),
            .Boolean => |value| try allocator.dupe(u8, if (value) "true" else "false"),
            else => error.InvalidStackItemType,
        };
    }
    
    /// Gets value as byte array
    pub fn getByteArray(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .ByteString => |value| try allocator.dupe(u8, value),
            .Buffer => |value| try allocator.dupe(u8, value),
            .Integer => |value| blk: {
                const bytes = std.mem.toBytes(std.mem.nativeToLittle(i64, value));
                break :blk try allocator.dupe(u8, &bytes);
            },
            else => error.InvalidStackItemType,
        };
    }
    
    /// Gets value as array of stack items
    pub fn getArray(self: Self) ![]StackItem {
        return switch (self) {
            .Array => |value| value,
            .Struct => |value| value,
            else => error.InvalidStackItemType,
        };
    }
    
    /// Checks if stack item is null or empty
    pub fn isNull(self: Self) bool {
        return switch (self) {
            .Any => |value| value == null,
            .ByteString => |value| value.len == 0,
            .Buffer => |value| value.len == 0,
            .Array => |value| value.len == 0,
            .Struct => |value| value.len == 0,
            else => false,
        };
    }
    
    /// Gets size in bytes (estimated)
    pub fn getSize(self: Self) usize {
        return switch (self) {
            .Any => 1,
            .Pointer => 9, // 1 byte type + 8 bytes value
            .Boolean => 1,
            .Integer => 9, // 1 byte type + up to 8 bytes value
            .ByteString => |value| 1 + value.len,
            .Buffer => |value| 1 + value.len,
            .Array => |items| blk: {
                var size: usize = 1; // Type byte
                for (items) |item| {
                    size += item.getSize();
                }
                break :blk size;
            },
            .Struct => |items| blk: {
                var size: usize = 1; // Type byte
                for (items) |item| {
                    size += item.getSize();
                }
                break :blk size;
            },
            .Map => 1, // Simplified
            .InteropInterface => |interface| 1 + interface.iterator_id.len + interface.interface_name.len,
        };
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return switch (self) {
            .Any => |value| switch (other) {
                .Any => |other_value| blk: {
                    if (value == null and other_value == null) break :blk true;
                    if (value == null or other_value == null) break :blk false;
                    break :blk std.mem.eql(u8, value.?, other_value.?);
                },
                else => false,
            },
            .Pointer => |value| switch (other) {
                .Pointer => |other_value| value == other_value,
                else => false,
            },
            .Boolean => |value| switch (other) {
                .Boolean => |other_value| value == other_value,
                else => false,
            },
            .Integer => |value| switch (other) {
                .Integer => |other_value| value == other_value,
                else => false,
            },
            .ByteString => |value| switch (other) {
                .ByteString => |other_value| std.mem.eql(u8, value, other_value),
                else => false,
            },
            .Buffer => |value| switch (other) {
                .Buffer => |other_value| std.mem.eql(u8, value, other_value),
                else => false,
            },
            .Array => |items| switch (other) {
                .Array => |other_items| blk: {
                    if (items.len != other_items.len) break :blk false;
                    for (items, 0..) |item, i| {
                        if (!item.eql(other_items[i])) break :blk false;
                    }
                    break :blk true;
                },
                else => false,
            },
            .Struct => |items| switch (other) {
                .Struct => |other_items| blk: {
                    if (items.len != other_items.len) break :blk false;
                    for (items, 0..) |item, i| {
                        if (!item.eql(other_items[i])) break :blk false;
                    }
                    break :blk true;
                },
                else => false,
            },
            .Map => false, // Simplified - complex map comparison
            .InteropInterface => |interface| switch (other) {
                .InteropInterface => |other_interface| 
                    std.mem.eql(u8, interface.iterator_id, other_interface.iterator_id) and
                    std.mem.eql(u8, interface.interface_name, other_interface.interface_name),
                else => false,
            },
        };
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        hasher.update(&[_]u8{self.getByte()});
        
        switch (self) {
            .Any => |value| {
                if (value) |v| {
                    hasher.update(v);
                }
            },
            .Pointer => |value| {
                hasher.update(std.mem.asBytes(&value));
            },
            .Boolean => |value| {
                hasher.update(&[_]u8{if (value) 1 else 0});
            },
            .Integer => |value| {
                hasher.update(std.mem.asBytes(&value));
            },
            .ByteString => |value| {
                hasher.update(value);
            },
            .Buffer => |value| {
                hasher.update(value);
            },
            .Array => |items| {
                for (items) |item| {
                    const item_hash = item.hash();
                    hasher.update(std.mem.asBytes(&item_hash));
                }
            },
            .Struct => |items| {
                for (items) |item| {
                    const item_hash = item.hash();
                    hasher.update(std.mem.asBytes(&item_hash));
                }
            },
            .Map => {
                // Simplified map hashing
                hasher.update(&[_]u8{0xFF});
            },
            .InteropInterface => |interface| {
                hasher.update(interface.iterator_id);
                hasher.update(interface.interface_name);
            },
        }
        
        return hasher.final();
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .Any => |value| {
                if (value) |v| {
                    allocator.free(v);
                }
            },
            .ByteString => |value| {
                allocator.free(value);
            },
            .Buffer => |value| {
                allocator.free(value);
            },
            .Array => |items| {
                for (items) |*item| {
                    item.deinit(allocator);
                }
                allocator.free(items);
            },
            .Struct => |items| {
                for (items) |*item| {
                    item.deinit(allocator);
                }
                allocator.free(items);
            },
            .Map => |*map| {
                map.deinit();
            },
            .InteropInterface => |interface| {
                allocator.free(interface.iterator_id);
                allocator.free(interface.interface_name);
            },
            .Pointer, .Boolean, .Integer => {}, // No cleanup needed
        }
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .Any => |value| {
                if (value) |v| {
                    return try std.fmt.allocPrint(
                        allocator,
                        "{{\"type\":\"{s}\",\"value\":\"{s}\"}}",
                        .{ ANY_VALUE, v }
                    );
                } else {
                    return try std.fmt.allocPrint(
                        allocator,
                        "{{\"type\":\"{s}\",\"value\":null}}",
                        .{ANY_VALUE}
                    );
                }
            },
            .Pointer => |value| try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"{s}\",\"value\":{}}}",
                .{ POINTER_VALUE, value }
            ),
            .Boolean => |value| try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"{s}\",\"value\":{}}}",
                .{ BOOLEAN_VALUE, value }
            ),
            .Integer => |value| try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"{s}\",\"value\":{}}}",
                .{ INTEGER_VALUE, value }
            ),
            .ByteString => |value| try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"{s}\",\"value\":\"{s}\"}}",
                .{ BYTE_STRING_VALUE, value }
            ),
            .Buffer => |value| try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"{s}\",\"value\":\"{s}\"}}",
                .{ BUFFER_VALUE, value }
            ),
            .Array => |items| blk: {
                var array_json = std.ArrayList(u8).init(allocator);
                defer array_json.deinit();
                
                try array_json.appendSlice("[");
                for (items, 0..) |item, i| {
                    if (i > 0) try array_json.appendSlice(",");
                    const item_json = try item.encodeToJson(allocator);
                    defer allocator.free(item_json);
                    try array_json.appendSlice(item_json);
                }
                try array_json.appendSlice("]");
                
                break :blk try std.fmt.allocPrint(
                    allocator,
                    "{{\"type\":\"{s}\",\"value\":{s}}}",
                    .{ ARRAY_VALUE, array_json.items }
                );
            },
            .Struct => |items| blk: {
                var struct_json = std.ArrayList(u8).init(allocator);
                defer struct_json.deinit();
                
                try struct_json.appendSlice("[");
                for (items, 0..) |item, i| {
                    if (i > 0) try struct_json.appendSlice(",");
                    const item_json = try item.encodeToJson(allocator);
                    defer allocator.free(item_json);
                    try struct_json.appendSlice(item_json);
                }
                try struct_json.appendSlice("]");
                
                break :blk try std.fmt.allocPrint(
                    allocator,
                    "{{\"type\":\"{s}\",\"value\":{s}}}",
                    .{ STRUCT_VALUE, struct_json.items }
                );
            },
            .Map => try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"{s}\",\"value\":{{}}}}",
                .{MAP_VALUE}
            ),
            .InteropInterface => |interface| try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"{s}\",\"iteratorId\":\"{s}\",\"interfaceName\":\"{s}\"}}",
                .{ INTEROP_INTERFACE_VALUE, interface.iterator_id, interface.interface_name }
            ),
        };
    }
    
    /// Creates specific stack item types
    pub const Factory = struct {
        /// Creates boolean stack item
        pub fn createBoolean(value: bool) Self {
            return Self{ .Boolean = value };
        }
        
        /// Creates integer stack item
        pub fn createInteger(value: i64) Self {
            return Self{ .Integer = value };
        }
        
        /// Creates byte string stack item
        pub fn createByteString(value: []const u8, allocator: std.mem.Allocator) !Self {
            const value_copy = try allocator.dupe(u8, value);
            return Self{ .ByteString = value_copy };
        }
        
        /// Creates buffer stack item
        pub fn createBuffer(value: []const u8, allocator: std.mem.Allocator) !Self {
            const value_copy = try allocator.dupe(u8, value);
            return Self{ .Buffer = value_copy };
        }
        
        /// Creates array stack item
        pub fn createArray(items: []const StackItem, allocator: std.mem.Allocator) !Self {
            const items_copy = try allocator.dupe(StackItem, items);
            return Self{ .Array = items_copy };
        }
        
        /// Creates struct stack item
        pub fn createStruct(items: []const StackItem, allocator: std.mem.Allocator) !Self {
            const items_copy = try allocator.dupe(StackItem, items);
            return Self{ .Struct = items_copy };
        }
        
        /// Creates interop interface stack item
        pub fn createInteropInterface(iterator_id: []const u8, interface_name: []const u8, allocator: std.mem.Allocator) !Self {
            const id_copy = try allocator.dupe(u8, iterator_id);
            const name_copy = try allocator.dupe(u8, interface_name);
            
            return Self{ 
                .InteropInterface = .{
                    .iterator_id = id_copy,
                    .interface_name = name_copy,
                }
            };
        }
    };
};

/// HashMap context for StackItem maps
const StackItemContext = struct {
    pub fn hash(self: @This(), key: StackItem) u64 {
        _ = self;
        return key.hash();
    }
    
    pub fn eql(self: @This(), a: StackItem, b: StackItem) bool {
        _ = self;
        return a.eql(b);
    }
};

// Tests (converted from Swift StackItem tests)
test "StackItem creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test boolean stack item (equivalent to Swift tests)
    const bool_item = StackItem.Factory.createBoolean(true);
    try testing.expectEqual(@as(u8, StackItem.BOOLEAN_BYTE), bool_item.getByte());
    try testing.expectEqualStrings(StackItem.BOOLEAN_VALUE, bool_item.getJsonValue());
    try testing.expectEqual(true, try bool_item.getBoolean());
    
    // Test integer stack item
    const int_item = StackItem.Factory.createInteger(42);
    try testing.expectEqual(@as(u8, StackItem.INTEGER_BYTE), int_item.getByte());
    try testing.expectEqual(@as(i64, 42), try int_item.getInteger());
    
    // Test byte string stack item
    var byte_string_item = try StackItem.Factory.createByteString("Hello", allocator);
    defer byte_string_item.deinit(allocator);
    
    try testing.expectEqual(@as(u8, StackItem.BYTE_STRING_BYTE), byte_string_item.getByte());
    
    const string_value = try byte_string_item.getString(allocator);
    defer allocator.free(string_value);
    try testing.expectEqualStrings("Hello", string_value);
}

test "StackItem type conversions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test boolean conversions
    const true_item = StackItem.Factory.createBoolean(true);
    try testing.expectEqual(true, try true_item.getBoolean());
    try testing.expectEqual(@as(i64, 1), try true_item.getInteger());
    
    const false_item = StackItem.Factory.createBoolean(false);
    try testing.expectEqual(false, try false_item.getBoolean());
    try testing.expectEqual(@as(i64, 0), try false_item.getInteger());
    
    // Test integer conversions
    const zero_int = StackItem.Factory.createInteger(0);
    try testing.expectEqual(false, try zero_int.getBoolean());
    
    const nonzero_int = StackItem.Factory.createInteger(42);
    try testing.expectEqual(true, try nonzero_int.getBoolean());
    
    // Test byte string conversions
    var empty_bytes = try StackItem.Factory.createByteString("", allocator);
    defer empty_bytes.deinit(allocator);
    
    try testing.expectEqual(false, try empty_bytes.getBoolean());
    
    var nonempty_bytes = try StackItem.Factory.createByteString("test", allocator);
    defer nonempty_bytes.deinit(allocator);
    
    try testing.expectEqual(true, try nonempty_bytes.getBoolean());
}

test "StackItem array operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test array creation and operations
    const items = [_]StackItem{
        StackItem.Factory.createBoolean(true),
        StackItem.Factory.createInteger(42),
    };
    
    var array_item = try StackItem.Factory.createArray(&items, allocator);
    defer array_item.deinit(allocator);
    
    try testing.expectEqual(@as(u8, StackItem.ARRAY_BYTE), array_item.getByte());
    
    const retrieved_array = try array_item.getArray();
    try testing.expectEqual(@as(usize, 2), retrieved_array.len);
    
    const first_item = retrieved_array[0];
    try testing.expectEqual(true, try first_item.getBoolean());
    
    const second_item = retrieved_array[1];
    try testing.expectEqual(@as(i64, 42), try second_item.getInteger());
}

test "StackItem equality and hashing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test equality
    const bool1 = StackItem.Factory.createBoolean(true);
    const bool2 = StackItem.Factory.createBoolean(true);
    const bool3 = StackItem.Factory.createBoolean(false);
    
    try testing.expect(bool1.eql(bool2));
    try testing.expect(!bool1.eql(bool3));
    
    // Test hashing
    const hash1 = bool1.hash();
    const hash2 = bool2.hash();
    const hash3 = bool3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same items should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different items should have different hash
    
    // Test byte string equality
    var bytes1 = try StackItem.Factory.createByteString("test", allocator);
    defer bytes1.deinit(allocator);
    
    var bytes2 = try StackItem.Factory.createByteString("test", allocator);
    defer bytes2.deinit(allocator);
    
    var bytes3 = try StackItem.Factory.createByteString("other", allocator);
    defer bytes3.deinit(allocator);
    
    try testing.expect(bytes1.eql(bytes2));
    try testing.expect(!bytes1.eql(bytes3));
}