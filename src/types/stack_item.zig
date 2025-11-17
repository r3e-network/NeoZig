//! Stack Item Implementation
//!
//! Complete conversion from NeoSwift StackItem.swift
//! Provides Neo VM stack item types and operations.

const std = @import("std");
const ArrayList = std.array_list.Managed;

const errors = @import("../core/errors.zig");
const StringUtils = @import("../utils/string_extensions.zig").StringUtils;
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
        if (std.mem.eql(u8, json_value, INTEROP_INTERFACE_VALUE)) return Self{ .InteropInterface = .{ .iterator_id = "", .interface_name = "" } };
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
            INTEROP_INTERFACE_BYTE => Self{ .InteropInterface = .{ .iterator_id = "", .interface_name = "" } },
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
                .InteropInterface => |other_interface| std.mem.eql(u8, interface.iterator_id, other_interface.iterator_id) and
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
                var it = map.iterator();
                while (it.next()) |entry| {
                    entry.key_ptr.deinit(allocator);
                    entry.value_ptr.deinit(allocator);
                }
                map.deinit();
            },
            .InteropInterface => |interface| {
                allocator.free(interface.iterator_id);
                allocator.free(interface.interface_name);
            },
            .Pointer, .Boolean, .Integer => {}, // No cleanup needed
        }
    }

    /// Decodes a stack item from its JSON representation (Neo RPC format)
    pub fn decodeFromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) {
            return errors.SerializationError.InvalidFormat;
        }

        const obj = json_value.object;
        const type_field = obj.get("type") orelse return errors.SerializationError.InvalidFormat;
        const item_type = type_field.string;

        if (std.mem.eql(u8, item_type, ANY_VALUE)) {
            if (obj.get("value")) |value_json| {
                const rendered = try stringifyJsonValue(value_json, allocator);
                return Self{ .Any = rendered };
            }
            return Self{ .Any = null };
        }

        if (std.mem.eql(u8, item_type, POINTER_VALUE) or std.mem.eql(u8, item_type, INTEGER_VALUE)) {
            const value_json = obj.get("value") orelse return errors.SerializationError.InvalidFormat;
            const parsed_int = try parseJsonInteger(value_json);
            if (std.mem.eql(u8, item_type, POINTER_VALUE)) {
                return Self{ .Pointer = parsed_int };
            }
            return Self{ .Integer = parsed_int };
        }

        if (std.mem.eql(u8, item_type, BOOLEAN_VALUE)) {
            const value_json = obj.get("value") orelse return errors.SerializationError.InvalidFormat;
            const parsed_bool = try parseJsonBoolean(value_json);
            return Self{ .Boolean = parsed_bool };
        }

        if (std.mem.eql(u8, item_type, BYTE_STRING_VALUE) or std.mem.eql(u8, item_type, BUFFER_VALUE)) {
            const value_json = obj.get("value") orelse return errors.SerializationError.InvalidFormat;
            const bytes = try parseJsonBytes(value_json, allocator);
            if (std.mem.eql(u8, item_type, BYTE_STRING_VALUE)) {
                return Self{ .ByteString = bytes };
            }
            return Self{ .Buffer = bytes };
        }

        if (std.mem.eql(u8, item_type, ARRAY_VALUE) or std.mem.eql(u8, item_type, STRUCT_VALUE)) {
            const value_json = obj.get("value") orelse return errors.SerializationError.InvalidFormat;
            if (value_json != .array) return errors.SerializationError.InvalidFormat;

            var items = ArrayList(Self).init(allocator);
            defer items.deinit();

            for (value_json.array.items) |child| {
                var child_item = try Self.decodeFromJson(child, allocator);
                var child_guard = true;
                defer if (child_guard) child_item.deinit(allocator);
                try items.append(child_item);
                child_guard = false;
            }

            const owned_items = try items.toOwnedSlice();
            if (std.mem.eql(u8, item_type, ARRAY_VALUE)) {
                return Self{ .Array = owned_items };
            }
            return Self{ .Struct = owned_items };
        }

        if (std.mem.eql(u8, item_type, MAP_VALUE)) {
            const value_json = obj.get("value") orelse return errors.SerializationError.InvalidFormat;
            if (value_json != .array) return errors.SerializationError.InvalidFormat;

            var map = std.HashMap(Self, Self, StackItemContext, std.hash_map.default_max_load_percentage).init(allocator);
            var map_guard = true;
            defer if (map_guard) {
                var it = map.iterator();
                while (it.next()) |entry| {
                    entry.key_ptr.deinit(allocator);
                    entry.value_ptr.deinit(allocator);
                }
                map.deinit();
            };

            for (value_json.array.items) |entry_json| {
                if (entry_json != .object) return errors.SerializationError.InvalidFormat;
                const entry_obj = entry_json.object;

                const key_json = entry_obj.get("key") orelse return errors.SerializationError.InvalidFormat;
                const value_json_inner = entry_obj.get("value") orelse return errors.SerializationError.InvalidFormat;

                var key_item = try Self.decodeFromJson(key_json, allocator);
                var key_guard = true;
                defer if (key_guard) key_item.deinit(allocator);

                var value_item = try Self.decodeFromJson(value_json_inner, allocator);
                var value_guard = true;
                defer if (value_guard) value_item.deinit(allocator);

                try map.put(key_item, value_item);
                key_guard = false;
                value_guard = false;
            }

            map_guard = false;
            return Self{ .Map = map };
        }

        if (std.mem.eql(u8, item_type, INTEROP_INTERFACE_VALUE)) {
            const iterator_field = iteratorIdField(obj) orelse return errors.SerializationError.InvalidFormat;
            const interface_field = interfaceNameField(obj) orelse return errors.SerializationError.InvalidFormat;

            if (iterator_field != .string or interface_field != .string) {
                return errors.SerializationError.InvalidFormat;
            }

            const iterator_copy = try allocator.dupe(u8, iterator_field.string);
            errdefer allocator.free(iterator_copy);

            const interface_copy = try allocator.dupe(u8, interface_field.string);

            return Self{ .InteropInterface = .{
                .iterator_id = iterator_copy,
                .interface_name = interface_copy,
            } };
        }

        return errors.SerializationError.InvalidFormat;
    }

    fn parseJsonInteger(value: std.json.Value) !i64 {
        return switch (value) {
            .integer => |int_value| @as(i64, int_value),
            .string => |string_value| std.fmt.parseInt(i64, string_value, 10) catch errors.SerializationError.InvalidFormat,
            else => errors.SerializationError.InvalidFormat,
        };
    }

    fn parseJsonBoolean(value: std.json.Value) !bool {
        switch (value) {
            .bool => |bool_value| return bool_value,
            .integer => |int_value| return int_value != 0,
            .string => |string_value| {
                if (std.ascii.eqlIgnoreCase(string_value, "true")) return true;
                if (std.ascii.eqlIgnoreCase(string_value, "false")) return false;
                return errors.SerializationError.InvalidFormat;
            },
            else => return errors.SerializationError.InvalidFormat,
        }
    }

    fn parseJsonBytes(value: std.json.Value, allocator: std.mem.Allocator) ![]const u8 {
        return switch (value) {
            .string => |string_value| StringUtils.base64Decoded(string_value, allocator) catch {
                return allocator.dupe(u8, string_value);
            },
            .null => allocator.dupe(u8, ""),
            else => errors.SerializationError.InvalidFormat,
        };
    }

    fn stringifyJsonValue(value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
        var writer_state = std.io.Writer.Allocating.init(allocator);
        defer writer_state.deinit();

        var stringify = std.json.Stringify{ .writer = &writer_state.writer, .options = .{} };
        try stringify.write(value);

        return try writer_state.toOwnedSlice();
    }

    fn iteratorIdField(obj: std.json.ObjectMap) ?std.json.Value {
        if (obj.get("id")) |id_field| return id_field;
        if (obj.get("iteratorid")) |iter_lower| return iter_lower;
        if (obj.get("iteratorId")) |iter_camel| return iter_camel;
        return null;
    }

    fn interfaceNameField(obj: std.json.ObjectMap) ?std.json.Value {
        if (obj.get("interface")) |interface_field| return interface_field;
        if (obj.get("interfacename")) |lower| return lower;
        if (obj.get("interfaceName")) |camel| return camel;
        return null;
    }

    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .Any => |value| {
                if (value) |v| {
                    return try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":\"{s}\"}}", .{ ANY_VALUE, v });
                } else {
                    return try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":null}}", .{ANY_VALUE});
                }
            },
            .Pointer => |value| try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":{}}}", .{ POINTER_VALUE, value }),
            .Boolean => |value| try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":{}}}", .{ BOOLEAN_VALUE, value }),
            .Integer => |value| try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":{}}}", .{ INTEGER_VALUE, value }),
            .ByteString => |value| try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":\"{s}\"}}", .{ BYTE_STRING_VALUE, value }),
            .Buffer => |value| try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":\"{s}\"}}", .{ BUFFER_VALUE, value }),
            .Array => |items| blk: {
                var array_json = ArrayList(u8).init(allocator);
                defer array_json.deinit();

                try array_json.appendSlice("[");
                for (items, 0..) |item, i| {
                    if (i > 0) try array_json.appendSlice(",");
                    const item_json = try item.encodeToJson(allocator);
                    defer allocator.free(item_json);
                    try array_json.appendSlice(item_json);
                }
                try array_json.appendSlice("]");

                break :blk try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":{s}}}", .{ ARRAY_VALUE, array_json.items });
            },
            .Struct => |items| blk: {
                var struct_json = ArrayList(u8).init(allocator);
                defer struct_json.deinit();

                try struct_json.appendSlice("[");
                for (items, 0..) |item, i| {
                    if (i > 0) try struct_json.appendSlice(",");
                    const item_json = try item.encodeToJson(allocator);
                    defer allocator.free(item_json);
                    try struct_json.appendSlice(item_json);
                }
                try struct_json.appendSlice("]");

                break :blk try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":{s}}}", .{ STRUCT_VALUE, struct_json.items });
            },
            .Map => try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"value\":{{}}}}", .{MAP_VALUE}),
            .InteropInterface => |interface| try std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"iteratorId\":\"{s}\",\"interfaceName\":\"{s}\"}}", .{ INTEROP_INTERFACE_VALUE, interface.iterator_id, interface.interface_name }),
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

            return Self{ .InteropInterface = .{
                .iterator_id = id_copy,
                .interface_name = name_copy,
            } };
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
    try testing.expect(hash1 != hash3); // Different items should have different hash

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

test "StackItem decodeFromJson handles nested structures" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const json_text = "{ \"type\":\"Array\", \"value\":[{\"type\":\"Integer\",\"value\":\"42\"},{\"type\":\"Boolean\",\"value\":\"true\"},{\"type\":\"ByteString\",\"value\":\"SGVsbG8=\"}] }";

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    var decoded = try StackItem.decodeFromJson(parsed.value, allocator);
    defer decoded.deinit(allocator);

    const array_items = try decoded.getArray();
    try testing.expectEqual(@as(usize, 3), array_items.len);
    try testing.expectEqual(@as(i64, 42), try array_items[0].getInteger());

    const second_bool = try array_items[1].getBoolean();
    try testing.expect(second_bool);

    const bytes = try array_items[2].getByteArray(allocator);
    defer allocator.free(bytes);
    try testing.expectEqualStrings("Hello", bytes);
}

test "StackItem decodeFromJson handles map entries" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const json_text = "{ \"type\":\"Map\", \"value\":[{\"key\":{\"type\":\"ByteString\",\"value\":\"QQ==\"},\"value\":{\"type\":\"Integer\",\"value\":\"1\"}}] }";

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    var decoded = try StackItem.decodeFromJson(parsed.value, allocator);
    defer decoded.deinit(allocator);

    switch (decoded) {
        .Map => |*map| {
            try testing.expectEqual(@as(usize, 1), map.count());
            var it = map.iterator();
            const maybe_entry = it.next();
            try testing.expect(maybe_entry != null);
            const entry = maybe_entry.?;
            const value = try entry.value_ptr.*.getInteger();
            try testing.expectEqual(@as(i64, 1), value);
        },
        else => try testing.expect(false),
    }
}
