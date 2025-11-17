const std = @import("std");

/// Deeply clones a `std.json.Value` using the provided allocator.
pub fn cloneValue(value: std.json.Value, allocator: std.mem.Allocator) std.mem.Allocator.Error!std.json.Value {
    return switch (value) {
        .null => std.json.Value{ .null = {} },
        .bool => |v| std.json.Value{ .bool = v },
        .integer => |v| std.json.Value{ .integer = v },
        .float => |v| std.json.Value{ .float = v },
        .number_string => |s| std.json.Value{ .number_string = try allocator.dupe(u8, s) },
        .string => |s| std.json.Value{ .string = try allocator.dupe(u8, s) },
        .array => |arr| blk: {
            var new_arr = std.json.Array.init(allocator);
            errdefer new_arr.deinit();
            for (arr.items) |item| {
                const cloned = try cloneValue(item, allocator);
                try new_arr.append(cloned);
            }
            break :blk std.json.Value{ .array = new_arr };
        },
        .object => |obj| blk: {
            var new_map = std.json.ObjectMap.init(allocator);
            errdefer {
                var it_cleanup = new_map.iterator();
                while (it_cleanup.next()) |entry| {
                    freeValue(entry.value_ptr.*, allocator);
                }
                new_map.deinit();
            }
            var it = obj.iterator();
            while (it.next()) |entry| {
                const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
                const cloned = try cloneValue(entry.value_ptr.*, allocator);
                try new_map.put(key_copy, cloned);
            }
            break :blk std.json.Value{ .object = new_map };
        },
    };
}

/// Releases memory owned by a cloned `std.json.Value`.
pub fn freeValue(value: std.json.Value, allocator: std.mem.Allocator) void {
    switch (value) {
        .number_string => |s| allocator.free(s),
        .string => |s| allocator.free(s),
        .array => |arr| {
            var array = arr;
            for (array.items) |item| freeValue(item, allocator);
            array.deinit();
        },
        .object => |obj| {
            var map = obj;
            var it = map.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                freeValue(entry.value_ptr.*, allocator);
            }
            map.deinit();
        },
        else => {},
    }
}

/// Inserts a key-value pair into an object map, ensuring the key storage is owned.
pub fn putOwnedKey(
    object: *std.json.ObjectMap,
    allocator: std.mem.Allocator,
    key: []const u8,
    value: std.json.Value,
) !void {
    const key_copy = try allocator.dupe(u8, key);
    errdefer allocator.free(key_copy);
    try object.put(key_copy, value);
}

/// Parses JSON into a dynamically-owned `std.json.Value`.
pub fn parseOwned(allocator: std.mem.Allocator, bytes: []const u8, options: std.json.ParseOptions) !std.json.Value {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, options);
    defer parsed.deinit();
    return try cloneValue(parsed.value, allocator);
}
