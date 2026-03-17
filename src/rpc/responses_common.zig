const std = @import("std");

const errors = @import("../core/errors.zig");

pub fn stringifyJsonValue(value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
    return try std.json.stringifyAlloc(allocator, value, .{});
}

pub fn jsonValueToOwnedString(value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
    return switch (value) {
        .string => |str| try allocator.dupe(u8, str),
        .integer => |i| try std.fmt.allocPrint(allocator, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(allocator, "{}", .{f}),
        .bool => |b| try allocator.dupe(u8, if (b) "true" else "false"),
        .null => try allocator.dupe(u8, ""),
        else => try stringifyJsonValue(value, allocator),
    };
}

pub fn parseIntFromJson(comptime T: type, value: std.json.Value) !T {
    return switch (value) {
        .integer => |i| @as(T, @intCast(i)),
        .string => |str| std.fmt.parseInt(T, str, 10) catch errors.SerializationError.InvalidFormat,
        else => errors.SerializationError.InvalidFormat,
    };
}
