//! Byte manipulation utilities
//!
//! Converted from Swift Bytes extensions and utility functions.

const std = @import("std");

const errors = @import("../core/errors.zig");
const BytesExtensions = @import("bytes_extensions.zig").BytesUtils;

pub fn toHex(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
    return try BytesExtensions.toHexString(bytes, allocator);
}

pub fn fromHex(hex_str: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
    if (clean_hex.len % 2 != 0) return errors.ValidationError.InvalidParameter;

    const bytes = try allocator.alloc(u8, clean_hex.len / 2);
    _ = std.fmt.hexToBytes(bytes, clean_hex) catch {
        allocator.free(bytes);
        return errors.ValidationError.InvalidParameter;
    };
    return bytes;
}

pub fn reverse(bytes: []u8) void {
    std.mem.reverse(u8, bytes);
}

pub fn reversed(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const result = try allocator.dupe(u8, bytes);
    reverse(result);
    return result;
}
