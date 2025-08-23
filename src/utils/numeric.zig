//! Numeric utilities
//!
//! Converted from Swift numeric extensions and operations.

const std = @import("std");

pub fn toLittleEndianBytes(comptime T: type, value: T) [@sizeOf(T)]u8 {
    return std.mem.toBytes(std.mem.nativeToLittle(T, value));
}

pub fn toBigEndianBytes(comptime T: type, value: T) [@sizeOf(T)]u8 {
    return std.mem.toBytes(std.mem.nativeToBig(T, value));
}