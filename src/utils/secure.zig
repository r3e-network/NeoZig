//! Helpers for securely clearing sensitive byte buffers.

const std = @import("std");

pub fn secureZeroBytes(buf: []u8) void {
    if (buf.len == 0) return;
    const volatile_ptr: [*]volatile u8 = @volatileCast(buf.ptr);
    std.crypto.secureZero(u8, volatile_ptr[0..buf.len]);
}

/// Securely clears a writable slice that is typed as `[]const u8`.
/// Caller must ensure the backing storage is mutable (e.g. heap allocated).
pub fn secureZeroConstBytes(buf: []const u8) void {
    secureZeroBytes(@constCast(buf));
}

pub fn secureZeroFree(allocator: std.mem.Allocator, buf: []u8) void {
    secureZeroBytes(buf);
    allocator.free(buf);
}
