//! Cryptographically secure random number generation (Production Implementation)

const std = @import("std");



/// Fills a buffer with cryptographically secure random bytes
pub fn fillBytes(buffer: []u8) void {
    std.crypto.random.bytes(buffer);
}

/// Generates a single random byte
pub fn randomByte() u8 {
    return std.crypto.random.int(u8);
}

/// Generates a random integer of the specified type
pub fn randomInt(comptime T: type) T {
    return std.crypto.random.int(T);
}

/// Generates a random integer in the specified range [min, max)
pub fn randomIntRange(comptime T: type, min: T, max: T) T {
    if (min >= max) return min;
    return min + (std.crypto.random.int(T) % (max - min));
}

/// Generates a random boolean value
pub fn randomBool() bool {
    return std.crypto.random.boolean();
}

/// Fills a fixed-size array with random bytes
pub fn randomArray(comptime size: usize) [size]u8 {
    var array: [size]u8 = undefined;
    fillBytes(&array);
    return array;
}