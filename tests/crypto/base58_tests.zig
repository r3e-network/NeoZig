//! Base58/Base58Check tests for the production codec in utils/base58.zig

const std = @import("std");
const testing = std.testing;
const base58 = @import("../../src/utils/base58.zig");
const errors = @import("../../src/core/errors.zig");

test "encode/decode roundtrip" {
    const allocator = testing.allocator;
    const payload = [_]u8{ 0x00, 0x01, 0x02, 0x03 };

    const encoded = try base58.encode(&payload, allocator);
    defer allocator.free(encoded);

    const decoded = try base58.decode(encoded, allocator);
    defer allocator.free(decoded);

    try testing.expectEqualSlices(u8, &payload, decoded);
}

test "leading zeros preserved" {
    const allocator = testing.allocator;
    const payload = [_]u8{ 0x00, 0x00, 0x01, 0x02 };

    const encoded = try base58.encode(&payload, allocator);
    defer allocator.free(encoded);

    const decoded = try base58.decode(encoded, allocator);
    defer allocator.free(decoded);

    try testing.expectEqualSlices(u8, &payload, decoded);
    try testing.expect(std.mem.startsWith(u8, encoded, "11"));
}

test "invalid character rejected" {
    const allocator = testing.allocator;
    try testing.expectError(errors.ValidationError.InvalidParameter, base58.decode("0OIl", allocator));
}

test "base58check roundtrip" {
    const allocator = testing.allocator;
    var data = [_]u8{ 0x35, 0x93, 0xad, 0x15, 0x72, 0xa4, 0xb3, 0x5c, 0x4b, 0x92, 0x54, 0x83, 0xce, 0x17, 0x01, 0xb7, 0x87, 0x42, 0xdc, 0x46, 0x0f };

    const encoded = try base58.encodeCheck(&data, allocator);
    defer allocator.free(encoded);

    const decoded = try base58.decodeCheck(encoded, allocator);
    defer allocator.free(decoded);

    try testing.expectEqualSlices(u8, &data, decoded);
}

test "base58check checksum validation" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const encoded = try base58.encodeCheck(&data, allocator);
    defer allocator.free(encoded);

    var corrupted = try allocator.dupe(u8, encoded);
    defer allocator.free(corrupted);
    corrupted[corrupted.len - 1] ^= 0xFF;

    try testing.expectError(errors.ValidationError.InvalidChecksum, base58.decodeCheck(corrupted, allocator));
}
