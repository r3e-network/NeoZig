//! WIF (Wallet Import Format) tests aligned to current implementation.

const std = @import("std");
const testing = std.testing;
const wif = @import("../../src/crypto/wif.zig");
const errors = @import("../../src/core/errors.zig");
const base58 = @import("../../src/utils/base58.zig");
const PrivateKey = @import("../../src/crypto/keys.zig").PrivateKey;

test "encode/decode roundtrip mainnet compressed" {
    const allocator = testing.allocator;

    const priv_hex = "9117f4bf9be717c9a90994326897f4243503accd06712162267e77f18b49c3a3";
    const priv = try PrivateKey.fromHex(priv_hex);

    const encoded = try wif.encode(priv, true, wif.NetworkType.mainnet, allocator);
    defer allocator.free(encoded);

    var decoded = try wif.decode(encoded, allocator);
    defer decoded.deinit();

    try testing.expect(decoded.compressed);
    try testing.expectEqual(@intFromEnum(wif.NetworkType.mainnet), @intFromEnum(decoded.network));
    try testing.expect(std.mem.eql(u8, priv.toSlice(), decoded.private_key.toSlice()));
}

test "invalid lengths rejected" {
    const allocator = testing.allocator;
    try testing.expectError(errors.CryptoError.InvalidWIF, wif.decode("short", allocator));
    try testing.expectError(errors.CryptoError.InvalidWIF, wif.decode("L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13AExtra", allocator));
}

test "checksum corruption detected" {
    const allocator = testing.allocator;
    const priv = PrivateKey.generate();
    const encoded = try wif.encode(priv, true, wif.NetworkType.mainnet, allocator);
    defer allocator.free(encoded);

    var bytes = try base58.decode(encoded, allocator);
    defer allocator.free(bytes);
    bytes[bytes.len - 1] ^= 0xFF;

    const corrupted = try base58.encode(bytes, allocator);
    defer allocator.free(corrupted);

    try testing.expectError(errors.CryptoError.InvalidWIF, wif.decode(corrupted, allocator));
}

test "network versions parsed" {
    const allocator = testing.allocator;
    const priv = PrivateKey.generate();

    const mainnet = try wif.encode(priv, true, wif.NetworkType.mainnet, allocator);
    defer allocator.free(mainnet);
    var decoded_main = try wif.decode(mainnet, allocator);
    defer decoded_main.deinit();
    try testing.expectEqual(wif.NetworkType.mainnet, decoded_main.network);

    const testnet = try wif.encode(priv, true, wif.NetworkType.testnet, allocator);
    defer allocator.free(testnet);
    var decoded_test = try wif.decode(testnet, allocator);
    defer decoded_test.deinit();
    try testing.expectEqual(wif.NetworkType.testnet, decoded_test.network);
}
