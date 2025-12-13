//! Neo Zig SDK Examples
//!
//! Small, self-contained examples that compile and run offline.

const std = @import("std");
const neo = @import("neo-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.log.info("Neo Zig SDK Examples", .{});
    std.log.info("====================", .{});

    try demonstrateHashes(allocator);
    try demonstrateKeysAndAddresses(allocator);
    try demonstrateWifRoundtrip(allocator);

    std.log.info("All examples completed successfully.", .{});
}

fn demonstrateHashes(allocator: std.mem.Allocator) !void {
    const message = "Neo Zig SDK hash example";

    const sha = neo.Hash256.sha256(message);
    const sha_hex = try sha.string(allocator);
    defer allocator.free(sha_hex);
    std.log.info("SHA256(\"{s}\") = {s}...", .{ message, sha_hex[0..16] });

    const double_sha = neo.crypto.BytesHashUtils.hash256(message);
    const double_sha_hex = try double_sha.string(allocator);
    defer allocator.free(double_sha_hex);
    std.log.info("Double SHA256 = {s}...", .{double_sha_hex[0..16]});

    const hash160 = try neo.crypto.hash160(message);
    const hash160_hex = try hash160.string(allocator);
    defer allocator.free(hash160_hex);
    std.log.info("Hash160 = {s}...", .{hash160_hex[0..16]});
}

fn demonstrateKeysAndAddresses(allocator: std.mem.Allocator) !void {
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var mutable = key_pair;
        mutable.zeroize();
    }

    const address = try key_pair.public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    std.log.info("Generated address: {s}", .{address_str});

    const parsed = try neo.Address.fromString(address_str, allocator);
    try std.testing.expect(parsed.eql(address));
}

fn demonstrateWifRoundtrip(allocator: std.mem.Allocator) !void {
    const key_pair = try neo.crypto.generateKeyPair(true);
    defer {
        var mutable = key_pair;
        mutable.zeroize();
    }

    const wif = try neo.crypto.encodeWIF(key_pair.private_key, true, .mainnet, allocator);
    defer allocator.free(wif);
    std.log.info("WIF: {s}", .{wif});

    var decoded = try neo.crypto.decodeWIF(wif, allocator);
    defer decoded.deinit();

    try std.testing.expect(decoded.private_key.eql(key_pair.private_key));
    try std.testing.expect(decoded.compressed);
}
