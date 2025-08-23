//! WIF (Wallet Import Format) encoding and decoding (Production Implementation)

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const PrivateKey = @import("keys.zig").PrivateKey;

pub const NetworkType = enum {
    mainnet,
    testnet,
    
    pub fn getWifVersion(self: NetworkType) u8 {
        return switch (self) {
            .mainnet => constants.AddressConstants.WIF_VERSION,
            .testnet => constants.AddressConstants.WIF_VERSION_TESTNET,
        };
    }
};

pub const WIFDecodeResult = struct {
    private_key: PrivateKey,
    compressed: bool,
    network: NetworkType,
};

pub fn encode(private_key: PrivateKey, compressed: bool, network: NetworkType, allocator: std.mem.Allocator) ![]u8 {
    const payload_size: usize = 1 + constants.KeySizes.PRIVATE_KEY_SIZE + (if (compressed) @as(usize, 1) else @as(usize, 0)) + 4;
    
    var payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);
    
    var pos: usize = 0;
    
    payload[pos] = network.getWifVersion();
    pos += 1;
    
    @memcpy(payload[pos..pos + constants.KeySizes.PRIVATE_KEY_SIZE], private_key.toSlice());
    pos += constants.KeySizes.PRIVATE_KEY_SIZE;
    
    if (compressed) {
        payload[pos] = 0x01;
        pos += 1;
    }
    
    const data_to_hash = payload[0..pos];
    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(data_to_hash);
    var hash1: [32]u8 = undefined;
    hasher1.final(&hash1);
    
    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&hash1);
    var hash2: [32]u8 = undefined;
    hasher2.final(&hash2);
    
    @memcpy(payload[pos..pos + 4], hash2[0..4]);
    
    const base58 = @import("../utils/base58.zig");
    return try base58.encode(payload, allocator);
}

pub fn decode(wif_string: []const u8, allocator: std.mem.Allocator) !WIFDecodeResult {
    const base58 = @import("../utils/base58.zig");
    var decoded = try base58.decode(wif_string, allocator);
    defer allocator.free(decoded);
    
    if (decoded.len < 37) return errors.CryptoError.InvalidWIF;
    
    const compressed = decoded.len == 38;
    const expected_len: usize = if (compressed) 38 else 37;
    
    if (decoded.len != expected_len) return errors.CryptoError.InvalidWIF;
    
    const version = decoded[0];
    const checksum_start = decoded.len - 4;
    const data_end = checksum_start;
    const provided_checksum = decoded[checksum_start..];
    
    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(decoded[0..data_end]);
    var hash1: [32]u8 = undefined;
    hasher1.final(&hash1);
    
    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&hash1);
    var hash2: [32]u8 = undefined;
    hasher2.final(&hash2);
    
    const calculated_checksum = hash2[0..4];
    if (!std.mem.eql(u8, provided_checksum, calculated_checksum)) {
        return errors.CryptoError.InvalidWIF;
    }
    
    const network = switch (version) {
        constants.AddressConstants.WIF_VERSION => NetworkType.mainnet,
        constants.AddressConstants.WIF_VERSION_TESTNET => NetworkType.testnet,
        else => return errors.CryptoError.InvalidWIF,
    };
    
    const key_start: usize = 1;
    const key_end = key_start + constants.KeySizes.PRIVATE_KEY_SIZE;
    const key_bytes = decoded[key_start..key_end];
    
    if (compressed) {
        const compressed_flag = decoded[key_end];
        if (compressed_flag != 0x01) return errors.CryptoError.InvalidWIF;
    }
    
    var private_key_bytes: [constants.KeySizes.PRIVATE_KEY_SIZE]u8 = undefined;
    @memcpy(&private_key_bytes, key_bytes);
    const private_key = try PrivateKey.init(private_key_bytes);
    
    return WIFDecodeResult{
        .private_key = private_key,
        .compressed = compressed,
        .network = network,
    };
}

pub fn validate(wif_string: []const u8, allocator: std.mem.Allocator) bool {
    const result = decode(wif_string, allocator);
    return result != error.InvalidWIF and result != error.OutOfMemory;
}