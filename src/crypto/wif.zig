//! WIF (Wallet Import Format) encoding and decoding (Production Implementation)

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const PrivateKey = @import("keys.zig").PrivateKey;
const secure = @import("../utils/secure.zig");

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

    /// Zeroizes sensitive key material.
    pub fn deinit(self: *WIFDecodeResult) void {
        self.private_key.zeroize();
    }
};

pub fn encode(private_key: PrivateKey, compressed: bool, network: NetworkType, allocator: std.mem.Allocator) ![]u8 {
    const base58 = @import("../utils/base58.zig");
    var data: [1 + constants.PRIVATE_KEY_SIZE + 1]u8 = undefined;
    const data_len: usize = 1 + constants.PRIVATE_KEY_SIZE + (if (compressed) @as(usize, 1) else @as(usize, 0));

    data[0] = network.getWifVersion();
    @memcpy(data[1 .. 1 + constants.PRIVATE_KEY_SIZE], private_key.toSlice());
    if (compressed) data[1 + constants.PRIVATE_KEY_SIZE] = 0x01;
    defer secure.secureZeroBytes(data[0..data_len]);

    return try base58.encodeCheck(data[0..data_len], allocator);
}

pub fn decode(wif_string: []const u8, allocator: std.mem.Allocator) !WIFDecodeResult {
    const base58 = @import("../utils/base58.zig");
    var decoded = base58.decodeCheck(wif_string, allocator) catch |err| switch (err) {
        errors.ValidationError.InvalidParameter,
        errors.ValidationError.InvalidChecksum,
        => return errors.CryptoError.InvalidWIF,
        else => return err,
    };
    defer secure.secureZeroFree(allocator, decoded);

    if (decoded.len != 1 + constants.PRIVATE_KEY_SIZE and decoded.len != 1 + constants.PRIVATE_KEY_SIZE + 1) {
        return errors.CryptoError.InvalidWIF;
    }

    const compressed = decoded.len == 1 + constants.PRIVATE_KEY_SIZE + 1;
    const version = decoded[0];

    const network = switch (version) {
        constants.AddressConstants.WIF_VERSION => NetworkType.mainnet,
        constants.AddressConstants.WIF_VERSION_TESTNET => NetworkType.testnet,
        else => return errors.CryptoError.InvalidWIF,
    };

    const key_start: usize = 1;
    const key_end = key_start + constants.PRIVATE_KEY_SIZE;
    const key_bytes = decoded[key_start..key_end];

    if (compressed) {
        const compressed_flag = decoded[key_end];
        if (compressed_flag != 0x01) return errors.CryptoError.InvalidWIF;
    }

    var private_key_bytes: [constants.PRIVATE_KEY_SIZE]u8 = undefined;
    @memcpy(&private_key_bytes, key_bytes);
    const private_key = try PrivateKey.init(private_key_bytes);

    return WIFDecodeResult{
        .private_key = private_key,
        .compressed = compressed,
        .network = network,
    };
}

pub fn validate(wif_string: []const u8, allocator: std.mem.Allocator) bool {
    var decoded = decode(wif_string, allocator) catch return false;
    decoded.deinit();
    return true;
}
