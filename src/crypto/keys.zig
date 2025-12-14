//! Cryptographic key management for Neo blockchain (Production Implementation)

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;
const Address = @import("../types/address.zig").Address;
const random = @import("random.zig");
const secp256r1 = @import("secp256r1.zig");

/// Private key for ECDSA operations on secp256r1 curve
pub const PrivateKey = struct {
    bytes: [constants.PRIVATE_KEY_SIZE]u8,

    const Self = @This();

    pub fn init(bytes: [constants.PRIVATE_KEY_SIZE]u8) !Self {
        const key = Self{ .bytes = bytes };
        if (!key.isValid()) return errors.CryptoError.InvalidKey;
        return key;
    }

    pub fn fromSlice(slice: []const u8) !Self {
        if (slice.len != constants.PRIVATE_KEY_SIZE) return errors.CryptoError.InvalidKey;
        var bytes: [constants.PRIVATE_KEY_SIZE]u8 = undefined;
        @memcpy(&bytes, slice);
        return try Self.init(bytes);
    }

    pub fn fromHex(hex_str: []const u8) !Self {
        const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
        if (clean_hex.len != constants.PRIVATE_KEY_SIZE * 2) return errors.CryptoError.InvalidKey;

        var bytes: [constants.PRIVATE_KEY_SIZE]u8 = undefined;
        _ = std.fmt.hexToBytes(&bytes, clean_hex) catch return errors.CryptoError.InvalidKey;
        return try Self.init(bytes);
    }

    pub fn generate() Self {
        while (true) {
            var bytes: [constants.PRIVATE_KEY_SIZE]u8 = undefined;
            random.fillBytes(&bytes);

            const scalar = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &bytes));
            if (scalar > 0 and scalar < secp256r1.Secp256r1.N) {
                return Self{ .bytes = bytes };
            }
        }
    }

    pub fn isValid(self: Self) bool {
        const scalar = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &self.bytes));
        return scalar > 0 and scalar < secp256r1.Secp256r1.N;
    }

    pub fn getPublicKey(self: Self, compressed: bool) !PublicKey {
        return try PublicKey.fromPrivateKey(self, compressed);
    }

    pub fn sign(self: Self, hash: Hash256) !Signature {
        const signatures = @import("signatures.zig");
        return try signatures.Signature.create(hash, self);
    }

    pub fn toHex(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hex = std.fmt.bytesToHex(self.bytes, .lower);
        return try allocator.dupe(u8, &hex);
    }

    pub fn toSlice(self: *const Self) []const u8 {
        return self.bytes[0..];
    }

    pub fn eql(self: Self, other: Self) bool {
        return std.crypto.timing_safe.eql(@TypeOf(self.bytes), self.bytes, other.bytes);
    }

    pub fn zeroize(self: *Self) void {
        std.crypto.secureZero(u8, &self.bytes);
    }

    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        try writer.print("PrivateKey(***REDACTED***)", .{});
    }
};

/// Public key for ECDSA operations on secp256r1 curve
pub const PublicKey = struct {
    data: [65]u8,
    len: u8,
    compressed: bool,

    const Self = @This();

    pub fn init(bytes: []const u8, compressed: bool) !Self {
        const expected_size = if (compressed) constants.PUBLIC_KEY_SIZE_COMPRESSED else 65;
        if (bytes.len != expected_size) return errors.CryptoError.InvalidKey;

        if (compressed) {
            if (bytes[0] != 0x02 and bytes[0] != 0x03) return errors.CryptoError.InvalidKey;
        } else {
            if (bytes[0] != 0x04) return errors.CryptoError.InvalidKey;
        }

        var result: Self = .{
            .data = std.mem.zeroes([65]u8),
            .len = @intCast(bytes.len),
            .compressed = compressed,
        };
        @memcpy(result.data[0..bytes.len], bytes);
        return result;
    }

    /// Initializes a public key from its encoded bytes, inferring compression from the size.
    pub fn initFromBytes(bytes: []const u8) !Self {
        const compressed = switch (bytes.len) {
            constants.PUBLIC_KEY_SIZE_COMPRESSED => true,
            65 => false,
            else => return errors.CryptoError.InvalidKey,
        };
        return try Self.init(bytes, compressed);
    }

    pub fn fromPrivateKey(private_key: PrivateKey, compressed: bool) !Self {
        var key_bytes: [constants.PRIVATE_KEY_SIZE]u8 = undefined;
        @memcpy(&key_bytes, private_key.toSlice());
        defer std.crypto.secureZero(u8, &key_bytes);

        // Avoid using a global allocator for a small, fixed-size key derivation.
        var scratch: [65]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        const public_key_bytes = try secp256r1.derivePublicKey(key_bytes, compressed, fba.allocator());
        return try Self.init(public_key_bytes, compressed);
    }

    pub fn isValid(self: Self) bool {
        if (self.compressed) {
            return self.len == constants.PUBLIC_KEY_SIZE_COMPRESSED and
                (self.data[0] == 0x02 or self.data[0] == 0x03);
        } else {
            return self.len == 65 and self.data[0] == 0x04;
        }
    }

    pub fn toAddress(self: Self, version: u8) !Address {
        const script_hash = try self.toHash160();
        return Address.fromHash160WithVersion(script_hash, version);
    }

    pub fn toHash160(self: Self) !@import("../types/hash160.zig").Hash160 {
        // Build the verification script without heap allocation.
        var script_buf: [72]u8 = undefined;
        var offset: usize = 0;

        script_buf[offset] = 0x0C;
        offset += 1;
        script_buf[offset] = @intCast(self.len);
        offset += 1;

        const pk_len: usize = @intCast(self.len);
        @memcpy(script_buf[offset .. offset + pk_len], self.toSlice());
        offset += pk_len;

        script_buf[offset] = 0x41;
        offset += 1;

        const syscall_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, constants.InteropServices.SYSTEM_CRYPTO_CHECK_SIG));
        @memcpy(script_buf[offset .. offset + syscall_bytes.len], &syscall_bytes);
        offset += syscall_bytes.len;

        // Neo N3 script hash = RIPEMD160(SHA256(script)), returned as a Hash160.
        return try @import("../types/hash160.zig").Hash160.fromScript(script_buf[0..offset]);
    }

    pub fn toSlice(self: *const Self) []const u8 {
        const slice_len: usize = @intCast(self.len);
        return self.data[0..slice_len];
    }

    pub fn toHex(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(self.toSlice())});
    }

    pub fn toCompressed(self: Self) !Self {
        if (self.compressed) return self;
        const point = try secp256r1.pointFromUncompressed(self.toSlice());
        var compressed_buf: [constants.PUBLIC_KEY_SIZE_COMPRESSED]u8 = undefined;
        compressed_buf[0] = if ((point.y & 1) == 0) 0x02 else 0x03;
        const x_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, point.x));
        @memcpy(compressed_buf[1..], &x_bytes);
        return try Self.init(&compressed_buf, true);
    }

    pub fn toUncompressed(self: Self) !Self {
        if (!self.compressed) return self;
        const point = try secp256r1.pointFromCompressed(self.toSlice());
        var uncompressed_buf: [65]u8 = undefined;
        uncompressed_buf[0] = 0x04;
        const x_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, point.x));
        const y_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, point.y));
        @memcpy(uncompressed_buf[1..33], &x_bytes);
        @memcpy(uncompressed_buf[33..], &y_bytes);
        return try Self.init(&uncompressed_buf, false);
    }

    pub fn fromHex(hex_str: []const u8) !Self {
        const clean = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
        if (clean.len != constants.PUBLIC_KEY_SIZE_COMPRESSED * 2 and clean.len != 65 * 2) {
            return errors.CryptoError.InvalidKey;
        }
        var buf: [65]u8 = undefined;
        const bytes = std.fmt.hexToBytes(&buf, clean) catch return errors.CryptoError.InvalidKey;
        const is_compressed = bytes.len == constants.PUBLIC_KEY_SIZE_COMPRESSED;
        return try Self.init(bytes, is_compressed);
    }

    pub fn eql(self: Self, other: Self) bool {
        return self.compressed == other.compressed and std.mem.eql(u8, self.toSlice(), other.toSlice());
    }
};

/// Key pair containing both private and public keys
pub const KeyPair = struct {
    private_key: PrivateKey,
    public_key: PublicKey,

    const Self = @This();

    pub fn init(private_key: PrivateKey, public_key: PublicKey) Self {
        return Self{ .private_key = private_key, .public_key = public_key };
    }

    pub fn generate(compressed: bool) !Self {
        const private_key = PrivateKey.generate();
        const public_key = try private_key.getPublicKey(compressed);
        return Self.init(private_key, public_key);
    }

    pub fn fromPrivateKey(private_key: PrivateKey, compressed: bool) !Self {
        const public_key = try private_key.getPublicKey(compressed);
        return Self.init(private_key, public_key);
    }

    pub fn isValid(self: Self) bool {
        const derived_public_key = self.private_key.getPublicKey(self.public_key.compressed) catch return false;
        return self.public_key.eql(derived_public_key);
    }

    pub fn zeroize(self: *Self) void {
        self.private_key.zeroize();
        // Public key bytes are not sensitive; no-op beyond this point.
    }

    /// Convenience to match patterns that expect a deinit hook.
    pub fn deinit(self: *Self) void {
        self.zeroize();
    }
};

// Import after declarations to avoid circular dependency
const Signature = @import("signatures.zig").Signature;
