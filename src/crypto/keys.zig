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
        return try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
    }
    
    pub fn toSlice(self: Self) []const u8 {
        return &self.bytes;
    }
    
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
    
    pub fn zeroize(self: *Self) void {
        @memset(&self.bytes, 0);
        std.crypto.utils.secureZero(u8, &self.bytes);
    }
    
    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self; _ = fmt; _ = options;
        try writer.print("PrivateKey(***REDACTED***)");
    }
};

/// Public key for ECDSA operations on secp256r1 curve
pub const PublicKey = struct {
    bytes: []const u8,
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
        
        return Self{ .bytes = bytes, .compressed = compressed };
    }
    
    pub fn fromPrivateKey(private_key: PrivateKey, compressed: bool) !Self {
        var key_bytes: [constants.PRIVATE_KEY_SIZE]u8 = undefined;
        @memcpy(&key_bytes, private_key.toSlice());
        
        const public_key_bytes = try secp256r1.derivePublicKey(key_bytes, compressed, std.heap.page_allocator);
        return try Self.init(public_key_bytes, compressed);
    }
    
    pub fn isValid(self: Self) bool {
        if (self.compressed) {
            return self.bytes.len == constants.PUBLIC_KEY_SIZE_COMPRESSED and
                   (self.bytes[0] == 0x02 or self.bytes[0] == 0x03);
        } else {
            return self.bytes.len == 65 and self.bytes[0] == 0x04;
        }
    }
    
    pub fn toAddress(self: Self, version: u8) !Address {
        const script_hash = try self.toHash160();
        return Address.fromHash160WithVersion(script_hash, version);
    }
    
    pub fn toHash160(self: Self) !@import("../types/hash160.zig").Hash160 {
        var script = std.ArrayList(u8).init(std.heap.page_allocator);
        defer script.deinit();
        
        try script.append(0x0C);
        try script.append(@intCast(self.bytes.len));
        try script.appendSlice(self.bytes);
        try script.append(0x41);
        try script.append(0x9D);
        
        const ripemd160_impl = @import("ripemd160.zig");
        const hash_result = ripemd160_impl.ripemd160(script.items);
        return @import("../types/hash160.zig").Hash160.init(hash_result);
    }
    
    pub fn toSlice(self: Self) []const u8 {
        return self.bytes;
    }
    
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.bytes, other.bytes);
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
    
    pub fn isValid(self: Self) bool {
        const derived_public_key = self.private_key.getPublicKey(self.public_key.compressed) catch return false;
        return self.public_key.eql(derived_public_key);
    }
    
    pub fn zeroize(self: *Self) void {
        self.private_key.zeroize();
    }
};

// Import after declarations to avoid circular dependency
const Signature = @import("signatures.zig").Signature;