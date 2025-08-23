//! ECDSA signature operations for Neo blockchain (Production Implementation)

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;

/// ECDSA signature using secp256r1 curve
pub const Signature = struct {
    bytes: [constants.SIGNATURE_SIZE]u8,
    
    const Self = @This();
    
    pub fn init(bytes: [constants.SIGNATURE_SIZE]u8) Self {
        return Self{ .bytes = bytes };
    }
    
    pub fn fromSlice(slice: []const u8) !Self {
        if (slice.len != constants.SIGNATURE_SIZE) return errors.CryptoError.InvalidSignature;
        var bytes: [constants.SIGNATURE_SIZE]u8 = undefined;
        @memcpy(&bytes, slice);
        return Self.init(bytes);
    }
    
    pub fn fromHex(hex_str: []const u8) !Self {
        const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
        if (clean_hex.len != constants.SIGNATURE_SIZE * 2) return errors.CryptoError.InvalidSignature;
        
        var bytes: [constants.SIGNATURE_SIZE]u8 = undefined;
        _ = std.fmt.hexToBytes(&bytes, clean_hex) catch return errors.CryptoError.InvalidSignature;
        return Self.init(bytes);
    }
    
    pub fn create(hash: Hash256, private_key: anytype) !Self {
        const secp256r1 = @import("secp256r1.zig");
        
        var hash_bytes: [32]u8 = undefined;
        @memcpy(&hash_bytes, hash.toSlice());
        
        var key_bytes: [32]u8 = undefined;
        @memcpy(&key_bytes, private_key.toSlice());
        
        const signature_bytes = try secp256r1.sign(hash_bytes, key_bytes);
        return Self.init(signature_bytes);
    }
    
    pub fn verify(self: Self, hash: Hash256, public_key: anytype) !bool {
        const secp256r1 = @import("secp256r1.zig");
        
        var hash_bytes: [32]u8 = undefined;
        @memcpy(&hash_bytes, hash.toSlice());
        
        return try secp256r1.verify(hash_bytes, self.bytes, public_key.toSlice());
    }
    
    pub fn getR(self: Self) [32]u8 {
        var r: [32]u8 = undefined;
        @memcpy(&r, self.bytes[0..32]);
        return r;
    }
    
    pub fn getS(self: Self) [32]u8 {
        var s: [32]u8 = undefined;
        @memcpy(&s, self.bytes[32..64]);
        return s;
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
    
    pub fn isValid(self: Self) bool {
        const zero_bytes = std.mem.zeroes([32]u8);
        const r_bytes = self.bytes[0..32];
        const s_bytes = self.bytes[32..64];
        
        return !std.mem.eql(u8, r_bytes, &zero_bytes) and !std.mem.eql(u8, s_bytes, &zero_bytes);
    }
}