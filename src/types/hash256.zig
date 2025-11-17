//! Hash256 implementation for Neo blockchain
//!
//! Complete conversion from NeoSwift Hash256 type with full API compatibility.

const std = @import("std");


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

/// Hash256 represents a 256-bit (32-byte) hash
pub const Hash256 = struct {
    bytes: [constants.HASH256_SIZE]u8,
    
    const Self = @This();
    
    pub const ZERO: Hash256 = Hash256{ .bytes = std.mem.zeroes([constants.HASH256_SIZE]u8) };
    
    pub fn init() Self {
        return ZERO;
    }
    
    pub fn initWithBytes(hash_bytes: []const u8) !Self {
        if (hash_bytes.len != constants.HASH256_SIZE) {
            return errors.throwIllegalArgument("Hash must be 32 bytes long");
        }
        var bytes: [constants.HASH256_SIZE]u8 = undefined;
        @memcpy(&bytes, hash_bytes);
        return Self{ .bytes = bytes };
    }
    
    pub fn initWithString(hash_str: []const u8) !Self {
        const clean_hex = if (std.mem.startsWith(u8, hash_str, "0x")) hash_str[2..] else hash_str;
        if (clean_hex.len != constants.HASH256_SIZE * 2) {
            return errors.throwIllegalArgument("Hash string must be 64 hex characters");
        }
        
        var bytes: [constants.HASH256_SIZE]u8 = undefined;
        _ = std.fmt.hexToBytes(&bytes, clean_hex) catch {
            return errors.throwIllegalArgument("Invalid hexadecimal string");
        };
        return Self{ .bytes = bytes };
    }
    
    pub fn string(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hex = std.fmt.bytesToHex(self.bytes, .lower);
        return try allocator.dupe(u8, &hex);
    }
    
    pub fn toArray(self: Self) [constants.HASH256_SIZE]u8 {
        return self.bytes;
    }
    
    pub fn toLittleEndianArray(self: Self) [constants.HASH256_SIZE]u8 {
        var reversed = self.bytes;
        std.mem.reverse(u8, &reversed);
        return reversed;
    }
    
    pub fn sha256(data: []const u8) Self {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(data);
        var hash_result: [constants.HASH256_SIZE]u8 = undefined;
        hasher.final(&hash_result);
        return Self{ .bytes = hash_result };
    }
    
    pub fn doubleSha256(data: []const u8) Self {
        const first_hash = sha256(data);
        return sha256(&first_hash.bytes);
    }
    
    pub fn toSlice(self: Self) []const u8 {
        return &self.bytes;
    }
    
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
    
    pub fn isZero(self: Self) bool {
        return std.mem.eql(u8, &self.bytes, &ZERO.bytes);
    }
    
    pub fn compare(self: Self, other: Self) std.math.Order {
        return std.mem.order(u8, &self.bytes, &other.bytes);
    }
    
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&self.bytes);
        return hasher.final();
    }
    
    pub fn serialize(self: Self, writer: anytype) !void {
        const little_endian = self.toLittleEndianArray();
        try writer.writeBytes(&little_endian);
    }
    
    pub fn deserialize(reader: anytype) !Self {
        var bytes: [constants.HASH256_SIZE]u8 = undefined;
        try reader.readBytes(&bytes);
        std.mem.reverse(u8, &bytes);
        return Self{ .bytes = bytes };
    }
};
