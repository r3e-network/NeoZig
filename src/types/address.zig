//! Neo address implementation
//!
//! Complete conversion from Swift address handling with Base58Check encoding.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("hash160.zig").Hash160;

pub const Address = struct {
    script_hash: Hash160,
    version: u8,
    
    const Self = @This();
    
    pub fn init(script_hash: Hash160, version: u8) Self {
        return Self{ .script_hash = script_hash, .version = version };
    }
    
    pub fn fromHash160(script_hash: Hash160) Self {
        return Self{ .script_hash = script_hash, .version = constants.AddressConstants.ADDRESS_VERSION };
    }
    
    pub fn fromHash160WithVersion(script_hash: Hash160, version: u8) Self {
        return Self{ .script_hash = script_hash, .version = version };
    }
    
    pub fn fromString(address_str: []const u8, allocator: std.mem.Allocator) !Self {
        const base58 = @import("../utils/base58.zig");
        var decoded = try base58.decodeCheck(address_str, allocator);
        defer allocator.free(decoded);
        
        if (decoded.len != 21) return errors.ValidationError.InvalidAddress;
        
        const version = decoded[0];
        const hash_bytes = decoded[1..21];
        const script_hash = try Hash160.initWithBytes(hash_bytes);
        
        return Self{ .script_hash = script_hash, .version = version };
    }
    
    pub fn toHash160(self: Self) Hash160 {
        return self.script_hash;
    }
    
    pub fn toString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var payload: [21]u8 = undefined;
        payload[0] = self.version;
        @memcpy(payload[1..21], &self.script_hash.toArray());
        
        const base58 = @import("../utils/base58.zig");
        return try base58.encodeCheck(&payload, allocator);
    }
    
    pub fn isValid(self: Self) bool {
        return self.version == constants.AddressConstants.ADDRESS_VERSION or
               self.version == constants.AddressConstants.MULTISIG_ADDRESS_VERSION;
    }
    
    pub fn isStandard(self: Self) bool {
        return self.version == constants.AddressConstants.ADDRESS_VERSION;
    }
    
    pub fn isMultiSig(self: Self) bool {
        return self.version == constants.AddressConstants.MULTISIG_ADDRESS_VERSION;
    }
    
    pub fn eql(self: Self, other: Self) bool {
        return self.version == other.version and self.script_hash.eql(other.script_hash);
    }
    
    pub fn validateString(address_str: []const u8, allocator: std.mem.Allocator) bool {
        const address = fromString(address_str, allocator) catch return false;
        return address.isValid();
    }
};