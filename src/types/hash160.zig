//! Hash160 implementation for Neo blockchain
//!
//! Complete conversion from NeoSwift/Sources/NeoSwift/types/Hash160.swift
//! Maintains 100% API compatibility with Swift implementation.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

/// Hash160 represents a 160-bit (20-byte) hash (complete Swift conversion)
pub const Hash160 = struct {
    /// Raw hash bytes stored in big-endian order (matches Swift)
    bytes: [constants.HASH160_SIZE]u8,
    
    const Self = @This();
    
    /// Zero-value hash (equivalent to Swift Hash160.ZERO)
    pub const ZERO: Hash160 = Hash160{ .bytes = std.mem.zeroes([constants.HASH160_SIZE]u8) };
    
    /// Creates a new Hash160 with zero bytes (equivalent to Swift init())
    pub fn init() Self {
        return ZERO;
    }
    
    /// Creates Hash160 from byte array (equivalent to Swift init(_ hash: Bytes))
    pub fn initWithBytes(hash_bytes: []const u8) !Self {
        if (hash_bytes.len != constants.HASH160_SIZE) {
            return errors.throwIllegalArgument("Hash must be 20 bytes long");
        }
        
        var bytes: [constants.HASH160_SIZE]u8 = undefined;
        @memcpy(&bytes, hash_bytes);
        return Self{ .bytes = bytes };
    }
    
    /// Creates Hash160 from hex string (equivalent to Swift init(_ hash: String))
    pub fn initWithString(hash_str: []const u8) !Self {
        // Remove "0x" prefix if present
        const clean_hex = if (std.mem.startsWith(u8, hash_str, "0x"))
            hash_str[2..]
        else
            hash_str;
            
        if (clean_hex.len != constants.HASH160_SIZE * 2) {
            return errors.throwIllegalArgument("Hash string must be 40 hex characters");
        }
        
        // Validate hex characters
        for (clean_hex) |char| {
            if (!std.ascii.isHex(char)) {
                return errors.throwIllegalArgument("String argument is not hexadecimal");
            }
        }
        
        var bytes: [constants.HASH160_SIZE]u8 = undefined;
        _ = std.fmt.hexToBytes(&bytes, clean_hex) catch {
            return errors.throwIllegalArgument("Invalid hexadecimal string");
        };
        
        return Self{ .bytes = bytes };
    }
    
    /// Gets hex string representation (equivalent to Swift .string property)
    pub fn string(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
    }
    
    /// Returns hash as byte array in big-endian order (equivalent to Swift toArray())
    pub fn toArray(self: Self) [constants.HASH160_SIZE]u8 {
        return self.bytes;
    }
    
    /// Returns hash as byte array in little-endian order (equivalent to Swift toLittleEndianArray())
    pub fn toLittleEndianArray(self: Self) [constants.HASH160_SIZE]u8 {
        var reversed = self.bytes;
        std.mem.reverse(u8, &reversed);
        return reversed;
    }
    
    /// Converts to Neo address (equivalent to Swift toAddress())
    pub fn toAddress(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try scripthashToAddress(self.bytes, allocator);
    }
    
    /// Creates Hash160 from address (equivalent to Swift fromAddress(_ address: String))
    pub fn fromAddress(address: []const u8, allocator: std.mem.Allocator) !Self {
        const script_hash = try addressToScriptHash(address, allocator);
        defer allocator.free(script_hash);
        return try initWithBytes(script_hash);
    }
    
    /// Creates Hash160 from script bytes (equivalent to Swift fromScript(_ script: Bytes))
    pub fn fromScript(script: []const u8) !Self {
        const hash_result = try sha256ThenRipemd160(script);
        var reversed_hash = hash_result;
        std.mem.reverse(u8, &reversed_hash);
        return Self{ .bytes = reversed_hash };
    }
    
    /// Creates Hash160 from script hex string (equivalent to Swift fromScript(_ script: String))
    pub fn fromScriptHex(script_hex: []const u8, allocator: std.mem.Allocator) !Self {
        const script_bytes = try hexToBytes(script_hex, allocator);
        defer allocator.free(script_bytes);
        return try fromScript(script_bytes);
    }
    
    /// Creates Hash160 from public key (equivalent to Swift fromPublicKey)
    pub fn fromPublicKey(encoded_public_key: []const u8, allocator: std.mem.Allocator) !Self {
        const verification_script = try buildVerificationScript(encoded_public_key, allocator);
        defer allocator.free(verification_script);
        return try fromScript(verification_script);
    }
    
    /// Creates Hash160 from multiple public keys (equivalent to Swift fromPublicKeys)
    pub fn fromPublicKeys(
        pub_keys: []const []const u8, 
        signing_threshold: u32,
        allocator: std.mem.Allocator
    ) !Self {
        const verification_script = try buildMultiSigVerificationScript(pub_keys, signing_threshold, allocator);
        defer allocator.free(verification_script);
        return try fromScript(verification_script);
    }
    
    /// Serialization size (equivalent to Swift .size property)
    pub fn size() usize {
        return constants.HASH160_SIZE;
    }
    
    /// Serializes to binary writer (equivalent to Swift serialize(_ writer: BinaryWriter))
    pub fn serialize(self: Self, buffer: anytype) !void {
        const little_endian = self.toLittleEndianArray();
        try buffer.appendSlice(&little_endian);
    }
    
    /// Deserializes from binary reader (equivalent to Swift deserialize(_ reader: BinaryReader))
    pub fn deserialize(stream: anytype) !Self {
        var reader = @import("../serialization/binary_reader.zig").BinaryReader.init(stream);
        var bytes: [constants.HASH160_SIZE]u8 = undefined;
        try reader.readBytes(&bytes);
        
        // Convert from little-endian to big-endian
        std.mem.reverse(u8, &bytes);
        return Self{ .bytes = bytes };
    }
    
    /// Comparison for sorting (equivalent to Swift Comparable)
    pub fn compare(self: Self, other: Self) std.math.Order {
        // Convert to big integers for comparison (matches Swift BInt comparison)
        return std.mem.order(u8, &self.bytes, &other.bytes);
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
    
    /// Hash function for HashMap usage
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&self.bytes);
        return hasher.final();
    }
};

/// Utility functions (converted from Swift extensions)

/// SHA256 then RIPEMD160 hash (matches Swift .sha256ThenRipemd160())
fn sha256ThenRipemd160(data: []const u8) ![constants.HASH160_SIZE]u8 {
    // First apply SHA256
    var sha_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    sha_hasher.update(data);
    var sha_result: [32]u8 = undefined;
    sha_hasher.final(&sha_result);
    
    // Then apply RIPEMD160 (using our production implementation)
    const ripemd160_impl = @import("../crypto/ripemd160.zig");
    return ripemd160_impl.ripemd160(&sha_result);
}

/// Convert script hash to address (matches Swift .scripthashToAddress)
fn scripthashToAddress(script_hash: [constants.HASH160_SIZE]u8, allocator: std.mem.Allocator) ![]u8 {
    // Create payload: version + script_hash
    var payload: [21]u8 = undefined;
    payload[0] = constants.AddressConstants.ADDRESS_VERSION;
    @memcpy(payload[1..21], &script_hash);
    
    // Encode with Base58Check
    const base58 = @import("../utils/base58.zig");
    return try base58.encodeCheck(&payload, allocator);
}

/// Convert address to script hash (matches Swift .addressToScriptHash())
fn addressToScriptHash(address: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const base58 = @import("../utils/base58.zig");
    const decoded = try base58.decodeCheck(address, allocator);
    defer allocator.free(decoded);
    
    if (decoded.len != 21) {
        return errors.throwIllegalArgument("Invalid address format");
    }
    
    // Extract script hash (skip version byte)
    return try allocator.dupe(u8, decoded[1..21]);
}

/// Convert hex string to bytes
fn hexToBytes(hex_str: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
    
    if (clean_hex.len % 2 != 0) {
        return errors.throwIllegalArgument("Hex string must have even length");
    }
    
    var bytes = try allocator.alloc(u8, clean_hex.len / 2);
    _ = std.fmt.hexToBytes(bytes, clean_hex) catch {
        return errors.throwIllegalArgument("Invalid hexadecimal string");
    };
    
    return bytes;
}

/// Build verification script for single public key (matches Swift ScriptBuilder.buildVerificationScript)
fn buildVerificationScript(encoded_public_key: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var script = std.ArrayList(u8).init(allocator);
    defer script.deinit();
    
    // PUSHDATA public_key
    try script.append(0x0C); // PUSHDATA1
    try script.append(@intCast(encoded_public_key.len));
    try script.appendSlice(encoded_public_key);
    
    // SYSCALL CheckSig
    try script.append(0x41); // SYSCALL
    const syscall_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, constants.InteropServices.SYSTEM_CRYPTO_CHECK_SIG));
    try script.appendSlice(&syscall_bytes);
    
    return try script.toOwnedSlice();
}

/// Build multi-signature verification script (matches Swift ScriptBuilder.buildVerificationScript)
fn buildMultiSigVerificationScript(
    pub_keys: []const []const u8,
    signing_threshold: u32,
    allocator: std.mem.Allocator
) ![]u8 {
    if (pub_keys.len > constants.MAX_PUBLIC_KEYS_PER_MULTISIG_ACCOUNT) {
        return errors.throwIllegalArgument("Too many public keys for multi-sig");
    }
    
    if (signing_threshold == 0 or signing_threshold > pub_keys.len) {
        return errors.throwIllegalArgument("Invalid signing threshold");
    }
    
    var script = std.ArrayList(u8).init(allocator);
    defer script.deinit();
    
    // Push signing threshold
    if (signing_threshold <= 16) {
        try script.append(0x10 + @as(u8, @intCast(signing_threshold - 1))); // PUSH1-PUSH16
    } else {
        return errors.throwIllegalArgument("Signing threshold too large");
    }
    
    // Push public keys
    for (pub_keys) |pub_key| {
        try script.append(0x0C); // PUSHDATA1
        try script.append(@intCast(pub_key.len));
        try script.appendSlice(pub_key);
    }
    
    // Push number of public keys
    if (pub_keys.len <= 16) {
        try script.append(0x10 + @as(u8, @intCast(pub_keys.len - 1))); // PUSH1-PUSH16
    } else {
        return errors.throwIllegalArgument("Too many public keys");
    }
    
    // SYSCALL CheckMultisig
    try script.append(0x41); // SYSCALL
    const syscall_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, constants.InteropServices.SYSTEM_CRYPTO_CHECK_MULTISIG));
    try script.appendSlice(&syscall_bytes);
    
    return try script.toOwnedSlice();
}

// Tests (converted from Swift unit tests)
test "Hash160 creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test zero hash (matches Swift Hash160.ZERO)
    const zero_hash = Hash160.init();
    try testing.expect(zero_hash.eql(Hash160.ZERO));
    
    // Test hex string creation
    const hex_hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const hex_str = try hex_hash.string(allocator);
    defer allocator.free(hex_str);
    try testing.expectEqualStrings("1234567890abcdef1234567890abcdef12345678", hex_str);
    
    // Test byte array conversion
    const array = hex_hash.toArray();
    try testing.expectEqual(@as(usize, 20), array.len);
    
    // Test little-endian conversion
    const little_endian = hex_hash.toLittleEndianArray();
    try testing.expect(!std.mem.eql(u8, &array, &little_endian)); // Should be different
}

test "Hash160 address conversion" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test address conversion (matches Swift functionality)
    const hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    
    const address = try hash.toAddress(allocator);
    defer allocator.free(address);
    try testing.expect(address.len > 0);
    
    // Test round-trip conversion
    const recovered_hash = try Hash160.fromAddress(address, allocator);
    try testing.expect(hash.eql(recovered_hash));
}

test "Hash160 script hash creation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test script hash creation (matches Swift fromScript functionality)
    const script = [_]u8{ 0x0C, 0x21, 0x02, 0x03 }; // Simple script
    const script_hash = try Hash160.fromScript(&script);
    try testing.expect(!script_hash.eql(Hash160.ZERO));
    
    // Test hex script
    const script_hex = "0c21020304";
    const script_hash_hex = try Hash160.fromScriptHex(script_hex, allocator);
    try testing.expect(script_hash.eql(script_hash_hex));
}

test "Hash160 comparison and ordering" {
    const testing = std.testing;
    
    const hash1 = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const hash2 = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const hash3 = try Hash160.initWithString("abcdef1234567890abcdef1234567890abcdef12");
    
    // Test equality
    try testing.expect(hash1.eql(hash2));
    try testing.expect(!hash1.eql(hash3));
    
    // Test comparison (matches Swift Comparable)
    try testing.expect(hash1.compare(hash2) == .eq);
    try testing.expect(hash1.compare(hash3) != .eq);
}

test "Hash160 serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test serialization (matches Swift NeoSerializable)
    const hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try hash.serialize(&buffer);
    try testing.expectEqual(@as(usize, 20), buffer.items.len);
    
    // Test deserialization
    var stream = std.io.fixedBufferStream(buffer.items);
    const deserialized = try Hash160.deserialize(&stream);
    try testing.expect(hash.eql(deserialized));
}