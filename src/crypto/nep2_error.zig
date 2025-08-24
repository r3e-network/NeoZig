//! NEP-2 Error implementation
//!
//! Complete conversion from NeoSwift NEP2Error.swift
//! Provides specialized error handling for NEP-2 operations.

const std = @import("std");
const errors = @import("../core/errors.zig");

/// NEP-2 specific errors (converted from Swift NEP2Error)
pub const NEP2Error = union(enum) {
    InvalidPassphrase: []const u8,
    InvalidFormat: []const u8,
    
    const Self = @This();
    
    /// Creates invalid passphrase error (equivalent to Swift .invalidPassphrase)
    pub fn invalidPassphrase(message: []const u8) Self {
        return Self{ .InvalidPassphrase = message };
    }
    
    /// Creates invalid format error (equivalent to Swift .invalidFormat)
    pub fn invalidFormat(message: []const u8) Self {
        return Self{ .InvalidFormat = message };
    }
    
    /// Gets error description (equivalent to Swift .errorDescription)
    pub fn getErrorDescription(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .InvalidPassphrase => |message| try allocator.dupe(u8, message),
            .InvalidFormat => |message| try allocator.dupe(u8, message),
        };
    }
    
    /// Throws appropriate Zig error (utility method)
    pub fn throwError(self: Self, allocator: std.mem.Allocator) !void {
        const description = try self.getErrorDescription(allocator);
        defer allocator.free(description);
        
        std.log.err("NEP-2 Error: {s}", .{description});
        
        return switch (self) {
            .InvalidPassphrase => errors.WalletError.InvalidPassword,
            .InvalidFormat => errors.CryptoError.InvalidKey,
        };
    }
    
    /// Logs error without throwing
    pub fn logError(self: Self, allocator: std.mem.Allocator) void {
        const description = self.getErrorDescription(allocator) catch "Unknown NEP-2 error";
        defer allocator.free(description);
        
        std.log.err("NEP-2 Error: {s}", .{description});
    }
    
    /// Creates from Zig error (utility conversion)
    pub fn fromZigError(zig_error: anyerror, allocator: std.mem.Allocator) !Self {
        return switch (zig_error) {
            error.InvalidPassword => Self.invalidPassphrase(try allocator.dupe(u8, "Invalid password for NEP-2 decryption")),
            error.InvalidKey => Self.invalidFormat(try allocator.dupe(u8, "Invalid NEP-2 key format")),
            error.DecryptionFailed => Self.invalidPassphrase(try allocator.dupe(u8, "NEP-2 decryption failed - check password")),
            error.EncryptionFailed => Self.invalidFormat(try allocator.dupe(u8, "NEP-2 encryption failed - invalid key data")),
            else => Self.invalidFormat(try allocator.dupe(u8, "NEP-2 operation failed")),
        };
    }
    
    /// Validates NEP-2 operation result
    pub fn validateNEP2Result(result: anyerror!anytype, allocator: std.mem.Allocator) !void {
        result catch |err| {
            const nep2_error = try Self.fromZigError(err, allocator);
            try nep2_error.throwError(allocator);
        };
    }
    
    /// Checks if error indicates invalid passphrase
    pub fn isInvalidPassphrase(self: Self) bool {
        return switch (self) {
            .InvalidPassphrase => true,
            .InvalidFormat => false,
        };
    }
    
    /// Checks if error indicates invalid format
    pub fn isInvalidFormat(self: Self) bool {
        return switch (self) {
            .InvalidPassphrase => false,
            .InvalidFormat => true,
        };
    }
};

/// NEP-2 error utilities
pub const NEP2ErrorUtils = struct {
    /// Common NEP-2 error messages
    pub const INVALID_PASSPHRASE_MSG = "The provided passphrase is invalid for this NEP-2 encrypted key";
    pub const INVALID_FORMAT_MSG = "The provided string is not a valid NEP-2 encrypted key format";
    pub const ENCRYPTION_FAILED_MSG = "Failed to encrypt private key with NEP-2 format";
    pub const DECRYPTION_FAILED_MSG = "Failed to decrypt NEP-2 encrypted key";
    pub const INVALID_CHECKSUM_MSG = "NEP-2 key checksum validation failed";
    pub const INVALID_PREFIX_MSG = "NEP-2 key does not have valid prefix bytes";
    
    /// Creates common error instances
    pub fn createInvalidPassphraseError(allocator: std.mem.Allocator) !NEP2Error {
        return NEP2Error.invalidPassphrase(try allocator.dupe(u8, INVALID_PASSPHRASE_MSG));
    }
    
    pub fn createInvalidFormatError(allocator: std.mem.Allocator) !NEP2Error {
        return NEP2Error.invalidFormat(try allocator.dupe(u8, INVALID_FORMAT_MSG));
    }
    
    pub fn createEncryptionFailedError(allocator: std.mem.Allocator) !NEP2Error {
        return NEP2Error.invalidFormat(try allocator.dupe(u8, ENCRYPTION_FAILED_MSG));
    }
    
    pub fn createDecryptionFailedError(allocator: std.mem.Allocator) !NEP2Error {
        return NEP2Error.invalidPassphrase(try allocator.dupe(u8, DECRYPTION_FAILED_MSG));
    }
    
    /// Validates NEP-2 key format
    pub fn validateNEP2Format(nep2_key: []const u8) NEP2Error!void {
        if (nep2_key.len != 58) { // Standard NEP-2 length
            return NEP2Error.invalidFormat("NEP-2 key must be 58 characters long");
        }
        
        // Check Base58 characters
        const base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (nep2_key) |char| {
            if (std.mem.indexOf(u8, base58_alphabet, &[_]u8{char}) == null) {
                return NEP2Error.invalidFormat("NEP-2 key contains invalid Base58 characters");
            }
        }
    }
    
    /// Validates passphrase strength
    pub fn validatePassphrase(passphrase: []const u8) NEP2Error!void {
        if (passphrase.len == 0) {
            return NEP2Error.invalidPassphrase("Passphrase cannot be empty for NEP-2 encryption");
        }
        
        if (passphrase.len > 256) {
            return NEP2Error.invalidPassphrase("Passphrase too long for NEP-2 encryption");
        }
    }
};

// Tests (converted from Swift NEP2Error tests)
test "NEP2Error creation and descriptions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test invalid passphrase error (equivalent to Swift NEP2Error tests)
    const passphrase_error = NEP2Error.invalidPassphrase("Test passphrase error");
    const passphrase_description = try passphrase_error.getErrorDescription(allocator);
    defer allocator.free(passphrase_description);
    
    try testing.expectEqualStrings("Test passphrase error", passphrase_description);
    try testing.expect(passphrase_error.isInvalidPassphrase());
    try testing.expect(!passphrase_error.isInvalidFormat());
    
    // Test invalid format error
    const format_error = NEP2Error.invalidFormat("Test format error");
    const format_description = try format_error.getErrorDescription(allocator);
    defer allocator.free(format_description);
    
    try testing.expectEqualStrings("Test format error", format_description);
    try testing.expect(!format_error.isInvalidPassphrase());
    try testing.expect(format_error.isInvalidFormat());
}

test "NEP2ErrorUtils validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test NEP-2 format validation (equivalent to Swift validation tests)
    try testing.expectError(
        NEP2Error.InvalidFormat,
        NEP2ErrorUtils.validateNEP2Format("too_short")
    );
    
    try testing.expectError(
        NEP2Error.InvalidFormat,
        NEP2ErrorUtils.validateNEP2Format("invalid_base58_chars_@#$%^&*()")
    );
    
    // Test passphrase validation
    try testing.expectError(
        NEP2Error.InvalidPassphrase,
        NEP2ErrorUtils.validatePassphrase("")
    );
    
    try testing.expectError(
        NEP2Error.InvalidPassphrase,
        NEP2ErrorUtils.validatePassphrase("x" ** 300)
    );
    
    // Test valid passphrase
    try NEP2ErrorUtils.validatePassphrase("valid_passphrase_123");
}

test "NEP2ErrorUtils common errors" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test common error creation (equivalent to Swift common error tests)
    var invalid_passphrase = try NEP2ErrorUtils.createInvalidPassphraseError(allocator);
    const passphrase_desc = try invalid_passphrase.getErrorDescription(allocator);
    defer allocator.free(passphrase_desc);
    
    try testing.expect(std.mem.indexOf(u8, passphrase_desc, "passphrase is invalid") != null);
    
    var invalid_format = try NEP2ErrorUtils.createInvalidFormatError(allocator);
    const format_desc = try invalid_format.getErrorDescription(allocator);
    defer allocator.free(format_desc);
    
    try testing.expect(std.mem.indexOf(u8, format_desc, "not a valid NEP-2") != null);
    
    var encryption_failed = try NEP2ErrorUtils.createEncryptionFailedError(allocator);
    const encryption_desc = try encryption_failed.getErrorDescription(allocator);
    defer allocator.free(encryption_desc);
    
    try testing.expect(std.mem.indexOf(u8, encryption_desc, "encrypt") != null);
    
    var decryption_failed = try NEP2ErrorUtils.createDecryptionFailedError(allocator);
    const decryption_desc = try decryption_failed.getErrorDescription(allocator);
    defer allocator.free(decryption_desc);
    
    try testing.expect(std.mem.indexOf(u8, decryption_desc, "decrypt") != null);
}