//! Input Validation System
//!
//! Comprehensive input validation for all Neo Zig SDK operations
//! Ensures security and correctness of all external inputs.

const std = @import("std");
const ArrayList = std.array_list.Managed;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const Address = @import("../types/address.zig").Address;

/// Input validation utilities
pub const InputValidator = struct {
    /// Validates hex string format and length
    pub fn validateHexString(hex_str: []const u8, expected_bytes: ?usize) !void {
        // Check minimum length
        if (hex_str.len == 0) {
            return errors.ValidationError.InvalidParameter;
        }
        
        // Remove 0x prefix if present
        const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
        
        // Check even length
        if (clean_hex.len % 2 != 0) {
            return errors.ValidationError.InvalidParameter;
        }
        
        // Check expected length if specified
        if (expected_bytes) |expected| {
            if (clean_hex.len / 2 != expected) {
                return errors.ValidationError.ParameterOutOfRange;
            }
        }
        
        // Validate hex characters
        for (clean_hex) |char| {
            if (!std.ascii.isHex(char)) {
                return errors.ValidationError.InvalidParameter;
            }
        }
    }
    
    /// Validates Neo address format
    pub fn validateNeoAddress(address: []const u8, allocator: std.mem.Allocator) !void {
        if (address.len < 25 or address.len > 35) {
            return errors.ValidationError.InvalidAddress;
        }
        
        // Try to parse as address
        const parsed_address = Address.fromString(address, allocator) catch {
            return errors.ValidationError.InvalidAddress;
        };
        
        if (!parsed_address.isValid()) {
            return errors.ValidationError.InvalidAddress;
        }
    }
    
    /// Validates private key format
    pub fn validatePrivateKey(private_key_hex: []const u8) !void {
        try validateHexString(private_key_hex, constants.PRIVATE_KEY_SIZE);
        
        // Additional validation: key must not be zero or max value
        if (std.mem.eql(u8, private_key_hex, "0000000000000000000000000000000000000000000000000000000000000000")) {
            return errors.CryptoError.InvalidKey;
        }
        
        if (std.mem.eql(u8, private_key_hex, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) {
            return errors.CryptoError.InvalidKey;
        }
    }
    
    /// Validates public key format
    pub fn validatePublicKey(public_key_hex: []const u8) !void {
        const clean_hex = if (std.mem.startsWith(u8, public_key_hex, "0x")) public_key_hex[2..] else public_key_hex;
        
        // Check length (compressed or uncompressed)
        if (clean_hex.len != constants.PUBLIC_KEY_SIZE_COMPRESSED * 2 and clean_hex.len != 65 * 2) {
            return errors.CryptoError.InvalidKey;
        }
        
        try validateHexString(public_key_hex, null);
        
        // Validate prefix for compressed keys
        if (clean_hex.len == constants.PUBLIC_KEY_SIZE_COMPRESSED * 2) {
            const prefix = clean_hex[0..2];
            if (!std.mem.eql(u8, prefix, "02") and !std.mem.eql(u8, prefix, "03")) {
                return errors.CryptoError.InvalidKey;
            }
        }
        
        // Validate prefix for uncompressed keys
        if (clean_hex.len == 65 * 2) {
            const prefix = clean_hex[0..2];
            if (!std.mem.eql(u8, prefix, "04")) {
                return errors.CryptoError.InvalidKey;
            }
        }
    }
    
    /// Validates signature format
    pub fn validateSignature(signature_hex: []const u8) !void {
        try validateHexString(signature_hex, constants.SIGNATURE_SIZE);
        
        // Additional ECDSA signature validation would go here
        // Check that R and S components are valid
    }
    
    /// Validates WIF format
    pub fn validateWIF(wif: []const u8) !void {
        if (wif.len < 44 or wif.len > 53) {
            return errors.CryptoError.InvalidWIF;
        }
        
        // Check Base58 characters
        const base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (wif) |char| {
            if (std.mem.indexOf(u8, base58_alphabet, &[_]u8{char}) == null) {
                return errors.CryptoError.InvalidWIF;
            }
        }
    }
    
    /// Validates amount for token operations
    pub fn validateTokenAmount(amount: i64, decimals: u8) !void {
        if (amount < 0) {
            return errors.ValidationError.ParameterOutOfRange;
        }
        
        // Check against maximum value for given decimals
        const max_value = std.math.pow(i64, 10, decimals) * 1000000000; // Reasonable max
        if (amount > max_value) {
            return errors.ValidationError.ParameterOutOfRange;
        }
    }
    
    /// Validates contract parameter value
    pub fn validateContractParameter(param: @import("../types/contract_parameter.zig").ContractParameter) !void {
        switch (param) {
            .ByteArray => |data| {
                if (data.len > constants.MAX_TRANSACTION_SIZE) {
                    return errors.ValidationError.ParameterOutOfRange;
                }
            },
            .String => |str| {
                if (str.len > 1024 * 1024) { // 1MB max string
                    return errors.ValidationError.ParameterOutOfRange;
                }
                
                // Validate UTF-8
                if (!std.unicode.utf8ValidateSlice(str)) {
                    return errors.ValidationError.InvalidParameter;
                }
            },
            .Array => |items| {
                if (items.len > 1024) { // Max 1024 array items
                    return errors.ValidationError.ParameterOutOfRange;
                }
                
                // Recursively validate array items
                for (items) |item| {
                    try validateContractParameter(item);
                }
            },
            .PublicKey => |key| {
                // Validate public key prefix
                if (key[0] != 0x02 and key[0] != 0x03) {
                    return errors.ValidationError.InvalidParameter;
                }
            },
            else => {}, // Other types are always valid if properly constructed
        }
    }
    
    /// Validates transaction size and structure
    pub fn validateTransaction(transaction: anytype) !void {
        // Check version
        if (transaction.version != constants.CURRENT_TX_VERSION) {
            return errors.TransactionError.InvalidVersion;
        }
        
        // Check script size
        if (transaction.script.len > constants.MAX_TRANSACTION_SIZE) {
            return errors.TransactionError.TransactionTooLarge;
        }
        
        // Check attributes count
        if (transaction.attributes.len > constants.MAX_TRANSACTION_ATTRIBUTES) {
            return errors.TransactionError.InvalidTransaction;
        }
        
        // Check signers and witnesses match
        if (transaction.signers.len != transaction.witnesses.len) {
            return errors.TransactionError.InvalidWitness;
        }
        
        // Check valid until block is reasonable
        if (transaction.valid_until_block == 0) {
            return errors.TransactionError.InvalidTransaction;
        }
    }
    
    /// Validates URL format for RPC endpoints
    pub fn validateRpcEndpoint(endpoint: []const u8) !void {
        if (endpoint.len == 0) {
            return errors.ValidationError.InvalidParameter;
        }
        
        // Check protocol
        if (!std.mem.startsWith(u8, endpoint, "http://") and !std.mem.startsWith(u8, endpoint, "https://")) {
            return errors.ValidationError.InvalidParameter;
        }
        
        // Basic URL validation
        if (std.mem.indexOf(u8, endpoint, "://") == null) {
            return errors.ValidationError.InvalidParameter;
        }
        
        // Check for reasonable length
        if (endpoint.len > 1024) {
            return errors.ValidationError.ParameterOutOfRange;
        }
    }
    
    /// Validates JSON structure
    pub fn validateJsonStructure(json_str: []const u8, allocator: std.mem.Allocator) !void {
        _ = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch {
            return errors.ValidationError.InvalidFormat;
        };
        
        // Basic structure validation passed if parsing succeeded
    }
    
    /// Validates password strength
    pub fn validatePassword(password: []const u8) !void {
        if (password.len < 8) {
            return errors.ValidationError.ParameterOutOfRange;
        }
        
        if (password.len > 256) {
            return errors.ValidationError.ParameterOutOfRange;
        }
        
        // Check for basic character variety (optional - can be enhanced)
        var has_letter = false;
        var has_digit = false;
        
        for (password) |char| {
            if (std.ascii.isAlphabetic(char)) has_letter = true;
            if (std.ascii.isDigit(char)) has_digit = true;
        }
        
        if (!has_letter and !has_digit) {
            return errors.ValidationError.InvalidParameter;
        }
    }
};

/// Sanitization utilities
pub const Sanitizer = struct {
    /// Sanitizes string input for logging (removes sensitive data)
    pub fn sanitizeForLogging(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Remove potential private keys, passwords, etc.
        if (input.len == 64 or input.len == 66) { // Potential private key
            return try allocator.dupe(u8, "[PRIVATE_KEY_REDACTED]");
        }
        
        if (input.len > 40 and std.mem.indexOf(u8, input, "password") != null) {
            return try allocator.dupe(u8, "[PASSWORD_REDACTED]");
        }
        
        // Return safe copy
        return try allocator.dupe(u8, input);
    }
    
    /// Sanitizes error messages (removes sensitive information)
    pub fn sanitizeErrorMessage(error_msg: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Remove file paths and sensitive data from error messages
        var sanitized = ArrayList(u8).init(allocator);
        defer sanitized.deinit();
        
        var i: usize = 0;
        while (i < error_msg.len) {
            // Skip potential file paths
            if (i + 5 < error_msg.len and std.mem.eql(u8, error_msg[i..i+5], "/home")) {
                try sanitized.appendSlice("[PATH_REDACTED]");
                // Skip to next space or end
                while (i < error_msg.len and error_msg[i] != ' ') {
                    i += 1;
                }
            } else {
                try sanitized.append(error_msg[i]);
                i += 1;
            }
        }
        
        return try sanitized.toOwnedSlice();
    }
};

// Tests
test "Input validation utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test hex string validation
    try InputValidator.validateHexString("1234abcd", 4);
    try InputValidator.validateHexString("0x1234abcd", 4);
    
    // Test invalid hex strings
    try testing.expectError(errors.ValidationError.InvalidParameter, InputValidator.validateHexString("invalid", null));
    try testing.expectError(errors.ValidationError.InvalidParameter, InputValidator.validateHexString("123", null)); // Odd length
    try testing.expectError(errors.ValidationError.ParameterOutOfRange, InputValidator.validateHexString("1234", 1)); // Wrong length
    
    // Test private key validation
    try testing.expectError(errors.CryptoError.InvalidKey, InputValidator.validatePrivateKey("0000000000000000000000000000000000000000000000000000000000000000"));
    try testing.expectError(errors.CryptoError.InvalidKey, InputValidator.validatePrivateKey("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    
    // Test public key validation
    try InputValidator.validatePublicKey("02b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816");
    try testing.expectError(errors.CryptoError.InvalidKey, InputValidator.validatePublicKey("01invalid"));
    
    // Test WIF validation
    try testing.expectError(errors.CryptoError.InvalidWIF, InputValidator.validateWIF("invalid_wif"));
    try testing.expectError(errors.CryptoError.InvalidWIF, InputValidator.validateWIF(""));
    
    // Test password validation
    try InputValidator.validatePassword("strongPassword123");
    try testing.expectError(errors.ValidationError.ParameterOutOfRange, InputValidator.validatePassword("weak"));
    try testing.expectError(errors.ValidationError.ParameterOutOfRange, InputValidator.validatePassword("x" ** 300));
}

test "Token amount validation" {
    const testing = std.testing;
    
    // Test valid amounts
    try InputValidator.validateTokenAmount(100000000, 8); // 1 token with 8 decimals
    try InputValidator.validateTokenAmount(0, 8); // Zero amount
    
    // Test invalid amounts
    try testing.expectError(errors.ValidationError.ParameterOutOfRange, InputValidator.validateTokenAmount(-1, 8));
}

test "RPC endpoint validation" {
    const testing = std.testing;
    
    // Test valid endpoints
    try InputValidator.validateRpcEndpoint("http://localhost:20332");
    try InputValidator.validateRpcEndpoint("https://mainnet1.neo.coz.io:443");
    
    // Test invalid endpoints
    try testing.expectError(errors.ValidationError.InvalidParameter, InputValidator.validateRpcEndpoint(""));
    try testing.expectError(errors.ValidationError.InvalidParameter, InputValidator.validateRpcEndpoint("invalid_url"));
    try testing.expectError(errors.ValidationError.InvalidParameter, InputValidator.validateRpcEndpoint("ftp://invalid.com"));
}

test "JSON validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test valid JSON
    try InputValidator.validateJsonStructure("{\"key\":\"value\"}", allocator);
    try InputValidator.validateJsonStructure("[]", allocator);
    try InputValidator.validateJsonStructure("null", allocator);
    
    // Test invalid JSON
    try testing.expectError(errors.ValidationError.InvalidFormat, InputValidator.validateJsonStructure("{invalid}", allocator));
    try testing.expectError(errors.ValidationError.InvalidFormat, InputValidator.validateJsonStructure("", allocator));
}

test "Sanitization utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test private key sanitization
    const potential_private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const sanitized_key = try Sanitizer.sanitizeForLogging(potential_private_key, allocator);
    defer allocator.free(sanitized_key);
    
    try testing.expectEqualStrings("[PRIVATE_KEY_REDACTED]", sanitized_key);
    
    // Test normal string (should pass through)
    const normal_string = "normal log message";
    const sanitized_normal = try Sanitizer.sanitizeForLogging(normal_string, allocator);
    defer allocator.free(sanitized_normal);
    
    try testing.expectEqualStrings(normal_string, sanitized_normal);
    
    // Test error message sanitization
    const error_with_path = "Error in /home/user/secret/file.zig at line 123";
    const sanitized_error = try Sanitizer.sanitizeErrorMessage(error_with_path, allocator);
    defer allocator.free(sanitized_error);
    
    try testing.expect(std.mem.indexOf(u8, sanitized_error, "[PATH_REDACTED]") != null);
    try testing.expect(std.mem.indexOf(u8, sanitized_error, "/home") == null);
}
