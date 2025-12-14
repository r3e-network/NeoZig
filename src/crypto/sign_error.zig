//! Sign Error implementation
//!
//! Complete conversion from NeoSwift SignError.swift
//! Provides specialized error handling for signature operations.

const std = @import("std");
const builtin = @import("builtin");

const errors = @import("../core/errors.zig");

const log = std.log.scoped(.neo_crypto);

/// Sign-specific errors (converted from Swift SignError)
pub const SignError = union(enum) {
    HeaderOutOfRange: u8,
    RecoverFailed: void,

    const Self = @This();

    /// Creates header out of range error (equivalent to Swift .headerOutOfRange)
    pub fn headerOutOfRange(header_byte: u8) Self {
        return Self{ .HeaderOutOfRange = header_byte };
    }

    /// Creates recovery failed error (equivalent to Swift .recoverFailed)
    pub fn recoverFailed() Self {
        return Self{ .RecoverFailed = {} };
    }

    /// Gets error description (equivalent to Swift .errorDescription)
    pub fn getErrorDescription(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .HeaderOutOfRange => |header| {
                return try std.fmt.allocPrint(allocator, "Header byte out of range: {d}", .{header});
            },
            .RecoverFailed => {
                return try allocator.dupe(u8, "Could not recover public key from signature");
            },
        };
    }

    /// Throws appropriate Zig error (utility method)
    pub fn throwError(self: Self, allocator: std.mem.Allocator) !void {
        const description = try self.getErrorDescription(allocator);
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Sign Error: {s}", .{description});
        }

        return switch (self) {
            .HeaderOutOfRange => errors.CryptoError.InvalidSignature,
            .RecoverFailed => errors.CryptoError.SignatureVerificationFailed,
        };
    }

    /// Logs error without throwing
    pub fn logError(self: Self, allocator: std.mem.Allocator) void {
        const description = self.getErrorDescription(allocator) catch "Unknown sign error";
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Sign Error: {s}", .{description});
        }
    }

    /// Creates from Zig error (utility conversion)
    pub fn fromZigError(zig_error: anyerror, allocator: std.mem.Allocator) !Self {
        return switch (zig_error) {
            error.InvalidSignature => Self.headerOutOfRange(0xFF),
            error.SignatureVerificationFailed => Self.recoverFailed(),
            error.ECDSAOperationFailed => Self.recoverFailed(),
            else => Self.recoverFailed(),
        };
    }

    /// Validates signature header byte
    pub fn validateHeaderByte(header_byte: u8) SignError!void {
        // Valid recovery IDs are 0, 1, 2, 3 (plus 27 = 27-30)
        if (header_byte < 27 or header_byte > 30) {
            return SignError.headerOutOfRange(header_byte);
        }
    }

    /// Validates signature recovery possibility
    pub fn validateRecoveryPossible(signature_data: anytype) SignError!void {
        // Basic validation that signature can be used for recovery
        if (signature_data.r == 0 or signature_data.s == 0) {
            return SignError.recoverFailed();
        }

        // Validate recovery ID range
        try validateHeaderByte(signature_data.v);
    }

    /// Checks if error is recoverable
    pub fn isRecoverable(self: Self) bool {
        return switch (self) {
            .HeaderOutOfRange => true, // Can retry with different header
            .RecoverFailed => false, // Cannot recover from this
        };
    }

    /// Gets error severity
    pub fn getSeverity(self: Self) ErrorSeverity {
        return switch (self) {
            .HeaderOutOfRange => .Warning, // Can be corrected
            .RecoverFailed => .Error, // Serious problem
        };
    }
};

/// Error severity levels
pub const ErrorSeverity = enum {
    Warning,
    Error,
    Critical,

    pub fn toString(self: ErrorSeverity) []const u8 {
        return switch (self) {
            .Warning => "WARNING",
            .Error => "ERROR",
            .Critical => "CRITICAL",
        };
    }
};

/// Sign error utilities
pub const SignErrorUtils = struct {
    /// Validates signature components for signing operations
    pub fn validateSignatureComponents(r: u256, s: u256) SignError!void {
        const secp256r1 = @import("secp256r1.zig");

        if (r == 0 or r >= secp256r1.Secp256r1.N) {
            return SignError.recoverFailed();
        }

        if (s == 0 or s >= secp256r1.Secp256r1.N) {
            return SignError.recoverFailed();
        }
    }

    /// Validates recovery parameters
    pub fn validateRecoveryParameters(recovery_id: u8, message_hash: []const u8) SignError!void {
        try SignError.validateHeaderByte(recovery_id + 27);

        if (message_hash.len != 32) {
            return SignError.recoverFailed();
        }
    }

    /// Creates error from failed recovery attempt
    pub fn createRecoveryFailedError(attempted_recovery_id: u8, allocator: std.mem.Allocator) !SignError {
        _ = allocator;

        if (attempted_recovery_id > 3) {
            return SignError.headerOutOfRange(attempted_recovery_id + 27);
        } else {
            return SignError.recoverFailed();
        }
    }

    /// Handles signature operation errors
    pub fn handleSignatureError(
        operation: []const u8,
        zig_error: anyerror,
        allocator: std.mem.Allocator,
    ) !void {
        const sign_error = try SignError.fromZigError(zig_error, allocator);

        if (!builtin.is_test) {
            log.debug("Signature operation '{s}' failed", .{operation});
        }
        try sign_error.throwError(allocator);
    }
};

// Tests (converted from Swift SignError tests)
test "SignError creation and descriptions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test header out of range error (equivalent to Swift SignError tests)
    const header_error = SignError.headerOutOfRange(31);
    const header_description = try header_error.getErrorDescription(allocator);
    defer allocator.free(header_description);

    try testing.expect(std.mem.indexOf(u8, header_description, "31") != null);
    try testing.expect(std.mem.indexOf(u8, header_description, "out of range") != null);
    try testing.expect(header_error.isRecoverable());
    try testing.expectEqual(ErrorSeverity.Warning, header_error.getSeverity());

    // Test recovery failed error
    const recover_error = SignError.recoverFailed();
    const recover_description = try recover_error.getErrorDescription(allocator);
    defer allocator.free(recover_description);

    try testing.expect(std.mem.indexOf(u8, recover_description, "recover public key") != null);
    try testing.expect(!recover_error.isRecoverable());
    try testing.expectEqual(ErrorSeverity.Error, recover_error.getSeverity());
}

test "SignError validation functions" {
    const testing = std.testing;

    // Test header byte validation (equivalent to Swift validation tests)
    try SignError.validateHeaderByte(27); // Valid
    try SignError.validateHeaderByte(28); // Valid
    try SignError.validateHeaderByte(29); // Valid
    try SignError.validateHeaderByte(30); // Valid

    try testing.expectError(SignError.HeaderOutOfRange, SignError.validateHeaderByte(26)); // Too low
    try testing.expectError(SignError.HeaderOutOfRange, SignError.validateHeaderByte(31)); // Too high
    try testing.expectError(SignError.HeaderOutOfRange, SignError.validateHeaderByte(0)); // Way too low
    try testing.expectError(SignError.HeaderOutOfRange, SignError.validateHeaderByte(255)); // Way too high
}

test "SignErrorUtils utility functions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const secp256r1 = @import("secp256r1.zig");

    // Test signature component validation
    try SignErrorUtils.validateSignatureComponents(1, 1); // Valid

    try testing.expectError(SignError.RecoverFailed, SignErrorUtils.validateSignatureComponents(0, 1) // Invalid R
    );

    try testing.expectError(SignError.RecoverFailed, SignErrorUtils.validateSignatureComponents(1, 0) // Invalid S
    );

    try testing.expectError(SignError.RecoverFailed, SignErrorUtils.validateSignatureComponents(secp256r1.Secp256r1.N, 1) // R too large
    );

    // Test recovery parameter validation
    const valid_hash = [_]u8{0xAB} ** 32;
    try SignErrorUtils.validateRecoveryParameters(1, &valid_hash);

    try testing.expectError(SignError.HeaderOutOfRange, SignErrorUtils.validateRecoveryParameters(5, &valid_hash) // Invalid recovery ID
    );

    const invalid_hash = [_]u8{0xCD} ** 16; // Wrong length
    try testing.expectError(SignError.RecoverFailed, SignErrorUtils.validateRecoveryParameters(1, &invalid_hash));
}

test "SignError conversion and handling" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test error creation from failed recovery
    var recovery_error = try SignErrorUtils.createRecoveryFailedError(2, allocator);
    try testing.expect(recovery_error == .RecoverFailed);

    var header_error = try SignErrorUtils.createRecoveryFailedError(5, allocator);
    try testing.expect(header_error == .HeaderOutOfRange);

    // Test error handling for signature operations
    try testing.expectError(errors.CryptoError.SignatureVerificationFailed, SignErrorUtils.handleSignatureError("test_sign", error.RecoverFailed, allocator));
}
