//! Transaction Error implementation
//!
//! Complete conversion from NeoSwift TransactionError.swift
//! Provides specialized error handling for transaction operations.

const std = @import("std");
const builtin = @import("builtin");

const errors = @import("../core/errors.zig");
const constants = @import("../core/constants.zig");

const log = std.log.scoped(.neo_transaction);

/// Transaction-specific errors (converted from Swift TransactionError)
pub const TransactionError = union(enum) {
    ScriptFormat: []const u8,
    SignerConfiguration: []const u8,
    TransactionConfiguration: []const u8,

    const Self = @This();

    /// Creates script format error (equivalent to Swift .scriptFormat)
    pub fn scriptFormat(message: []const u8) Self {
        return Self{ .ScriptFormat = message };
    }

    /// Creates signer configuration error (equivalent to Swift .signerConfiguration)
    pub fn signerConfiguration(message: []const u8) Self {
        return Self{ .SignerConfiguration = message };
    }

    /// Creates transaction configuration error (equivalent to Swift .transactionConfiguration)
    pub fn transactionConfiguration(message: []const u8) Self {
        return Self{ .TransactionConfiguration = message };
    }

    /// Gets error description (equivalent to Swift .errorDescription)
    pub fn getErrorDescription(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .ScriptFormat => |message| try allocator.dupe(u8, message),
            .SignerConfiguration => |message| try allocator.dupe(u8, message),
            .TransactionConfiguration => |message| try allocator.dupe(u8, message),
        };
    }

    /// Throws appropriate Zig error (utility method)
    pub fn throwError(self: Self, allocator: std.mem.Allocator) !void {
        const description = try self.getErrorDescription(allocator);
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Transaction Error: {s}", .{description});
        }

        return switch (self) {
            .ScriptFormat => errors.TransactionError.InvalidScript,
            .SignerConfiguration => errors.TransactionError.InvalidSigner,
            .TransactionConfiguration => errors.TransactionError.InvalidTransaction,
        };
    }

    /// Logs error without throwing
    pub fn logError(self: Self, allocator: std.mem.Allocator) void {
        const description = self.getErrorDescription(allocator) catch "Unknown transaction error";
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Transaction Error: {s}", .{description});
        }
    }

    /// Creates from Zig error (utility conversion)
    pub fn fromZigError(zig_error: anyerror, context: []const u8, allocator: std.mem.Allocator) !Self {
        const message = try std.fmt.allocPrint(allocator, "{s}: {}", .{ context, zig_error });

        return switch (zig_error) {
            error.InvalidScript => Self.scriptFormat(message),
            error.InvalidSigner => Self.signerConfiguration(message),
            error.InvalidTransaction => Self.transactionConfiguration(message),
            error.TransactionTooLarge => Self.transactionConfiguration(message),
            error.InvalidWitness => Self.signerConfiguration(message),
            else => Self.transactionConfiguration(message),
        };
    }

    /// Validates transaction component
    pub fn validateTransactionComponent(component: TransactionComponent, data: []const u8) TransactionError!void {
        switch (component) {
            .Script => {
                if (data.len == 0) {
                    return TransactionError.scriptFormat("Transaction script cannot be empty");
                }
                if (data.len > constants.MAX_TRANSACTION_SIZE) {
                    return TransactionError.scriptFormat("Transaction script too large");
                }
            },
            .Signer => {
                if (data.len != 20) { // Script hash length
                    return TransactionError.signerConfiguration("Invalid signer script hash length");
                }
            },
            .Witness => {
                if (data.len > constants.MAX_TRANSACTION_SIZE) {
                    return TransactionError.signerConfiguration("Witness too large");
                }
            },
            .Attribute => {
                if (data.len > 1024) { // Reasonable attribute limit
                    return TransactionError.transactionConfiguration("Transaction attribute too large");
                }
            },
        }
    }

    /// Gets error severity
    pub fn getSeverity(self: Self) ErrorSeverity {
        return switch (self) {
            .ScriptFormat => .Error,
            .SignerConfiguration => .Error,
            .TransactionConfiguration => .Warning,
        };
    }

    /// Checks if error is recoverable
    pub fn isRecoverable(self: Self) bool {
        return switch (self) {
            .ScriptFormat => false, // Script errors are usually fatal
            .SignerConfiguration => true, // Signer config can be fixed
            .TransactionConfiguration => true, // Transaction config can be adjusted
        };
    }
};

/// Transaction component types for validation
pub const TransactionComponent = enum {
    Script,
    Signer,
    Witness,
    Attribute,

    pub fn toString(self: TransactionComponent) []const u8 {
        return switch (self) {
            .Script => "Script",
            .Signer => "Signer",
            .Witness => "Witness",
            .Attribute => "Attribute",
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

/// Transaction error utilities
pub const TransactionErrorUtils = struct {
    /// Common error messages
    pub const EMPTY_SCRIPT_MSG = "Transaction script cannot be empty";
    pub const SCRIPT_TOO_LARGE_MSG = "Transaction script exceeds maximum size";
    pub const INVALID_SIGNER_MSG = "Invalid signer configuration";
    pub const INSUFFICIENT_SIGNERS_MSG = "Insufficient signers for transaction";
    pub const WITNESS_MISMATCH_MSG = "Number of witnesses does not match signers";
    pub const INVALID_ATTRIBUTES_MSG = "Invalid transaction attributes";

    /// Creates common error instances
    pub fn createEmptyScriptError(allocator: std.mem.Allocator) !TransactionError {
        return TransactionError.scriptFormat(try allocator.dupe(u8, EMPTY_SCRIPT_MSG));
    }

    pub fn createScriptTooLargeError(allocator: std.mem.Allocator) !TransactionError {
        return TransactionError.scriptFormat(try allocator.dupe(u8, SCRIPT_TOO_LARGE_MSG));
    }

    pub fn createInvalidSignerError(allocator: std.mem.Allocator) !TransactionError {
        return TransactionError.signerConfiguration(try allocator.dupe(u8, INVALID_SIGNER_MSG));
    }

    pub fn createInsufficientSignersError(allocator: std.mem.Allocator) !TransactionError {
        return TransactionError.signerConfiguration(try allocator.dupe(u8, INSUFFICIENT_SIGNERS_MSG));
    }

    pub fn createWitnessMismatchError(allocator: std.mem.Allocator) !TransactionError {
        return TransactionError.signerConfiguration(try allocator.dupe(u8, WITNESS_MISMATCH_MSG));
    }

    pub fn createInvalidAttributesError(allocator: std.mem.Allocator) !TransactionError {
        return TransactionError.transactionConfiguration(try allocator.dupe(u8, INVALID_ATTRIBUTES_MSG));
    }

    /// Handles transaction validation errors
    pub fn handleValidationError(
        component: TransactionComponent,
        zig_error: anyerror,
        allocator: std.mem.Allocator,
    ) !void {
        const context = try std.fmt.allocPrint(allocator, "Transaction {s} validation failed", .{component.toString()});
        defer allocator.free(context);

        const tx_error = try TransactionError.fromZigError(zig_error, context, allocator);
        try tx_error.throwError(allocator);
    }

    /// Validates complete transaction structure
    pub fn validateTransactionStructure(
        script_len: usize,
        signer_count: usize,
        witness_count: usize,
        attribute_count: usize,
    ) TransactionError!void {
        // Validate script
        try Self.validateTransactionComponent(.Script, &[_]u8{0} ** script_len);

        // Validate signer/witness match
        if (signer_count != witness_count) {
            return TransactionError.signerConfiguration("Signer count must match witness count");
        }

        // Validate attribute count
        if (attribute_count > constants.MAX_TRANSACTION_ATTRIBUTES) {
            return TransactionError.transactionConfiguration("Too many transaction attributes");
        }

        // Validate minimum requirements
        if (signer_count == 0) {
            return TransactionError.signerConfiguration("Transaction must have at least one signer");
        }
    }
};

// Tests (converted from Swift TransactionError tests)
test "TransactionError creation and descriptions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test script format error (equivalent to Swift TransactionError tests)
    const script_error = TransactionError.scriptFormat("Test script error");
    const script_description = try script_error.getErrorDescription(allocator);
    defer allocator.free(script_description);

    try testing.expectEqualStrings("Test script error", script_description);
    try testing.expectEqual(ErrorSeverity.Error, script_error.getSeverity());
    try testing.expect(!script_error.isRecoverable());

    // Test signer configuration error
    const signer_error = TransactionError.signerConfiguration("Test signer error");
    const signer_description = try signer_error.getErrorDescription(allocator);
    defer allocator.free(signer_description);

    try testing.expectEqualStrings("Test signer error", signer_description);
    try testing.expectEqual(ErrorSeverity.Error, signer_error.getSeverity());
    try testing.expect(signer_error.isRecoverable());

    // Test transaction configuration error
    const tx_error = TransactionError.transactionConfiguration("Test transaction error");
    const tx_description = try tx_error.getErrorDescription(allocator);
    defer allocator.free(tx_description);

    try testing.expectEqualStrings("Test transaction error", tx_description);
    try testing.expectEqual(ErrorSeverity.Warning, tx_error.getSeverity());
    try testing.expect(tx_error.isRecoverable());
}

test "TransactionErrorUtils validation" {
    const testing = std.testing;

    // Test transaction component validation
    const valid_script = [_]u8{0x40}; // RET
    try TransactionError.validateTransactionComponent(.Script, &valid_script);

    const empty_script = [_]u8{};
    try testing.expectError(TransactionError.ScriptFormat, TransactionError.validateTransactionComponent(.Script, &empty_script));

    const large_script = [_]u8{0} ** (constants.MAX_TRANSACTION_SIZE + 1);
    try testing.expectError(TransactionError.ScriptFormat, TransactionError.validateTransactionComponent(.Script, &large_script));

    // Test signer validation
    const valid_signer = [_]u8{0} ** 20; // Valid script hash length
    try TransactionError.validateTransactionComponent(.Signer, &valid_signer);

    const invalid_signer = [_]u8{0} ** 19; // Invalid length
    try testing.expectError(TransactionError.SignerConfiguration, TransactionError.validateTransactionComponent(.Signer, &invalid_signer));
}

test "TransactionErrorUtils structure validation" {
    const testing = std.testing;

    // Test complete transaction structure validation
    try TransactionErrorUtils.validateTransactionStructure(
        100, // script length
        2, // signer count
        2, // witness count (matches signers)
        1, // attribute count
    );

    // Test signer/witness mismatch
    try testing.expectError(TransactionError.SignerConfiguration, TransactionErrorUtils.validateTransactionStructure(100, 2, 3, 1) // Mismatched counts
    );

    // Test no signers
    try testing.expectError(TransactionError.SignerConfiguration, TransactionErrorUtils.validateTransactionStructure(100, 0, 0, 1) // No signers
    );

    // Test too many attributes
    try testing.expectError(TransactionError.TransactionConfiguration, TransactionErrorUtils.validateTransactionStructure(100, 1, 1, 20) // Too many attributes
    );
}
