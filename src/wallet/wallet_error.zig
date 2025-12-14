//! Wallet Error Implementation
//!
//! Complete conversion from NeoSwift WalletError.swift
//! Provides wallet-specific error handling.

const std = @import("std");
const builtin = @import("builtin");

const log = std.log.scoped(.neo_wallet);

/// Wallet-specific errors (converted from Swift WalletError)
pub const WalletError = union(enum) {
    /// Account state error
    AccountState: []const u8,
    /// Account not found error
    AccountNotFound: void,
    /// No accounts provided error
    NoAccountsProvided: void,
    /// Invalid password error
    InvalidPassword: void,
    /// Wallet locked error
    WalletLocked: void,
    /// Invalid wallet format error
    InvalidWalletFormat: void,
    /// Insufficient funds error
    InsufficientFunds: void,

    const Self = @This();

    /// Creates account state error (equivalent to Swift .accountState)
    pub fn accountState(message: []const u8) Self {
        return Self{ .AccountState = message };
    }

    /// Creates account not found error
    pub fn accountNotFound() Self {
        return Self{ .AccountNotFound = {} };
    }

    /// Creates no accounts provided error
    pub fn noAccountsProvided() Self {
        return Self{ .NoAccountsProvided = {} };
    }

    /// Creates invalid password error
    pub fn invalidPassword() Self {
        return Self{ .InvalidPassword = {} };
    }

    /// Creates wallet locked error
    pub fn walletLocked() Self {
        return Self{ .WalletLocked = {} };
    }

    /// Creates invalid wallet format error
    pub fn invalidWalletFormat() Self {
        return Self{ .InvalidWalletFormat = {} };
    }

    /// Creates insufficient funds error
    pub fn insufficientFunds() Self {
        return Self{ .InsufficientFunds = {} };
    }

    /// Gets error description (equivalent to Swift errorDescription)
    pub fn getErrorDescription(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .AccountState => |message| {
                return try allocator.dupe(u8, message);
            },
            .AccountNotFound => {
                return try allocator.dupe(u8, "Account not found in wallet");
            },
            .NoAccountsProvided => {
                return try allocator.dupe(u8, "No accounts provided to initialize a wallet");
            },
            .InvalidPassword => {
                return try allocator.dupe(u8, "Invalid password for wallet decryption");
            },
            .WalletLocked => {
                return try allocator.dupe(u8, "Wallet is locked and requires password");
            },
            .InvalidWalletFormat => {
                return try allocator.dupe(u8, "Invalid wallet file format");
            },
            .InsufficientFunds => {
                return try allocator.dupe(u8, "Insufficient funds for transaction");
            },
        };
    }

    /// Throws appropriate Zig error
    pub fn throwError(self: Self, allocator: std.mem.Allocator) !void {
        const description = try self.getErrorDescription(allocator);
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Wallet Error: {s}", .{description});
        }

        return switch (self) {
            .AccountState => error.WalletAccountState,
            .AccountNotFound => error.WalletAccountNotFound,
            .NoAccountsProvided => error.WalletNoAccounts,
            .InvalidPassword => error.WalletInvalidPassword,
            .WalletLocked => error.WalletLocked,
            .InvalidWalletFormat => error.WalletInvalidFormat,
            .InsufficientFunds => error.WalletInsufficientFunds,
        };
    }

    /// Logs error without throwing
    pub fn logError(self: Self, allocator: std.mem.Allocator) void {
        const description = self.getErrorDescription(allocator) catch "Unknown wallet error";
        defer allocator.free(description);

        if (!builtin.is_test) {
            log.debug("Wallet Error: {s}", .{description});
        }
    }

    /// Gets error severity
    pub fn getSeverity(self: Self) ErrorSeverity {
        return switch (self) {
            .AccountState => .Warning,
            .AccountNotFound => .Error,
            .NoAccountsProvided => .Error,
            .InvalidPassword => .Error,
            .WalletLocked => .Warning,
            .InvalidWalletFormat => .Error,
            .InsufficientFunds => .Warning,
        };
    }

    /// Checks if error is recoverable
    pub fn isRecoverable(self: Self) bool {
        return switch (self) {
            .AccountState => true, // Can be corrected
            .AccountNotFound => false, // Account doesn't exist
            .NoAccountsProvided => false, // Need to provide accounts
            .InvalidPassword => true, // Can retry with correct password
            .WalletLocked => true, // Can unlock with password
            .InvalidWalletFormat => false, // File format issue
            .InsufficientFunds => true, // Can add more funds
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

// Tests (converted from Swift WalletError tests)
test "WalletError creation and descriptions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test account state error (equivalent to Swift tests)
    const account_error = WalletError.accountState("Account state is invalid");
    const account_description = try account_error.getErrorDescription(allocator);
    defer allocator.free(account_description);

    try testing.expectEqualStrings("Account state is invalid", account_description);
    try testing.expectEqual(ErrorSeverity.Warning, account_error.getSeverity());
    try testing.expect(account_error.isRecoverable());

    // Test account not found error
    const not_found_error = WalletError.accountNotFound();
    const not_found_description = try not_found_error.getErrorDescription(allocator);
    defer allocator.free(not_found_description);

    try testing.expect(std.mem.indexOf(u8, not_found_description, "not found") != null);
    try testing.expectEqual(ErrorSeverity.Error, not_found_error.getSeverity());
    try testing.expect(!not_found_error.isRecoverable());

    // Test no accounts provided error
    const no_accounts_error = WalletError.noAccountsProvided();
    const no_accounts_description = try no_accounts_error.getErrorDescription(allocator);
    defer allocator.free(no_accounts_description);

    try testing.expect(std.mem.indexOf(u8, no_accounts_description, "No accounts") != null);
}

test "WalletError utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test error throwing
    const invalid_password_error = WalletError.invalidPassword();

    try testing.expectError(error.WalletInvalidPassword, invalid_password_error.throwError(allocator));

    // Test insufficient funds error
    const insufficient_funds_error = WalletError.insufficientFunds();
    try testing.expect(insufficient_funds_error.isRecoverable());
    try testing.expectEqual(ErrorSeverity.Warning, insufficient_funds_error.getSeverity());

    // Test wallet locked error
    const locked_error = WalletError.walletLocked();
    try testing.expect(locked_error.isRecoverable());

    // Test invalid format error
    const format_error = WalletError.invalidWalletFormat();
    try testing.expect(!format_error.isRecoverable());
    try testing.expectEqual(ErrorSeverity.Error, format_error.getSeverity());
}
