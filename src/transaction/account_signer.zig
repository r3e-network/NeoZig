//! Account Signer implementation
//!
//! Complete conversion from NeoSwift AccountSigner.swift
//! Provides account-based transaction signing with witness scopes.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Address = @import("../types/address.zig").Address;
const Signer = @import("transaction_builder.zig").Signer;
const WitnessScope = @import("transaction_builder.zig").WitnessScope;
const Account = @import("transaction_builder.zig").Account;

/// Account signer for transactions (converted from Swift AccountSigner)
pub const AccountSigner = struct {
    /// Associated account
    account: Account,
    /// Base signer
    signer: Signer,

    const Self = @This();

    /// Creates account signer (equivalent to Swift private init)
    fn initPrivate(account: Account, scope: WitnessScope) !Self {
        const signer = Signer.init(account.getScriptHash(), scope);

        return Self{
            .account = account,
            .signer = signer,
        };
    }

    /// Creates signer with none scope (equivalent to Swift none(_ account: Account))
    pub fn none(account: Account) !Self {
        return try initPrivate(account, .None);
    }

    /// Creates signer with none scope from hash (equivalent to Swift none(_ accountHash: Hash160))
    pub fn noneFromHash(account_hash: Hash160, allocator: std.mem.Allocator) !Self {
        const address = try account_hash.toAddress(allocator);
        defer allocator.free(address);

        const account = Account.fromAddress(address, allocator) catch {
            return errors.throwIllegalArgument("Cannot create account from hash");
        };

        return try initPrivate(account, .None);
    }

    /// Creates signer with calledByEntry scope (equivalent to Swift calledByEntry(_ account: Account))
    pub fn calledByEntry(account: Account) !Self {
        return try initPrivate(account, .CalledByEntry);
    }

    /// Creates signer with calledByEntry scope from hash (equivalent to Swift calledByEntry(_ accountHash: Hash160))
    pub fn calledByEntryFromHash(account_hash: Hash160, allocator: std.mem.Allocator) !Self {
        const address = try account_hash.toAddress(allocator);
        defer allocator.free(address);

        const account = Account.fromAddress(address, allocator) catch {
            return errors.throwIllegalArgument("Cannot create account from hash");
        };

        return try initPrivate(account, .CalledByEntry);
    }

    /// Creates signer with global scope (equivalent to Swift global(_ account: Account))
    pub fn global(account: Account) !Self {
        return try initPrivate(account, .Global);
    }

    /// Creates signer with global scope from hash (equivalent to Swift global(_ accountHash: Hash160))
    pub fn globalFromHash(account_hash: Hash160, allocator: std.mem.Allocator) !Self {
        const address = try account_hash.toAddress(allocator);
        defer allocator.free(address);

        const account = Account.fromAddress(address, allocator) catch {
            return errors.throwIllegalArgument("Cannot create account from hash");
        };

        return try initPrivate(account, .Global);
    }

    /// Creates signer with custom contracts scope (additional utility)
    pub fn customContracts(account: Account, allowed_contracts: []const Hash160) !Self {
        var signer = try initPrivate(account, .CustomContracts);
        signer.signer.allowed_contracts = allowed_contracts;
        return signer;
    }

    /// Creates signer with custom groups scope (additional utility)
    pub fn customGroups(account: Account, allowed_groups: []const [33]u8) !Self {
        var signer = try initPrivate(account, .CustomGroups);
        signer.signer.allowed_groups = allowed_groups;
        return signer;
    }

    /// Gets account (equivalent to Swift .account property)
    pub fn getAccount(self: Self) Account {
        return self.account;
    }

    /// Gets signer (equivalent to Swift base signer access)
    pub fn getSigner(self: Self) Signer {
        return self.signer;
    }

    /// Gets script hash (equivalent to Swift script hash access)
    pub fn getScriptHash(self: Self) Hash160 {
        return self.signer.signer_hash;
    }

    /// Gets witness scope (equivalent to Swift scope access)
    pub fn getWitnessScope(self: Self) WitnessScope {
        return self.signer.scopes;
    }

    /// Validates signer configuration (equivalent to Swift validation)
    pub fn validate(self: Self) !void {
        try self.signer.validate();

        // Additional account-specific validation
        if (!self.account.getScriptHash().eql(self.signer.signer_hash)) {
            return errors.TransactionError.InvalidSigner;
        }
    }

    /// Converts to base signer for transaction use
    pub fn toSigner(self: Self) Signer {
        return self.signer;
    }

    /// Checks if signer can be used in specific context
    pub fn canBeUsedInContext(self: Self, context: SigningContext) bool {
        return switch (self.signer.scopes) {
            .None => context == .Transaction,
            .Global => true,
            .CalledByEntry => context == .EntryContract,
            .CustomContracts => context == .AllowedContract,
            .CustomGroups => context == .AllowedGroup,
            .WitnessRules => false, // Would need rule evaluation
        };
    }
};

/// Signing context enumeration (additional utility)
pub const SigningContext = enum {
    Transaction,
    EntryContract,
    AllowedContract,
    AllowedGroup,
    WitnessRule,
};

/// Account signer factory (utility methods)
pub const AccountSignerFactory = struct {
    /// Creates appropriate signer for common scenarios
    pub fn createForTransfer(sender: Account, receiver: Hash160) !AccountSigner {
        // Use calledByEntry scope for token transfers
        _ = receiver; // For future use in custom logic
        return try AccountSigner.calledByEntry(sender);
    }

    /// Creates signer for contract interaction
    pub fn createForContractCall(caller: Account, contract: Hash160) !AccountSigner {
        // Use calledByEntry scope with specific contract
        _ = contract; // For future custom contract scope
        return try AccountSigner.calledByEntry(caller);
    }

    /// Creates multi-signature compatible signer
    pub fn createForMultiSig(accounts: []const Account, allocator: std.mem.Allocator) ![]AccountSigner {
        var signers = try allocator.alloc(AccountSigner, accounts.len);

        for (accounts, 0..) |account, i| {
            signers[i] = try AccountSigner.calledByEntry(account);
        }

        return signers;
    }

    /// Creates signer with minimal permissions (fee-only)
    pub fn createFeeOnly(fee_account: Account) !AccountSigner {
        return try AccountSigner.none(fee_account);
    }
};

// Tests (converted from Swift AccountSigner tests)
test "AccountSigner creation with different scopes" {
    const testing = std.testing;
    _ = testing.allocator;

    // Create test account
    const test_account = Account.init(Hash160.ZERO);

    // Test none scope (equivalent to Swift none tests)
    const none_signer = try AccountSigner.none(test_account);
    try testing.expectEqual(WitnessScope.None, none_signer.getWitnessScope());
    try testing.expect(none_signer.getScriptHash().eql(Hash160.ZERO));

    // Test calledByEntry scope (equivalent to Swift calledByEntry tests)
    const entry_signer = try AccountSigner.calledByEntry(test_account);
    try testing.expectEqual(WitnessScope.CalledByEntry, entry_signer.getWitnessScope());

    // Test global scope (equivalent to Swift global tests)
    const global_signer = try AccountSigner.global(test_account);
    try testing.expectEqual(WitnessScope.Global, global_signer.getWitnessScope());
}

test "AccountSigner creation from hash" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const test_hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");

    // Test none from hash (equivalent to Swift none hash tests)
    const none_signer = try AccountSigner.noneFromHash(test_hash, allocator);
    try testing.expectEqual(WitnessScope.None, none_signer.getWitnessScope());
    try testing.expect(none_signer.getScriptHash().eql(test_hash));

    // Test calledByEntry from hash
    const entry_signer = try AccountSigner.calledByEntryFromHash(test_hash, allocator);
    try testing.expectEqual(WitnessScope.CalledByEntry, entry_signer.getWitnessScope());

    // Test global from hash
    const global_signer = try AccountSigner.globalFromHash(test_hash, allocator);
    try testing.expectEqual(WitnessScope.Global, global_signer.getWitnessScope());
}

test "AccountSigner validation and context" {
    const testing = std.testing;
    _ = testing.allocator;

    const test_account = Account.init(Hash160.ZERO);

    // Test signer validation (equivalent to Swift validation tests)
    const signer = try AccountSigner.calledByEntry(test_account);
    try signer.validate();

    // Test signing context (equivalent to Swift context tests)
    try testing.expect(signer.canBeUsedInContext(.EntryContract));
    try testing.expect(!signer.canBeUsedInContext(.AllowedContract));

    const global_signer = try AccountSigner.global(test_account);
    try testing.expect(global_signer.canBeUsedInContext(.Transaction));
    try testing.expect(global_signer.canBeUsedInContext(.EntryContract));
    try testing.expect(global_signer.canBeUsedInContext(.AllowedContract));
}

test "AccountSigner factory methods" {
    const testing = std.testing;
    _ = testing.allocator;

    const sender_account = Account.init(Hash160.ZERO);
    const receiver_hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");

    // Test transfer signer creation
    const transfer_signer = try AccountSignerFactory.createForTransfer(sender_account, receiver_hash);
    try testing.expectEqual(WitnessScope.CalledByEntry, transfer_signer.getWitnessScope());

    // Test contract call signer creation
    const contract_signer = try AccountSignerFactory.createForContractCall(sender_account, receiver_hash);
    try testing.expectEqual(WitnessScope.CalledByEntry, contract_signer.getWitnessScope());

    // Test fee-only signer creation
    const fee_signer = try AccountSignerFactory.createFeeOnly(sender_account);
    try testing.expectEqual(WitnessScope.None, fee_signer.getWitnessScope());
}
