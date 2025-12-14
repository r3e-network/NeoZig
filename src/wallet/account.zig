//! Account implementation
//!
//! Complete conversion from NeoSwift Account.swift
//! Represents a Neo account with single-sig or multi-sig capabilities.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Address = @import("../types/address.zig").Address;
const ECKeyPair = @import("../crypto/ec_key_pair.zig").ECKeyPair;
const VerificationScript = @import("verification_script.zig").VerificationScript;
const secure = @import("../utils/secure.zig");

/// Neo account (converted from Swift Account)
pub const Account = struct {
    /// EC key pair if available
    key_pair: ?ECKeyPair,
    /// Account address
    address: Address,
    /// Account label
    label: ?[]const u8,
    /// Verification script
    verification_script: ?VerificationScript,
    /// Lock status
    is_locked: bool,
    /// Encrypted private key (NEP-2 format)
    encrypted_private_key: ?[]const u8,
    /// Parent wallet reference
    wallet: ?*anyopaque, // stub for Wallet reference
    /// Signing threshold (nil for single-sig)
    signing_threshold: ?u32,
    /// Number of participants (nil for single-sig)
    nr_of_participants: ?u32,

    allocator: std.mem.Allocator,

    const Self = @This();

    /// Creates account from key pair (equivalent to Swift init(keyPair:))
    pub fn initFromKeyPair(
        allocator: std.mem.Allocator,
        key_pair: ECKeyPair,
        signing_threshold: ?u32,
        nr_of_participants: ?u32,
    ) !Self {
        const address_str = try key_pair.getAddress(allocator);
        defer allocator.free(address_str);

        const address = try Address.fromString(address_str, allocator);
        const verification_script = try VerificationScript.initFromPublicKey(key_pair.getPublicKey(), allocator);

        return Self{
            .key_pair = key_pair,
            .address = address,
            .label = try allocator.dupe(u8, address_str),
            .verification_script = verification_script,
            .is_locked = false,
            .encrypted_private_key = null,
            .wallet = null,
            .signing_threshold = signing_threshold,
            .nr_of_participants = nr_of_participants,
            .allocator = allocator,
        };
    }

    /// Creates account from address (equivalent to Swift init(address:label:))
    pub fn initFromAddress(
        allocator: std.mem.Allocator,
        address: Address,
        label: ?[]const u8,
        verification_script: ?VerificationScript,
        signing_threshold: ?u32,
        nr_of_participants: ?u32,
    ) !Self {
        return Self{
            .key_pair = null,
            .address = address,
            .label = if (label) |l| try allocator.dupe(u8, l) else null,
            .verification_script = verification_script,
            .is_locked = false,
            .encrypted_private_key = null,
            .wallet = null,
            .signing_threshold = signing_threshold,
            .nr_of_participants = nr_of_participants,
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        if (self.key_pair) |*kp| {
            kp.zeroize();
        }

        if (self.label) |label| {
            self.allocator.free(label);
        }

        if (self.encrypted_private_key) |key| {
            secure.secureZeroConstBytes(key); // Secure clear
            self.allocator.free(key);
        }

        if (self.verification_script) |*script| {
            script.deinit(self.allocator);
        }
    }

    /// Gets script hash (equivalent to Swift getScriptHash())
    pub fn getScriptHash(self: Self) !Hash160 {
        if (self.verification_script) |script| {
            return try script.getScriptHash();
        }

        if (self.key_pair) |kp| {
            return try kp.getScriptHash(self.allocator);
        }

        // Extract from address
        return self.address.toHash160();
    }

    /// Gets address (equivalent to Swift .address property)
    pub fn getAddress(self: Self) Address {
        return self.address;
    }

    /// Gets label (equivalent to Swift .label property)
    pub fn getLabel(self: Self) ?[]const u8 {
        return self.label;
    }

    /// Sets label (equivalent to Swift label setting)
    pub fn setLabel(self: *Self, label: ?[]const u8) !void {
        if (self.label) |old_label| {
            self.allocator.free(old_label);
        }

        self.label = if (label) |l| try self.allocator.dupe(u8, l) else null;
    }

    /// Checks if account is multi-sig (equivalent to Swift .isMultiSig property)
    pub fn isMultiSig(self: Self) bool {
        return self.signing_threshold != null and self.nr_of_participants != null;
    }

    /// Checks if account is default (equivalent to Swift .isDefault property)
    pub fn isDefault(self: Self) bool {
        // Would check with parent wallet
        _ = self;
        return false; // stub
    }

    /// Checks if account is locked (equivalent to Swift .isLocked property)
    pub fn isLocked(self: Self) bool {
        return self.is_locked;
    }

    /// Locks account (equivalent to Swift lock())
    pub fn lock(self: *Self) void {
        self.is_locked = true;
    }

    /// Unlocks account (equivalent to Swift unlock())
    pub fn unlock(self: *Self) void {
        self.is_locked = false;
    }

    /// Checks if has private key (equivalent to Swift private key availability)
    pub fn hasPrivateKey(self: Self) bool {
        return self.key_pair != null or self.encrypted_private_key != null;
    }

    /// Gets private key (equivalent to Swift private key access)
    pub fn getPrivateKey(self: Self) !@import("../crypto/keys.zig").PrivateKey {
        if (self.key_pair) |kp| {
            return kp.getPrivateKey();
        }

        return errors.WalletError.AccountNotFound;
    }

    /// Gets public key (equivalent to Swift public key access)
    pub fn getPublicKey(self: Self) !@import("../crypto/keys.zig").PublicKey {
        if (self.key_pair) |kp| {
            return kp.getPublicKey();
        }

        return errors.WalletError.AccountNotFound;
    }

    /// Signs message (equivalent to Swift signing)
    pub fn signMessage(self: Self, message: []const u8, allocator: std.mem.Allocator) !@import("../crypto/sign.zig").SignatureData {
        if (self.key_pair) |kp| {
            return try @import("../crypto/sign.zig").Sign.signMessage(message, kp, allocator);
        }

        return errors.WalletError.AccountNotFound;
    }

    /// Encrypts private key (equivalent to Swift encryption)
    pub fn encryptPrivateKey(self: *Self, password: []const u8) !void {
        if (self.key_pair) |kp| {
            const nep2 = @import("../crypto/nep2.zig");
            const encrypted = try nep2.NEP2.encrypt(
                password,
                kp,
                @import("nep6_wallet.zig").ScryptParams.DEFAULT,
                self.allocator,
            );

            if (self.encrypted_private_key) |old_key| {
                secure.secureZeroConstBytes(old_key);
                self.allocator.free(old_key);
            }

            self.encrypted_private_key = encrypted;

            // Clear key pair for security
            var mutable_kp = kp;
            mutable_kp.zeroize();
            self.key_pair = null;
        }
    }

    /// Decrypts private key (equivalent to Swift decryption)
    pub fn decryptPrivateKey(self: *Self, password: []const u8) !void {
        if (self.encrypted_private_key) |encrypted| {
            const nep2 = @import("../crypto/nep2.zig");
            const key_pair = try nep2.NEP2.decrypt(
                password,
                encrypted,
                @import("nep6_wallet.zig").ScryptParams.DEFAULT,
                self.allocator,
            );

            self.key_pair = key_pair;
        }
    }

    /// Creates single-signature account (factory method)
    pub fn createSingleSig(allocator: std.mem.Allocator, key_pair: ECKeyPair) !Self {
        return try Self.initFromKeyPair(allocator, key_pair, null, null);
    }

    /// Creates multi-signature account (factory method)
    pub fn createMultiSig(
        allocator: std.mem.Allocator,
        address: Address,
        signing_threshold: u32,
        nr_of_participants: u32,
        verification_script: VerificationScript,
    ) !Self {
        return try Self.initFromAddress(
            allocator,
            address,
            null,
            verification_script,
            signing_threshold,
            nr_of_participants,
        );
    }

    /// Creates account from address string (utility method)
    pub fn fromAddressString(allocator: std.mem.Allocator, address_str: []const u8) !Self {
        const address = try Address.fromString(address_str, allocator);
        return try Self.initFromAddress(allocator, address, null, null, null, null);
    }
};

/// Verification script (converted from Swift VerificationScript)
pub const VerificationScript = struct {
    script: []const u8,
    script_hash: Hash160,

    const Self = @This();

    /// Creates verification script from public key (equivalent to Swift init)
    pub fn initFromPublicKey(public_key: @import("../crypto/keys.zig").PublicKey, allocator: std.mem.Allocator) !Self {
        const script = try @import("../script/script_builder.zig").ScriptBuilder.buildVerificationScript(
            public_key.toSlice(),
            allocator,
        );

        const script_hash = try Hash160.fromScript(script);

        return Self{
            .script = script,
            .script_hash = script_hash,
        };
    }

    /// Creates verification script from script bytes
    pub fn initFromScript(script: []const u8, allocator: std.mem.Allocator) !Self {
        const script_copy = try allocator.dupe(u8, script);
        const script_hash = try Hash160.fromScript(script);

        return Self{
            .script = script_copy,
            .script_hash = script_hash,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
    }

    /// Gets script hash
    pub fn getScriptHash(self: Self) Hash160 {
        return self.script_hash;
    }

    /// Gets script bytes
    pub fn getScript(self: Self) []const u8 {
        return self.script;
    }

    /// Gets script size
    pub fn getSize(self: Self) usize {
        return self.script.len;
    }
};

// Tests (converted from Swift Account tests)
test "Account creation from key pair" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test single-sig account creation (equivalent to Swift Account tests)
    const key_pair = try ECKeyPair.createRandom();
    var account = try Account.initFromKeyPair(allocator, key_pair, null, null);
    defer account.deinit();

    try testing.expect(account.key_pair != null);
    try testing.expect(account.address.isValid());
    try testing.expect(!account.isMultiSig());
    try testing.expect(!account.isLocked());
    try testing.expect(account.hasPrivateKey());

    // Test script hash generation
    const script_hash = try account.getScriptHash();
    try testing.expect(!script_hash.eql(Hash160.ZERO));
}

test "Account multi-signature creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test multi-sig account creation (equivalent to Swift multi-sig tests)
    const address = Address.fromHash160(Hash160.ZERO);
    const verification_script = try VerificationScript.initFromScript(&[_]u8{0x40}, allocator); // RET

    var multi_sig_account = try Account.createMultiSig(
        allocator,
        address,
        2, // 2-of-3 multi-sig
        3,
        verification_script,
    );
    defer multi_sig_account.deinit();

    try testing.expect(multi_sig_account.isMultiSig());
    try testing.expectEqual(@as(u32, 2), multi_sig_account.signing_threshold.?);
    try testing.expectEqual(@as(u32, 3), multi_sig_account.nr_of_participants.?);
    try testing.expect(!multi_sig_account.hasPrivateKey()); // Multi-sig doesn't store private keys
}

test "Account lock and security operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key_pair = try ECKeyPair.createRandom();
    var account = try Account.initFromKeyPair(allocator, key_pair, null, null);
    defer account.deinit();

    // Test locking (equivalent to Swift lock/unlock tests)
    try testing.expect(!account.isLocked());

    account.lock();
    try testing.expect(account.isLocked());

    account.unlock();
    try testing.expect(!account.isLocked());

    // Test private key encryption (equivalent to Swift encryption tests)
    try account.encryptPrivateKey("test_password");
    try testing.expect(account.encrypted_private_key != null);
    try testing.expect(account.key_pair == null); // Should be cleared after encryption

    // Test private key decryption
    try account.decryptPrivateKey("test_password");
    try testing.expect(account.key_pair != null); // Should be restored
}

test "Account label management" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key_pair = try ECKeyPair.createRandom();
    var account = try Account.initFromKeyPair(allocator, key_pair, null, null);
    defer account.deinit();

    // Test label operations (equivalent to Swift label tests)
    const original_label = account.getLabel();
    try testing.expect(original_label != null);

    try account.setLabel("New Account Label");
    const new_label = account.getLabel();
    try testing.expect(new_label != null);
    try testing.expectEqualStrings("New Account Label", new_label.?);

    // Test clearing label
    try account.setLabel(null);
    try testing.expect(account.getLabel() == null);
}

test "VerificationScript operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test verification script creation (equivalent to Swift VerificationScript tests)
    const key_pair = try ECKeyPair.createRandom();
    var verification_script = try VerificationScript.initFromPublicKey(key_pair.getPublicKey(), allocator);
    defer verification_script.deinit(allocator);

    try testing.expect(verification_script.getScript().len > 0);
    try testing.expect(!verification_script.getScriptHash().eql(Hash160.ZERO));

    // Test script from bytes
    const test_script = [_]u8{ 0x0C, 0x21, 0x02, 0x03, 0x41, 0x30, 0x64, 0x76, 0x41 }; // Mock verification script
    var script_from_bytes = try VerificationScript.initFromScript(&test_script, allocator);
    defer script_from_bytes.deinit(allocator);

    try testing.expectEqualSlices(u8, &test_script, script_from_bytes.getScript());
    try testing.expectEqual(test_script.len, script_from_bytes.getSize());
}

test "Account signing operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key_pair = try ECKeyPair.createRandom();
    var account = try Account.initFromKeyPair(allocator, key_pair, null, null);
    defer account.deinit();

    // Test message signing (equivalent to Swift signing tests)
    const message = "Test message for account signing";
    const signature_data = try account.signMessage(message, allocator);

    try testing.expect(signature_data.isValid());
    try testing.expect(signature_data.r != 0);
    try testing.expect(signature_data.s != 0);

    // Test private key access
    const private_key = try account.getPrivateKey();
    try testing.expect(private_key.isValid());

    const public_key = try account.getPublicKey();
    try testing.expect(public_key.isValid());
}
