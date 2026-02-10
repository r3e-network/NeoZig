//! Account implementation
//!
//! Neo N3 
//! Represents a Neo account with single-sig or multi-sig capabilities.

const std = @import("std");

const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Address = @import("../types/address.zig").Address;
const ECKeyPair = @import("../crypto/ec_key_pair.zig").ECKeyPair;
const KeyPair = @import("../crypto/keys.zig").KeyPair;
const PrivateKey = @import("../crypto/keys.zig").PrivateKey;
const VerificationScript = @import("verification_script.zig").VerificationScript;
const secure = @import("../utils/secure.zig");

/// Neo account
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

    /// Creates account from key pair)
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

    /// Creates account from address)
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

    /// Gets script hash)
    pub fn getScriptHash(self: Self) !Hash160 {
        if (self.verification_script) |script| {
            return script.getScriptHash();
        }

        if (self.key_pair) |kp| {
            return try kp.getScriptHash(self.allocator);
        }

        // Extract from address
        return self.address.toHash160();
    }

    /// Gets address
    pub fn getAddress(self: Self) Address {
        return self.address;
    }

    /// Gets verification script (borrowed; do not deinit).
    pub fn getVerificationScript(self: *const Self) ?*const VerificationScript {
        if (self.verification_script) |*script| {
            return script;
        }
        return null;
    }

    /// Gets key pair if available.
    pub fn getKeyPair(self: Self) ?ECKeyPair {
        return self.key_pair;
    }

    /// Gets label
    pub fn getLabel(self: Self) ?[]const u8 {
        return self.label;
    }

    /// Gets encrypted private key (NEP-2), if present.
    pub fn getEncryptedPrivateKey(self: Self) ?[]const u8 {
        return self.encrypted_private_key;
    }

    /// Sets label
    pub fn setLabel(self: *Self, label: ?[]const u8) !void {
        if (self.label) |old_label| {
            self.allocator.free(old_label);
        }

        self.label = if (label) |l| try self.allocator.dupe(u8, l) else null;
    }

    /// Gets the signing threshold for multi-sig accounts.
    pub fn getSigningThreshold(self: Self) ?u32 {
        return self.signing_threshold;
    }

    /// Gets the number of participants for multi-sig accounts.
    pub fn getParticipantCount(self: Self) ?u32 {
        return self.nr_of_participants;
    }

    /// Checks if the account can directly sign.
    pub fn canSign(self: Self) bool {
        return self.key_pair != null and !self.is_locked;
    }

    /// Compares accounts for equality (based on address).
    pub fn eql(self: Self, other: Self) bool {
        return self.address.eql(other.address);
    }

    /// Creates a deep copy of the account.
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        var label: ?[]const u8 = null;
        errdefer if (label) |label_copy| allocator.free(label_copy);
        if (self.label) |l| {
            label = try allocator.dupe(u8, l);
        }

        var verification_script: ?VerificationScript = null;
        errdefer if (verification_script) |*script| script.deinit(allocator);
        if (self.verification_script) |script| {
            verification_script = try VerificationScript.initFromScript(script.getScript(), allocator);
        }

        var encrypted_private_key: ?[]const u8 = null;
        errdefer if (encrypted_private_key) |key| {
            secure.secureZeroConstBytes(key);
            allocator.free(key);
        };
        if (self.encrypted_private_key) |key| {
            encrypted_private_key = try allocator.dupe(u8, key);
        }

        return Self{
            .key_pair = if (self.key_pair) |kp| kp else null,
            .address = self.address,
            .label = label,
            .verification_script = verification_script,
            .is_locked = self.is_locked,
            .encrypted_private_key = encrypted_private_key,
            .wallet = self.wallet,
            .signing_threshold = self.signing_threshold,
            .nr_of_participants = self.nr_of_participants,
            .allocator = allocator,
        };
    }

    /// Checks if account is multi-sig
    pub fn isMultiSig(self: Self) bool {
        return self.signing_threshold != null and self.nr_of_participants != null;
    }

    /// Validates basic account consistency.
    pub fn validate(self: Self) !void {
        if (!self.address.isValid()) {
            return errors.ValidationError.InvalidAddress;
        }

        if (self.key_pair) |kp| {
            if (!kp.isValid()) {
                return errors.ValidationError.InvalidParameter;
            }
        }

        if (self.verification_script) |script| {
            const expected = self.address.toHash160();
            if (!script.getScriptHash().eql(expected)) {
                return errors.ValidationError.InvalidParameter;
            }
        }

        if ((self.signing_threshold != null) != (self.nr_of_participants != null)) {
            return errors.ValidationError.InvalidParameter;
        }

        if (self.signing_threshold) |threshold| {
            const participants = self.nr_of_participants.?;
            if (threshold == 0 or participants == 0 or threshold > participants) {
                return errors.ValidationError.InvalidParameter;
            }
        }
    }

    /// Checks if account is default
    pub fn isDefault(self: Self) bool {
        // Would check with parent wallet
        _ = self;
        return false; // stub
    }

    /// Checks if account is locked
    pub fn isLocked(self: Self) bool {
        return self.is_locked;
    }

    /// Locks account)
    pub fn lock(self: *Self) void {
        self.is_locked = true;
    }

    /// Unlocks account)
    pub fn unlock(self: *Self) void {
        self.is_locked = false;
    }

    /// Checks if has private key
    pub fn hasPrivateKey(self: Self) bool {
        return self.key_pair != null or self.encrypted_private_key != null;
    }

    /// Gets private key
    pub fn getPrivateKey(self: Self) !@import("../crypto/keys.zig").PrivateKey {
        if (self.is_locked) {
            return errors.WalletError.WalletLocked;
        }

        if (self.key_pair) |kp| {
            return kp.getPrivateKey();
        }

        if (self.encrypted_private_key != null) {
            return errors.WalletError.WalletLocked;
        }

        return errors.WalletError.AccountNotFound;
    }

    /// Gets public key
    pub fn getPublicKey(self: Self) !@import("../crypto/keys.zig").PublicKey {
        if (self.key_pair) |kp| {
            return kp.getPublicKey();
        }

        if (self.encrypted_private_key != null) {
            return errors.WalletError.WalletLocked;
        }

        return errors.WalletError.AccountNotFound;
    }

    /// Signs message
    pub fn signMessage(self: Self, message: []const u8, allocator: std.mem.Allocator) !@import("../crypto/sign.zig").SignatureData {
        if (self.is_locked) {
            return errors.WalletError.WalletLocked;
        }

        if (self.key_pair) |kp| {
            return try @import("../crypto/sign.zig").Sign.signMessage(message, kp, allocator);
        }

        if (self.encrypted_private_key != null) {
            return errors.WalletError.WalletLocked;
        }

        return errors.WalletError.AccountNotFound;
    }

    /// Encrypts private key
    pub fn encryptPrivateKey(self: *Self, password: []const u8) !void {
        const kp = self.key_pair orelse return errors.WalletError.AccountNotFound;
        const nep2 = @import("../crypto/nep2.zig");
        var key_pair = KeyPair.init(kp.getPrivateKey(), kp.getPublicKey());
        defer key_pair.zeroize();
        const encrypted = try nep2.NEP2.encrypt(
            password,
            key_pair,
            @import("nep6_wallet.zig").ScryptParams.DEFAULT,
            self.allocator,
        );

        if (self.encrypted_private_key) |old_key| {
            secure.secureZeroConstBytes(old_key);
            self.allocator.free(old_key);
        }

        self.encrypted_private_key = encrypted;

        // Clear key pair for security
        if (self.key_pair) |*existing| {
            existing.zeroize();
        }
        self.key_pair = null;
        self.is_locked = true;
    }

    /// Convenience encrypt method used by legacy tests.
    pub fn encrypt(self: *Self, password: []const u8, allocator: std.mem.Allocator) !void {
        _ = allocator;
        try self.encryptPrivateKey(password);
        self.lock();
    }

    /// Decrypts private key
    pub fn decryptPrivateKey(self: *Self, password: []const u8) !void {
        const encrypted = self.encrypted_private_key orelse return errors.WalletError.AccountNotFound;
        const nep2 = @import("../crypto/nep2.zig");
        var decrypted_pair = try nep2.NEP2.decrypt(
            password,
            encrypted,
            @import("nep6_wallet.zig").ScryptParams.DEFAULT,
            self.allocator,
        );
        const key_pair = ECKeyPair.init(decrypted_pair.private_key, decrypted_pair.public_key);
        decrypted_pair.zeroize();

        if (self.key_pair) |*existing| {
            existing.zeroize();
        }
        self.key_pair = key_pair;
        self.is_locked = false;
    }

    /// Convenience decrypt method used by legacy tests.
    pub fn decrypt(self: *Self, password: []const u8, allocator: std.mem.Allocator) !void {
        _ = allocator;
        try self.decryptPrivateKey(password);
        self.unlock();
    }

    /// Creates an account from a key pair.
    pub fn init(key_pair: ECKeyPair, allocator: std.mem.Allocator) !Self {
        return try Self.initFromKeyPair(allocator, key_pair, null, null);
    }

    /// Creates account from private key (wallet convenience).
    pub fn initWithPrivateKey(private_key: PrivateKey, compressed: bool, allocator: std.mem.Allocator) !Self {
        const public_key = try private_key.getPublicKey(compressed);
        const ec_key_pair = ECKeyPair.init(private_key, public_key);
        return try Self.initFromKeyPair(allocator, ec_key_pair, null, null);
    }

    /// Creates a random account).
    pub fn create(allocator: std.mem.Allocator) !Self {
        const key_pair = try ECKeyPair.createRandom();
        return try Self.init(key_pair, allocator);
    }

    /// Creates account from verification script.
    pub fn fromVerificationScript(verification_script: VerificationScript, allocator: std.mem.Allocator) !Self {
        const script = verification_script.getScript();
        const cloned_script = try VerificationScript.initFromScript(script, allocator);
        const address = Address.fromHash160(cloned_script.getScriptHash());
        const label = try address.toString(allocator);
        defer allocator.free(label);
        return try Self.initFromAddress(allocator, address, label, cloned_script, null, null);
    }

    /// Creates account from public key (watch-only).
    pub fn fromPublicKey(public_key: @import("../crypto/keys.zig").PublicKey, allocator: std.mem.Allocator) !Self {
        const verification_script = try VerificationScript.initFromPublicKey(public_key, allocator);
        return try Self.fromVerificationScript(verification_script, allocator);
    }

    /// Creates account from a generic key pair (wallet convenience).
    pub fn fromKeyPair(key_pair: KeyPair, allocator: std.mem.Allocator) !Self {
        const ec_key_pair = ECKeyPair.init(key_pair.private_key, key_pair.public_key);
        return try Self.initFromKeyPair(allocator, ec_key_pair, null, null);
    }

    /// Creates account from WIF (wallet convenience).
    pub fn fromWif(wif_string: []const u8, allocator: std.mem.Allocator) !Self {
        var decode_result = try @import("../crypto/wif.zig").decode(wif_string, allocator);
        defer decode_result.deinit();
        return try Self.initWithPrivateKey(decode_result.private_key, decode_result.compressed, allocator);
    }

    /// Creates a multi-signature account.
    pub fn createMultiSigAccount(
        public_keys: []const @import("../crypto/keys.zig").PublicKey,
        signing_threshold: u32,
        allocator: std.mem.Allocator,
    ) !Self {
        if (public_keys.len == 0) {
            return errors.throwIllegalArgument("At least one public key required for multi-sig");
        }
        if (signing_threshold == 0 or signing_threshold > public_keys.len) {
            return errors.throwIllegalArgument("Invalid signing threshold for multi-sig");
        }

        var key_slices = try allocator.alloc([]const u8, public_keys.len);
        defer allocator.free(key_slices);
        for (public_keys, 0..) |key, i| {
            key_slices[i] = key.toSlice();
        }

        const script = try @import("../script/script_builder.zig").ScriptBuilder.buildMultiSigVerificationScript(
            key_slices,
            signing_threshold,
            allocator,
        );
        defer allocator.free(script);

        const verification_script = try VerificationScript.initFromScript(script, allocator);
        const address = Address.fromHash160(verification_script.getScriptHash());
        const label = try address.toString(allocator);
        defer allocator.free(label);

        return try Self.initFromAddress(
            allocator,
            address,
            label,
            verification_script,
            signing_threshold,
            @intCast(public_keys.len),
        );
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
        if (signing_threshold == 0 or nr_of_participants == 0 or signing_threshold > nr_of_participants) {
            return errors.throwIllegalArgument("Invalid signing threshold for multi-sig");
        }
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

    /// Creates account from address string (legacy convenience).
    pub fn fromAddress(address: []const u8, allocator: std.mem.Allocator) !Self {
        return try Self.fromAddressString(allocator, address);
    }

    /// Creates a watch-only account from a script hash.
    pub fn fromScriptHash(allocator: std.mem.Allocator, script_hash: Hash160) !Self {
        const address = Address.fromHash160(script_hash);
        return try Self.initFromAddress(allocator, address, null, null, null, null);
    }

    /// Replaces account keys with a new private key.
    pub fn withPrivateKey(self: *Self, private_key: PrivateKey, compressed: bool, allocator: std.mem.Allocator) !void {
        self.* = try Self.initWithPrivateKey(private_key, compressed, allocator);
    }
};

// Tests
test "Account creation from key pair" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test single-sig account creation
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

    // Test multi-sig account creation
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

    // Test locking
    try testing.expect(!account.isLocked());

    account.lock();
    try testing.expect(account.isLocked());

    account.unlock();
    try testing.expect(!account.isLocked());

    // Test private key encryption
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

    // Test label operations
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

    // Test verification script creation
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

    // Test message signing
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
