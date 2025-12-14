//! BIP-39 Account implementation
//!
//! Complete conversion from NeoSwift Bip39Account.swift
//! Provides BIP-39 mnemonic-based account generation.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const Address = @import("../types/address.zig").Address;
const PrivateKey = @import("../crypto/keys.zig").PrivateKey;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const KeyPair = @import("../crypto/keys.zig").KeyPair;
const Account = @import("../transaction/transaction_builder.zig").Account;
const secure = @import("../utils/secure.zig");

/// BIP-39 compatible Neo account (converted from Swift Bip39Account)
pub const Bip39Account = struct {
    /// Generated BIP-39 mnemonic
    mnemonic: []const u8,
    /// Base account
    account: Account,
    /// BIP-32 node derived from the BIP-39 seed (used for deterministic child keys)
    bip32_node: @import("../crypto/bip32.zig").Bip32ECKeyPair,
    /// Allocator for memory management
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Creates BIP-39 account (equivalent to Swift private init)
    fn initPrivate(allocator: std.mem.Allocator, key_pair: KeyPair, mnemonic: []const u8, bip32_node: @import("../crypto/bip32.zig").Bip32ECKeyPair) !Self {
        const address = try key_pair.public_key.toAddress(constants.AddressConstants.ADDRESS_VERSION);
        const account = Account.fromKeyPair(key_pair, address);

        return Self{
            .mnemonic = try allocator.dupe(u8, mnemonic),
            .account = account,
            .bip32_node = bip32_node,
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        if (self.account.private_key) |*pk| {
            pk.zeroize();
        }
        self.bip32_node.deinit();

        secure.secureZeroConstBytes(self.mnemonic);
        self.allocator.free(@constCast(self.mnemonic));
    }

    /// Generates new BIP-39 account (equivalent to Swift create(_ password: String))
    pub fn create(allocator: std.mem.Allocator, password: []const u8) !Self {
        // Generate BIP-39 mnemonic
        const mnemonic_words = try generateMnemonic(allocator);
        defer secure.secureZeroFree(allocator, mnemonic_words);

        // Create mnemonic with passphrase
        const seed = try mnemonicToSeed(mnemonic_words, password, allocator);
        defer secure.secureZeroFree(allocator, seed);

        var bip32_node = try @import("../crypto/bip32.zig").Bip32ECKeyPair.generateKeyPair(seed, allocator);
        errdefer bip32_node.deinit();

        // Generate private key from seed (Key = SHA-256(BIP_39_SEED))
        const private_key_hash = Hash256.sha256(seed);
        var private_key = try PrivateKey.init(private_key_hash.toArray());
        errdefer private_key.zeroize();

        // Create key pair
        const public_key = try private_key.getPublicKey(true);
        var key_pair = KeyPair.init(private_key, public_key);
        errdefer key_pair.zeroize();

        // `key_pair` now holds a copy of the private key; clear the temporary.
        private_key.zeroize();

        const result = try Self.initPrivate(allocator, key_pair, mnemonic_words, bip32_node);
        // Clear local copies after successful construction.
        key_pair.zeroize();
        bip32_node.deinit();
        return result;
    }

    /// Recovers account from BIP-39 mnemonic (equivalent to Swift fromBip39Mneumonic)
    pub fn fromBip39Mnemonic(
        allocator: std.mem.Allocator,
        password: []const u8,
        mnemonic: []const u8,
    ) !Self {
        // Validate mnemonic
        if (!validateMnemonic(mnemonic)) {
            return errors.throwIllegalArgument("Invalid BIP-39 mnemonic");
        }

        // Generate seed from mnemonic and passphrase
        const seed = try mnemonicToSeed(mnemonic, password, allocator);
        defer secure.secureZeroFree(allocator, seed);

        var bip32_node = try @import("../crypto/bip32.zig").Bip32ECKeyPair.generateKeyPair(seed, allocator);
        errdefer bip32_node.deinit();

        // Generate private key from seed
        const private_key_hash = Hash256.sha256(seed);
        var private_key = try PrivateKey.init(private_key_hash.toArray());
        errdefer private_key.zeroize();

        // Create key pair
        const public_key = try private_key.getPublicKey(true);
        var key_pair = KeyPair.init(private_key, public_key);
        errdefer key_pair.zeroize();

        private_key.zeroize();

        const result = try Self.initPrivate(allocator, key_pair, mnemonic, bip32_node);
        key_pair.zeroize();
        bip32_node.deinit();
        return result;
    }

    /// Gets mnemonic (equivalent to Swift .mnemonic property)
    pub fn getMnemonic(self: Self) []const u8 {
        return self.mnemonic;
    }

    /// Gets account (equivalent to Swift base account access)
    pub fn getAccount(self: Self) Account {
        return self.account;
    }

    /// Gets script hash (equivalent to Swift script hash access)
    pub fn getScriptHash(self: Self) Hash160 {
        return self.account.getScriptHash();
    }

    /// Gets address (equivalent to Swift address access)
    pub fn getAddress(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const address = self.account.getAddress();
        return try address.toString(allocator);
    }

    /// Gets private key (equivalent to Swift private key access)
    pub fn getPrivateKey(self: Self) !PrivateKey {
        return try self.account.getPrivateKey();
    }

    /// Gets public key (equivalent to Swift public key access)
    pub fn getPublicKey(self: Self) !PublicKey {
        const private_key = try self.getPrivateKey();
        return try private_key.getPublicKey(true);
    }

    /// Derives child account (using BIP-32 derivation)
    pub fn deriveChild(self: Self, child_index: u32, hardened: bool) !Bip39Account {
        var child_node = try self.bip32_node.deriveChild(child_index, hardened, self.allocator);
        errdefer child_node.deinit();

        const result = try Self.initPrivate(self.allocator, child_node.key_pair, self.mnemonic, child_node);
        child_node.deinit();
        return result;
    }
};

/// BIP-39 mnemonic utilities
const BIP39Utils = struct {
    const WORD_LIST = @import("bip39_word_list_en.zig").WORD_LIST;

    /// Generates a 12-word BIP-39 mnemonic (128 bits entropy).
    pub fn generateMnemonic(allocator: std.mem.Allocator) ![]u8 {
        var entropy: [16]u8 = undefined;
        std.crypto.random.bytes(&entropy);
        return try entropyToMnemonic(&entropy, allocator);
    }

    /// Converts entropy to BIP-39 mnemonic words.
    pub fn entropyToMnemonic(entropy: []const u8, allocator: std.mem.Allocator) ![]u8 {
        switch (entropy.len) {
            16, 20, 24, 28, 32 => {},
            else => return errors.throwIllegalArgument("Entropy must be 128-256 bits (16-32 bytes)"),
        }

        const entropy_bits: usize = entropy.len * 8;
        const checksum_bits: usize = entropy_bits / 32;
        const total_bits: usize = entropy_bits + checksum_bits;
        const word_count: usize = total_bits / 11;

        // Compute checksum bits.
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        sha.update(entropy);
        var digest: [32]u8 = undefined;
        sha.final(&digest);

        var output = ArrayList(u8).init(allocator);
        defer output.deinit();

        for (0..word_count) |word_idx| {
            var idx: u16 = 0;
            for (0..11) |bit| {
                const bit_pos = word_idx * 11 + bit;
                const bit_value = getEntropyBit(entropy, digest[0], entropy_bits, bit_pos);
                idx = (idx << 1) | @as(u16, @intCast(bit_value));
            }

            if (word_idx != 0) try output.append(' ');
            try output.appendSlice(WORD_LIST[idx]);
        }

        return try output.toOwnedSlice();
    }

    /// Validates mnemonic word list membership and checksum.
    pub fn validateMnemonic(mnemonic: []const u8) bool {
        var iter = std.mem.tokenizeScalar(u8, mnemonic, ' ');
        var indices: [24]u16 = undefined;
        var count: usize = 0;

        while (iter.next()) |word| {
            if (count >= indices.len) return false;
            const idx = wordIndex(word) orelse return false;
            indices[count] = idx;
            count += 1;
        }

        const valid_count = switch (count) {
            12, 15, 18, 21, 24 => true,
            else => false,
        };
        if (!valid_count) return false;

        const total_bits: usize = count * 11;
        const entropy_bits: usize = total_bits * 32 / 33;
        const checksum_bits: usize = total_bits - entropy_bits;
        const entropy_len: usize = entropy_bits / 8;

        // Reconstruct entropy bytes.
        var entropy: [32]u8 = std.mem.zeroes([32]u8);
        for (0..entropy_bits) |bit_pos| {
            const bit = getBitFromIndices(indices[0..count], bit_pos);
            const byte_index = bit_pos / 8;
            const bit_index: u3 = @intCast(7 - (bit_pos % 8));
            entropy[byte_index] |= @as(u8, bit) << bit_index;
        }

        // Compute expected checksum.
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        sha.update(entropy[0..entropy_len]);
        var digest: [32]u8 = undefined;
        sha.final(&digest);

        for (0..checksum_bits) |k| {
            const bit_pos = entropy_bits + k;
            const actual = getBitFromIndices(indices[0..count], bit_pos);
            const expected: u8 = (digest[0] >> @intCast(7 - k)) & 1;
            if (actual != expected) return false;
        }

        return true;
    }

    /// Converts mnemonic to seed
    pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (!std.unicode.utf8ValidateSlice(mnemonic)) {
            return errors.throwIllegalArgument("Mnemonic must be valid UTF-8");
        }
        if (!std.unicode.utf8ValidateSlice(passphrase)) {
            return errors.throwIllegalArgument("Passphrase must be valid UTF-8");
        }
        if (containsNonAscii(mnemonic) or containsNonAscii(passphrase)) {
            return errors.throwIllegalArgument("BIP-39 requires NFKD normalization for non-ASCII mnemonics/passphrases (not supported yet)");
        }

        // Match NeoSwift behavior: split/join words so extra whitespace doesn't change the seed.
        // (NeoSwift uses `mnemonic.split(separator: " ")` before deriving the seed.)
        var normalized_mnemonic = ArrayList(u8).init(allocator);
        defer {
            secure.secureZeroBytes(normalized_mnemonic.items);
            normalized_mnemonic.deinit();
        }

        var word_iter = std.mem.tokenizeScalar(u8, mnemonic, ' ');
        var appended: bool = false;
        while (word_iter.next()) |word| {
            if (appended) try normalized_mnemonic.append(' ');
            try normalized_mnemonic.appendSlice(word);
            appended = true;
        }

        if (!appended) return errors.throwIllegalArgument("Invalid BIP-39 mnemonic");
        if (!@This().validateMnemonic(normalized_mnemonic.items)) return errors.throwIllegalArgument("Invalid BIP-39 mnemonic");

        // PBKDF2 with mnemonic as password and "mnemonic" + passphrase as salt
        var salt = ArrayList(u8).init(allocator);
        defer {
            secure.secureZeroBytes(salt.items);
            salt.deinit();
        }

        try salt.appendSlice("mnemonic");
        try salt.appendSlice(passphrase);

        const hashing = @import("../crypto/hashing.zig");
        return try hashing.pbkdf2HmacSha512(normalized_mnemonic.items, salt.items, 2048, 64, allocator);
    }

    fn containsNonAscii(bytes: []const u8) bool {
        for (bytes) |b| {
            if ((b & 0x80) != 0) return true;
        }
        return false;
    }

    fn wordIndex(word: []const u8) ?u16 {
        for (WORD_LIST, 0..) |entry, i| {
            if (std.mem.eql(u8, entry, word)) return @intCast(i);
        }
        return null;
    }

    fn getEntropyBit(entropy: []const u8, checksum_byte: u8, entropy_bits: usize, bit_pos: usize) u8 {
        if (bit_pos < entropy_bits) {
            const byte_index = bit_pos / 8;
            const bit_index: u3 = @intCast(7 - (bit_pos % 8));
            return (entropy[byte_index] >> bit_index) & 1;
        }

        const checksum_pos = bit_pos - entropy_bits;
        const bit_index: u3 = @intCast(7 - checksum_pos);
        return (checksum_byte >> bit_index) & 1;
    }

    fn getBitFromIndices(indices: []const u16, bit_pos: usize) u8 {
        const word_index = bit_pos / 11;
        const bit_in_word = bit_pos % 11;
        const idx = indices[word_index];
        return @intCast((idx >> @intCast(10 - bit_in_word)) & 1);
    }
};

/// Export utility functions at module level
pub const generateMnemonic = BIP39Utils.generateMnemonic;
pub const validateMnemonic = BIP39Utils.validateMnemonic;
pub const mnemonicToSeed = BIP39Utils.mnemonicToSeed;

// Tests (converted from Swift Bip39Account tests)
test "Bip39Account creation and mnemonic generation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test account creation (equivalent to Swift create tests)
    var bip39_account = try Bip39Account.create(allocator, "test_password");
    defer bip39_account.deinit();

    // Test mnemonic properties
    const mnemonic = bip39_account.getMnemonic();
    try testing.expect(mnemonic.len > 0);
    try testing.expect(validateMnemonic(mnemonic));

    // Test account properties
    const script_hash = bip39_account.getScriptHash();
    try testing.expect(!script_hash.eql(Hash160.ZERO));

    const address = try bip39_account.getAddress(allocator);
    defer allocator.free(address);
    try testing.expect(address.len > 0);
}

test "Bip39Account recovery from mnemonic" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create account and get mnemonic
    var original_account = try Bip39Account.create(allocator, "recovery_password");
    defer original_account.deinit();

    const original_mnemonic = original_account.getMnemonic();
    const original_script_hash = original_account.getScriptHash();

    // Recover account from mnemonic (equivalent to Swift fromBip39Mnemonic tests)
    var recovered_account = try Bip39Account.fromBip39Mnemonic(
        allocator,
        "recovery_password",
        original_mnemonic,
    );
    defer recovered_account.deinit();

    // Should have same script hash
    try testing.expect(original_script_hash.eql(recovered_account.getScriptHash()));

    // Should have same mnemonic
    try testing.expectEqualStrings(original_mnemonic, recovered_account.getMnemonic());
}

test "Bip39Account child derivation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var parent_account = try Bip39Account.create(allocator, "derivation_password");
    defer parent_account.deinit();

    // Test child derivation (equivalent to Swift child derivation tests)
    var child_account = try parent_account.deriveChild(0, false);
    defer child_account.deinit();

    // Child should be different from parent
    try testing.expect(!parent_account.getScriptHash().eql(child_account.getScriptHash()));

    // Child should have same mnemonic (shares same seed)
    try testing.expectEqualStrings(parent_account.getMnemonic(), child_account.getMnemonic());
}

test "BIP39 mnemonic utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test mnemonic generation (equivalent to Swift mnemonic tests)
    const mnemonic = try generateMnemonic(allocator);
    defer allocator.free(mnemonic);

    try testing.expect(mnemonic.len > 0);
    try testing.expect(validateMnemonic(mnemonic));

    // Test mnemonic validation
    try testing.expect(!validateMnemonic("invalid short mnemonic"));
    try testing.expect(!validateMnemonic(""));

    try testing.expectError(errors.NeoError.IllegalArgument, mnemonicToSeed("invalid short mnemonic", "", allocator));

    // Test seed generation
    const test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const seed_empty = try mnemonicToSeed(test_mnemonic, "", allocator);
    defer secure.secureZeroFree(allocator, seed_empty);
    try testing.expectEqual(@as(usize, 64), seed_empty.len); // BIP-39 seed is 64 bytes

    // BIP-0039 test vector (passphrase = "")
    // https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#Test_vectors
    const expected_seed_empty_hex =
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" ++
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    var expected_seed_empty: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_seed_empty, expected_seed_empty_hex);
    try testing.expectEqualSlices(u8, &expected_seed_empty, seed_empty);

    // Normalization: extra whitespace in the mnemonic should not change the derived seed.
    const seed_spaced = try mnemonicToSeed("  abandon abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon about   ", "", allocator);
    defer secure.secureZeroFree(allocator, seed_spaced);
    try testing.expectEqualSlices(u8, seed_empty, seed_spaced);

    const seed_trezor = try mnemonicToSeed(test_mnemonic, "TREZOR", allocator);
    defer secure.secureZeroFree(allocator, seed_trezor);
    try testing.expectEqual(@as(usize, 64), seed_trezor.len);

    // BIP-0039 test vector (passphrase = "TREZOR")
    const expected_seed_trezor_hex =
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553" ++
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    var expected_seed_trezor: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_seed_trezor, expected_seed_trezor_hex);
    try testing.expectEqualSlices(u8, &expected_seed_trezor, seed_trezor);
}

test "Bip39Account private key operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var bip39_account = try Bip39Account.create(allocator, "key_test_password");
    defer bip39_account.deinit();

    // Test private key access (equivalent to Swift private key tests)
    const private_key = try bip39_account.getPrivateKey();
    try testing.expect(private_key.isValid());

    // Test public key derivation
    const public_key = try bip39_account.getPublicKey();
    try testing.expect(public_key.isValid());

    // Verify key pair consistency
    const derived_public = try private_key.getPublicKey(true);
    try testing.expect(public_key.eql(derived_public));
}

test "Bip39Account deterministic NeoSwift vector" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    var bip39_account = try Bip39Account.fromBip39Mnemonic(allocator, "", test_mnemonic);
    defer bip39_account.deinit();

    const expected_private_key = try PrivateKey.fromHex("62a772f85e4be6226108b56c0b1cf935c2490e434adec864fe47b189f1ed517d");
    const private_key = try bip39_account.getPrivateKey();
    try testing.expect(private_key.eql(expected_private_key));

    const public_key = try bip39_account.getPublicKey();
    var expected_public_key_bytes: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_public_key_bytes, "0358dbd787ce6ce717c3718f95ebd527c97d2b6e7cbde02c034b1cf5882a18f2fb");
    try testing.expectEqualSlices(u8, &expected_public_key_bytes, public_key.toSlice());

    // Verify verification script bytes (single-sig).
    const ScriptBuilder = @import("../script/script_builder.zig").ScriptBuilder;
    const verification_script = try ScriptBuilder.buildVerificationScript(public_key.toSlice(), allocator);
    defer allocator.free(verification_script);

    const expected_script_hex = "0c21" ++
        "0358dbd787ce6ce717c3718f95ebd527c97d2b6e7cbde02c034b1cf5882a18f2fb" ++
        "4156e7b327";
    var expected_script: [40]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_script, expected_script_hex);
    try testing.expectEqualSlices(u8, &expected_script, verification_script);

    const expected_script_hash = try Hash160.fromHex("a8ddd585d807694285e4b048d090b3cf5b2888ec");
    try testing.expect(bip39_account.getScriptHash().eql(expected_script_hash));

    const address = try bip39_account.getAddress(allocator);
    defer allocator.free(address);
    try testing.expectEqualStrings("NhUdmRjvFtviZMrZut4X5Gv5vidp85355J", address);
}
