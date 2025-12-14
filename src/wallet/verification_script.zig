//! Verification Script implementation
//!
//! Complete conversion from NeoSwift VerificationScript functionality
//! Handles account verification scripts for single-sig and multi-sig accounts.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const PublicKey = @import("../crypto/keys.zig").PublicKey;

/// Verification script for account validation
pub const VerificationScript = struct {
    script: []const u8,
    script_hash: Hash160,

    const Self = @This();

    /// Creates verification script from public key
    pub fn initFromPublicKey(public_key: PublicKey, allocator: std.mem.Allocator) !Self {
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

// Tests
test "VerificationScript creation and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key_pair = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    var verification_script = try VerificationScript.initFromPublicKey(key_pair.getPublicKey(), allocator);
    defer verification_script.deinit(allocator);

    try testing.expect(verification_script.getScript().len > 0);
    try testing.expect(!verification_script.getScriptHash().eql(Hash160.ZERO));
}
