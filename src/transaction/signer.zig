//! Signer Implementation
//!
//! Complete conversion from NeoSwift Signer.swift
//! Provides transaction signer with scope management.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const WitnessScope = @import("witness_scope_complete.zig").WitnessScope;
const PublicKey = @import("../crypto/keys.zig").PublicKey;
const WitnessRule = @import("witness_rule.zig").WitnessRule;
const TransactionError = @import("transaction_error.zig").TransactionError;

/// Transaction signer (converted from Swift Signer)
pub const Signer = struct {
    /// Script hash of the signer account
    signer_hash: Hash160,
    /// Witness scopes
    scopes: []WitnessScope,
    /// Allowed contracts (for CustomContracts scope)
    allowed_contracts: []Hash160,
    /// Allowed groups (for CustomGroups scope)
    allowed_groups: []PublicKey,
    /// Witness rules (for Rules scope)
    rules: []WitnessRule,
    
    const Self = @This();
    
    /// Creates new signer (equivalent to Swift internal init)
    pub fn init(signer_hash: Hash160, scope: WitnessScope, allocator: std.mem.Allocator) !Self {
        const scopes = try allocator.dupe(WitnessScope, &[_]WitnessScope{scope});
        
        return Self{
            .signer_hash = signer_hash,
            .scopes = scopes,
            .allowed_contracts = &[_]Hash160{},
            .allowed_groups = &[_]PublicKey{},
            .rules = &[_]WitnessRule{},
        };
    }
    
    /// Creates signer with multiple configuration (equivalent to Swift private init)
    pub fn initComplete(
        signer_hash: Hash160,
        scopes: []WitnessScope,
        allowed_contracts: []Hash160,
        allowed_groups: []PublicKey,
        rules: []WitnessRule,
        allocator: std.mem.Allocator,
    ) !Self {
        return Self{
            .signer_hash = signer_hash,
            .scopes = try allocator.dupe(WitnessScope, scopes),
            .allowed_contracts = try allocator.dupe(Hash160, allowed_contracts),
            .allowed_groups = try allocator.dupe(PublicKey, allowed_groups),
            .rules = try allocator.dupe(WitnessRule, rules),
        };
    }
    
    /// Gets the script hash
    pub fn getScriptHash(self: Self) Hash160 {
        return self.signer_hash;
    }
    
    /// Gets witness scope (first scope if multiple)
    pub fn getWitnessScope(self: Self) WitnessScope {
        if (self.scopes.len > 0) return self.scopes[0];
        return WitnessScope.None;
    }
    
    /// Gets all witness scopes
    pub fn getAllScopes(self: Self) []const WitnessScope {
        return self.scopes;
    }
    
    /// Checks if has specific scope
    pub fn hasScope(self: Self, scope: WitnessScope) bool {
        for (self.scopes) |existing_scope| {
            if (existing_scope.eql(scope)) return true;
        }
        return false;
    }
    
    /// Sets allowed contracts (equivalent to Swift setAllowedContracts)
    pub fn setAllowedContracts(self: *Self, allowed_contracts: []const Hash160, allocator: std.mem.Allocator) !void {
        if (allowed_contracts.len == 0) return;
        
        // Check for global scope conflict
        if (self.hasScope(WitnessScope.Global)) {
            return TransactionError.SignerConfiguration.init("Cannot set allowed contracts on signer with global scope");
        }
        
        // Check maximum limit
        if (self.allowed_contracts.len + allowed_contracts.len > constants.MAX_SIGNER_SUBITEMS) {
            return TransactionError.SignerConfiguration.init("Too many allowed contracts");
        }
        
        // Remove None scope if present
        var filtered_scopes = ArrayList(WitnessScope).init(allocator);
        defer filtered_scopes.deinit();
        
        for (self.scopes) |scope| {
            if (!scope.eql(WitnessScope.None)) {
                try filtered_scopes.append(scope);
            }
        }
        
        // Add CustomContracts scope if not present
        if (!self.hasScope(WitnessScope.CustomContracts)) {
            try filtered_scopes.append(WitnessScope.CustomContracts);
        }
        
        // Update scopes
        allocator.free(self.scopes);
        self.scopes = try filtered_scopes.toOwnedSlice();
        
        // Update allowed contracts
        const new_contracts = try std.mem.concat(allocator, Hash160, &[_][]const Hash160{ self.allowed_contracts, allowed_contracts });
        allocator.free(self.allowed_contracts);
        self.allowed_contracts = new_contracts;
    }
    
    /// Sets allowed groups (equivalent to Swift setAllowedGroups)
    pub fn setAllowedGroups(self: *Self, allowed_groups: []const PublicKey, allocator: std.mem.Allocator) !void {
        if (allowed_groups.len == 0) return;
        
        // Check for global scope conflict
        if (self.hasScope(WitnessScope.Global)) {
            return TransactionError.SignerConfiguration.init("Cannot set allowed groups on signer with global scope");
        }
        
        // Check maximum limit
        if (self.allowed_groups.len + allowed_groups.len > constants.MAX_SIGNER_SUBITEMS) {
            return TransactionError.SignerConfiguration.init("Too many allowed groups");
        }
        
        // Remove None scope if present
        var filtered_scopes = ArrayList(WitnessScope).init(allocator);
        defer filtered_scopes.deinit();
        
        for (self.scopes) |scope| {
            if (!scope.eql(WitnessScope.None)) {
                try filtered_scopes.append(scope);
            }
        }
        
        // Add CustomGroups scope if not present
        if (!self.hasScope(WitnessScope.CustomGroups)) {
            try filtered_scopes.append(WitnessScope.CustomGroups);
        }
        
        // Update scopes
        allocator.free(self.scopes);
        self.scopes = try filtered_scopes.toOwnedSlice();
        
        // Update allowed groups
        const new_groups = try std.mem.concat(allocator, PublicKey, &[_][]const PublicKey{ self.allowed_groups, allowed_groups });
        allocator.free(self.allowed_groups);
        self.allowed_groups = new_groups;
    }
    
    /// Sets witness rules (equivalent to Swift setRules)
    pub fn setRules(self: *Self, rules: []const WitnessRule, allocator: std.mem.Allocator) !void {
        if (rules.len == 0) return;
        
        // Check for global scope conflict
        if (self.hasScope(WitnessScope.Global)) {
            return TransactionError.SignerConfiguration.init("Cannot set rules on signer with global scope");
        }
        
        // Remove None scope if present and add Rules scope
        var filtered_scopes = ArrayList(WitnessScope).init(allocator);
        defer filtered_scopes.deinit();
        
        for (self.scopes) |scope| {
            if (!scope.eql(WitnessScope.None)) {
                try filtered_scopes.append(scope);
            }
        }
        
        if (!self.hasScope(WitnessScope.Rules)) {
            try filtered_scopes.append(WitnessScope.Rules);
        }
        
        // Update scopes
        allocator.free(self.scopes);
        self.scopes = try filtered_scopes.toOwnedSlice();
        
        // Update rules
        allocator.free(self.rules);
        self.rules = try allocator.dupe(WitnessRule, rules);
    }
    
    /// Checks if signer can sign for specific contract
    pub fn canSignFor(self: Self, contract_hash: Hash160) bool {
        // Global scope can sign for anything
        if (self.hasScope(WitnessScope.Global)) return true;
        
        // CalledByEntry scope can sign for entry contract
        if (self.hasScope(WitnessScope.CalledByEntry)) return true;
        
        // CustomContracts scope - check allowed contracts
        if (self.hasScope(WitnessScope.CustomContracts)) {
            for (self.allowed_contracts) |allowed| {
                if (allowed.eql(contract_hash)) return true;
            }
        }
        
        return false;
    }
    
    /// Gets all allowed contracts
    pub fn getAllowedContracts(self: Self) []const Hash160 {
        return self.allowed_contracts;
    }
    
    /// Gets all allowed groups
    pub fn getAllowedGroups(self: Self) []const PublicKey {
        return self.allowed_groups;
    }
    
    /// Gets all witness rules
    pub fn getRules(self: Self) []const WitnessRule {
        return self.rules;
    }
    
    /// Validates signer configuration
    pub fn validate(self: Self) !void {
        if (self.scopes.len == 0) {
            return TransactionError.SignerConfiguration.init("Signer must have at least one scope");
        }
        
        // Validate scope combinations
        if (self.hasScope(WitnessScope.Global) and self.scopes.len > 1) {
            return TransactionError.SignerConfiguration.init("Global scope cannot be combined with other scopes");
        }
        
        // Validate allowed contracts limit
        if (self.allowed_contracts.len > constants.MAX_SIGNER_SUBITEMS) {
            return TransactionError.SignerConfiguration.init("Too many allowed contracts");
        }
        
        // Validate allowed groups limit
        if (self.allowed_groups.len > constants.MAX_SIGNER_SUBITEMS) {
            return TransactionError.SignerConfiguration.init("Too many allowed groups");
        }
    }
    
    /// Gets estimated witness size
    pub fn getEstimatedWitnessSize(self: Self) usize {
        // Base size for signature + verification script
        var size: usize = 64 + 40; // Signature + verification script
        
        // Add overhead for custom scopes
        if (self.hasScope(WitnessScope.CustomContracts)) {
            size += self.allowed_contracts.len * 20; // Hash160 size
        }
        
        if (self.hasScope(WitnessScope.CustomGroups)) {
            size += self.allowed_groups.len * 33; // Compressed public key size
        }
        
        if (self.hasScope(WitnessScope.Rules)) {
            size += self.rules.len * 32; // Estimated rule size
        }
        
        return size;
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        if (!self.signer_hash.eql(other.signer_hash) or 
            self.scopes.len != other.scopes.len or
            self.allowed_contracts.len != other.allowed_contracts.len or
            self.allowed_groups.len != other.allowed_groups.len or
            self.rules.len != other.rules.len) {
            return false;
        }
        
        // Compare scopes
        for (self.scopes, 0..) |scope, i| {
            if (!scope.eql(other.scopes[i])) return false;
        }
        
        // Compare allowed contracts
        for (self.allowed_contracts, 0..) |contract, i| {
            if (!contract.eql(other.allowed_contracts[i])) return false;
        }
        
        // Compare allowed groups
        for (self.allowed_groups, 0..) |group, i| {
            if (!group.eql(other.allowed_groups[i])) return false;
        }
        
        // Compare rules
        for (self.rules, 0..) |rule, i| {
            if (!rule.eql(other.rules[i])) return false;
        }
        
        return true;
    }
    
    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        const signer_hash = self.signer_hash.hash();
        hasher.update(std.mem.asBytes(&signer_hash));
        
        for (self.scopes) |scope| {
            const scope_hash = scope.hash();
            hasher.update(std.mem.asBytes(&scope_hash));
        }
        
        for (self.allowed_contracts) |contract| {
            const contract_hash = contract.hash();
            hasher.update(std.mem.asBytes(&contract_hash));
        }
        
        for (self.allowed_groups) |group| {
            const group_hash = group.hash();
            hasher.update(std.mem.asBytes(&group_hash));
        }
        
        for (self.rules) |rule| {
            const rule_hash = rule.hash();
            hasher.update(std.mem.asBytes(&rule_hash));
        }
        
        return hasher.final();
    }
    
    /// JSON encoding
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const signer_hash_str = try self.signer_hash.toString(allocator);
        defer allocator.free(signer_hash_str);
        
        // Encode scopes
        var scopes_json = ArrayList(u8).init(allocator);
        defer scopes_json.deinit();
        
        try scopes_json.appendSlice("[");
        for (self.scopes, 0..) |scope, i| {
            if (i > 0) try scopes_json.appendSlice(",");
            const scope_json = try scope.encodeToJson(allocator);
            defer allocator.free(scope_json);
            try scopes_json.appendSlice(scope_json);
        }
        try scopes_json.appendSlice("]");
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"signerHash\":\"{s}\",\"scopes\":{s}}}",
            .{ signer_hash_str, scopes_json.items }
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.scopes);
        allocator.free(self.allowed_contracts);
        allocator.free(self.allowed_groups);
        allocator.free(self.rules);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        return Self{
            .signer_hash = self.signer_hash,
            .scopes = try allocator.dupe(WitnessScope, self.scopes),
            .allowed_contracts = try allocator.dupe(Hash160, self.allowed_contracts),
            .allowed_groups = try allocator.dupe(PublicKey, self.allowed_groups),
            .rules = try allocator.dupe(WitnessRule, self.rules),
        };
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const signer_hash_str = try self.signer_hash.toString(allocator);
        defer allocator.free(signer_hash_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "Signer(hash: {s}, scopes: {}, contracts: {}, groups: {}, rules: {})",
            .{ 
                signer_hash_str, 
                self.scopes.len, 
                self.allowed_contracts.len, 
                self.allowed_groups.len, 
                self.rules.len 
            }
        );
    }
};

// Tests (converted from Swift Signer tests)
test "Signer creation and basic properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test signer creation (equivalent to Swift tests)
    const signer_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    var signer = try Signer.init(signer_hash, WitnessScope.CalledByEntry, allocator);
    defer signer.deinit(allocator);
    
    try testing.expect(signer.getScriptHash().eql(signer_hash));
    try testing.expectEqual(WitnessScope.CalledByEntry, signer.getWitnessScope());
    try testing.expect(signer.hasScope(WitnessScope.CalledByEntry));
    try testing.expect(!signer.hasScope(WitnessScope.Global));
    
    // Test validation
    try signer.validate();
}

test "Signer scope management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test multiple scopes
    const signer_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const scopes = [_]WitnessScope{ WitnessScope.CalledByEntry, WitnessScope.CustomContracts };
    
    var signer = try Signer.initComplete(
        signer_hash,
        &scopes,
        &[_]Hash160{},
        &[_]PublicKey{},
        &[_]WitnessRule{},
        allocator,
    );
    defer signer.deinit(allocator);
    
    try testing.expectEqual(@as(usize, 2), signer.getAllScopes().len);
    try testing.expect(signer.hasScope(WitnessScope.CalledByEntry));
    try testing.expect(signer.hasScope(WitnessScope.CustomContracts));
}

test "Signer allowed contracts management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test setting allowed contracts
    const signer_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    var signer = try Signer.init(signer_hash, WitnessScope.None, allocator);
    defer signer.deinit(allocator);
    
    const contract1 = try Hash160.initWithString("0xabcdef1234567890abcdef1234567890abcdef12");
    const contract2 = try Hash160.initWithString("0x9876543210fedcba9876543210fedcba98765432");
    const allowed_contracts = [_]Hash160{ contract1, contract2 };
    
    try signer.setAllowedContracts(&allowed_contracts, allocator);
    
    try testing.expect(signer.hasScope(WitnessScope.CustomContracts));
    try testing.expectEqual(@as(usize, 2), signer.getAllowedContracts().len);
    try testing.expect(signer.canSignFor(contract1));
    try testing.expect(signer.canSignFor(contract2));
    
    // Test with disallowed contract
    const other_contract = try Hash160.initWithString("0x1111111111111111111111111111111111111111");
    try testing.expect(!signer.canSignFor(other_contract));
}

test "Signer global scope restrictions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test global scope restrictions
    const signer_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    var global_signer = try Signer.init(signer_hash, WitnessScope.Global, allocator);
    defer global_signer.deinit(allocator);
    
    // Should be able to sign for any contract
    const any_contract = try Hash160.initWithString("0x9999999999999999999999999999999999999999");
    try testing.expect(global_signer.canSignFor(any_contract));
    
    // Should not be able to set allowed contracts
    const contract = try Hash160.initWithString("0xabcdef1234567890abcdef1234567890abcdef12");
    const contracts = [_]Hash160{contract};
    
    try testing.expectError(
        TransactionError.SignerConfiguration,
        global_signer.setAllowedContracts(&contracts, allocator)
    );
}

test "Signer equality and hashing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test equality
    const signer_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    var signer1 = try Signer.init(signer_hash, WitnessScope.CalledByEntry, allocator);
    defer signer1.deinit(allocator);
    
    var signer2 = try Signer.init(signer_hash, WitnessScope.CalledByEntry, allocator);
    defer signer2.deinit(allocator);
    
    var signer3 = try Signer.init(signer_hash, WitnessScope.Global, allocator);
    defer signer3.deinit(allocator);
    
    try testing.expect(signer1.eql(signer2));
    try testing.expect(!signer1.eql(signer3));
    
    // Test hashing
    const hash1 = signer1.hash();
    const hash2 = signer2.hash();
    const hash3 = signer3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same signers should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different signers should have different hash
}