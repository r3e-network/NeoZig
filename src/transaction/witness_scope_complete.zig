//! Complete Witness Scope implementation
//!
//! Complete conversion from NeoSwift WitnessScope.swift
//! Provides comprehensive witness scope functionality with combination operations.

const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");

/// Complete witness scope (converted from Swift WitnessScope)
pub const CompleteWitnessScope = enum(u8) {
    /// Witness only used for transactions, disabled in contracts
    None = 0x00,
    /// Limits witness to contract called in transaction
    CalledByEntry = 0x01,
    /// Allows specification of additional contracts
    CustomContracts = 0x10,
    /// Allows specification of contract groups
    CustomGroups = 0x20,
    /// Current context must satisfy specified rules
    WitnessRules = 0x40,
    /// Global scope - allows use in all contexts
    Global = 0x80,

    const Self = @This();

    /// Gets JSON value (equivalent to Swift .jsonValue property)
    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .None => "None",
            .CalledByEntry => "CalledByEntry",
            .CustomContracts => "CustomContracts",
            .CustomGroups => "CustomGroups",
            .WitnessRules => "WitnessRules",
            .Global => "Global",
        };
    }

    /// Gets byte value (equivalent to Swift .byte property)
    pub fn getByte(self: Self) u8 {
        return @intFromEnum(self);
    }

    /// Creates from byte value (equivalent to Swift ByteEnum.throwingValueOf)
    pub fn fromByte(byte_value: u8) ?Self {
        return switch (byte_value) {
            0x00 => .None,
            0x01 => .CalledByEntry,
            0x10 => .CustomContracts,
            0x20 => .CustomGroups,
            0x40 => .WitnessRules,
            0x80 => .Global,
            else => null,
        };
    }

    /// Creates from byte value with error (equivalent to Swift throwingValueOf)
    pub fn throwingValueOf(byte_value: u8) !Self {
        return Self.fromByte(byte_value) orelse {
            return errors.throwIllegalArgument("Invalid witness scope byte value");
        };
    }

    /// Creates from JSON value (equivalent to Swift fromJsonValue)
    pub fn fromJsonValue(json_value: []const u8) ?Self {
        if (std.mem.eql(u8, json_value, "None")) return .None;
        if (std.mem.eql(u8, json_value, "CalledByEntry")) return .CalledByEntry;
        if (std.mem.eql(u8, json_value, "CustomContracts")) return .CustomContracts;
        if (std.mem.eql(u8, json_value, "CustomGroups")) return .CustomGroups;
        if (std.mem.eql(u8, json_value, "WitnessRules")) return .WitnessRules;
        if (std.mem.eql(u8, json_value, "Global")) return .Global;
        return null;
    }

    /// Gets all witness scopes (equivalent to Swift allCases)
    pub fn getAllCases() []const Self {
        return &[_]Self{ .None, .CalledByEntry, .CustomContracts, .CustomGroups, .WitnessRules, .Global };
    }

    /// Combines scopes into single byte (equivalent to Swift combineScopes)
    pub fn combineScopes(scopes: []const Self) u8 {
        var combined: u8 = 0;
        for (scopes) |scope| {
            combined |= scope.getByte();
        }
        return combined;
    }

    /// Extracts scopes from combined byte (equivalent to Swift extractCombinedScopes)
    pub fn extractCombinedScopes(combined_scopes: u8, allocator: std.mem.Allocator) ![]Self {
        if (combined_scopes == Self.None.getByte()) {
            var result = try allocator.alloc(Self, 1);
            result[0] = .None;
            return result;
        }

        var scopes = ArrayList(Self).init(allocator);
        defer scopes.deinit();

        const all_cases = getAllCases();
        for (all_cases) |scope| {
            if (scope != .None and (combined_scopes & scope.getByte()) != 0) {
                try scopes.append(scope);
            }
        }

        return try scopes.toOwnedSlice();
    }

    /// Checks if scope allows contract calls
    pub fn allowsContractCalls(self: Self) bool {
        return switch (self) {
            .None => false,
            .CalledByEntry => true,
            .CustomContracts => true,
            .CustomGroups => true,
            .WitnessRules => true,
            .Global => true,
        };
    }

    /// Checks if scope requires additional data
    pub fn requiresAdditionalData(self: Self) bool {
        return switch (self) {
            .CustomContracts => true,
            .CustomGroups => true,
            .WitnessRules => true,
            else => false,
        };
    }

    /// Gets scope description
    pub fn getDescription(self: Self) []const u8 {
        return switch (self) {
            .None => "Witness only for transactions, disabled in contracts",
            .CalledByEntry => "Limits witness to contract called in transaction",
            .CustomContracts => "Allows specification of additional contracts",
            .CustomGroups => "Allows specification of contract groups",
            .WitnessRules => "Current context must satisfy specified rules",
            .Global => "Global scope - allows use in all contexts",
        };
    }

    /// Validates scope configuration
    pub fn validateScope(self: Self, has_additional_data: bool) !void {
        if (self.requiresAdditionalData() and !has_additional_data) {
            return errors.TransactionError.InvalidSigner;
        }

        if (!self.requiresAdditionalData() and has_additional_data) {
            return errors.TransactionError.InvalidSigner;
        }
    }

    /// Checks if scopes are compatible
    pub fn areCompatible(scope1: Self, scope2: Self) bool {
        // Global cannot be combined with others
        if (scope1 == .Global or scope2 == .Global) {
            return scope1 == scope2;
        }

        // None cannot be combined with others
        if (scope1 == .None or scope2 == .None) {
            return scope1 == scope2;
        }

        return true;
    }

    /// Decodes from JSON (equivalent to Swift Codable)
    pub fn decodeFromJson(json_value: std.json.Value) !Self {
        return switch (json_value) {
            .string => |s| {
                return Self.fromJsonValue(s) orelse {
                    return errors.ValidationError.InvalidParameter;
                };
            },
            .integer => |i| {
                return Self.fromByte(@intCast(i)) orelse {
                    return errors.ValidationError.InvalidParameter;
                };
            },
            else => errors.ValidationError.InvalidFormat,
        };
    }

    /// Encodes to JSON (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        const value = try allocator.dupe(u8, self.getJsonValue());
        return std.json.Value{ .string = value };
    }
};

/// Witness scopes from string (converted from Swift @WitnessScopesFromString)
pub const WitnessScopesFromString = struct {
    scopes: []const CompleteWitnessScope,

    const Self = @This();

    /// Creates from scopes array
    pub fn init(scopes: []const CompleteWitnessScope) Self {
        return Self{ .scopes = scopes };
    }

    /// Parses from string (equivalent to Swift property wrapper decoding)
    pub fn fromString(string_value: []const u8, allocator: std.mem.Allocator) !Self {
        // Remove spaces and split by commas
        var cleaned = ArrayList(u8).init(allocator);
        defer cleaned.deinit();

        for (string_value) |char| {
            if (char != ' ') {
                try cleaned.append(char);
            }
        }

        var scopes = ArrayList(CompleteWitnessScope).init(allocator);
        defer scopes.deinit();

        var scope_iterator = std.mem.splitScalar(u8, cleaned.items, ',');
        while (scope_iterator.next()) |scope_str| {
            if (CompleteWitnessScope.fromJsonValue(scope_str)) |scope| {
                try scopes.append(scope);
            }
        }

        return Self{
            .scopes = try scopes.toOwnedSlice(),
        };
    }

    /// Converts to string (equivalent to Swift property wrapper encoding)
    pub fn toString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.scopes.len == 0) return try allocator.dupe(u8, "");

        var result = ArrayList(u8).init(allocator);
        defer result.deinit();

        for (self.scopes, 0..) |scope, i| {
            if (i > 0) try result.appendSlice(",");
            try result.appendSlice(scope.getJsonValue());
        }

        return try result.toOwnedSlice();
    }

    /// Cleanup resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.scopes);
    }

    /// Gets combined byte value
    pub fn getCombinedByte(self: Self) u8 {
        return CompleteWitnessScope.combineScopes(self.scopes);
    }

    /// Checks if contains specific scope
    pub fn contains(self: Self, scope: CompleteWitnessScope) bool {
        for (self.scopes) |s| {
            if (s == scope) return true;
        }
        return false;
    }

    /// Validates scope combination
    pub fn validate(self: Self) !void {
        if (self.scopes.len == 0) {
            return errors.TransactionError.InvalidSigner;
        }

        // Check for incompatible combinations
        for (self.scopes) |scope1| {
            for (self.scopes) |scope2| {
                if (!CompleteWitnessScope.areCompatible(scope1, scope2)) {
                    return errors.TransactionError.InvalidSigner;
                }
            }
        }

        // Global cannot be combined with others
        if (self.contains(.Global) and self.scopes.len > 1) {
            return errors.TransactionError.InvalidSigner;
        }
    }
};

/// Witness scope utilities
pub const WitnessScopeUtils = struct {
    /// Creates common scope combinations
    pub fn createCommonScopes(allocator: std.mem.Allocator) !CommonScopes {
        return CommonScopes{
            .none_only = try allocator.dupe(CompleteWitnessScope, &[_]CompleteWitnessScope{.None}),
            .called_by_entry_only = try allocator.dupe(CompleteWitnessScope, &[_]CompleteWitnessScope{.CalledByEntry}),
            .global_only = try allocator.dupe(CompleteWitnessScope, &[_]CompleteWitnessScope{.Global}),
            .custom_contracts_and_groups = try allocator.dupe(CompleteWitnessScope, &[_]CompleteWitnessScope{ .CustomContracts, .CustomGroups }),
        };
    }

    /// Validates scope for transaction type
    pub fn validateScopeForTransactionType(scope: CompleteWitnessScope, tx_type: TransactionType) !void {
        switch (tx_type) {
            .TokenTransfer => {
                if (!scope.allowsContractCalls()) {
                    return errors.TransactionError.InvalidSigner;
                }
            },
            .ContractDeployment => {
                if (scope == .None) {
                    return errors.TransactionError.InvalidSigner;
                }
            },
            .GovernanceVote => {
                if (scope != .Global and scope != .CalledByEntry) {
                    return errors.TransactionError.InvalidSigner;
                }
            },
            .FeeOnly => {
                if (scope != .None) {
                    return errors.TransactionError.InvalidSigner;
                }
            },
        }
    }

    /// Gets recommended scope for operation
    pub fn getRecommendedScope(operation: TransactionType) CompleteWitnessScope {
        return switch (operation) {
            .TokenTransfer => .CalledByEntry,
            .ContractDeployment => .CalledByEntry,
            .GovernanceVote => .Global,
            .FeeOnly => .None,
        };
    }
};

/// Common scope combinations
pub const CommonScopes = struct {
    none_only: []const CompleteWitnessScope,
    called_by_entry_only: []const CompleteWitnessScope,
    global_only: []const CompleteWitnessScope,
    custom_contracts_and_groups: []const CompleteWitnessScope,

    pub fn deinit(self: *CommonScopes, allocator: std.mem.Allocator) void {
        allocator.free(self.none_only);
        allocator.free(self.called_by_entry_only);
        allocator.free(self.global_only);
        allocator.free(self.custom_contracts_and_groups);
    }
};

/// Transaction types for scope validation
pub const TransactionType = enum {
    TokenTransfer,
    ContractDeployment,
    GovernanceVote,
    FeeOnly,
};

// Tests (converted from Swift WitnessScope tests)
test "CompleteWitnessScope values and properties" {
    const testing = std.testing;

    // Test scope values (equivalent to Swift WitnessScope tests)
    try testing.expectEqual(@as(u8, 0x00), CompleteWitnessScope.None.getByte());
    try testing.expectEqual(@as(u8, 0x01), CompleteWitnessScope.CalledByEntry.getByte());
    try testing.expectEqual(@as(u8, 0x10), CompleteWitnessScope.CustomContracts.getByte());
    try testing.expectEqual(@as(u8, 0x20), CompleteWitnessScope.CustomGroups.getByte());
    try testing.expectEqual(@as(u8, 0x40), CompleteWitnessScope.WitnessRules.getByte());
    try testing.expectEqual(@as(u8, 0x80), CompleteWitnessScope.Global.getByte());

    // Test JSON values
    try testing.expectEqualStrings("None", CompleteWitnessScope.None.getJsonValue());
    try testing.expectEqualStrings("CalledByEntry", CompleteWitnessScope.CalledByEntry.getJsonValue());
    try testing.expectEqualStrings("Global", CompleteWitnessScope.Global.getJsonValue());

    // Test descriptions
    try testing.expect(std.mem.indexOf(u8, CompleteWitnessScope.None.getDescription(), "transactions") != null);
    try testing.expect(std.mem.indexOf(u8, CompleteWitnessScope.Global.getDescription(), "all contexts") != null);
}

test "CompleteWitnessScope combination operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test scope combination (equivalent to Swift combineScopes tests)
    const scopes = [_]CompleteWitnessScope{ .CalledByEntry, .CustomContracts };
    const combined_byte = CompleteWitnessScope.combineScopes(&scopes);
    try testing.expectEqual(@as(u8, 0x11), combined_byte); // 0x01 | 0x10 = 0x11

    // Test scope extraction (equivalent to Swift extractCombinedScopes tests)
    const extracted_scopes = try CompleteWitnessScope.extractCombinedScopes(combined_byte, allocator);
    defer allocator.free(extracted_scopes);

    try testing.expectEqual(@as(usize, 2), extracted_scopes.len);
    try testing.expect(std.mem.indexOf(CompleteWitnessScope, extracted_scopes, &[_]CompleteWitnessScope{.CalledByEntry}) != null);
    try testing.expect(std.mem.indexOf(CompleteWitnessScope, extracted_scopes, &[_]CompleteWitnessScope{.CustomContracts}) != null);

    // Test None scope extraction
    const none_scopes = try CompleteWitnessScope.extractCombinedScopes(0x00, allocator);
    defer allocator.free(none_scopes);

    try testing.expectEqual(@as(usize, 1), none_scopes.len);
    try testing.expectEqual(CompleteWitnessScope.None, none_scopes[0]);
}

test "WitnessScopesFromString operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test parsing from string (equivalent to Swift property wrapper tests)
    var scopes_from_string = try WitnessScopesFromString.fromString("CalledByEntry,CustomContracts", allocator);
    defer scopes_from_string.deinit(allocator);

    try testing.expectEqual(@as(usize, 2), scopes_from_string.scopes.len);
    try testing.expect(scopes_from_string.contains(.CalledByEntry));
    try testing.expect(scopes_from_string.contains(.CustomContracts));

    // Test string conversion
    const string_representation = try scopes_from_string.toString(allocator);
    defer allocator.free(string_representation);

    try testing.expect(std.mem.indexOf(u8, string_representation, "CalledByEntry") != null);
    try testing.expect(std.mem.indexOf(u8, string_representation, "CustomContracts") != null);

    // Test validation
    try scopes_from_string.validate();

    // Test invalid combination (Global with others)
    var invalid_scopes = try WitnessScopesFromString.fromString("Global,CalledByEntry", allocator);
    defer invalid_scopes.deinit(allocator);

    try testing.expectError(errors.TransactionError.InvalidSigner, invalid_scopes.validate());
}

test "WitnessScopeUtils utility functions" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test scope compatibility (equivalent to Swift compatibility tests)
    try testing.expect(CompleteWitnessScope.areCompatible(.CalledByEntry, .CustomContracts));
    try testing.expect(CompleteWitnessScope.areCompatible(.CustomContracts, .CustomGroups));
    try testing.expect(!CompleteWitnessScope.areCompatible(.Global, .CalledByEntry));
    try testing.expect(!CompleteWitnessScope.areCompatible(.None, .CalledByEntry));

    // Test additional data requirements
    try testing.expect(!CompleteWitnessScope.None.requiresAdditionalData());
    try testing.expect(!CompleteWitnessScope.CalledByEntry.requiresAdditionalData());
    try testing.expect(CompleteWitnessScope.CustomContracts.requiresAdditionalData());
    try testing.expect(CompleteWitnessScope.CustomGroups.requiresAdditionalData());
    try testing.expect(CompleteWitnessScope.WitnessRules.requiresAdditionalData());
    try testing.expect(!CompleteWitnessScope.Global.requiresAdditionalData());

    // Test contract call allowance
    try testing.expect(!CompleteWitnessScope.None.allowsContractCalls());
    try testing.expect(CompleteWitnessScope.CalledByEntry.allowsContractCalls());
    try testing.expect(CompleteWitnessScope.Global.allowsContractCalls());

    // Test recommended scopes
    try testing.expectEqual(CompleteWitnessScope.CalledByEntry, WitnessScopeUtils.getRecommendedScope(.TokenTransfer));
    try testing.expectEqual(CompleteWitnessScope.Global, WitnessScopeUtils.getRecommendedScope(.GovernanceVote));
    try testing.expectEqual(CompleteWitnessScope.None, WitnessScopeUtils.getRecommendedScope(.FeeOnly));

    // Test scope validation for transaction types
    try WitnessScopeUtils.validateScopeForTransactionType(.CalledByEntry, .TokenTransfer);
    try WitnessScopeUtils.validateScopeForTransactionType(.Global, .GovernanceVote);
    try WitnessScopeUtils.validateScopeForTransactionType(.None, .FeeOnly);

    try testing.expectError(errors.TransactionError.InvalidSigner, WitnessScopeUtils.validateScopeForTransactionType(.None, .TokenTransfer));
}
