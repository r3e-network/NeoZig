//! Witness Action Implementation
//!
//! Complete conversion from NeoSwift WitnessAction.swift
//! Provides witness action types for witness rules.

const std = @import("std");



/// Witness action for witness rules (converted from Swift WitnessAction)
pub const WitnessAction = enum(u8) {
    /// Deny action
    Deny = 0,
    /// Allow action
    Allow = 1,
    
    /// Gets JSON value (equivalent to Swift jsonValue)
    pub fn toJsonString(self: WitnessAction) []const u8 {
        return switch (self) {
            .Deny => "Deny",
            .Allow => "Allow",
        };
    }
    
    /// Gets byte value (equivalent to Swift byte property)
    pub fn toByte(self: WitnessAction) u8 {
        return @intFromEnum(self);
    }
    
    /// Creates from byte value (equivalent to Swift ByteEnum protocol)
    pub fn fromByte(byte_value: u8) ?WitnessAction {
        return switch (byte_value) {
            0 => .Deny,
            1 => .Allow,
            else => null,
        };
    }
    
    /// Creates from JSON string
    pub fn fromJsonString(json_string: []const u8) ?WitnessAction {
        if (std.mem.eql(u8, json_string, "Deny")) return .Deny;
        if (std.mem.eql(u8, json_string, "Allow")) return .Allow;
        return null;
    }
    
    /// Gets all available actions
    pub fn getAllActions() []const WitnessAction {
        const actions = [_]WitnessAction{ .Deny, .Allow };
        return &actions;
    }
    
    /// Checks if action allows witness usage
    pub fn isAllow(self: WitnessAction) bool {
        return self == .Allow;
    }
    
    /// Checks if action denies witness usage
    pub fn isDeny(self: WitnessAction) bool {
        return self == .Deny;
    }
    
    /// Gets opposite action
    pub fn opposite(self: WitnessAction) WitnessAction {
        return switch (self) {
            .Deny => .Allow,
            .Allow => .Deny,
        };
    }
    
    /// Combines two actions (AND logic)
    pub fn combineAnd(self: WitnessAction, other: WitnessAction) WitnessAction {
        // Both must allow for result to allow
        if (self == .Allow and other == .Allow) {
            return .Allow;
        }
        return .Deny;
    }
    
    /// Combines two actions (OR logic)
    pub fn combineOr(self: WitnessAction, other: WitnessAction) WitnessAction {
        // Either can allow for result to allow
        if (self == .Allow or other == .Allow) {
            return .Allow;
        }
        return .Deny;
    }
    
    /// Gets action description
    pub fn getDescription(self: WitnessAction) []const u8 {
        return switch (self) {
            .Deny => "Denies witness usage",
            .Allow => "Allows witness usage",
        };
    }
    
    /// Gets action priority (for conflict resolution)
    pub fn getPriority(self: WitnessAction) u8 {
        return switch (self) {
            .Deny => 1, // Higher priority (more restrictive)
            .Allow => 0, // Lower priority
        };
    }
    
    /// Resolves conflict between actions (highest priority wins)
    pub fn resolveConflict(actions: []const WitnessAction) WitnessAction {
        var highest_priority: u8 = 0;
        var result = WitnessAction.Allow;
        
        for (actions) |action| {
            const priority = action.getPriority();
            if (priority > highest_priority) {
                highest_priority = priority;
                result = action;
            }
        }
        
        return result;
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: WitnessAction, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "\"{s}\"", .{self.toJsonString()});
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8) !WitnessAction {
        if (std.mem.startsWith(u8, json_str, "\"") and std.mem.endsWith(u8, json_str, "\"")) {
            const content = json_str[1 .. json_str.len - 1];
            return WitnessAction.fromJsonString(content) orelse error.InvalidWitnessAction;
        }
        
        return WitnessAction.fromJsonString(json_str) orelse error.InvalidWitnessAction;
    }
    
    /// Format for display
    pub fn format(self: WitnessAction, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "WitnessAction.{s} ({})",
            .{ self.toJsonString(), self.toByte() }
        );
    }
};

/// Witness action utilities
pub const WitnessActionUtils = struct {
    /// Evaluates action against condition result
    pub fn evaluateAction(action: WitnessAction, condition_result: bool) bool {
        return switch (action) {
            .Allow => condition_result,      // Allow if condition is true
            .Deny => !condition_result,     // Deny if condition is true (inverse logic)
        };
    }
    
    /// Creates action from boolean preference
    pub fn fromBoolean(allow: bool) WitnessAction {
        return if (allow) .Allow else .Deny;
    }
    
    /// Gets default action for security
    pub fn getDefaultSecureAction() WitnessAction {
        return .Deny; // Default to deny for security
    }
    
    /// Gets default action for convenience
    pub fn getDefaultConvenientAction() WitnessAction {
        return .Allow; // Default to allow for convenience
    }
    
    /// Validates action compatibility with scope
    pub fn validateActionForScope(action: WitnessAction, scope_type: []const u8) !void {
        _ = action;
        _ = scope_type;
        // Basic validation - all actions are compatible with all scopes
        // More complex validation could be added here
    }
    
    /// Gets recommended action for operation type
    pub fn getRecommendedAction(operation_type: []const u8) WitnessAction {
        // Conservative recommendations
        if (std.mem.eql(u8, operation_type, "transfer")) return .Allow;
        if (std.mem.eql(u8, operation_type, "deploy")) return .Deny;   // More restrictive
        if (std.mem.eql(u8, operation_type, "update")) return .Deny;   // More restrictive
        if (std.mem.eql(u8, operation_type, "destroy")) return .Deny;  // More restrictive
        
        return .Deny; // Default to deny for unknown operations
    }
};

// Tests (converted from Swift WitnessAction tests)
test "WitnessAction creation and properties" {
    const testing = std.testing;
    
    // Test action creation and properties (equivalent to Swift tests)
    try testing.expectEqualStrings("Allow", WitnessAction.Allow.toJsonString());
    try testing.expectEqualStrings("Deny", WitnessAction.Deny.toJsonString());
    
    try testing.expectEqual(@as(u8, 1), WitnessAction.Allow.toByte());
    try testing.expectEqual(@as(u8, 0), WitnessAction.Deny.toByte());
    
    try testing.expect(WitnessAction.Allow.isAllow());
    try testing.expect(!WitnessAction.Allow.isDeny());
    try testing.expect(WitnessAction.Deny.isDeny());
    try testing.expect(!WitnessAction.Deny.isAllow());
}

test "WitnessAction conversion operations" {
    const testing = std.testing;
    
    // Test from byte conversion
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.fromByte(1).?);
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.fromByte(0).?);
    try testing.expect(WitnessAction.fromByte(99) == null);
    
    // Test from JSON string conversion
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.fromJsonString("Allow").?);
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.fromJsonString("Deny").?);
    try testing.expect(WitnessAction.fromJsonString("Invalid") == null);
    
    // Test opposite action
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.Allow.opposite());
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.Deny.opposite());
}

test "WitnessAction logical operations" {
    const testing = std.testing;
    
    // Test AND logic
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.Allow.combineAnd(.Allow));
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.Allow.combineAnd(.Deny));
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.Deny.combineAnd(.Allow));
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.Deny.combineAnd(.Deny));
    
    // Test OR logic
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.Allow.combineOr(.Allow));
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.Allow.combineOr(.Deny));
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.Deny.combineOr(.Allow));
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.Deny.combineOr(.Deny));
}

test "WitnessActionUtils utility functions" {
    const testing = std.testing;
    
    // Test action evaluation
    try testing.expect(WitnessActionUtils.evaluateAction(.Allow, true));   // Allow + true = true
    try testing.expect(!WitnessActionUtils.evaluateAction(.Allow, false)); // Allow + false = false
    try testing.expect(!WitnessActionUtils.evaluateAction(.Deny, true));   // Deny + true = false (inverse)
    try testing.expect(WitnessActionUtils.evaluateAction(.Deny, false));   // Deny + false = true (inverse)
    
    // Test from boolean
    try testing.expectEqual(WitnessAction.Allow, WitnessActionUtils.fromBoolean(true));
    try testing.expectEqual(WitnessAction.Deny, WitnessActionUtils.fromBoolean(false));
    
    // Test default actions
    try testing.expectEqual(WitnessAction.Deny, WitnessActionUtils.getDefaultSecureAction());
    try testing.expectEqual(WitnessAction.Allow, WitnessActionUtils.getDefaultConvenientAction());
    
    // Test recommended actions
    try testing.expectEqual(WitnessAction.Allow, WitnessActionUtils.getRecommendedAction("transfer"));
    try testing.expectEqual(WitnessAction.Deny, WitnessActionUtils.getRecommendedAction("deploy"));
    try testing.expectEqual(WitnessAction.Deny, WitnessActionUtils.getRecommendedAction("unknown"));
}

test "WitnessAction conflict resolution" {
    const testing = std.testing;
    
    // Test conflict resolution
    const actions1 = [_]WitnessAction{ .Allow, .Allow, .Allow };
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.resolveConflict(&actions1));
    
    const actions2 = [_]WitnessAction{ .Allow, .Deny, .Allow };
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.resolveConflict(&actions2)); // Deny has higher priority
    
    const actions3 = [_]WitnessAction{ .Deny, .Deny };
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.resolveConflict(&actions3));
    
    // Test empty actions
    const no_actions = [_]WitnessAction{};
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.resolveConflict(&no_actions)); // Default
}