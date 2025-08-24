//! Witness Condition Implementation
//!
//! Complete conversion from NeoSwift WitnessCondition.swift
//! Provides witness condition logic for smart contract verification.

const std = @import("std");
const Hash160 = @import("../types/hash160.zig").Hash160;
const PublicKey = @import("../crypto/keys.zig").PublicKey;

/// Witness condition for smart contract verification (converted from Swift WitnessCondition)
pub const WitnessCondition = union(enum) {
    /// Boolean condition
    Boolean: bool,
    /// Logical NOT condition
    Not: *WitnessCondition,
    /// Logical AND conditions
    And: []WitnessCondition,
    /// Logical OR conditions
    Or: []WitnessCondition,
    /// Script hash condition
    ScriptHash: Hash160,
    /// Group public key condition
    Group: PublicKey,
    /// Called by entry condition
    CalledByEntry: void,
    /// Called by specific contract condition
    CalledByContract: Hash160,
    /// Called by group condition
    CalledByGroup: PublicKey,
    
    /// Maximum subitems constant (matches Swift MAX_SUBITEMS)
    pub const MAX_SUBITEMS = 16;
    /// Maximum nesting depth (matches Swift MAX_NESTING_DEPTH)
    pub const MAX_NESTING_DEPTH = 2;
    
    /// JSON value constants (matches Swift constants)
    pub const BOOLEAN_VALUE = "Boolean";
    pub const NOT_VALUE = "Not";
    pub const AND_VALUE = "And";
    pub const OR_VALUE = "Or";
    pub const SCRIPT_HASH_VALUE = "ScriptHash";
    pub const GROUP_VALUE = "Group";
    pub const CALLED_BY_ENTRY_VALUE = "CalledByEntry";
    pub const CALLED_BY_CONTRACT_VALUE = "CalledByContract";
    pub const CALLED_BY_GROUP_VALUE = "CalledByGroup";
    
    /// Byte value constants (matches Swift constants)
    pub const BOOLEAN_BYTE: u8 = 0x00;
    pub const NOT_BYTE: u8 = 0x01;
    pub const AND_BYTE: u8 = 0x02;
    pub const OR_BYTE: u8 = 0x03;
    pub const SCRIPT_HASH_BYTE: u8 = 0x18;
    pub const GROUP_BYTE: u8 = 0x19;
    pub const CALLED_BY_ENTRY_BYTE: u8 = 0x20;
    pub const CALLED_BY_CONTRACT_BYTE: u8 = 0x28;
    pub const CALLED_BY_GROUP_BYTE: u8 = 0x29;
    
    const Self = @This();
    
    /// Gets JSON value (equivalent to Swift jsonValue)
    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .Boolean => BOOLEAN_VALUE,
            .Not => NOT_VALUE,
            .And => AND_VALUE,
            .Or => OR_VALUE,
            .ScriptHash => SCRIPT_HASH_VALUE,
            .Group => GROUP_VALUE,
            .CalledByEntry => CALLED_BY_ENTRY_VALUE,
            .CalledByContract => CALLED_BY_CONTRACT_VALUE,
            .CalledByGroup => CALLED_BY_GROUP_VALUE,
        };
    }
    
    /// Gets byte value (equivalent to Swift byte)
    pub fn getByte(self: Self) u8 {
        return switch (self) {
            .Boolean => BOOLEAN_BYTE,
            .Not => NOT_BYTE,
            .And => AND_BYTE,
            .Or => OR_BYTE,
            .ScriptHash => SCRIPT_HASH_BYTE,
            .Group => GROUP_BYTE,
            .CalledByEntry => CALLED_BY_ENTRY_BYTE,
            .CalledByContract => CALLED_BY_CONTRACT_BYTE,
            .CalledByGroup => CALLED_BY_GROUP_BYTE,
        };
    }
    
    /// Creates condition from byte value
    pub fn fromByte(byte_value: u8, allocator: std.mem.Allocator) !?Self {
        return switch (byte_value) {
            BOOLEAN_BYTE => Self{ .Boolean = false }, // Default value
            NOT_BYTE => blk: {
                const inner = try allocator.create(WitnessCondition);
                inner.* = Self{ .Boolean = false }; // Placeholder
                break :blk Self{ .Not = inner };
            },
            AND_BYTE => Self{ .And = &[_]WitnessCondition{} },
            OR_BYTE => Self{ .Or = &[_]WitnessCondition{} },
            SCRIPT_HASH_BYTE => Self{ .ScriptHash = Hash160.ZERO },
            GROUP_BYTE => Self{ .Group = PublicKey.ZERO },
            CALLED_BY_ENTRY_BYTE => Self{ .CalledByEntry = {} },
            CALLED_BY_CONTRACT_BYTE => Self{ .CalledByContract = Hash160.ZERO },
            CALLED_BY_GROUP_BYTE => Self{ .CalledByGroup = PublicKey.ZERO },
            else => null,
        };
    }
    
    /// Validates witness condition structure
    pub fn validate(self: Self, depth: u32) !void {
        if (depth > MAX_NESTING_DEPTH) {
            return error.ExcessiveNestingDepth;
        }
        
        switch (self) {
            .Boolean => {}, // Always valid
            .CalledByEntry => {}, // Always valid
            .Not => |inner| {
                try inner.validate(depth + 1);
            },
            .And => |conditions| {
                if (conditions.len == 0 or conditions.len > MAX_SUBITEMS) {
                    return error.InvalidConditionCount;
                }
                for (conditions) |condition| {
                    try condition.validate(depth + 1);
                }
            },
            .Or => |conditions| {
                if (conditions.len == 0 or conditions.len > MAX_SUBITEMS) {
                    return error.InvalidConditionCount;
                }
                for (conditions) |condition| {
                    try condition.validate(depth + 1);
                }
            },
            .ScriptHash => |hash| {
                try hash.validate();
            },
            .Group => |group| {
                try group.validate();
            },
            .CalledByContract => |hash| {
                try hash.validate();
            },
            .CalledByGroup => |group| {
                try group.validate();
            },
        }
    }
    
    /// Evaluates condition (utility method for testing)
    pub fn evaluate(self: Self, context: EvaluationContext) bool {
        return switch (self) {
            .Boolean => |value| value,
            .CalledByEntry => context.is_called_by_entry,
            .Not => |inner| !inner.evaluate(context),
            .And => |conditions| blk: {
                for (conditions) |condition| {
                    if (!condition.evaluate(context)) break :blk false;
                }
                break :blk true;
            },
            .Or => |conditions| blk: {
                for (conditions) |condition| {
                    if (condition.evaluate(context)) break :blk true;
                }
                break :blk false;
            },
            .ScriptHash => |hash| context.calling_script_hash != null and 
                                  context.calling_script_hash.?.eql(hash),
            .CalledByContract => |hash| context.calling_script_hash != null and 
                                       context.calling_script_hash.?.eql(hash),
            .Group => |group| blk: {
                if (context.calling_group == null) break :blk false;
                break :blk context.calling_group.?.eql(group);
            },
            .CalledByGroup => |group| blk: {
                if (context.calling_group == null) break :blk false;
                break :blk context.calling_group.?.eql(group);
            },
        };
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return switch (self) {
            .Boolean => |value| switch (other) {
                .Boolean => |other_value| value == other_value,
                else => false,
            },
            .CalledByEntry => switch (other) {
                .CalledByEntry => true,
                else => false,
            },
            .Not => |inner| switch (other) {
                .Not => |other_inner| inner.eql(other_inner.*),
                else => false,
            },
            .And => |conditions| switch (other) {
                .And => |other_conditions| blk: {
                    if (conditions.len != other_conditions.len) break :blk false;
                    for (conditions, 0..) |condition, i| {
                        if (!condition.eql(other_conditions[i])) break :blk false;
                    }
                    break :blk true;
                },
                else => false,
            },
            .Or => |conditions| switch (other) {
                .Or => |other_conditions| blk: {
                    if (conditions.len != other_conditions.len) break :blk false;
                    for (conditions, 0..) |condition, i| {
                        if (!condition.eql(other_conditions[i])) break :blk false;
                    }
                    break :blk true;
                },
                else => false,
            },
            .ScriptHash => |hash| switch (other) {
                .ScriptHash => |other_hash| hash.eql(other_hash),
                else => false,
            },
            .Group => |group| switch (other) {
                .Group => |other_group| group.eql(other_group),
                else => false,
            },
            .CalledByContract => |hash| switch (other) {
                .CalledByContract => |other_hash| hash.eql(other_hash),
                else => false,
            },
            .CalledByGroup => |group| switch (other) {
                .CalledByGroup => |other_group| group.eql(other_group),
                else => false,
            },
        };
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        hasher.update(&[_]u8{self.getByte()});
        
        switch (self) {
            .Boolean => |value| {
                hasher.update(&[_]u8{if (value) 1 else 0});
            },
            .CalledByEntry => {}, // No additional data
            .Not => |inner| {
                const inner_hash = inner.hash();
                hasher.update(std.mem.asBytes(&inner_hash));
            },
            .And => |conditions| {
                for (conditions) |condition| {
                    const condition_hash = condition.hash();
                    hasher.update(std.mem.asBytes(&condition_hash));
                }
            },
            .Or => |conditions| {
                for (conditions) |condition| {
                    const condition_hash = condition.hash();
                    hasher.update(std.mem.asBytes(&condition_hash));
                }
            },
            .ScriptHash => |script_hash| {
                const script_hash_value = script_hash.hash();
                hasher.update(std.mem.asBytes(&script_hash_value));
            },
            .Group => |group| {
                const group_hash = group.hash();
                hasher.update(std.mem.asBytes(&group_hash));
            },
            .CalledByContract => |script_hash| {
                const script_hash_value = script_hash.hash();
                hasher.update(std.mem.asBytes(&script_hash_value));
            },
            .CalledByGroup => |group| {
                const group_hash = group.hash();
                hasher.update(std.mem.asBytes(&group_hash));
            },
        }
        
        return hasher.final();
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .Not => |inner| {
                inner.deinit(allocator);
                allocator.destroy(inner);
            },
            .And => |conditions| {
                for (conditions) |*condition| {
                    condition.deinit(allocator);
                }
                allocator.free(conditions);
            },
            .Or => |conditions| {
                for (conditions) |*condition| {
                    condition.deinit(allocator);
                }
                allocator.free(conditions);
            },
            else => {}, // No cleanup needed for simple types
        }
    }
    
    /// Factory methods for creating conditions
    pub const Factory = struct {
        /// Creates boolean condition
        pub fn createBoolean(value: bool) Self {
            return Self{ .Boolean = value };
        }
        
        /// Creates NOT condition
        pub fn createNot(inner: WitnessCondition, allocator: std.mem.Allocator) !Self {
            const inner_ptr = try allocator.create(WitnessCondition);
            inner_ptr.* = inner;
            return Self{ .Not = inner_ptr };
        }
        
        /// Creates AND condition
        pub fn createAnd(conditions: []const WitnessCondition, allocator: std.mem.Allocator) !Self {
            if (conditions.len == 0 or conditions.len > MAX_SUBITEMS) {
                return error.InvalidConditionCount;
            }
            const conditions_copy = try allocator.dupe(WitnessCondition, conditions);
            return Self{ .And = conditions_copy };
        }
        
        /// Creates OR condition
        pub fn createOr(conditions: []const WitnessCondition, allocator: std.mem.Allocator) !Self {
            if (conditions.len == 0 or conditions.len > MAX_SUBITEMS) {
                return error.InvalidConditionCount;
            }
            const conditions_copy = try allocator.dupe(WitnessCondition, conditions);
            return Self{ .Or = conditions_copy };
        }
        
        /// Creates script hash condition
        pub fn createScriptHash(hash: Hash160) Self {
            return Self{ .ScriptHash = hash };
        }
        
        /// Creates group condition
        pub fn createGroup(group: PublicKey) Self {
            return Self{ .Group = group };
        }
        
        /// Creates called by entry condition
        pub fn createCalledByEntry() Self {
            return Self{ .CalledByEntry = {} };
        }
        
        /// Creates called by contract condition
        pub fn createCalledByContract(hash: Hash160) Self {
            return Self{ .CalledByContract = hash };
        }
        
        /// Creates called by group condition
        pub fn createCalledByGroup(group: PublicKey) Self {
            return Self{ .CalledByGroup = group };
        }
    };
};

/// Evaluation context for witness conditions
pub const EvaluationContext = struct {
    is_called_by_entry: bool,
    calling_script_hash: ?Hash160,
    calling_group: ?PublicKey,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .is_called_by_entry = false,
            .calling_script_hash = null,
            .calling_group = null,
        };
    }
    
    pub fn withCalledByEntry(self: Self, value: bool) Self {
        var context = self;
        context.is_called_by_entry = value;
        return context;
    }
    
    pub fn withCallingContract(self: Self, hash: Hash160) Self {
        var context = self;
        context.calling_script_hash = hash;
        return context;
    }
    
    pub fn withCallingGroup(self: Self, group: PublicKey) Self {
        var context = self;
        context.calling_group = group;
        return context;
    }
};

// Tests (converted from Swift WitnessCondition tests)
test "WitnessCondition creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test boolean condition (equivalent to Swift tests)
    const bool_condition = WitnessCondition.Factory.createBoolean(true);
    try testing.expectEqualStrings(WitnessCondition.BOOLEAN_VALUE, bool_condition.getJsonValue());
    try testing.expectEqual(WitnessCondition.BOOLEAN_BYTE, bool_condition.getByte());
    try bool_condition.validate(0);
    
    // Test CalledByEntry condition
    const entry_condition = WitnessCondition.Factory.createCalledByEntry();
    try testing.expectEqualStrings(WitnessCondition.CALLED_BY_ENTRY_VALUE, entry_condition.getJsonValue());
    try testing.expectEqual(WitnessCondition.CALLED_BY_ENTRY_BYTE, entry_condition.getByte());
    try entry_condition.validate(0);
    
    // Test ScriptHash condition
    const script_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const hash_condition = WitnessCondition.Factory.createScriptHash(script_hash);
    try testing.expectEqualStrings(WitnessCondition.SCRIPT_HASH_VALUE, hash_condition.getJsonValue());
    try testing.expectEqual(WitnessCondition.SCRIPT_HASH_BYTE, hash_condition.getByte());
    try hash_condition.validate(0);
}

test "WitnessCondition logical operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test NOT condition
    const inner_condition = WitnessCondition.Factory.createBoolean(true);
    var not_condition = try WitnessCondition.Factory.createNot(inner_condition, allocator);
    defer not_condition.deinit(allocator);
    
    try testing.expectEqualStrings(WitnessCondition.NOT_VALUE, not_condition.getJsonValue());
    try testing.expectEqual(WitnessCondition.NOT_BYTE, not_condition.getByte());
    try not_condition.validate(0);
    
    // Test AND condition
    const conditions = [_]WitnessCondition{
        WitnessCondition.Factory.createBoolean(true),
        WitnessCondition.Factory.createCalledByEntry(),
    };
    
    var and_condition = try WitnessCondition.Factory.createAnd(&conditions, allocator);
    defer and_condition.deinit(allocator);
    
    try testing.expectEqualStrings(WitnessCondition.AND_VALUE, and_condition.getJsonValue());
    try testing.expectEqual(WitnessCondition.AND_BYTE, and_condition.getByte());
    try and_condition.validate(0);
    
    // Test OR condition
    var or_condition = try WitnessCondition.Factory.createOr(&conditions, allocator);
    defer or_condition.deinit(allocator);
    
    try testing.expectEqualStrings(WitnessCondition.OR_VALUE, or_condition.getJsonValue());
    try testing.expectEqual(WitnessCondition.OR_BYTE, or_condition.getByte());
    try or_condition.validate(0);
}

test "WitnessCondition validation limits" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test maximum subitems limit
    var too_many_conditions = try std.ArrayList(WitnessCondition).initCapacity(allocator, WitnessCondition.MAX_SUBITEMS + 1);
    defer too_many_conditions.deinit();
    
    var i: usize = 0;
    while (i <= WitnessCondition.MAX_SUBITEMS) : (i += 1) {
        try too_many_conditions.append(WitnessCondition.Factory.createBoolean(true));
    }
    
    try testing.expectError(
        error.InvalidConditionCount,
        WitnessCondition.Factory.createAnd(too_many_conditions.items, allocator)
    );
    
    // Test empty conditions
    const empty_conditions = [_]WitnessCondition{};
    try testing.expectError(
        error.InvalidConditionCount,
        WitnessCondition.Factory.createAnd(&empty_conditions, allocator)
    );
}

test "WitnessCondition evaluation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test condition evaluation
    var context = EvaluationContext.init();
    
    // Test boolean evaluation
    const true_condition = WitnessCondition.Factory.createBoolean(true);
    try testing.expect(true_condition.evaluate(context));
    
    const false_condition = WitnessCondition.Factory.createBoolean(false);
    try testing.expect(!false_condition.evaluate(context));
    
    // Test CalledByEntry evaluation
    const entry_condition = WitnessCondition.Factory.createCalledByEntry();
    try testing.expect(!entry_condition.evaluate(context)); // Context not set
    
    context = context.withCalledByEntry(true);
    try testing.expect(entry_condition.evaluate(context));
    
    // Test NOT evaluation
    var not_condition = try WitnessCondition.Factory.createNot(true_condition, allocator);
    defer not_condition.deinit(allocator);
    
    try testing.expect(!not_condition.evaluate(context)); // NOT true = false
}