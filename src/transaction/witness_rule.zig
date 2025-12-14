//! Witness Rule implementation
//!
//! Complete conversion from NeoSwift WitnessRule.swift, WitnessAction.swift, WitnessCondition.swift
//! Provides complete witness rule system for advanced transaction validation.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const BinaryWriter = @import("../serialization/binary_writer.zig").BinaryWriter;
const BinaryReader = @import("../serialization/binary_reader.zig").BinaryReader;

/// Witness rule (converted from Swift WitnessRule)
pub const WitnessRule = struct {
    action: WitnessAction,
    condition: WitnessCondition,

    const Self = @This();

    /// Creates witness rule (equivalent to Swift init)
    pub fn init(action: WitnessAction, condition: WitnessCondition) Self {
        return Self{
            .action = action,
            .condition = condition,
        };
    }

    /// Gets serialized size (equivalent to Swift .size property)
    pub fn size(self: Self) usize {
        return 1 + self.condition.size();
    }

    /// Serializes witness rule (equivalent to Swift serialize(_ writer: BinaryWriter))
    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try writer.writeByte(@intFromEnum(self.action));
        try self.condition.serialize(writer);
    }

    /// Deserializes witness rule (equivalent to Swift deserialize(_ reader: BinaryReader))
    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        const action_byte = try reader.readByte();
        const action = WitnessAction.fromByte(action_byte) orelse {
            return errors.throwIllegalArgument("Invalid witness action byte");
        };

        const condition = try WitnessCondition.deserialize(reader, allocator);

        return Self.init(action, condition);
    }

    /// Validates witness rule
    pub fn validate(self: Self) !void {
        try self.condition.validate();
    }

    /// Frees any resources owned by this rule's condition.
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.condition.deinit(allocator);
    }

    /// Deep-clones this rule, producing an owned copy of the condition tree.
    pub fn cloneOwned(self: Self, allocator: std.mem.Allocator) !Self {
        return Self{
            .action = self.action,
            .condition = try self.condition.cloneOwned(allocator),
        };
    }

    /// Evaluates witness rule against context (additional utility)
    pub fn evaluate(self: Self, context: WitnessContext) bool {
        const condition_result = self.condition.evaluate(context);

        return switch (self.action) {
            .Allow => condition_result,
            .Deny => !condition_result,
        };
    }

    /// Compares witness rules for equality
    pub fn eql(self: Self, other: Self) bool {
        return self.action == other.action and self.condition.eql(other.condition);
    }

    /// Hash function for HashMap usage
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&[_]u8{@intFromEnum(self.action)});
        hasher.update(&[_]u8{@intFromEnum(self.condition)});
        return hasher.final();
    }
};

/// Witness action (converted from Swift WitnessAction)
pub const WitnessAction = enum(u8) {
    Deny = 0x00,
    Allow = 0x01,

    const Self = @This();

    /// Gets byte value (equivalent to Swift .byte property)
    pub fn getByte(self: Self) u8 {
        return @intFromEnum(self);
    }

    /// Creates from byte value (equivalent to Swift throwingValueOf)
    pub fn fromByte(byte_value: u8) ?Self {
        return switch (byte_value) {
            0x00 => .Deny,
            0x01 => .Allow,
            else => null,
        };
    }

    /// Gets JSON value (equivalent to Swift JSON encoding)
    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .Deny => "Deny",
            .Allow => "Allow",
        };
    }

    /// Creates from JSON value
    pub fn fromJsonValue(json_value: []const u8) ?Self {
        if (std.mem.eql(u8, json_value, "Deny")) return .Deny;
        if (std.mem.eql(u8, json_value, "Allow")) return .Allow;
        return null;
    }

    /// Gets all cases (equivalent to Swift CaseIterable)
    pub fn getAllCases() []const Self {
        return &[_]Self{ .Deny, .Allow };
    }
};

/// Witness condition (converted from Swift WitnessCondition)
pub const WitnessCondition = union(enum(u8)) {
    Boolean: bool,
    Not: struct {
        condition: *WitnessCondition,
        owns_condition: bool,
    },
    And: struct {
        conditions: []WitnessCondition,
        owns_conditions: bool,
    },
    Or: struct {
        conditions: []WitnessCondition,
        owns_conditions: bool,
    },
    ScriptHash: Hash160,
    Group: [33]u8,
    CalledByEntry: void,
    CalledByContract: Hash160,
    CalledByGroup: [33]u8,

    const Self = @This();

    /// Creates boolean condition
    pub fn boolean(value: bool) Self {
        return Self{ .Boolean = value };
    }

    /// Creates NOT condition
    pub fn not(condition: *WitnessCondition) Self {
        return Self{ .Not = .{ .condition = condition, .owns_condition = false } };
    }

    /// Creates NOT condition that owns the allocated child.
    pub fn notOwned(condition: *WitnessCondition) Self {
        return Self{ .Not = .{ .condition = condition, .owns_condition = true } };
    }

    /// Creates AND condition
    pub fn and_condition(conditions: []WitnessCondition) Self {
        return Self{ .And = .{ .conditions = conditions, .owns_conditions = false } };
    }

    /// Creates OR condition
    pub fn or_condition(conditions: []WitnessCondition) Self {
        return Self{ .Or = .{ .conditions = conditions, .owns_conditions = false } };
    }

    /// Creates script hash condition
    pub fn scriptHash(hash: Hash160) Self {
        return Self{ .ScriptHash = hash };
    }

    /// Creates group condition
    pub fn group(public_key: [33]u8) Self {
        return Self{ .Group = public_key };
    }

    /// Creates called by entry condition
    pub fn calledByEntry() Self {
        return Self{ .CalledByEntry = {} };
    }

    /// Creates called by contract condition
    pub fn calledByContract(contract: Hash160) Self {
        return Self{ .CalledByContract = contract };
    }

    /// Creates called by group condition
    pub fn calledByGroup(group_key: [33]u8) Self {
        return Self{ .CalledByGroup = group_key };
    }

    /// Gets serialized size (equivalent to Swift .size property)
    pub fn size(self: Self) usize {
        var total_size: usize = 1; // Type byte

        switch (self) {
            .Boolean => total_size += 1,
            .Not => |not_condition| total_size += not_condition.condition.size(),
            .And => |and_payload| {
                total_size += getVarIntSize(and_payload.conditions.len);
                for (and_payload.conditions) |condition| {
                    total_size += condition.size();
                }
            },
            .Or => |or_payload| {
                total_size += getVarIntSize(or_payload.conditions.len);
                for (or_payload.conditions) |condition| {
                    total_size += condition.size();
                }
            },
            .ScriptHash, .CalledByContract => total_size += 20,
            .Group, .CalledByGroup => total_size += 33,
            .CalledByEntry => {}, // No additional data
        }

        return total_size;
    }

    /// Serializes condition (equivalent to Swift serialize)
    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        const condition_type: u8 = switch (self) {
            .Boolean => 0x00,
            .Not => 0x01,
            .And => 0x02,
            .Or => 0x03,
            .ScriptHash => 0x18,
            .Group => 0x19,
            .CalledByEntry => 0x20,
            .CalledByContract => 0x28,
            .CalledByGroup => 0x29,
        };

        try writer.writeByte(condition_type);

        switch (self) {
            .Boolean => |value| try writer.writeByte(if (value) 1 else 0),
            .Not => |not_condition| try not_condition.condition.serialize(writer),
            .And => |and_payload| {
                try writer.writeVarInt(and_payload.conditions.len);
                for (and_payload.conditions) |condition| {
                    try condition.serialize(writer);
                }
            },
            .Or => |or_payload| {
                try writer.writeVarInt(or_payload.conditions.len);
                for (or_payload.conditions) |condition| {
                    try condition.serialize(writer);
                }
            },
            .ScriptHash => |hash| try writer.writeBytes(&hash.toArray()),
            .Group => |group_key| try writer.writeBytes(&group_key),
            .CalledByEntry => {},
            .CalledByContract => |hash| try writer.writeBytes(&hash.toArray()),
            .CalledByGroup => |group_key| try writer.writeBytes(&group_key),
        }
    }

    /// Deserializes condition (equivalent to Swift deserialize)
    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        const condition_type = try reader.readByte();

        return switch (condition_type) {
            0x00 => {
                const value = (try reader.readByte()) != 0;
                return Self{ .Boolean = value };
            },
            0x01 => {
                const condition = try allocator.create(WitnessCondition);
                errdefer allocator.destroy(condition);
                condition.* = try Self.deserialize(reader, allocator);
                return Self.notOwned(condition);
            },
            0x02 => {
                const count = try reader.readVarInt();
                const conditions = try allocator.alloc(WitnessCondition, @intCast(count));
                errdefer allocator.free(conditions);
                var filled: usize = 0;
                errdefer {
                    for (conditions[0..filled]) |*cond| {
                        cond.deinit(allocator);
                    }
                }

                for (conditions) |*condition| {
                    condition.* = try Self.deserialize(reader, allocator);
                    filled += 1;
                }
                return Self{ .And = .{ .conditions = conditions, .owns_conditions = true } };
            },
            0x03 => {
                const count = try reader.readVarInt();
                const conditions = try allocator.alloc(WitnessCondition, @intCast(count));
                errdefer allocator.free(conditions);
                var filled: usize = 0;
                errdefer {
                    for (conditions[0..filled]) |*cond| {
                        cond.deinit(allocator);
                    }
                }

                for (conditions) |*condition| {
                    condition.* = try Self.deserialize(reader, allocator);
                    filled += 1;
                }
                return Self{ .Or = .{ .conditions = conditions, .owns_conditions = true } };
            },
            0x18 => {
                var hash_bytes: [20]u8 = undefined;
                try reader.readBytes(&hash_bytes);
                return Self{ .ScriptHash = Hash160.fromArray(hash_bytes) };
            },
            0x19 => {
                var group_key: [33]u8 = undefined;
                try reader.readBytes(&group_key);
                return Self{ .Group = group_key };
            },
            0x20 => Self{ .CalledByEntry = {} },
            0x28 => {
                var hash_bytes: [20]u8 = undefined;
                try reader.readBytes(&hash_bytes);
                return Self{ .CalledByContract = Hash160.fromArray(hash_bytes) };
            },
            0x29 => {
                var group_key: [33]u8 = undefined;
                try reader.readBytes(&group_key);
                return Self{ .CalledByGroup = group_key };
            },
            else => return errors.throwIllegalArgument("Invalid witness condition type"),
        };
    }

    /// Frees any resources owned by this condition.
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .Not => |not_condition| {
                not_condition.condition.deinit(allocator);
                if (not_condition.owns_condition) {
                    allocator.destroy(not_condition.condition);
                }
            },
            .And => |and_payload| {
                for (and_payload.conditions) |*condition| {
                    condition.deinit(allocator);
                }
                if (and_payload.owns_conditions) {
                    allocator.free(and_payload.conditions);
                }
            },
            .Or => |or_payload| {
                for (or_payload.conditions) |*condition| {
                    condition.deinit(allocator);
                }
                if (or_payload.owns_conditions) {
                    allocator.free(or_payload.conditions);
                }
            },
            else => {},
        }
    }

    /// Deep-clones this condition, returning an owned copy suitable for independent `deinit`.
    pub fn cloneOwned(self: Self, allocator: std.mem.Allocator) !Self {
        return switch (self) {
            .Boolean => |value| Self{ .Boolean = value },
            .ScriptHash => |hash| Self{ .ScriptHash = hash },
            .Group => |group_key| Self{ .Group = group_key },
            .CalledByEntry => Self{ .CalledByEntry = {} },
            .CalledByContract => |hash| Self{ .CalledByContract = hash },
            .CalledByGroup => |group_key| Self{ .CalledByGroup = group_key },
            .Not => |not_condition| {
                const cloned_child = try allocator.create(WitnessCondition);
                errdefer allocator.destroy(cloned_child);
                cloned_child.* = try not_condition.condition.*.cloneOwned(allocator);
                return Self{ .Not = .{ .condition = cloned_child, .owns_condition = true } };
            },
            .And => |and_payload| {
                const cloned_conditions = try allocator.alloc(WitnessCondition, and_payload.conditions.len);
                errdefer allocator.free(cloned_conditions);
                var filled: usize = 0;
                errdefer {
                    for (cloned_conditions[0..filled]) |*condition| {
                        condition.deinit(allocator);
                    }
                }

                for (and_payload.conditions, 0..) |condition, idx| {
                    cloned_conditions[idx] = try condition.cloneOwned(allocator);
                    filled = idx + 1;
                }

                return Self{ .And = .{ .conditions = cloned_conditions, .owns_conditions = true } };
            },
            .Or => |or_payload| {
                const cloned_conditions = try allocator.alloc(WitnessCondition, or_payload.conditions.len);
                errdefer allocator.free(cloned_conditions);
                var filled: usize = 0;
                errdefer {
                    for (cloned_conditions[0..filled]) |*condition| {
                        condition.deinit(allocator);
                    }
                }

                for (or_payload.conditions, 0..) |condition, idx| {
                    cloned_conditions[idx] = try condition.cloneOwned(allocator);
                    filled = idx + 1;
                }

                return Self{ .Or = .{ .conditions = cloned_conditions, .owns_conditions = true } };
            },
        };
    }

    /// Validates condition
    pub fn validate(self: Self) !void {
        switch (self) {
            .Not => |not_condition| try not_condition.condition.validate(),
            .And => |and_payload| {
                if (and_payload.conditions.len == 0) {
                    return errors.throwIllegalArgument("Compound condition cannot be empty");
                }
                for (and_payload.conditions) |condition| {
                    try condition.validate();
                }
            },
            .Or => |or_payload| {
                if (or_payload.conditions.len == 0) {
                    return errors.throwIllegalArgument("Compound condition cannot be empty");
                }
                for (or_payload.conditions) |condition| {
                    try condition.validate();
                }
            },
            else => {}, // Other conditions are always valid
        }
    }

    /// Evaluates condition against context
    pub fn evaluate(self: Self, context: WitnessContext) bool {
        return switch (self) {
            .Boolean => |value| value,
            .Not => |not_condition| !not_condition.condition.evaluate(context),
            .And => |and_payload| {
                for (and_payload.conditions) |condition| {
                    if (!condition.evaluate(context)) return false;
                }
                return true;
            },
            .Or => |or_payload| {
                for (or_payload.conditions) |condition| {
                    if (condition.evaluate(context)) return true;
                }
                return false;
            },
            .ScriptHash => |hash| context.calling_script_hash != null and context.calling_script_hash.?.eql(hash),
            .Group => |group_key| context.hasGroup(group_key),
            .CalledByEntry => context.is_entry_script,
            .CalledByContract => |hash| context.calling_script_hash != null and context.calling_script_hash.?.eql(hash),
            .CalledByGroup => |group_key| context.hasGroup(group_key),
        };
    }

    /// Compares conditions for equality
    pub fn eql(self: Self, other: Self) bool {
        const self_type = @as(u8, @intFromEnum(self));
        const other_type = @as(u8, @intFromEnum(other));

        if (self_type != other_type) return false;

        return switch (self) {
            .Boolean => |a| a == other.Boolean,
            .Not => |a| a.condition.eql(other.Not.condition.*),
            .And => |a| {
                if (a.conditions.len != other.And.conditions.len) return false;
                for (a.conditions, other.And.conditions) |cond_a, cond_b| {
                    if (!cond_a.eql(cond_b)) return false;
                }
                return true;
            },
            .Or => |a| {
                if (a.conditions.len != other.Or.conditions.len) return false;
                for (a.conditions, other.Or.conditions) |cond_a, cond_b| {
                    if (!cond_a.eql(cond_b)) return false;
                }
                return true;
            },
            .ScriptHash => |a| a.eql(other.ScriptHash),
            .Group => |a| std.mem.eql(u8, &a, &other.Group),
            .CalledByEntry => true,
            .CalledByContract => |a| a.eql(other.CalledByContract),
            .CalledByGroup => |a| std.mem.eql(u8, &a, &other.CalledByGroup),
        };
    }
};

/// Witness context for evaluation (additional utility)
pub const WitnessContext = struct {
    calling_script_hash: ?Hash160,
    is_entry_script: bool,
    groups: []const [33]u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .calling_script_hash = null,
            .is_entry_script = false,
            .groups = &[_][33]u8{},
        };
    }

    /// Checks if context has specific group
    pub fn hasGroup(self: Self, group: [33]u8) bool {
        for (self.groups) |ctx_group| {
            if (std.mem.eql(u8, &ctx_group, &group)) {
                return true;
            }
        }
        return false;
    }

    /// Sets calling script hash
    pub fn setCallingScriptHash(self: *Self, hash: Hash160) void {
        self.calling_script_hash = hash;
    }

    /// Sets entry script flag
    pub fn setIsEntryScript(self: *Self, is_entry: bool) void {
        self.is_entry_script = is_entry;
    }

    /// Adds group to context
    pub fn addGroup(self: *Self, group: [33]u8, allocator: std.mem.Allocator) !void {
        var new_groups = try allocator.alloc([33]u8, self.groups.len + 1);
        @memcpy(new_groups[0..self.groups.len], self.groups);
        new_groups[self.groups.len] = group;

        if (self.groups.len > 0) {
            allocator.free(self.groups);
        }
        self.groups = new_groups;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.groups.len > 0) {
            allocator.free(self.groups);
        }
        self.* = Self.init();
    }
};

/// Helper function for VarInt size calculation
fn getVarIntSize(value: usize) usize {
    if (value < 0xFD) return 1;
    if (value <= 0xFFFF) return 3;
    if (value <= 0xFFFFFFFF) return 5;
    return 9;
}

// Tests (converted from Swift WitnessRule, WitnessAction, WitnessCondition tests)
test "WitnessAction operations" {
    const testing = std.testing;

    // Test witness action values (equivalent to Swift WitnessAction tests)
    try testing.expectEqual(@as(u8, 0x00), WitnessAction.Deny.getByte());
    try testing.expectEqual(@as(u8, 0x01), WitnessAction.Allow.getByte());

    // Test from byte conversion
    try testing.expectEqual(WitnessAction.Deny, WitnessAction.fromByte(0x00).?);
    try testing.expectEqual(WitnessAction.Allow, WitnessAction.fromByte(0x01).?);
    try testing.expectEqual(@as(?WitnessAction, null), WitnessAction.fromByte(0xFF));

    // Test JSON values
    try testing.expectEqualStrings("Deny", WitnessAction.Deny.getJsonValue());
    try testing.expectEqualStrings("Allow", WitnessAction.Allow.getJsonValue());

    // Test all cases
    const all_cases = WitnessAction.getAllCases();
    try testing.expectEqual(@as(usize, 2), all_cases.len);
}

test "WitnessCondition creation and basic operations" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test basic condition creation (equivalent to Swift WitnessCondition tests)
    const bool_condition = WitnessCondition.boolean(true);
    try testing.expectEqual(.Boolean, std.meta.activeTag(bool_condition));

    const script_hash_condition = WitnessCondition.scriptHash(Hash160.ZERO);
    try testing.expectEqual(.ScriptHash, std.meta.activeTag(script_hash_condition));

    const entry_condition = WitnessCondition.calledByEntry();
    try testing.expectEqual(.CalledByEntry, std.meta.activeTag(entry_condition));

    // Test size calculation
    try testing.expect(bool_condition.size() >= 2); // Type + value
    try testing.expect(script_hash_condition.size() >= 21); // Type + hash
    try testing.expect(entry_condition.size() >= 1); // Type only
}

test "WitnessCondition compound operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test compound conditions (equivalent to Swift compound condition tests)
    const conditions = try allocator.alloc(WitnessCondition, 2);
    defer allocator.free(conditions);

    conditions[0] = WitnessCondition.boolean(true);
    conditions[1] = WitnessCondition.calledByEntry();

    const and_condition = WitnessCondition.and_condition(conditions);
    const or_condition = WitnessCondition.or_condition(conditions);

    // Test size includes all sub-conditions
    const and_size = and_condition.size();
    const or_size = or_condition.size();

    try testing.expect(and_size > conditions[0].size());
    try testing.expect(or_size > conditions[1].size());

    // Test validation
    try and_condition.validate();
    try or_condition.validate();
}

test "WitnessCondition deserialize frees owned memory" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Build a compound condition containing both a slice (AND) and a heap pointer (NOT).
    var entry_condition = WitnessCondition.calledByEntry();
    const not_condition = WitnessCondition.not(&entry_condition);

    var conditions = [_]WitnessCondition{
        WitnessCondition.boolean(true),
        not_condition,
    };
    const and_condition = WitnessCondition.and_condition(&conditions);

    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    try and_condition.serialize(&writer);

    var reader = BinaryReader.init(writer.toSlice());
    var decoded = try WitnessCondition.deserialize(&reader, allocator);
    decoded.deinit(allocator);
}

test "WitnessCondition deserialize cleans up on error" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // AND with 2 subconditions, but only one is present -> triggers UnexpectedEndOfData
    const bytes = [_]u8{ 0x02, 0x02, 0x00, 0x01 };
    var reader = BinaryReader.init(&bytes);
    try testing.expectError(errors.SerializationError.UnexpectedEndOfData, WitnessCondition.deserialize(&reader, allocator));
}

test "WitnessRule creation and operations" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test witness rule creation (equivalent to Swift WitnessRule tests)
    const condition = WitnessCondition.boolean(true);
    const rule = WitnessRule.init(WitnessAction.Allow, condition);

    try testing.expectEqual(WitnessAction.Allow, rule.action);

    // Test size calculation
    const rule_size = rule.size();
    try testing.expect(rule_size >= 2); // Action + condition

    // Test validation
    try rule.validate();

    // Test equality
    const same_rule = WitnessRule.init(WitnessAction.Allow, WitnessCondition.boolean(true));
    const different_rule = WitnessRule.init(WitnessAction.Deny, WitnessCondition.boolean(true));

    try testing.expect(rule.eql(same_rule));
    try testing.expect(!rule.eql(different_rule));
}

test "WitnessRule serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test witness rule serialization (equivalent to Swift serialization tests)
    const condition = WitnessCondition.scriptHash(Hash160.ZERO);
    const rule = WitnessRule.init(WitnessAction.Allow, condition);

    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();

    try rule.serialize(&writer);

    const serialized_data = writer.toSlice();
    try testing.expect(serialized_data.len > 0);
    try testing.expectEqual(@as(u8, 0x01), serialized_data[0]); // Allow action

    // Test deserialization
    var reader = BinaryReader.init(serialized_data);
    const deserialized_rule = try WitnessRule.deserialize(&reader, allocator);

    try testing.expect(rule.eql(deserialized_rule));
}

test "WitnessCondition evaluation" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test condition evaluation (additional utility tests)
    var context = WitnessContext.init();
    context.setIsEntryScript(true);
    context.setCallingScriptHash(Hash160.ZERO);

    // Test boolean condition
    const true_condition = WitnessCondition.boolean(true);
    try testing.expect(true_condition.evaluate(context));

    const false_condition = WitnessCondition.boolean(false);
    try testing.expect(!false_condition.evaluate(context));

    // Test called by entry condition
    const entry_condition = WitnessCondition.calledByEntry();
    try testing.expect(entry_condition.evaluate(context));

    context.setIsEntryScript(false);
    try testing.expect(!entry_condition.evaluate(context));

    // Test script hash condition
    const script_condition = WitnessCondition.scriptHash(Hash160.ZERO);
    try testing.expect(script_condition.evaluate(context));

    const different_hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const different_script_condition = WitnessCondition.scriptHash(different_hash);
    try testing.expect(!different_script_condition.evaluate(context));
}

test "WitnessRule evaluation" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test rule evaluation (equivalent to Swift rule evaluation tests)
    var context = WitnessContext.init();
    context.setIsEntryScript(true);

    // Test allow rule with true condition
    const allow_rule = WitnessRule.init(WitnessAction.Allow, WitnessCondition.calledByEntry());
    try testing.expect(allow_rule.evaluate(context));

    // Test deny rule with true condition
    const deny_rule = WitnessRule.init(WitnessAction.Deny, WitnessCondition.calledByEntry());
    try testing.expect(!deny_rule.evaluate(context));

    // Test with false condition
    context.setIsEntryScript(false);
    try testing.expect(!allow_rule.evaluate(context));
    try testing.expect(deny_rule.evaluate(context)); // Deny of false = true
}
