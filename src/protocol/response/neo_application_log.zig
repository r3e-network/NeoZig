//! Neo ApplicationLog Implementation
//!
//! Complete conversion from NeoSwift NeoApplicationLog.swift
//! Provides application execution log structure.

const std = @import("std");

const ArrayList = std.ArrayList;

const Hash256 = @import("../../types/hash256.zig").Hash256;
const NeoVMStateType = @import("../../types/neo_vm_state_type.zig").NeoVMStateType;
const StackItem = @import("../../types/stack_item.zig").StackItem;
const Notification = @import("notification.zig").Notification;
const errors = @import("../../core/errors.zig");

/// Application execution (converted from Swift ApplicationExecution)
pub const ApplicationExecution = struct {
    /// Trigger type
    trigger: []const u8,
    /// VM state
    vm_state: NeoVMStateType,
    /// Exception message
    exception: ?[]const u8,
    /// Gas consumed
    gas_consumed: []const u8,
    /// Stack result
    stack: []StackItem,
    /// Notifications
    notifications: []Notification,

    const Self = @This();

    pub fn init(
        trigger: []const u8,
        vm_state: NeoVMStateType,
        exception: ?[]const u8,
        gas_consumed: []const u8,
        stack: []StackItem,
        notifications: []Notification,
    ) Self {
        return Self{
            .trigger = trigger,
            .vm_state = vm_state,
            .exception = exception,
            .gas_consumed = gas_consumed,
            .stack = stack,
            .notifications = notifications,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const trigger = try allocator.dupe(u8, obj.get("trigger").?.string);
        const vm_state_value = obj.get("vmstate") orelse return errors.SerializationError.InvalidFormat;
        const vm_state = try NeoVMStateType.decodeFromJson(vm_state_value);
        const gas_consumed = try allocator.dupe(u8, obj.get("gasconsumed").?.string);

        const exception = if (obj.get("exception")) |value| switch (value) {
            .null => null,
            .string => |str| try allocator.dupe(u8, str),
            else => try stringifyJsonValue(value, allocator),
        } else null;

        var stack_items = ArrayList(StackItem).init(allocator);
        defer stack_items.deinit();
        if (obj.get("stack")) |stack_value| {
            if (stack_value != .array) return errors.SerializationError.InvalidFormat;
            for (stack_value.array) |entry| {
                var stack_item = try StackItem.decodeFromJson(entry, allocator);
                var guard = true;
                defer if (guard) stack_item.deinit(allocator);
                try stack_items.append(stack_item);
                guard = false;
            }
        }

        var notifications = ArrayList(Notification).init(allocator);
        defer notifications.deinit();
        if (obj.get("notifications")) |notifications_value| {
            if (notifications_value != .array) return errors.SerializationError.InvalidFormat;
            for (notifications_value.array) |notification_value| {
                var notification = try Notification.fromJson(notification_value, allocator);
                var notif_guard = true;
                defer if (notif_guard) notification.deinit(allocator);
                try notifications.append(notification);
                notif_guard = false;
            }
        }

        return Self{
            .trigger = trigger,
            .vm_state = vm_state,
            .exception = exception,
            .gas_consumed = gas_consumed,
            .stack = try stack_items.toOwnedSlice(),
            .notifications = try notifications.toOwnedSlice(),
        };
    }

    pub fn isSuccessful(self: Self) bool {
        return self.vm_state == .Halt;
    }

    pub fn hasFault(self: Self) bool {
        return self.vm_state == .Fault;
    }

    pub fn hasException(self: Self) bool {
        return self.exception != null;
    }

    pub fn hasNotifications(self: Self) bool {
        return self.notifications.len > 0;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.trigger.len > 0) allocator.free(self.trigger);
        if (self.exception) |exception| {
            allocator.free(exception);
        }
        if (self.gas_consumed.len > 0) allocator.free(self.gas_consumed);
        if (self.stack.len > 0) {
            for (self.stack) |*item| {
                item.deinit(allocator);
            }
            allocator.free(self.stack);
        }

        if (self.notifications.len > 0) {
            for (self.notifications) |*notification| {
                notification.deinit(allocator);
            }
            allocator.free(self.notifications);
        }
    }
};

/// Application log (converted from Swift NeoApplicationLog)
pub const NeoApplicationLog = struct {
    /// Transaction hash
    tx_id: Hash256,
    /// Executions
    executions: []ApplicationExecution,

    const Self = @This();

    pub fn init(tx_id: Hash256, executions: []ApplicationExecution) Self {
        return Self{
            .tx_id = tx_id,
            .executions = executions,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        const tx_id = try Hash256.initWithString(obj.get("txid").?.string);

        var executions = ArrayList(ApplicationExecution).init(allocator);
        defer executions.deinit();
        if (obj.get("executions")) |exec_array| {
            if (exec_array != .array) return errors.SerializationError.InvalidFormat;
            for (exec_array.array) |execution_value| {
                var execution = try ApplicationExecution.fromJson(execution_value, allocator);
                var exec_guard = true;
                defer if (exec_guard) execution.deinit(allocator);
                try executions.append(execution);
                exec_guard = false;
            }
        }

        return Self{
            .tx_id = tx_id,
            .executions = try executions.toOwnedSlice(),
        };
    }

    pub fn getTransactionId(self: Self) Hash256 {
        return self.tx_id;
    }

    pub fn getExecutionCount(self: Self) usize {
        return self.executions.len;
    }

    pub fn hasSuccessfulExecution(self: Self) bool {
        for (self.executions) |execution| {
            if (execution.isSuccessful()) return true;
        }
        return false;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (self.executions) |*execution| {
            execution.deinit(allocator);
        }
        if (self.executions.len > 0) allocator.free(self.executions);
    }
};

fn stringifyJsonValue(value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
    return try std.json.stringifyAlloc(allocator, value, .{});
}

// Tests
test "ApplicationExecution fromJson parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const json_text =
        "{" ++
        "\"trigger\":\"Application\"," ++
        "\"vmstate\":\"HALT\"," ++
        "\"exception\":null," ++
        "\"gasconsumed\":\"1000000\"," ++
        "\"stack\":[{\"type\":\"Integer\",\"value\":\"1\"}]," ++
        "\"notifications\":[{\"contract\":\"0123456789abcdef0123456789abcdef01234567\",\"eventname\":\"Transfer\",\"state\":{\"type\":\"Boolean\",\"value\":\"true\"}}]" ++
        "}";

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    var execution = try ApplicationExecution.fromJson(parsed.value, allocator);
    defer execution.deinit(allocator);

    try testing.expect(execution.isSuccessful());
    try testing.expectEqualStrings("Application", execution.trigger);
    try testing.expectEqualStrings("1000000", execution.gas_consumed);
    try testing.expectEqual(@as(usize, 1), execution.stack.len);
    try testing.expectEqual(@as(i64, 1), try execution.stack[0].getInteger());
    try testing.expectEqual(@as(usize, 1), execution.notifications.len);
}

test "NeoApplicationLog fromJson parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const json_text =
        "{" ++
        "\"txid\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"," ++
        "\"executions\":[{" ++
        "\"trigger\":\"Application\"," ++
        "\"vmstate\":\"HALT\"," ++
        "\"exception\":null," ++
        "\"gasconsumed\":\"1000000\"," ++
        "\"stack\":[{\"type\":\"Boolean\",\"value\":\"true\"}]," ++
        "\"notifications\":[]" ++
        "}]" ++
        "}";

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    var log = try NeoApplicationLog.fromJson(parsed.value, allocator);
    defer log.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), log.getExecutionCount());
    try testing.expect(log.hasSuccessfulExecution());
}
