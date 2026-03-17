const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const NeoVMStateType = @import("../types/neo_vm_state_type.zig").NeoVMStateType;
const StackItem = @import("../types/stack_item.zig").StackItem;
const common = @import("responses_common.zig");

const stringifyJsonValue = common.stringifyJsonValue;

/// Invocation result
pub const InvocationResult = struct {
    script: []const u8,
    state: NeoVMStateType,
    gas_consumed: []const u8,
    exception: ?[]const u8,
    stack: []StackItem,
    session: ?[]const u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .script = "",
            .state = .None,
            .gas_consumed = "",
            .exception = null,
            .stack = &[_]StackItem{},
            .session = null,
        };
    }

    pub fn getFirstStackItem(self: Self) !StackItem {
        if (self.stack.len == 0) {
            return errors.throwIllegalState("Stack is empty");
        }
        return self.stack[0];
    }

    pub fn hasFaulted(self: Self) bool {
        return self.state == .Fault;
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const script = try allocator.dupe(u8, obj.get("script").?.string);
        const state_value = obj.get("state") orelse return errors.SerializationError.InvalidFormat;
        const state = try NeoVMStateType.decodeFromJson(state_value);
        const gas_consumed = try allocator.dupe(u8, obj.get("gasconsumed").?.string);
        const exception = if (obj.get("exception")) |ex| try allocator.dupe(u8, ex.string) else null;

        var stack_items = ArrayList(StackItem).init(allocator);
        defer stack_items.deinit();
        if (obj.get("stack")) |stack_array| {
            if (stack_array != .array) return errors.SerializationError.InvalidFormat;
            for (stack_array.array.items) |item| {
                var parsed_item = try StackItem.decodeFromJson(item, allocator);
                var item_guard = true;
                defer if (item_guard) parsed_item.deinit(allocator);
                try stack_items.append(parsed_item);
                item_guard = false;
            }
        }

        return Self{
            .script = script,
            .state = state,
            .gas_consumed = gas_consumed,
            .exception = exception,
            .stack = try stack_items.toOwnedSlice(),
            .session = if (obj.get("session")) |s| try allocator.dupe(u8, s.string) else null,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.script.len > 0) allocator.free(@constCast(self.script));
        if (self.gas_consumed.len > 0) allocator.free(@constCast(self.gas_consumed));

        if (self.exception) |ex| {
            if (ex.len > 0) allocator.free(@constCast(ex));
        }

        if (self.stack.len > 0) {
            for (self.stack) |*item| {
                item.deinit(allocator);
            }
            allocator.free(self.stack);
        }

        if (self.session) |sess| {
            if (sess.len > 0) allocator.free(@constCast(sess));
        }
    }
};

/// Application log response
pub const NeoApplicationLog = struct {
    tx_id: Hash256,
    executions: []Execution,

    pub fn init() NeoApplicationLog {
        return NeoApplicationLog{
            .tx_id = Hash256.ZERO,
            .executions = &[_]Execution{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoApplicationLog {
        const obj = json_value.object;

        const tx_id = try Hash256.initWithString(obj.get("txid").?.string);

        var executions = ArrayList(Execution).init(allocator);
        defer executions.deinit();
        if (obj.get("executions")) |exec_array| {
            if (exec_array != .array) return errors.SerializationError.InvalidFormat;
            for (exec_array.array.items) |item| {
                var execution = try Execution.fromJson(item, allocator);
                var execution_guard = true;
                defer if (execution_guard) execution.deinit(allocator);
                try executions.append(execution);
                execution_guard = false;
            }
        }

        return NeoApplicationLog{
            .tx_id = tx_id,
            .executions = try executions.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *NeoApplicationLog, allocator: std.mem.Allocator) void {
        if (self.executions.len > 0) {
            for (self.executions) |*execution| {
                execution.deinit(allocator);
            }
            allocator.free(self.executions);
        }
    }
};

/// Execution
pub const Execution = struct {
    trigger: []const u8,
    vm_state: NeoVMStateType,
    exception: ?[]const u8,
    gas_consumed: []const u8,
    stack: []StackItem,
    notifications: []Notification,

    pub fn init() Execution {
        return Execution{
            .trigger = "",
            .vm_state = .None,
            .exception = null,
            .gas_consumed = "",
            .stack = &[_]StackItem{},
            .notifications = &[_]Notification{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Execution {
        const obj = json_value.object;

        const trigger = try allocator.dupe(u8, obj.get("trigger").?.string);
        const vm_state_value = obj.get("vmstate") orelse return errors.SerializationError.InvalidFormat;
        const vm_state = try NeoVMStateType.decodeFromJson(vm_state_value);
        const gas_consumed = try allocator.dupe(u8, obj.get("gasconsumed").?.string);

        const exception = if (obj.get("exception")) |ex|
            switch (ex) {
                .string => |value| try allocator.dupe(u8, value),
                .null => null,
                else => try stringifyJsonValue(ex, allocator),
            }
        else
            null;

        var stack_items = ArrayList(StackItem).init(allocator);
        defer stack_items.deinit();
        if (obj.get("stack")) |stack_value| {
            if (stack_value != .array) return errors.SerializationError.InvalidFormat;
            for (stack_value.array.items) |entry| {
                var parsed_item = try StackItem.decodeFromJson(entry, allocator);
                var item_guard = true;
                defer if (item_guard) parsed_item.deinit(allocator);
                try stack_items.append(parsed_item);
                item_guard = false;
            }
        }

        var notifications_list = ArrayList(Notification).init(allocator);
        defer notifications_list.deinit();
        if (obj.get("notifications")) |notifications_value| {
            if (notifications_value != .array) return errors.SerializationError.InvalidFormat;
            for (notifications_value.array.items) |notification_value| {
                var notification = try Notification.fromJson(notification_value, allocator);
                var notification_guard = true;
                defer if (notification_guard) notification.deinit(allocator);
                try notifications_list.append(notification);
                notification_guard = false;
            }
        }

        return Execution{
            .trigger = trigger,
            .vm_state = vm_state,
            .exception = exception,
            .gas_consumed = gas_consumed,
            .stack = try stack_items.toOwnedSlice(),
            .notifications = try notifications_list.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *Execution, allocator: std.mem.Allocator) void {
        if (self.trigger.len > 0) allocator.free(@constCast(self.trigger));
        if (self.gas_consumed.len > 0) allocator.free(@constCast(self.gas_consumed));
        if (self.exception) |ex| {
            if (ex.len > 0) allocator.free(@constCast(ex));
        }

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

/// Notification
pub const Notification = struct {
    contract: Hash160,
    event_name: []const u8,
    state: StackItem,

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Notification {
        const obj = json_value.object;

        const contract = try Hash160.initWithString(obj.get("contract").?.string);
        const event_name = try allocator.dupe(u8, obj.get("eventname").?.string);
        const state_value = obj.get("state") orelse return errors.SerializationError.InvalidFormat;
        var state = try StackItem.decodeFromJson(state_value, allocator);
        errdefer state.deinit(allocator);

        return Notification{
            .contract = contract,
            .event_name = event_name,
            .state = state,
        };
    }

    pub fn deinit(self: *Notification, allocator: std.mem.Allocator) void {
        if (self.event_name.len > 0) allocator.free(@constCast(self.event_name));
        self.state.deinit(allocator);
    }
};
