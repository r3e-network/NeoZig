//! Neo ApplicationLog Implementation
//!
//! Complete conversion from NeoSwift NeoApplicationLog.swift
//! Provides application execution log structure.

const std = @import("std");
const Hash256 = @import("../../types/hash256.zig").Hash256;
const NeoVMStateType = @import("../../types/neo_vm_state_type.zig").NeoVMStateType;
const Notification = @import("notification.zig").Notification;

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
    stack: []const u8,
    /// Notifications
    notifications: []Notification,
    
    const Self = @This();
    
    pub fn init(
        trigger: []const u8,
        vm_state: NeoVMStateType,
        exception: ?[]const u8,
        gas_consumed: []const u8,
        stack: []const u8,
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
        allocator.free(self.trigger);
        if (self.exception) |exception| {
            allocator.free(exception);
        }
        allocator.free(self.gas_consumed);
        allocator.free(self.stack);
        
        for (self.notifications) |*notification| {
            notification.deinit(allocator);
        }
        allocator.free(self.notifications);
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
        allocator.free(self.executions);
    }
};

// Tests
test "ApplicationExecution creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const trigger = try allocator.dupe(u8, "Application");
    const gas_consumed = try allocator.dupe(u8, "1000000");
    const stack = try allocator.dupe(u8, "[]");
    
    var execution = ApplicationExecution.init(
        trigger,
        NeoVMStateType.Halt,
        null,
        gas_consumed,
        stack,
        &[_]Notification{},
    );
    defer execution.deinit(allocator);
    
    try testing.expect(execution.isSuccessful());
    try testing.expect(!execution.hasFault());
    try testing.expect(!execution.hasException());
    try testing.expect(!execution.hasNotifications());
}