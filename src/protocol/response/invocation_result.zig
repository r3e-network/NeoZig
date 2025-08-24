//! Invocation Result Implementation
//!
//! Complete conversion from NeoSwift InvocationResult.swift
//! Provides smart contract invocation result structure.

const std = @import("std");
const NeoVMStateType = @import("../../types/neo_vm_state_type.zig").NeoVMStateType;
const StackItem = @import("../../types/stack_item.zig").StackItem;

/// Pending signature structure (converted from Swift PendingSignature)
pub const PendingSignature = struct {
    type: []const u8,
    data: []const u8,
    items: std.HashMap([]const u8, SignatureItem, StringContext, std.hash_map.default_max_load_percentage),
    
    const Self = @This();
    const StringContext = std.HashMap.StringContext;
    
    pub fn init(type_str: []const u8, data: []const u8, allocator: std.mem.Allocator) Self {
        return Self{
            .type = type_str,
            .data = data,
            .items = std.HashMap([]const u8, SignatureItem, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.items.deinit();
    }
};

/// Signature item structure
pub const SignatureItem = struct {
    script: []const u8,
    parameters: ?[]const u8,
    signatures: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    
    const Self = @This();
    const StringContext = std.HashMap.StringContext;
    
    pub fn init(script: []const u8, allocator: std.mem.Allocator) Self {
        return Self{
            .script = script,
            .parameters = null,
            .signatures = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.signatures.deinit();
    }
};

/// Notification structure (referenced in InvocationResult)
pub const Notification = struct {
    contract: []const u8,
    event_name: []const u8,
    state: StackItem,
    
    const Self = @This();
    
    pub fn init(contract: []const u8, event_name: []const u8, state: StackItem) Self {
        return Self{
            .contract = contract,
            .event_name = event_name,
            .state = state,
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.contract);
        allocator.free(self.event_name);
        self.state.deinit(allocator);
    }
};

/// Diagnostics structure (referenced in InvocationResult)
pub const Diagnostics = struct {
    invoked_contracts: [][]const u8,
    storage_changes: []StorageChange,
    
    const Self = @This();
    
    pub fn init(invoked_contracts: [][]const u8, storage_changes: []StorageChange) Self {
        return Self{
            .invoked_contracts = invoked_contracts,
            .storage_changes = storage_changes,
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (self.invoked_contracts) |contract| {
            allocator.free(contract);
        }
        allocator.free(self.invoked_contracts);
        
        for (self.storage_changes) |*change| {
            change.deinit(allocator);
        }
        allocator.free(self.storage_changes);
    }
};

/// Storage change structure
pub const StorageChange = struct {
    key: []const u8,
    value: []const u8,
    
    const Self = @This();
    
    pub fn init(key: []const u8, value: []const u8) Self {
        return Self{ .key = key, .value = value };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

/// Invocation result structure (converted from Swift InvocationResult)
pub const InvocationResult = struct {
    /// Invocation script
    script: []const u8,
    /// VM execution state
    state: NeoVMStateType,
    /// Gas consumed
    gas_consumed: []const u8,
    /// Exception message (if any)
    exception: ?[]const u8,
    /// Contract notifications
    notifications: ?[]Notification,
    /// Diagnostics information
    diagnostics: ?Diagnostics,
    /// Result stack
    stack: []StackItem,
    /// Transaction hex (if built)
    tx: ?[]const u8,
    /// Pending signature (if needed)
    pending_signature: ?PendingSignature,
    /// Session ID (for iterators)
    session_id: ?[]const u8,
    
    const Self = @This();
    
    /// Creates new InvocationResult (equivalent to Swift init)
    pub fn init(
        script: []const u8,
        state: NeoVMStateType,
        gas_consumed: []const u8,
        exception: ?[]const u8,
        notifications: ?[]Notification,
        diagnostics: ?Diagnostics,
        stack: []StackItem,
        tx: ?[]const u8,
        pending_signature: ?PendingSignature,
        session_id: ?[]const u8,
    ) Self {
        return Self{
            .script = script,
            .state = state,
            .gas_consumed = gas_consumed,
            .exception = exception,
            .notifications = notifications,
            .diagnostics = diagnostics,
            .stack = stack,
            .tx = tx,
            .pending_signature = pending_signature,
            .session_id = session_id,
        };
    }
    
    /// Checks if state is fault (equivalent to Swift hasStateFault)
    pub fn hasStateFault(self: Self) bool {
        return self.state == .Fault;
    }
    
    /// Checks if invocation was successful
    pub fn isSuccessful(self: Self) bool {
        return self.state == .Halt;
    }
    
    /// Gets first stack item (equivalent to Swift getFirstStackItem)
    pub fn getFirstStackItem(self: Self) !StackItem {
        if (self.stack.len == 0) {
            return error.EmptyStack;
        }
        return self.stack[0];
    }
    
    /// Gets stack item count
    pub fn getStackItemCount(self: Self) usize {
        return self.stack.len;
    }
    
    /// Checks if has exception
    pub fn hasException(self: Self) bool {
        return self.exception != null;
    }
    
    /// Checks if has notifications
    pub fn hasNotifications(self: Self) bool {
        return self.notifications != null and self.notifications.?.len > 0;
    }
    
    /// Checks if has session (for iterators)
    pub fn hasSession(self: Self) bool {
        return self.session_id != null;
    }
    
    /// Gets gas consumed as integer
    pub fn getGasConsumedAsInt(self: Self) !u64 {
        return try std.fmt.parseInt(u64, self.gas_consumed, 10);
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.script, other.script) and
               self.state == other.state and
               std.mem.eql(u8, self.gas_consumed, other.gas_consumed) and
               self.stack.len == other.stack.len;
    }
    
    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.script);
        hasher.update(&[_]u8{@intFromEnum(self.state)});
        hasher.update(self.gas_consumed);
        return hasher.final();
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
        allocator.free(self.gas_consumed);
        
        if (self.exception) |exception| {
            allocator.free(exception);
        }
        
        if (self.notifications) |notifications| {
            for (notifications) |*notification| {
                notification.deinit(allocator);
            }
            allocator.free(notifications);
        }
        
        if (self.diagnostics) |*diagnostics| {
            diagnostics.deinit(allocator);
        }
        
        for (self.stack) |*item| {
            item.deinit(allocator);
        }
        allocator.free(self.stack);
        
        if (self.tx) |tx| {
            allocator.free(tx);
        }
        
        if (self.pending_signature) |*pending| {
            pending.deinit();
        }
        
        if (self.session_id) |session| {
            allocator.free(session);
        }
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const state_str = switch (self.state) {
            .Halt => "HALT",
            .Fault => "FAULT",
            .Break => "BREAK",
        };
        
        return try std.fmt.allocPrint(
            allocator,
            "InvocationResult(state: {s}, gas: {s}, stack: {}, notifications: {})",
            .{ 
                state_str, 
                self.gas_consumed, 
                self.stack.len, 
                if (self.notifications) |n| n.len else 0 
            }
        );
    }
};

// Tests (converted from Swift InvocationResult tests)
test "InvocationResult creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test successful invocation
    const script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ==");
    const gas_consumed = try allocator.dupe(u8, "1000000");
    
    var successful_result = InvocationResult.init(
        script,
        NeoVMStateType.Halt,
        gas_consumed,
        null,
        null,
        null,
        &[_]StackItem{},
        null,
        null,
        null,
    );
    defer successful_result.deinit(allocator);
    
    try testing.expect(successful_result.isSuccessful());
    try testing.expect(!successful_result.hasStateFault());
    try testing.expect(!successful_result.hasException());
    try testing.expectEqual(@as(u64, 1000000), try successful_result.getGasConsumedAsInt());
    
    // Test fault invocation
    const fault_script = try allocator.dupe(u8, "fault_script");
    const fault_gas = try allocator.dupe(u8, "500000");
    const exception = try allocator.dupe(u8, "Runtime exception");
    
    var fault_result = InvocationResult.init(
        fault_script,
        NeoVMStateType.Fault,
        fault_gas,
        exception,
        null,
        null,
        &[_]StackItem{},
        null,
        null,
        null,
    );
    defer fault_result.deinit(allocator);
    
    try testing.expect(!fault_result.isSuccessful());
    try testing.expect(fault_result.hasStateFault());
    try testing.expect(fault_result.hasException());
}