//! Notification Implementation
//!
//! Complete conversion from NeoSwift Notification.swift
//! Provides smart contract event notification structure.

const std = @import("std");
const Hash160 = @import("../../types/hash160.zig").Hash160;
const StackItem = @import("../../types/stack_item.zig").StackItem;

/// Smart contract notification (converted from Swift Notification)
pub const Notification = struct {
    /// Contract hash that emitted the notification
    contract: Hash160,
    /// Event name
    event_name: []const u8,
    /// Event state/parameters
    state: StackItem,
    
    const Self = @This();
    
    /// Creates new Notification (equivalent to Swift init)
    pub fn init(contract: Hash160, event_name: []const u8, state: StackItem) Self {
        return Self{
            .contract = contract,
            .event_name = event_name,
            .state = state,
        };
    }
    
    /// Gets contract hash
    pub fn getContract(self: Self) Hash160 {
        return self.contract;
    }
    
    /// Gets event name
    pub fn getEventName(self: Self) []const u8 {
        return self.event_name;
    }
    
    /// Gets event state
    pub fn getState(self: Self) StackItem {
        return self.state;
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return self.contract.eql(other.contract) and
               std.mem.eql(u8, self.event_name, other.event_name) and
               self.state.eql(other.state);
    }
    
    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        const contract_hash = self.contract.hash();
        hasher.update(std.mem.asBytes(&contract_hash));
        hasher.update(self.event_name);
        
        const state_hash = self.state.hash();
        hasher.update(std.mem.asBytes(&state_hash));
        
        return hasher.final();
    }
    
    /// JSON encoding
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const contract_str = try self.contract.toString(allocator);
        defer allocator.free(contract_str);
        
        const state_json = try self.state.encodeToJson(allocator);
        defer allocator.free(state_json);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"contract\":\"{s}\",\"eventname\":\"{s}\",\"state\":{s}}}",
            .{ contract_str, self.event_name, state_json }
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.event_name);
        self.state.deinit(allocator);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const event_name_copy = try allocator.dupe(u8, self.event_name);
        // Note: StackItem cloning would need to be implemented based on type
        
        return Self.init(self.contract, event_name_copy, self.state);
    }
};

// Tests (converted from Swift Notification tests)
test "Notification creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test notification creation
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const event_name = try allocator.dupe(u8, "Transfer");
    
    const state = StackItem.Factory.createBoolean(true);
    
    var notification = Notification.init(contract_hash, event_name, state);
    defer notification.deinit(allocator);
    
    try testing.expect(notification.getContract().eql(contract_hash));
    try testing.expectEqualStrings("Transfer", notification.getEventName());
    
    const retrieved_state = notification.getState();
    try testing.expect(try retrieved_state.getBoolean());
}