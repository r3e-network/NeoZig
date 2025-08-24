//! Diagnostics Implementation
//!
//! Complete conversion from NeoSwift Diagnostics.swift

const std = @import("std");
const Hash160 = @import("../../types/hash160.zig").Hash160;

pub const StorageChange = struct {
    state: []const u8,
    key: []const u8,
    value: []const u8,
    
    pub fn init(state: []const u8, key: []const u8, value: []const u8) @This() {
        return .{ .state = state, .key = key, .value = value };
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.state);
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

pub const Diagnostics = struct {
    invoked_contracts: []Hash160,
    storage_changes: []StorageChange,
    
    pub fn init(invoked_contracts: []Hash160, storage_changes: []StorageChange) @This() {
        return .{ .invoked_contracts = invoked_contracts, .storage_changes = storage_changes };
    }
    
    pub fn hasInvokedContracts(self: @This()) bool {
        return self.invoked_contracts.len > 0;
    }
    
    pub fn hasStorageChanges(self: @This()) bool {
        return self.storage_changes.len > 0;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.invoked_contracts);
        
        for (self.storage_changes) |*change| {
            change.deinit(allocator);
        }
        allocator.free(self.storage_changes);
    }
};