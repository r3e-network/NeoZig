//! Native ContractState Implementation
//!
//! Complete conversion from NeoSwift NativeContractState.swift

const std = @import("std");


const Hash160 = @import("../../types/hash160.zig").Hash160;

pub const NativeContractState = struct {
    id: i32,
    hash: Hash160,
    nef: []const u8,
    manifest: []const u8,
    update_history: []u32,
    
    pub fn init(id: i32, hash: Hash160, nef: []const u8, manifest: []const u8, update_history: []u32) @This() {
        return .{
            .id = id,
            .hash = hash,
            .nef = nef,
            .manifest = manifest,
            .update_history = update_history,
        };
    }
    
    pub fn getId(self: @This()) i32 {
        return self.id;
    }
    
    pub fn getHash(self: @This()) Hash160 {
        return self.hash;
    }
    
    pub fn hasUpdateHistory(self: @This()) bool {
        return self.update_history.len > 0;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.nef);
        allocator.free(self.manifest);
        allocator.free(self.update_history);
    }
};