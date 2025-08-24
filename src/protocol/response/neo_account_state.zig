//! Neo AccountState Implementation
//!
//! Complete conversion from NeoSwift NeoAccountState.swift

const std = @import("std");
const Hash160 = @import("../../types/hash160.zig").Hash160;

pub const NeoAccountState = struct {
    version: u8,
    script_hash: Hash160,
    frozen: bool,
    votes: ?[][]const u8,
    balances: []TokenBalance,
    
    pub const TokenBalance = struct {
        asset: Hash160,
        value: []const u8,
        
        pub fn init(asset: Hash160, value: []const u8) @This() {
            return .{ .asset = asset, .value = value };
        }
        
        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.value);
        }
    };
    
    pub fn init(version: u8, script_hash: Hash160, frozen: bool, votes: ?[][]const u8, balances: []TokenBalance) @This() {
        return .{
            .version = version,
            .script_hash = script_hash,
            .frozen = frozen,
            .votes = votes,
            .balances = balances,
        };
    }
    
    pub fn isFrozen(self: @This()) bool {
        return self.frozen;
    }
    
    pub fn hasVotes(self: @This()) bool {
        return self.votes != null and self.votes.?.len > 0;
    }
    
    pub fn getBalanceCount(self: @This()) usize {
        return self.balances.len;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        if (self.votes) |votes| {
            for (votes) |vote| {
                allocator.free(vote);
            }
            allocator.free(votes);
        }
        
        for (self.balances) |*balance| {
            balance.deinit(allocator);
        }
        allocator.free(self.balances);
    }
};