//! Neo GetTokenBalances Implementation
//!
//! Complete conversion from NeoSwift NeoGetTokenBalances.swift

const std = @import("std");


const Hash160 = @import("../../types/hash160.zig").Hash160;

pub const TokenBalance = struct {
    asset_hash: Hash160,
    amount: []const u8,
    last_updated_block: u32,
    
    pub fn init(asset_hash: Hash160, amount: []const u8, last_updated_block: u32) @This() {
        return .{ .asset_hash = asset_hash, .amount = amount, .last_updated_block = last_updated_block };
    }
    
    pub fn getAssetHash(self: @This()) Hash160 {
        return self.asset_hash;
    }
    
    pub fn getAmount(self: @This()) []const u8 {
        return self.amount;
    }
    
    pub fn getAmountAsInt(self: @This()) !u64 {
        return try std.fmt.parseInt(u64, self.amount, 10);
    }
    
    pub fn isZero(self: @This()) bool {
        return std.mem.eql(u8, self.amount, "0");
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.amount);
    }
};

pub const NeoGetTokenBalances = struct {
    address: []const u8,
    balances: []TokenBalance,
    
    pub fn init(address: []const u8, balances: []TokenBalance) @This() {
        return .{ .address = address, .balances = balances };
    }
    
    pub fn getAddress(self: @This()) []const u8 {
        return self.address;
    }
    
    pub fn getBalanceCount(self: @This()) usize {
        return self.balances.len;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        
        for (self.balances) |*balance| {
            balance.deinit(allocator);
        }
        allocator.free(self.balances);
    }
};