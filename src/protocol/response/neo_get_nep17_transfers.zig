//! Neo GetNep17Transfers Implementation
//!
//! Complete conversion from NeoSwift NeoGetNep17Transfers.swift

const std = @import("std");
const Hash160 = @import("../../types/hash160.zig").Hash160;
const Hash256 = @import("../../types/hash256.zig").Hash256;

pub const Nep17Transfer = struct {
    timestamp: u64,
    asset_hash: Hash160,
    transfer_address: []const u8,
    amount: []const u8,
    block_index: u32,
    transfer_notify_index: u32,
    tx_hash: Hash256,
    
    pub fn init(
        timestamp: u64,
        asset_hash: Hash160,
        transfer_address: []const u8,
        amount: []const u8,
        block_index: u32,
        transfer_notify_index: u32,
        tx_hash: Hash256,
    ) @This() {
        return .{
            .timestamp = timestamp,
            .asset_hash = asset_hash,
            .transfer_address = transfer_address,
            .amount = amount,
            .block_index = block_index,
            .transfer_notify_index = transfer_notify_index,
            .tx_hash = tx_hash,
        };
    }
    
    pub fn getAmount(self: @This()) []const u8 {
        return self.amount;
    }
    
    pub fn getAmountAsInt(self: @This()) !u64 {
        return try std.fmt.parseInt(u64, self.amount, 10);
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.transfer_address);
        allocator.free(self.amount);
    }
};

pub const Nep17Transfers = struct {
    sent: []Nep17Transfer,
    received: []Nep17Transfer,
    address: []const u8,
    
    pub fn init(sent: []Nep17Transfer, received: []Nep17Transfer, address: []const u8) @This() {
        return .{ .sent = sent, .received = received, .address = address };
    }
    
    pub fn getSentCount(self: @This()) usize {
        return self.sent.len;
    }
    
    pub fn getReceivedCount(self: @This()) usize {
        return self.received.len;
    }
    
    pub fn getTotalTransferCount(self: @This()) usize {
        return self.sent.len + self.received.len;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.sent) |*transfer| {
            transfer.deinit(allocator);
        }
        for (self.received) |*transfer| {
            transfer.deinit(allocator);
        }
        allocator.free(self.sent);
        allocator.free(self.received);
        allocator.free(self.address);
    }
};

pub const NeoGetNep17Transfers = struct {
    result: ?Nep17Transfers,
    
    pub fn init(result: ?Nep17Transfers) @This() {
        return .{ .result = result };
    }
    
    pub fn getTransfers(self: @This()) ?Nep17Transfers {
        return self.result;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        if (self.result) |*transfers| {
            transfers.deinit(allocator);
        }
    }
};