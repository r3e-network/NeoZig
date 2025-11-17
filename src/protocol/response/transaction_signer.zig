//! TransactionSigner Implementation
//!
//! Complete conversion from NeoSwift TransactionSigner.swift

const std = @import("std");


const Hash160 = @import("../../types/hash160.zig").Hash160;

pub const TransactionSigner = struct {
    account: Hash160,
    scopes: []const u8,
    allowed_contracts: ?[]Hash160,
    allowed_groups: ?[][]const u8,
    rules: ?[][]const u8,
    
    pub fn init(account: Hash160, scopes: []const u8) @This() {
        return .{
            .account = account,
            .scopes = scopes,
            .allowed_contracts = null,
            .allowed_groups = null,
            .rules = null,
        };
    }
    
    pub fn getAccount(self: @This()) Hash160 {
        return self.account;
    }
    
    pub fn getScopes(self: @This()) []const u8 {
        return self.scopes;
    }
    
    pub fn hasAllowedContracts(self: @This()) bool {
        return self.allowed_contracts != null and self.allowed_contracts.?.len > 0;
    }
    
    pub fn hasAllowedGroups(self: @This()) bool {
        return self.allowed_groups != null and self.allowed_groups.?.len > 0;
    }
    
    pub fn eql(self: @This(), other: @This()) bool {
        return self.account.eql(other.account) and 
               std.mem.eql(u8, self.scopes, other.scopes);
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.scopes);
        
        if (self.allowed_contracts) |contracts| {
            allocator.free(contracts);
        }
        
        if (self.allowed_groups) |groups| {
            for (groups) |group| {
                allocator.free(group);
            }
            allocator.free(groups);
        }
        
        if (self.rules) |rules| {
            for (rules) |rule| {
                allocator.free(rule);
            }
            allocator.free(rules);
        }
    }
};