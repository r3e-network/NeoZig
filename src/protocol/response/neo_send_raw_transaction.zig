//! Neo SendRawTransaction Implementation
//!
//! Complete conversion from NeoSwift NeoSendRawTransaction.swift
//! Provides transaction broadcast response structure.

const std = @import("std");


const Hash256 = @import("../../types/hash256.zig").Hash256;

/// Raw transaction response (converted from Swift RawTransaction)
pub const RawTransaction = struct {
    /// Transaction hash
    hash: Hash256,
    
    const Self = @This();
    
    /// Creates new RawTransaction (equivalent to Swift init)
    pub fn init(hash: Hash256) Self {
        return Self{ .hash = hash };
    }
    
    /// Gets transaction hash
    pub fn getHash(self: Self) Hash256 {
        return self.hash;
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return self.hash.eql(other.hash);
    }
    
    /// Hash function
    pub fn hashValue(self: Self) u64 {
        return self.hash.hash();
    }
    
    /// JSON encoding
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hash_str = try self.hash.toString(allocator);
        defer allocator.free(hash_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"hash\":\"{s}\"}}",
            .{hash_str}
        );
    }
};

/// SendRawTransaction RPC response wrapper (converted from Swift NeoSendRawTransaction)
pub const NeoSendRawTransaction = struct {
    /// The transaction result
    result: ?RawTransaction,
    
    const Self = @This();
    
    /// Creates new SendRawTransaction response
    pub fn init(result: ?RawTransaction) Self {
        return Self{ .result = result };
    }
    
    /// Gets the transaction (equivalent to Swift transaction property)
    pub fn getTransaction(self: Self) ?RawTransaction {
        return self.result;
    }
    
    /// Checks if broadcast was successful
    pub fn isSuccessful(self: Self) bool {
        return self.result != null;
    }
    
    /// Gets transaction hash if available
    pub fn getTransactionHash(self: Self) ?Hash256 {
        if (self.result) |tx| {
            return tx.getHash();
        }
        return null;
    }
};

// Tests (converted from Swift NeoSendRawTransaction tests)
test "RawTransaction creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test raw transaction creation
    const tx_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    
    const raw_tx = RawTransaction.init(tx_hash);
    
    try testing.expect(raw_tx.getHash().eql(tx_hash));
    
    // Test JSON encoding
    const json_str = try raw_tx.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(std.mem.indexOf(u8, json_str, "hash") != null);
}

test "NeoSendRawTransaction response wrapper" {
    const testing = std.testing;
    
    // Test successful response
    const tx_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const raw_tx = RawTransaction.init(tx_hash);
    
    const response = NeoSendRawTransaction.init(raw_tx);
    
    try testing.expect(response.isSuccessful());
    try testing.expect(response.getTransaction() != null);
    try testing.expect(response.getTransactionHash() != null);
    try testing.expect(response.getTransactionHash().?.eql(tx_hash));
    
    // Test empty response
    const empty_response = NeoSendRawTransaction.init(null);
    try testing.expect(!empty_response.isSuccessful());
    try testing.expect(empty_response.getTransaction() == null);
    try testing.expect(empty_response.getTransactionHash() == null);
}