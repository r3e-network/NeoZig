//! Neo Block Implementation
//!
//! Complete conversion from NeoSwift NeoBlock.swift
//! Provides Neo block structure for blockchain data.

const std = @import("std");
const Hash256 = @import("../../types/hash256.zig").Hash256;
const NeoWitness = @import("neo_witness.zig").NeoWitness;
const Transaction = @import("transaction.zig").Transaction;

/// Neo block structure (converted from Swift NeoBlock)
pub const NeoBlock = struct {
    /// Block hash
    hash: Hash256,
    /// Block size in bytes
    size: u32,
    /// Block version
    version: u32,
    /// Previous block hash
    prev_block_hash: Hash256,
    /// Merkle root hash
    merkle_root_hash: Hash256,
    /// Block timestamp
    time: u64,
    /// Block index
    index: u32,
    /// Primary consensus node index
    primary: ?u32,
    /// Next consensus address
    next_consensus: []const u8,
    /// Block witnesses
    witnesses: ?[]NeoWitness,
    /// Block transactions
    transactions: ?[]Transaction,
    /// Number of confirmations
    confirmations: u32,
    /// Next block hash
    next_block_hash: ?Hash256,
    
    const Self = @This();
    
    /// Creates new NeoBlock (equivalent to Swift init)
    pub fn init(
        hash: Hash256,
        size: u32,
        version: u32,
        prev_block_hash: Hash256,
        merkle_root_hash: Hash256,
        time: u64,
        index: u32,
        primary: ?u32,
        next_consensus: []const u8,
        witnesses: ?[]NeoWitness,
        transactions: ?[]Transaction,
        confirmations: u32,
        next_block_hash: ?Hash256,
    ) Self {
        return Self{
            .hash = hash,
            .size = size,
            .version = version,
            .prev_block_hash = prev_block_hash,
            .merkle_root_hash = merkle_root_hash,
            .time = time,
            .index = index,
            .primary = primary,
            .next_consensus = next_consensus,
            .witnesses = witnesses,
            .transactions = transactions,
            .confirmations = confirmations,
            .next_block_hash = next_block_hash,
        };
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return self.hash.eql(other.hash) and
               self.size == other.size and
               self.version == other.version and
               self.prev_block_hash.eql(other.prev_block_hash) and
               self.merkle_root_hash.eql(other.merkle_root_hash) and
               self.time == other.time and
               self.index == other.index and
               self.primary == other.primary and
               std.mem.eql(u8, self.next_consensus, other.next_consensus) and
               self.confirmations == other.confirmations and
               ((self.next_block_hash == null and other.next_block_hash == null) or
                (self.next_block_hash != null and other.next_block_hash != null and 
                 self.next_block_hash.?.eql(other.next_block_hash.?)));
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hashValue(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        const block_hash = self.hash.hash();
        hasher.update(std.mem.asBytes(&block_hash));
        hasher.update(std.mem.asBytes(&self.size));
        hasher.update(std.mem.asBytes(&self.version));
        hasher.update(std.mem.asBytes(&self.index));
        
        return hasher.final();
    }
    
    /// Gets block hash
    pub fn getHash(self: Self) Hash256 {
        return self.hash;
    }
    
    /// Gets block index
    pub fn getIndex(self: Self) u32 {
        return self.index;
    }
    
    /// Gets block size
    pub fn getSize(self: Self) u32 {
        return self.size;
    }
    
    /// Gets block timestamp
    pub fn getTimestamp(self: Self) u64 {
        return self.time;
    }
    
    /// Gets transaction count
    pub fn getTransactionCount(self: Self) usize {
        if (self.transactions) |txs| {
            return txs.len;
        }
        return 0;
    }
    
    /// Gets witness count
    pub fn getWitnessCount(self: Self) usize {
        if (self.witnesses) |witnesses| {
            return witnesses.len;
        }
        return 0;
    }
    
    /// Checks if block has transactions
    pub fn hasTransactions(self: Self) bool {
        return self.transactions != null and self.transactions.?.len > 0;
    }
    
    /// Checks if block has witnesses
    pub fn hasWitnesses(self: Self) bool {
        return self.witnesses != null and self.witnesses.?.len > 0;
    }
    
    /// Checks if block is confirmed
    pub fn isConfirmed(self: Self) bool {
        return self.confirmations > 0;
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hash_str = try self.hash.toString(allocator);
        defer allocator.free(hash_str);
        
        const prev_hash_str = try self.prev_block_hash.toString(allocator);
        defer allocator.free(prev_hash_str);
        
        const merkle_root_str = try self.merkle_root_hash.toString(allocator);
        defer allocator.free(merkle_root_str);
        
        const primary_str = if (self.primary) |p|
            try std.fmt.allocPrint(allocator, "{}", .{p})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(primary_str);
        
        const next_hash_str = if (self.next_block_hash) |nh|
            try nh.toString(allocator)
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(next_hash_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"hash\":\"{s}\",\"size\":{},\"version\":{},\"previousblockhash\":\"{s}\",\"merkleroot\":\"{s}\",\"time\":{},\"index\":{},\"primary\":{s},\"nextconsensus\":\"{s}\",\"confirmations\":{},\"nextblockhash\":{s}}}",
            .{
                hash_str,
                self.size,
                self.version,
                prev_hash_str,
                merkle_root_str,
                self.time,
                self.index,
                primary_str,
                self.next_consensus,
                self.confirmations,
                next_hash_str,
            }
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const hash = try Hash256.initWithString(json_obj.get("hash").?.string);
        const size = @as(u32, @intCast(json_obj.get("size").?.integer));
        const version = @as(u32, @intCast(json_obj.get("version").?.integer));
        const prev_block_hash = try Hash256.initWithString(json_obj.get("previousblockhash").?.string);
        const merkle_root_hash = try Hash256.initWithString(json_obj.get("merkleroot").?.string);
        const time = @as(u64, @intCast(json_obj.get("time").?.integer));
        const index = @as(u32, @intCast(json_obj.get("index").?.integer));
        
        const primary = if (json_obj.get("primary")) |primary_value|
            switch (primary_value) {
                .integer => |i| @as(u32, @intCast(i)),
                .null => null,
                else => null,
            }
        else
            null;
        
        const next_consensus = try allocator.dupe(u8, json_obj.get("nextconsensus").?.string);
        const confirmations = @as(u32, @intCast(json_obj.get("confirmations").?.integer));
        
        const next_block_hash = if (json_obj.get("nextblockhash")) |next_hash_value|
            switch (next_hash_value) {
                .string => |s| try Hash256.initWithString(s),
                .null => null,
                else => null,
            }
        else
            null;
        
        return Self.init(
            hash,
            size,
            version,
            prev_block_hash,
            merkle_root_hash,
            time,
            index,
            primary,
            next_consensus,
            null, // witnesses - would need separate parsing
            null, // transactions - would need separate parsing
            confirmations,
            next_block_hash,
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.next_consensus);
        
        if (self.witnesses) |witnesses| {
            for (witnesses) |*witness| {
                witness.deinit(allocator);
            }
            allocator.free(witnesses);
        }
        
        if (self.transactions) |transactions| {
            for (transactions) |*tx| {
                tx.deinit(allocator);
            }
            allocator.free(transactions);
        }
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const next_consensus_copy = try allocator.dupe(u8, self.next_consensus);
        
        // Clone witnesses if present
        const witnesses_copy = if (self.witnesses) |witnesses| blk: {
            var witnesses_list = try std.ArrayList(NeoWitness).initCapacity(allocator, witnesses.len);
            defer witnesses_list.deinit();
            
            for (witnesses) |witness| {
                try witnesses_list.append(try witness.clone(allocator));
            }
            
            break :blk try witnesses_list.toOwnedSlice();
        } else null;
        
        // Clone transactions if present  
        const transactions_copy = if (self.transactions) |transactions| blk: {
            var tx_list = try std.ArrayList(Transaction).initCapacity(allocator, transactions.len);
            defer tx_list.deinit();
            
            for (transactions) |tx| {
                try tx_list.append(try tx.clone(allocator));
            }
            
            break :blk try tx_list.toOwnedSlice();
        } else null;
        
        return Self.init(
            self.hash,
            self.size,
            self.version,
            self.prev_block_hash,
            self.merkle_root_hash,
            self.time,
            self.index,
            self.primary,
            next_consensus_copy,
            witnesses_copy,
            transactions_copy,
            self.confirmations,
            self.next_block_hash,
        );
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hash_str = try self.hash.toString(allocator);
        defer allocator.free(hash_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "NeoBlock(index: {}, hash: {s}, size: {} bytes, txs: {}, confirmations: {})",
            .{ 
                self.index, 
                hash_str, 
                self.size, 
                self.getTransactionCount(), 
                self.confirmations 
            }
        );
    }
};

// Tests (converted from Swift NeoBlock tests)
test "NeoBlock creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test block creation (equivalent to Swift tests)
    const block_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const prev_hash = try Hash256.initWithString("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab");
    const merkle_root = try Hash256.initWithString("0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba98");
    
    const next_consensus = try allocator.dupe(u8, "NX8GreRFGFK5wpGMWetpX93HmtrezGogzk");
    defer allocator.free(next_consensus);
    
    var block = NeoBlock.init(
        block_hash,
        1024,           // size
        0,              // version
        prev_hash,
        merkle_root,
        1234567890,     // time
        12345,          // index
        0,              // primary
        next_consensus,
        null,           // witnesses
        null,           // transactions
        6,              // confirmations
        null,           // next_block_hash
    );
    defer block.deinit(allocator);
    
    // Verify block properties
    try testing.expect(block.getHash().eql(block_hash));
    try testing.expectEqual(@as(u32, 12345), block.getIndex());
    try testing.expectEqual(@as(u32, 1024), block.getSize());
    try testing.expectEqual(@as(u64, 1234567890), block.getTimestamp());
    try testing.expectEqual(@as(u32, 6), block.confirmations);
    try testing.expect(block.isConfirmed());
    try testing.expect(!block.hasTransactions());
    try testing.expect(!block.hasWitnesses());
}

test "NeoBlock equality and hashing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test equality (equivalent to Swift Hashable tests)
    const block_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const prev_hash = try Hash256.initWithString("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab");
    const merkle_root = try Hash256.initWithString("0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba98");
    
    const next_consensus1 = try allocator.dupe(u8, "NX8GreRFGFK5wpGMWetpX93HmtrezGogzk");
    defer allocator.free(next_consensus1);
    
    const next_consensus2 = try allocator.dupe(u8, "NX8GreRFGFK5wpGMWetpX93HmtrezGogzk");
    defer allocator.free(next_consensus2);
    
    var block1 = NeoBlock.init(block_hash, 1024, 0, prev_hash, merkle_root, 1234567890, 12345, 0, next_consensus1, null, null, 6, null);
    defer block1.deinit(allocator);
    
    var block2 = NeoBlock.init(block_hash, 1024, 0, prev_hash, merkle_root, 1234567890, 12345, 0, next_consensus2, null, null, 6, null);
    defer block2.deinit(allocator);
    
    try testing.expect(block1.eql(block2));
    
    const hash1 = block1.hash();
    const hash2 = block2.hash();
    try testing.expectEqual(hash1, hash2);
}

test "NeoBlock JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const block_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const prev_hash = try Hash256.initWithString("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab");
    const merkle_root = try Hash256.initWithString("0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba98");
    
    const next_consensus = try allocator.dupe(u8, "NX8GreRFGFK5wpGMWetpX93HmtrezGogzk");
    defer allocator.free(next_consensus);
    
    var original_block = NeoBlock.init(block_hash, 2048, 0, prev_hash, merkle_root, 1640995200, 100000, 2, next_consensus, null, null, 10, null);
    defer original_block.deinit(allocator);
    
    const json_str = try original_block.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "previousblockhash") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "merkleroot") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "nextconsensus") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "100000") != null);
    
    var decoded_block = try NeoBlock.decodeFromJson(json_str, allocator);
    defer decoded_block.deinit(allocator);
    
    try testing.expectEqual(original_block.index, decoded_block.index);
    try testing.expectEqual(original_block.size, decoded_block.size);
    try testing.expectEqual(original_block.time, decoded_block.time);
}