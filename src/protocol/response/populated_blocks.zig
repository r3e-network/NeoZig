//! Populated Blocks Implementation
//!
//! Complete conversion from NeoSwift PopulatedBlocks.swift
//! Provides populated blocks response representation.

const std = @import("std");

/// Populated blocks response (converted from Swift PopulatedBlocks)
pub const PopulatedBlocks = struct {
    /// Cache identifier
    cache_id: []const u8,
    /// Array of block indices
    blocks: []u32,
    
    const Self = @This();
    
    /// Creates new PopulatedBlocks (equivalent to Swift init)
    pub fn init(cache_id: []const u8, blocks: []u32) Self {
        return Self{
            .cache_id = cache_id,
            .blocks = blocks,
        };
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        if (!std.mem.eql(u8, self.cache_id, other.cache_id)) {
            return false;
        }
        
        if (self.blocks.len != other.blocks.len) {
            return false;
        }
        
        for (self.blocks, 0..) |block, i| {
            if (block != other.blocks[i]) {
                return false;
            }
        }
        
        return true;
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.cache_id);
        hasher.update(std.mem.sliceAsBytes(self.blocks));
        return hasher.final();
    }
    
    /// Gets the number of blocks
    pub fn getBlockCount(self: Self) usize {
        return self.blocks.len;
    }
    
    /// Checks if a specific block is populated
    pub fn hasBlock(self: Self, block_index: u32) bool {
        for (self.blocks) |block| {
            if (block == block_index) {
                return true;
            }
        }
        return false;
    }
    
    /// Gets the minimum block index
    pub fn getMinBlock(self: Self) ?u32 {
        if (self.blocks.len == 0) return null;
        
        var min_block = self.blocks[0];
        for (self.blocks[1..]) |block| {
            if (block < min_block) {
                min_block = block;
            }
        }
        return min_block;
    }
    
    /// Gets the maximum block index
    pub fn getMaxBlock(self: Self) ?u32 {
        if (self.blocks.len == 0) return null;
        
        var max_block = self.blocks[0];
        for (self.blocks[1..]) |block| {
            if (block > max_block) {
                max_block = block;
            }
        }
        return max_block;
    }
    
    /// Gets the block range
    pub fn getBlockRange(self: Self) ?struct { min: u32, max: u32 } {
        const min_block = self.getMinBlock() orelse return null;
        const max_block = self.getMaxBlock() orelse return null;
        return .{ .min = min_block, .max = max_block };
    }
    
    /// Checks if blocks are contiguous
    pub fn isContiguous(self: Self) bool {
        if (self.blocks.len <= 1) return true;
        
        // Sort a copy for checking
        var temp_allocator = std.heap.StackFallbackAllocator(1024){};
        const allocator = temp_allocator.get();
        
        var sorted_blocks = allocator.dupe(u32, self.blocks) catch return false;
        defer allocator.free(sorted_blocks);
        
        std.sort.insertion(u32, sorted_blocks, {}, std.sort.asc(u32));
        
        for (sorted_blocks[1..], 1..) |block, i| {
            if (block != sorted_blocks[i - 1] + 1) {
                return false;
            }
        }
        
        return true;
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var blocks_json = std.ArrayList(u8).init(allocator);
        defer blocks_json.deinit();
        
        try blocks_json.appendSlice("[");
        for (self.blocks, 0..) |block, i| {
            if (i > 0) try blocks_json.appendSlice(",");
            const block_str = try std.fmt.allocPrint(allocator, "{}", .{block});
            defer allocator.free(block_str);
            try blocks_json.appendSlice(block_str);
        }
        try blocks_json.appendSlice("]");
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"cacheId\":\"{s}\",\"blocks\":{s}}}",
            .{ self.cache_id, blocks_json.items }
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const cache_id_str = json_obj.get("cacheId").?.string;
        const blocks_array = json_obj.get("blocks").?.array;
        
        const cache_id = try allocator.dupe(u8, cache_id_str);
        
        var blocks = try std.ArrayList(u32).initCapacity(allocator, blocks_array.items.len);
        defer blocks.deinit();
        
        for (blocks_array.items) |block_value| {
            const block_index = @as(u32, @intCast(block_value.integer));
            try blocks.append(block_index);
        }
        
        return Self.init(cache_id, try blocks.toOwnedSlice());
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.cache_id);
        allocator.free(self.blocks);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const cache_id_copy = try allocator.dupe(u8, self.cache_id);
        const blocks_copy = try allocator.dupe(u32, self.blocks);
        return Self.init(cache_id_copy, blocks_copy);
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const range = self.getBlockRange();
        
        if (range) |r| {
            return try std.fmt.allocPrint(
                allocator,
                "PopulatedBlocks(cache: {s}, {} blocks: {}-{}{})",
                .{ 
                    self.cache_id, 
                    self.blocks.len, 
                    r.min, 
                    r.max, 
                    if (self.isContiguous()) " contiguous" else ""
                }
            );
        } else {
            return try std.fmt.allocPrint(
                allocator,
                "PopulatedBlocks(cache: {s}, {} blocks: empty)",
                .{ self.cache_id, self.blocks.len }
            );
        }
    }
    
    /// Gets blocks in sorted order
    pub fn getSortedBlocks(self: Self, allocator: std.mem.Allocator) ![]u32 {
        var sorted_blocks = try allocator.dupe(u32, self.blocks);
        std.sort.insertion(u32, sorted_blocks, {}, std.sort.asc(u32));
        return sorted_blocks;
    }
    
    /// Gets blocks in a specific range
    pub fn getBlocksInRange(self: Self, min_block: u32, max_block: u32, allocator: std.mem.Allocator) ![]u32 {
        var filtered_blocks = std.ArrayList(u32).init(allocator);
        defer filtered_blocks.deinit();
        
        for (self.blocks) |block| {
            if (block >= min_block and block <= max_block) {
                try filtered_blocks.append(block);
            }
        }
        
        return try filtered_blocks.toOwnedSlice();
    }
};

// Tests (converted from Swift PopulatedBlocks tests)
test "PopulatedBlocks creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test creation (equivalent to Swift init tests)
    const cache_id = "test_cache_123";
    const blocks = [_]u32{ 1, 2, 3, 5, 7 };
    
    const populated_blocks = PopulatedBlocks.init(cache_id, &blocks);
    
    try testing.expectEqualStrings(cache_id, populated_blocks.cache_id);
    try testing.expectEqual(@as(usize, 5), populated_blocks.getBlockCount());
    
    // Test block checking
    try testing.expect(populated_blocks.hasBlock(1));
    try testing.expect(populated_blocks.hasBlock(7));
    try testing.expect(!populated_blocks.hasBlock(4));
    try testing.expect(!populated_blocks.hasBlock(10));
}

test "PopulatedBlocks equality and hashing" {
    const testing = std.testing;
    
    // Test equality (equivalent to Swift Hashable tests)
    const cache_id = "test_cache";
    const blocks1 = [_]u32{ 1, 2, 3 };
    const blocks2 = [_]u32{ 1, 2, 3 };
    const blocks3 = [_]u32{ 1, 2, 4 };
    
    const populated1 = PopulatedBlocks.init(cache_id, &blocks1);
    const populated2 = PopulatedBlocks.init(cache_id, &blocks2);
    const populated3 = PopulatedBlocks.init(cache_id, &blocks3);
    
    try testing.expect(populated1.eql(populated2));
    try testing.expect(!populated1.eql(populated3));
    
    // Test hashing
    const hash1 = populated1.hash();
    const hash2 = populated2.hash();
    const hash3 = populated3.hash();
    
    try testing.expectEqual(hash1, hash2);
    try testing.expectNotEqual(hash1, hash3);
}

test "PopulatedBlocks range operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test range operations
    const cache_id = "test_cache";
    const blocks = [_]u32{ 5, 1, 9, 3, 7 };
    
    const populated_blocks = PopulatedBlocks.init(cache_id, &blocks);
    
    // Test min/max
    try testing.expectEqual(@as(u32, 1), populated_blocks.getMinBlock().?);
    try testing.expectEqual(@as(u32, 9), populated_blocks.getMaxBlock().?);
    
    // Test range
    const range = populated_blocks.getBlockRange().?;
    try testing.expectEqual(@as(u32, 1), range.min);
    try testing.expectEqual(@as(u32, 9), range.max);
    
    // Test contiguous check
    try testing.expect(!populated_blocks.isContiguous()); // 5,1,9,3,7 is not contiguous
    
    const contiguous_blocks = [_]u32{ 1, 2, 3, 4, 5 };
    const contiguous_populated = PopulatedBlocks.init(cache_id, &contiguous_blocks);
    try testing.expect(contiguous_populated.isContiguous());
    
    // Test filtered range
    const filtered = try populated_blocks.getBlocksInRange(3, 7, allocator);
    defer allocator.free(filtered);
    
    try testing.expectEqual(@as(usize, 3), filtered.len); // 5, 3, 7 are in range [3, 7]
}

test "PopulatedBlocks JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const cache_id = "test_cache_456";
    const blocks = [_]u32{ 10, 20, 30 };
    
    const original_populated = PopulatedBlocks.init(cache_id, &blocks);
    
    const json_str = try original_populated.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "test_cache_456") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "cacheId") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "blocks") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "10") != null);
    
    var decoded_populated = try PopulatedBlocks.decodeFromJson(json_str, allocator);
    defer decoded_populated.deinit(allocator);
    
    try testing.expect(original_populated.eql(decoded_populated));
}

test "PopulatedBlocks utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test sorting
    const cache_id = "test_cache";
    const blocks = [_]u32{ 5, 1, 9, 3, 7 };
    
    const populated_blocks = PopulatedBlocks.init(cache_id, &blocks);
    
    const sorted_blocks = try populated_blocks.getSortedBlocks(allocator);
    defer allocator.free(sorted_blocks);
    
    try testing.expectEqual(@as(usize, 5), sorted_blocks.len);
    try testing.expectEqual(@as(u32, 1), sorted_blocks[0]);
    try testing.expectEqual(@as(u32, 3), sorted_blocks[1]);
    try testing.expectEqual(@as(u32, 5), sorted_blocks[2]);
    try testing.expectEqual(@as(u32, 7), sorted_blocks[3]);
    try testing.expectEqual(@as(u32, 9), sorted_blocks[4]);
    
    // Test formatting
    const formatted = try populated_blocks.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "PopulatedBlocks") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, cache_id) != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "5 blocks") != null);
    
    // Test cloning
    var cloned_populated = try populated_blocks.clone(allocator);
    defer cloned_populated.deinit(allocator);
    
    try testing.expect(populated_blocks.eql(cloned_populated));
}

test "PopulatedBlocks empty blocks" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test empty blocks array
    const cache_id = "empty_cache";
    const empty_blocks = [_]u32{};
    
    const empty_populated = PopulatedBlocks.init(cache_id, &empty_blocks);
    
    try testing.expectEqual(@as(usize, 0), empty_populated.getBlockCount());
    try testing.expect(empty_populated.getMinBlock() == null);
    try testing.expect(empty_populated.getMaxBlock() == null);
    try testing.expect(empty_populated.getBlockRange() == null);
    try testing.expect(empty_populated.isContiguous()); // Empty is considered contiguous
    try testing.expect(!empty_populated.hasBlock(1));
    
    // Test formatting empty
    const formatted = try empty_populated.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "empty") != null);
}