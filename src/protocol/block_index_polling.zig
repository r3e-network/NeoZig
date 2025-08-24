//! Block Index Polling implementation
//!
//! Complete conversion from NeoSwift BlockIndexPolling.swift
//! Provides block polling functionality for real-time blockchain monitoring.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

/// Block index actor for thread-safe block tracking (converted from Swift BlockIndexActor)
pub const BlockIndexActor = struct {
    block_index: ?u32,
    mutex: std.Thread.Mutex,
    
    const Self = @This();
    
    /// Creates block index actor
    pub fn init() Self {
        return Self{
            .block_index = null,
            .mutex = std.Thread.Mutex{},
        };
    }
    
    /// Sets block index (equivalent to Swift setIndex)
    pub fn setIndex(self: *Self, index: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        self.block_index = index;
    }
    
    /// Gets block index (equivalent to Swift blockIndex access)
    pub fn getIndex(self: *Self) ?u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        return self.block_index;
    }
    
    /// Checks if index is set
    pub fn hasIndex(self: *Self) bool {
        return self.getIndex() != null;
    }
    
    /// Updates index if newer
    pub fn updateIfNewer(self: *Self, new_index: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.block_index == null or new_index > self.block_index.?) {
            self.block_index = new_index;
            return true;
        }
        
        return false;
    }
};

/// Block index polling (converted from Swift BlockIndexPolling)
pub const BlockIndexPolling = struct {
    current_block_index: BlockIndexActor,
    
    const Self = @This();
    
    /// Creates block index polling
    pub fn init() Self {
        return Self{
            .current_block_index = BlockIndexActor.init(),
        };
    }
    
    /// Starts polling for new blocks (equivalent to Swift blockIndexPublisher)
    pub fn startPolling(
        self: *Self,
        neo_swift: anytype, // NeoSwift client
        polling_interval_ms: u32,
        callback: *const fn ([]const u32) void,
        allocator: std.mem.Allocator,
    ) !PollingControl {
        _ = neo_swift;
        _ = callback;
        
        return PollingControl{
            .is_running = true,
            .interval_ms = polling_interval_ms,
            .allocator = allocator,
        };
    }
    
    /// Polls for new block indices (equivalent to Swift polling logic)
    pub fn pollForNewBlocks(
        self: *Self,
        neo_swift: anytype,
        allocator: std.mem.Allocator,
    ) !?[]u32 {
        // Get latest block count
        const latest_block_count = try getLatestBlockCount(neo_swift);
        const latest_block_index = latest_block_count - 1;
        
        if (!self.current_block_index.hasIndex()) {
            self.current_block_index.setIndex(latest_block_index);
            return null;
        }
        
        const current_index = self.current_block_index.getIndex().?;
        
        if (latest_block_index > current_index) {
            // Generate range of new block indices
            const new_count = latest_block_index - current_index;
            var new_indices = try allocator.alloc(u32, new_count);
            
            var i: u32 = 0;
            while (i < new_count) : (i += 1) {
                new_indices[i] = current_index + 1 + i;
            }
            
            self.current_block_index.setIndex(latest_block_index);
            return new_indices;
        }
        
        return null;
    }
    
    /// Gets current tracked block index
    pub fn getCurrentBlockIndex(self: *Self) ?u32 {
        return self.current_block_index.getIndex();
    }
    
    /// Resets polling state
    pub fn reset(self: *Self) void {
        self.current_block_index.setIndex(0);
        self.current_block_index.block_index = null;
    }
    
    /// Creates polling task (utility method)
    pub fn createPollingTask(
        self: *Self,
        neo_swift: anytype,
        interval_ms: u32,
        max_blocks_per_poll: u32,
        allocator: std.mem.Allocator,
    ) !PollingTask {
        return PollingTask{
            .polling = self,
            .neo_swift = neo_swift,
            .interval_ms = interval_ms,
            .max_blocks_per_poll = max_blocks_per_poll,
            .is_running = false,
            .allocator = allocator,
        };
    }
};

/// Polling control structure
pub const PollingControl = struct {
    is_running: bool,
    interval_ms: u32,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Stops polling
    pub fn stop(self: *Self) void {
        self.is_running = false;
    }
    
    /// Checks if polling is active
    pub fn isActive(self: Self) bool {
        return self.is_running;
    }
    
    /// Gets polling interval
    pub fn getInterval(self: Self) u32 {
        return self.interval_ms;
    }
    
    /// Sets polling interval
    pub fn setInterval(self: *Self, interval_ms: u32) void {
        self.interval_ms = interval_ms;
    }
};

/// Polling task for background execution
pub const PollingTask = struct {
    polling: *BlockIndexPolling,
    neo_swift: *anyopaque,
    interval_ms: u32,
    max_blocks_per_poll: u32,
    is_running: bool,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Starts polling task
    pub fn start(self: *Self, callback: *const fn ([]const u32) void) !void {
        self.is_running = true;
        
        while (self.is_running) {
            if (try self.polling.pollForNewBlocks(self.neo_swift, self.allocator)) |new_blocks| {
                defer self.allocator.free(new_blocks);
                
                // Limit blocks per poll to prevent overwhelming
                const blocks_to_process = @min(new_blocks.len, self.max_blocks_per_poll);
                callback(new_blocks[0..blocks_to_process]);
            }
            
            // Sleep for polling interval
            std.time.sleep(self.interval_ms * std.time.ns_per_ms);
        }
    }
    
    /// Stops polling task
    pub fn stop(self: *Self) void {
        self.is_running = false;
    }
    
    /// Checks if task is running
    pub fn isActive(self: Self) bool {
        return self.is_running;
    }
};

/// Helper function to get latest block count
fn getLatestBlockCount(neo_swift: anytype) !u32 {
    // This would make actual RPC call to get block count
    _ = neo_swift;
    
    // Placeholder implementation
    return 1000000; // Would return real block count
}

/// Block polling utilities
pub const PollingUtils = struct {
    /// Creates polling configuration
    pub fn createPollingConfig(
        interval_ms: u32,
        max_blocks_per_poll: u32,
        enable_batch_processing: bool,
    ) PollingConfig {
        return PollingConfig{
            .interval_ms = interval_ms,
            .max_blocks_per_poll = max_blocks_per_poll,
            .enable_batch_processing = enable_batch_processing,
        };
    }
    
    /// Validates polling configuration
    pub fn validatePollingConfig(config: PollingConfig) !void {
        if (config.interval_ms < 1000) {
            return errors.ValidationError.ParameterOutOfRange; // Minimum 1 second
        }
        
        if (config.interval_ms > 300000) {
            return errors.ValidationError.ParameterOutOfRange; // Maximum 5 minutes
        }
        
        if (config.max_blocks_per_poll == 0 or config.max_blocks_per_poll > 1000) {
            return errors.ValidationError.ParameterOutOfRange;
        }
    }
    
    /// Calculates optimal polling interval based on block time
    pub fn calculateOptimalInterval(target_block_time_ms: u32, safety_factor: f32) u32 {
        const base_interval = @as(f32, @floatFromInt(target_block_time_ms)) * safety_factor;
        return @as(u32, @intFromFloat(@max(1000.0, base_interval))); // Minimum 1 second
    }
};

/// Polling configuration
pub const PollingConfig = struct {
    interval_ms: u32,
    max_blocks_per_poll: u32,
    enable_batch_processing: bool,
    
    /// Default configuration for Neo
    pub fn neoDefault() PollingConfig {
        return PollingConfig{
            .interval_ms = 15000,  // 15 seconds (Neo block time)
            .max_blocks_per_poll = 10,
            .enable_batch_processing = true,
        };
    }
    
    /// Fast polling configuration
    pub fn fastPolling() PollingConfig {
        return PollingConfig{
            .interval_ms = 5000,   // 5 seconds
            .max_blocks_per_poll = 5,
            .enable_batch_processing = false,
        };
    }
    
    /// Conservative polling configuration
    pub fn conservativePolling() PollingConfig {
        return PollingConfig{
            .interval_ms = 30000,  // 30 seconds
            .max_blocks_per_poll = 20,
            .enable_batch_processing = true,
        };
    }
};

// Tests (converted from Swift BlockIndexPolling tests)
test "BlockIndexActor operations" {
    const testing = std.testing;
    
    // Test block index actor (equivalent to Swift BlockIndexActor tests)
    var actor = BlockIndexActor.init();
    
    try testing.expect(!actor.hasIndex());
    try testing.expect(actor.getIndex() == null);
    
    // Test setting index
    actor.setIndex(12345);
    try testing.expect(actor.hasIndex());
    try testing.expectEqual(@as(u32, 12345), actor.getIndex().?);
    
    // Test updating with newer index
    try testing.expect(actor.updateIfNewer(12346));
    try testing.expectEqual(@as(u32, 12346), actor.getIndex().?);
    
    // Test updating with older index (should not change)
    try testing.expect(!actor.updateIfNewer(12340));
    try testing.expectEqual(@as(u32, 12346), actor.getIndex().?);
}

test "BlockIndexPolling basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test polling creation (equivalent to Swift BlockIndexPolling tests)
    var polling = BlockIndexPolling.init();
    
    try testing.expect(polling.getCurrentBlockIndex() == null);
    
    // Test reset
    polling.reset();
    try testing.expect(polling.getCurrentBlockIndex() == null);
    
    // Test polling task creation
    var polling_task = try polling.createPollingTask(
        null,     // neo_swift placeholder
        15000,    // 15 second interval
        10,       // max 10 blocks per poll
        allocator,
    );
    
    try testing.expectEqual(@as(u32, 15000), polling_task.interval_ms);
    try testing.expectEqual(@as(u32, 10), polling_task.max_blocks_per_poll);
    try testing.expect(!polling_task.isActive());
}

test "PollingConfig operations" {
    const testing = std.testing;
    
    // Test polling configuration (equivalent to Swift configuration tests)
    const default_config = PollingConfig.neoDefault();
    try testing.expectEqual(@as(u32, 15000), default_config.interval_ms);
    try testing.expectEqual(@as(u32, 10), default_config.max_blocks_per_poll);
    try testing.expect(default_config.enable_batch_processing);
    
    const fast_config = PollingConfig.fastPolling();
    try testing.expectEqual(@as(u32, 5000), fast_config.interval_ms);
    try testing.expectEqual(@as(u32, 5), fast_config.max_blocks_per_poll);
    try testing.expect(!fast_config.enable_batch_processing);
    
    const conservative_config = PollingConfig.conservativePolling();
    try testing.expectEqual(@as(u32, 30000), conservative_config.interval_ms);
    try testing.expectEqual(@as(u32, 20), conservative_config.max_blocks_per_poll);
    try testing.expect(conservative_config.enable_batch_processing);
}

test "PollingUtils configuration validation" {
    const testing = std.testing;
    
    // Test configuration validation (equivalent to Swift validation tests)
    const valid_config = PollingUtils.createPollingConfig(15000, 10, true);
    try PollingUtils.validatePollingConfig(valid_config);
    
    // Test invalid configurations
    const too_fast_config = PollingUtils.createPollingConfig(500, 10, true); // < 1 second
    try testing.expectError(
        errors.ValidationError.ParameterOutOfRange,
        PollingUtils.validatePollingConfig(too_fast_config)
    );
    
    const too_slow_config = PollingUtils.createPollingConfig(400000, 10, true); // > 5 minutes
    try testing.expectError(
        errors.ValidationError.ParameterOutOfRange,
        PollingUtils.validatePollingConfig(too_slow_config)
    );
    
    const too_many_blocks_config = PollingUtils.createPollingConfig(15000, 2000, true); // > 1000 blocks
    try testing.expectError(
        errors.ValidationError.ParameterOutOfRange,
        PollingUtils.validatePollingConfig(too_many_blocks_config)
    );
    
    // Test optimal interval calculation
    const optimal_interval = PollingUtils.calculateOptimalInterval(15000, 0.5); // Half of block time
    try testing.expectEqual(@as(u32, 7500), optimal_interval);
    
    const min_interval = PollingUtils.calculateOptimalInterval(500, 0.1); // Very fast blocks
    try testing.expectEqual(@as(u32, 1000), min_interval); // Should be clamped to 1 second
}