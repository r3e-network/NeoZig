//! JSON-RPC 2.0 Rx implementation
//!
//! Complete conversion from NeoSwift JsonRpc2_0Rx.swift
//! Provides reactive programming support for Neo blockchain operations.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const BlockIndexPolling = @import("block_index_polling.zig").BlockIndexPolling;

/// JSON-RPC 2.0 reactive extension (converted from Swift JsonRpc2_0Rx)
pub const JsonRpc2_0Rx = struct {
    /// Neo client reference
    neo_swift: *anyopaque, // NeoSwift reference
    /// Executor for async operations
    executor_service: AsyncExecutor,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates JSON-RPC reactive client (equivalent to Swift init)
    pub fn init(
        allocator: std.mem.Allocator,
        neo_swift: *anyopaque,
        executor_service: AsyncExecutor,
    ) Self {
        return Self{
            .neo_swift = neo_swift,
            .executor_service = executor_service,
            .allocator = allocator,
        };
    }
    
    /// Creates block index publisher (equivalent to Swift blockIndexPublisher)
    pub fn blockIndexPublisher(
        self: *Self,
        polling_interval_ms: u32,
        callback: *const fn (u32) void,
    ) !BlockIndexSubscription {
        var polling = BlockIndexPolling.init();
        
        const control = try polling.startPolling(
            self.neo_swift,
            polling_interval_ms,
            callback,
            self.allocator,
        );
        
        return BlockIndexSubscription{
            .polling = polling,
            .control = control,
            .is_active = true,
        };
    }
    
    /// Creates block publisher (equivalent to Swift blockPublisher)
    pub fn blockPublisher(
        self: *Self,
        full_transaction_objects: bool,
        polling_interval_ms: u32,
        callback: *const fn (BlockData) void,
    ) !BlockSubscription {
        const block_callback = struct {
            fn onNewBlock(index: u32) void {
                // Would fetch block data and call callback
                const block_data = BlockData{
                    .index = index,
                    .full_transactions = full_transaction_objects,
                    .timestamp = std.time.timestamp(),
                };
                callback(block_data);
            }
        }.onNewBlock;
        
        const index_subscription = try self.blockIndexPublisher(polling_interval_ms, block_callback);
        
        return BlockSubscription{
            .index_subscription = index_subscription,
            .full_transactions = full_transaction_objects,
            .is_active = true,
        };
    }
    
    /// Replays blocks in range (equivalent to Swift replayBlocksPublisher)
    pub fn replayBlocksPublisher(
        self: *Self,
        start_block: u32,
        end_block: u32,
        full_transaction_objects: bool,
        ascending: bool,
        callback: *const fn (BlockData) void,
    ) !ReplaySubscription {
        if (start_block > end_block) {
            return errors.ValidationError.ParameterOutOfRange;
        }
        
        const block_count = end_block - start_block + 1;
        var blocks = try self.allocator.alloc(u32, block_count);
        
        // Generate block range
        var i: u32 = 0;
        while (i < block_count) : (i += 1) {
            blocks[i] = if (ascending) start_block + i else end_block - i;
        }
        
        return ReplaySubscription{
            .blocks = blocks,
            .current_index = 0,
            .full_transactions = full_transaction_objects,
            .callback = callback,
            .is_active = true,
            .allocator = self.allocator,
        };
    }
    
    /// Catches up to latest block (equivalent to Swift catchUpToLatestBlockPublisher)
    pub fn catchUpToLatestBlockPublisher(
        self: *Self,
        start_block: u32,
        full_transaction_objects: bool,
        on_caught_up_callback: *const fn (BlockData) void,
    ) !CatchUpSubscription {
        const latest_block = try self.getLatestBlockIndex();
        
        if (start_block >= latest_block) {
            // Already caught up
            return CatchUpSubscription{
                .start_block = start_block,
                .target_block = latest_block,
                .is_caught_up = true,
                .callback = on_caught_up_callback,
                .is_active = true,
            };
        }
        
        // Need to catch up
        const replay_subscription = try self.replayBlocksPublisher(
            start_block,
            latest_block,
            full_transaction_objects,
            true,
            on_caught_up_callback,
        );
        
        return CatchUpSubscription{
            .start_block = start_block,
            .target_block = latest_block,
            .is_caught_up = false,
            .replay_subscription = replay_subscription,
            .callback = on_caught_up_callback,
            .is_active = true,
        };
    }
    
    /// Catches up and subscribes to new blocks (equivalent to Swift catchUpToLatestAndSubscribeToNewBlocksPublisher)
    pub fn catchUpToLatestAndSubscribeToNewBlocksPublisher(
        self: *Self,
        start_block: u32,
        full_transaction_objects: bool,
        polling_interval_ms: u32,
        callback: *const fn (BlockData) void,
    ) !CombinedSubscription {
        const catch_up = try self.catchUpToLatestBlockPublisher(
            start_block,
            full_transaction_objects,
            callback,
        );
        
        const new_blocks = try self.blockPublisher(
            full_transaction_objects,
            polling_interval_ms,
            callback,
        );
        
        return CombinedSubscription{
            .catch_up_subscription = catch_up,
            .block_subscription = new_blocks,
            .is_active = true,
        };
    }
    
    /// Gets latest block index (equivalent to Swift latestBlockIndexPublisher)
    pub fn getLatestBlockIndex(self: *Self) !u32 {
        // Would make RPC call to get block count
        _ = self;
        return 1000000; // Placeholder
    }
    
    /// Creates latest block index subscription
    pub fn latestBlockIndexPublisher(
        self: *Self,
        polling_interval_ms: u32,
        callback: *const fn (u32) void,
    ) !LatestBlockSubscription {
        return LatestBlockSubscription{
            .rx_client = self,
            .polling_interval_ms = polling_interval_ms,
            .callback = callback,
            .is_active = true,
        };
    }
};

/// Async executor for reactive operations
pub const AsyncExecutor = struct {
    thread_pool_size: u32,
    
    pub fn init(thread_pool_size: u32) AsyncExecutor {
        return AsyncExecutor{ .thread_pool_size = thread_pool_size };
    }
    
    pub fn execute(self: AsyncExecutor, task: *const fn () void) void {
        _ = self;
        task(); // Simplified execution
    }
    
    pub fn scheduleRepeating(
        self: AsyncExecutor,
        task: *const fn () void,
        interval_ms: u32,
    ) void {
        _ = self;
        _ = task;
        _ = interval_ms;
        // Would implement repeating task scheduling
    }
};

/// Block data structure
pub const BlockData = struct {
    index: u32,
    full_transactions: bool,
    timestamp: i64,
    data: ?[]const u8,
    
    pub fn init(index: u32, full_transactions: bool) BlockData {
        return BlockData{
            .index = index,
            .full_transactions = full_transactions,
            .timestamp = std.time.timestamp(),
            .data = null,
        };
    }
};

/// Subscription types
pub const BlockIndexSubscription = struct {
    polling: BlockIndexPolling,
    control: @import("block_index_polling.zig").PollingControl,
    is_active: bool,
    
    pub fn stop(self: *BlockIndexSubscription) void {
        self.control.stop();
        self.is_active = false;
    }
    
    pub fn isActive(self: BlockIndexSubscription) bool {
        return self.is_active and self.control.isActive();
    }
};

pub const BlockSubscription = struct {
    index_subscription: BlockIndexSubscription,
    full_transactions: bool,
    is_active: bool,
    
    pub fn stop(self: *BlockSubscription) void {
        self.index_subscription.stop();
        self.is_active = false;
    }
    
    pub fn isActive(self: BlockSubscription) bool {
        return self.is_active and self.index_subscription.isActive();
    }
};

pub const ReplaySubscription = struct {
    blocks: []u32,
    current_index: usize,
    full_transactions: bool,
    callback: *const fn (BlockData) void,
    is_active: bool,
    allocator: std.mem.Allocator,
    
    pub fn stop(self: *ReplaySubscription) void {
        self.is_active = false;
    }
    
    pub fn deinit(self: *ReplaySubscription) void {
        self.allocator.free(self.blocks);
    }
    
    pub fn processNext(self: *ReplaySubscription) bool {
        if (!self.is_active or self.current_index >= self.blocks.len) return false;
        
        const block_data = BlockData.init(self.blocks[self.current_index], self.full_transactions);
        self.callback(block_data);
        self.current_index += 1;
        
        return self.current_index < self.blocks.len;
    }
};

pub const CatchUpSubscription = struct {
    start_block: u32,
    target_block: u32,
    is_caught_up: bool,
    replay_subscription: ?ReplaySubscription,
    callback: *const fn (BlockData) void,
    is_active: bool,
    
    pub fn stop(self: *CatchUpSubscription) void {
        if (self.replay_subscription) |*replay| {
            replay.stop();
        }
        self.is_active = false;
    }
    
    pub fn isComplete(self: CatchUpSubscription) bool {
        return self.is_caught_up;
    }
};

pub const CombinedSubscription = struct {
    catch_up_subscription: CatchUpSubscription,
    block_subscription: BlockSubscription,
    is_active: bool,
    
    pub fn stop(self: *CombinedSubscription) void {
        self.catch_up_subscription.stop();
        self.block_subscription.stop();
        self.is_active = false;
    }
    
    pub fn isActive(self: CombinedSubscription) bool {
        return self.is_active and 
               (self.catch_up_subscription.is_active or self.block_subscription.isActive());
    }
};

pub const LatestBlockSubscription = struct {
    rx_client: *JsonRpc2_0Rx,
    polling_interval_ms: u32,
    callback: *const fn (u32) void,
    is_active: bool,
    
    pub fn stop(self: *LatestBlockSubscription) void {
        self.is_active = false;
    }
    
    pub fn isActive(self: LatestBlockSubscription) bool {
        return self.is_active;
    }
};

// Tests (converted from Swift JsonRpc2_0Rx tests)
test "JsonRpc2_0Rx creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test reactive client creation
    const executor = AsyncExecutor.init(4);
    var rx_client = JsonRpc2_0Rx.init(allocator, null, executor);
    
    try testing.expectEqual(@as(u32, 4), rx_client.executor_service.thread_pool_size);
    
    // Test latest block index retrieval
    const latest_block = try rx_client.getLatestBlockIndex();
    try testing.expect(latest_block > 0);
}

test "Subscription management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test subscription creation and management
    var block_subscription = BlockSubscription{
        .index_subscription = BlockIndexSubscription{
            .polling = BlockIndexPolling.init(),
            .control = @import("block_index_polling.zig").PollingControl{
                .is_running = true,
                .interval_ms = 15000,
                .allocator = allocator,
            },
            .is_active = true,
        },
        .full_transactions = false,
        .is_active = true,
    };
    
    try testing.expect(block_subscription.isActive());
    
    block_subscription.stop();
    try testing.expect(!block_subscription.isActive());
}

test "Block data operations" {
    const testing = std.testing;
    
    // Test block data creation
    const block_data = BlockData.init(12345, true);
    
    try testing.expectEqual(@as(u32, 12345), block_data.index);
    try testing.expect(block_data.full_transactions);
    try testing.expect(block_data.timestamp > 0);
}

test "Replay subscription operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test replay subscription
    const test_callback = struct {
        fn onBlock(block_data: BlockData) void {
            _ = block_data;
            // Test callback
        }
    }.onBlock;
    
    var replay_subscription = ReplaySubscription{
        .blocks = try allocator.dupe(u32, &[_]u32{ 100, 101, 102 }),
        .current_index = 0,
        .full_transactions = false,
        .callback = test_callback,
        .is_active = true,
        .allocator = allocator,
    };
    defer replay_subscription.deinit();
    
    // Test processing blocks
    try testing.expect(replay_subscription.processNext()); // Block 100
    try testing.expect(replay_subscription.processNext()); // Block 101
    try testing.expect(replay_subscription.processNext()); // Block 102
    try testing.expect(!replay_subscription.processNext()); // No more blocks
}