//! Block Index Polling implementation
//!
//! Complete conversion from NeoSwift BlockIndexPolling.swift
//! Provides block polling functionality for real-time blockchain monitoring.

const std = @import("std");
const AtomicBool = std.atomic.Value(bool);
const AtomicU32 = std.atomic.Value(u32);

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

    pub fn reset(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.block_index = null;
    }
};

pub const PollingSource = struct {
    context: ?*anyopaque,
    get_block_count: *const fn (?*anyopaque) anyerror!u32,
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
        source: PollingSource,
        polling_interval_ms: u32,
        callback: *const fn ([]const u32, ?*anyopaque) void,
        callback_context: ?*anyopaque,
        callback_context_destructor: ?*const fn (std.mem.Allocator, ?*anyopaque) void,
        allocator: std.mem.Allocator,
    ) !PollingControl {
        if (source.context == null or source.get_block_count == null) {
            return errors.NeoError.UnsupportedOperation;
        }

        var control = PollingControl.init(polling_interval_ms, allocator);

        const task = try allocator.create(PollingTask);
        task.* = PollingTask.init(
            self,
            source,
            polling_interval_ms,
            std.math.maxInt(u32),
            callback,
            callback_context,
            callback_context_destructor,
            allocator,
        );

        const thread = std.Thread.spawn(.{}, pollTaskRunner, .{task}) catch |err| {
            task.deinit();
            allocator.destroy(task);
            return err;
        };

        control.task = task;
        control.thread = thread;

        return control;
    }

    /// Polls for new block indices (equivalent to Swift polling logic)
    pub fn pollForNewBlocks(
        self: *Self,
        source: PollingSource,
        allocator: std.mem.Allocator,
    ) !?[]u32 {
        const latest_block_count = try getLatestBlockCount(source);
        if (latest_block_count == 0) {
            return null;
        }

        const latest_block_index = latest_block_count - 1;

        if (!self.current_block_index.hasIndex()) {
            self.current_block_index.setIndex(latest_block_index);
            return null;
        }

        const current_index = self.current_block_index.getIndex().?;
        if (latest_block_index <= current_index) {
            return null;
        }

        const new_count = @as(usize, latest_block_index - current_index);
        var indices = try allocator.alloc(u32, new_count);
        var i: usize = 0;
        while (i < new_count) : (i += 1) {
            const offset = @as(u32, @intCast(i));
            indices[i] = current_index + 1 + offset;
        }

        self.current_block_index.setIndex(latest_block_index);
        return indices;
    }

    /// Gets current tracked block index
    pub fn getCurrentBlockIndex(self: *Self) ?u32 {
        return self.current_block_index.getIndex();
    }

    /// Resets polling state
    pub fn reset(self: *Self) void {
        self.current_block_index.reset();
    }
};

/// Polling control structure
pub const PollingControl = struct {
    is_running: AtomicBool,
    interval_ms: AtomicU32,
    allocator: std.mem.Allocator,
    task: ?*PollingTask,
    thread: ?std.Thread,

    const Self = @This();

    pub fn init(interval_ms: u32, allocator: std.mem.Allocator) Self {
        return Self{
            .is_running = AtomicBool.init(true),
            .interval_ms = AtomicU32.init(interval_ms),
            .allocator = allocator,
            .task = null,
            .thread = null,
        };
    }

    /// Stops polling
    pub fn stop(self: *Self) void {
        if (!self.is_running.load(.seq_cst)) return;
        self.is_running.store(false, .seq_cst);
        if (self.task) |task| {
            task.stop();
        }
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.task) |task| {
            task.deinit();
            self.allocator.destroy(task);
            self.task = null;
        }
    }

    /// Checks if polling is active
    pub fn isActive(self: *Self) bool {
        return self.is_running.load(.seq_cst);
    }

    /// Gets polling interval
    pub fn getInterval(self: *Self) u32 {
        return self.interval_ms.load(.seq_cst);
    }

    /// Sets polling interval
    pub fn setInterval(self: *Self, interval_ms: u32) void {
        self.interval_ms.store(interval_ms, .seq_cst);
        if (self.task) |task| {
            task.setInterval(interval_ms);
        }
    }
};

/// Polling task for background execution
const PollingTask = struct {
    polling: *BlockIndexPolling,
    source: PollingSource,
    interval_ms: AtomicU32,
    max_blocks_per_poll: u32,
    is_running: AtomicBool,
    allocator: std.mem.Allocator,
    callback: *const fn ([]const u32, ?*anyopaque) void,
    callback_context: ?*anyopaque,
    callback_destructor: ?*const fn (std.mem.Allocator, ?*anyopaque) void,

    const Self = @This();

    pub fn init(
        polling: *BlockIndexPolling,
        source: PollingSource,
        interval_ms: u32,
        max_blocks_per_poll: u32,
        callback: *const fn ([]const u32, ?*anyopaque) void,
        callback_context: ?*anyopaque,
        callback_destructor: ?*const fn (std.mem.Allocator, ?*anyopaque) void,
        allocator: std.mem.Allocator,
    ) Self {
        return Self{
            .polling = polling,
            .source = source,
            .interval_ms = AtomicU32.init(interval_ms),
            .max_blocks_per_poll = max_blocks_per_poll,
            .is_running = AtomicBool.init(true),
            .allocator = allocator,
            .callback = callback,
            .callback_context = callback_context,
            .callback_destructor = callback_destructor,
        };
    }

    pub fn loop(self: *Self) void {
        while (self.is_running.load(.seq_cst)) {
            const maybe_blocks = self.polling.pollForNewBlocks(self.source, self.allocator) catch |err| {
                std.log.err("pollForNewBlocks failed: {any}", .{err});
                std.time.sleep(self.interval_ms.load(.seq_cst) * std.time.ns_per_ms);
                continue;
            };

            if (maybe_blocks) |blocks| {
                defer self.allocator.free(blocks);
                const limit = @min(blocks.len, @as(usize, self.max_blocks_per_poll));
                if (limit > 0) {
                    self.callback(blocks[0..limit], self.callback_context);
                }
            }

            std.time.sleep(self.interval_ms.load(.seq_cst) * std.time.ns_per_ms);
        }
    }

    pub fn stop(self: *Self) void {
        self.is_running.store(false, .seq_cst);
    }

    pub fn setInterval(self: *Self, value: u32) void {
        self.interval_ms.store(value, .seq_cst);
    }

    pub fn deinit(self: *Self) void {
        if (self.callback_destructor) |destructor| {
            destructor(self.allocator, self.callback_context);
            self.callback_context = null;
        }
    }
};

fn pollTaskRunner(task: *PollingTask) void {
    task.loop();
}

/// Helper function to get latest block count
fn getLatestBlockCount(source: PollingSource) !u32 {
    const context = source.context orelse return errors.NeoError.UnsupportedOperation;
    return try source.get_block_count(context);
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
            .interval_ms = 15000, // 15 seconds (Neo block time)
            .max_blocks_per_poll = 10,
            .enable_batch_processing = true,
        };
    }

    /// Fast polling configuration
    pub fn fastPolling() PollingConfig {
        return PollingConfig{
            .interval_ms = 5000, // 5 seconds
            .max_blocks_per_poll = 5,
            .enable_batch_processing = false,
        };
    }

    /// Conservative polling configuration
    pub fn conservativePolling() PollingConfig {
        return PollingConfig{
            .interval_ms = 30000, // 30 seconds
            .max_blocks_per_poll = 20,
            .enable_batch_processing = true,
        };
    }
};

const PollingTestState = struct { value: u32 };

fn pollingTestGetBlockCount(ctx: ?*anyopaque) anyerror!u32 {
    const pointer = ctx orelse return errors.NeoError.UnsupportedOperation;
    const handle: *PollingTestState = @ptrCast(@alignCast(pointer));
    return handle.value;
}

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

    // Test polling creation (equivalent to Swift BlockIndexPolling tests)
    var polling = BlockIndexPolling.init();

    try testing.expect(polling.getCurrentBlockIndex() == null);

    // Test reset
    polling.reset();
    try testing.expect(polling.getCurrentBlockIndex() == null);
}

test "BlockIndexPolling new blocks detection" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var state = PollingTestState{ .value = 10 };

    var polling = BlockIndexPolling.init();
    const source = PollingSource{
        .context = &state,
        .get_block_count = pollingTestGetBlockCount,
    };

    try testing.expect((try polling.pollForNewBlocks(source, allocator)) == null);

    state.value = 13;
    const maybe_blocks = try polling.pollForNewBlocks(source, allocator);
    try testing.expect(maybe_blocks != null);

    const blocks = maybe_blocks.?;
    defer allocator.free(blocks);
    try testing.expectEqual(@as(usize, 3), blocks.len);
    try testing.expectEqual(@as(u32, 10), blocks[0]);
    try testing.expectEqual(@as(u32, 11), blocks[1]);
    try testing.expectEqual(@as(u32, 12), blocks[2]);
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
    try testing.expectError(errors.ValidationError.ParameterOutOfRange, PollingUtils.validatePollingConfig(too_fast_config));

    const too_slow_config = PollingUtils.createPollingConfig(400000, 10, true); // > 5 minutes
    try testing.expectError(errors.ValidationError.ParameterOutOfRange, PollingUtils.validatePollingConfig(too_slow_config));

    const too_many_blocks_config = PollingUtils.createPollingConfig(15000, 2000, true); // > 1000 blocks
    try testing.expectError(errors.ValidationError.ParameterOutOfRange, PollingUtils.validatePollingConfig(too_many_blocks_config));

    // Test optimal interval calculation
    const optimal_interval = PollingUtils.calculateOptimalInterval(15000, 0.5); // Half of block time
    try testing.expectEqual(@as(u32, 7500), optimal_interval);

    const min_interval = PollingUtils.calculateOptimalInterval(500, 0.1); // Very fast blocks
    try testing.expectEqual(@as(u32, 1000), min_interval); // Should be clamped to 1 second
}
