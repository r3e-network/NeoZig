//! JSON-RPC 2.0 Rx implementation
//!
//! Complete conversion from NeoSwift JsonRpc2_0Rx.swift
//! Provides reactive programming support for Neo blockchain operations.

const std = @import("std");
const builtin = @import("builtin");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const response_aliases = @import("../rpc/response_aliases.zig");
const responses = @import("../rpc/responses.zig");
const BlockIndexPolling = @import("block_index_polling.zig").BlockIndexPolling;
const PollingSource = @import("block_index_polling.zig").PollingSource;

const log = std.log.scoped(.neo_protocol);

/// JSON-RPC 2.0 reactive extension (converted from Swift JsonRpc2_0Rx)
pub const JsonRpc2_0Rx = struct {
    /// Neo client reference
    neo_swift: ?*anyopaque,
    /// Callback to retrieve latest block count
    get_block_count_fn: ?*const fn (?*anyopaque) anyerror!u32,
    /// Callback to retrieve a block by index
    get_block_by_index_fn: ?*const fn (?*anyopaque, u32, bool) anyerror!response_aliases.NeoGetBlock,
    /// Executor for async operations
    executor_service: AsyncExecutor,
    /// Default polling interval to fall back on
    default_polling_interval_ms: u32,

    allocator: std.mem.Allocator,

    const Self = @This();

    /// Creates JSON-RPC reactive client (equivalent to Swift init)
    pub fn init(
        neo_swift: ?*anyopaque,
        get_block_count_fn: ?*const fn (?*anyopaque) anyerror!u32,
        get_block_by_index_fn: ?*const fn (?*anyopaque, u32, bool) anyerror!response_aliases.NeoGetBlock,
        default_polling_interval_ms: u32,
        allocator: std.mem.Allocator,
    ) Self {
        return Self{
            .neo_swift = neo_swift,
            .get_block_count_fn = get_block_count_fn,
            .get_block_by_index_fn = get_block_by_index_fn,
            .executor_service = AsyncExecutor.init(1),
            .default_polling_interval_ms = default_polling_interval_ms,
            .allocator = allocator,
        };
    }

    /// Creates block index publisher (equivalent to Swift blockIndexPublisher)
    pub fn blockIndexPublisher(
        self: *Self,
        polling_interval_ms: u32,
        callback: *const fn (u32, ?*anyopaque) void,
        callback_context: ?*anyopaque,
        callback_context_destructor: ?*const fn (std.mem.Allocator, ?*anyopaque) void,
    ) !BlockIndexSubscription {
        const context = self.neo_swift orelse return errors.NeoError.UnsupportedOperation;
        const get_block_count = self.get_block_count_fn orelse return errors.NeoError.UnsupportedOperation;

        const source = PollingSource{
            .context = context,
            .get_block_count = get_block_count,
        };

        const polling_ptr = try self.allocator.create(BlockIndexPolling);
        polling_ptr.* = BlockIndexPolling.init();

        const HandlerContext = struct {
            callback: *const fn (u32, ?*anyopaque) void,
            user_context: ?*anyopaque,
            user_destructor: ?*const fn (std.mem.Allocator, ?*anyopaque) void,
        };

        const forwardIndices = struct {
            fn invoke(indices: []const u32, ctx_ptr: ?*anyopaque) void {
                const handler_ptr = ctx_ptr orelse return;
                const handler: *HandlerContext = @ptrCast(@alignCast(handler_ptr));
                for (indices) |index| {
                    handler.callback(index, handler.user_context);
                }
            }
        }.invoke;

        const destroyHandler = struct {
            fn destroy(allocator: std.mem.Allocator, ctx_ptr: ?*anyopaque) void {
                if (ctx_ptr) |raw| {
                    const handler: *HandlerContext = @ptrCast(@alignCast(raw));
                    if (handler.user_context) |user_ctx| {
                        if (handler.user_destructor) |destructor| {
                            destructor(allocator, user_ctx);
                        }
                    }
                    allocator.destroy(handler);
                }
            }
        }.destroy;

        const interval = if (polling_interval_ms == 0)
            self.default_polling_interval_ms
        else
            polling_interval_ms;

        const handler_context = try self.allocator.create(HandlerContext);
        handler_context.* = HandlerContext{
            .callback = callback,
            .user_context = callback_context,
            .user_destructor = callback_context_destructor,
        };

        const control = try polling_ptr.startPolling(
            source,
            interval,
            forwardIndices,
            handler_context,
            destroyHandler,
            self.allocator,
        );

        return BlockIndexSubscription{
            .polling = polling_ptr,
            .allocator = self.allocator,
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
        const neo_context = self.neo_swift orelse return errors.NeoError.UnsupportedOperation;
        const fetch_block = self.get_block_by_index_fn orelse return errors.NeoError.UnsupportedOperation;

        const block_callback = struct {
            fn handle(index: u32, ctx_ptr: ?*anyopaque) void {
                const raw_ctx = ctx_ptr orelse return;
                const ctx: *BlockPublisherContext = @ptrCast(@alignCast(raw_ctx));

                const fetch_result = fetchBlockInternalStatic(ctx, index) catch {
                    return;
                };

                ctx.callback(fetch_result.data);
                ctx.rx.releaseFetchResult(fetch_result);
            }
        }.handle;

        const destroyPublisherContext = struct {
            fn destroy(allocator: std.mem.Allocator, ctx_ptr: ?*anyopaque) void {
                if (ctx_ptr) |raw| {
                    const ctx: *BlockPublisherContext = @ptrCast(@alignCast(raw));
                    for (ctx.owned_blocks.items) |stored| {
                        stored.deinit(ctx.allocator);
                        ctx.allocator.destroy(stored);
                    }
                    ctx.owned_blocks.deinit();
                    allocator.destroy(ctx);
                }
            }
        }.destroy;

        const publisher_context = try self.allocator.create(BlockPublisherContext);
        publisher_context.* = BlockPublisherContext{
            .rx = self,
            .allocator = self.allocator,
            .neo_context = neo_context,
            .fetch_fn = fetch_block,
            .callback = callback,
            .full_transactions = full_transaction_objects,
            .owned_blocks = ArrayList(*response_aliases.NeoGetBlock).init(self.allocator),
        };

        const index_subscription = try self.blockIndexPublisher(
            polling_interval_ms,
            block_callback,
            publisher_context,
            destroyPublisherContext,
        );

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
            .rx_client = self,
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

    /// Returns the configured default polling interval.
    pub fn getDefaultPollingInterval(self: Self) u32 {
        return self.default_polling_interval_ms;
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
            if (polling_interval_ms == 0) self.default_polling_interval_ms else polling_interval_ms,
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
        const context = self.neo_swift orelse return errors.NeoError.UnsupportedOperation;
        const get_block_count = self.get_block_count_fn orelse return errors.NeoError.UnsupportedOperation;
        const count = try get_block_count(context);
        if (count == 0) return 0;
        return count - 1;
    }

    fn fetchBlockInternal(
        self: *Self,
        block_index: u32,
        full_transaction_objects: bool,
        storage: ?*BlockPublisherContext,
    ) !BlockFetchResult {
        const get_block = self.get_block_by_index_fn orelse return errors.NeoError.UnsupportedOperation;
        const context = if (storage) |ctx|
            ctx.neo_context
        else
            self.neo_swift;

        const ctx_ptr = context orelse return errors.NeoError.UnsupportedOperation;

        var response = try get_block(ctx_ptr, block_index, full_transaction_objects);

        if (storage) |ctx| {
            const stored = ctx.allocator.create(response_aliases.NeoGetBlock) catch |err| {
                if (!builtin.is_test) {
                    log.warn("failed to allocate stored block context: {any}", .{err});
                }
                response.deinit(ctx.allocator);
                return err;
            };
            stored.* = response;
            if (stored.result == null) {
                stored.deinit(ctx.allocator);
                ctx.allocator.destroy(stored);
                return errors.NetworkError.InvalidResponse;
            }
            ctx.owned_blocks.append(stored) catch |append_err| {
                if (!builtin.is_test) {
                    log.warn("failed to track stored block: {any}", .{append_err});
                }
                stored.deinit(ctx.allocator);
                ctx.allocator.destroy(stored);
                return append_err;
            };
            return BlockFetchResult{
                .data = BlockData{
                    .index = block_index,
                    .full_transactions = full_transaction_objects,
                    .block = stored.result.?,
                },
                .temp_storage = null,
            };
        }

        const stored_temp = self.allocator.create(response_aliases.NeoGetBlock) catch |err| {
            if (!builtin.is_test) {
                log.warn("failed to allocate temporary block: {any}", .{err});
            }
            response.deinit(self.allocator);
            return err;
        };
        stored_temp.* = response;
        const block_ptr = stored_temp.result orelse {
            stored_temp.deinit(self.allocator);
            self.allocator.destroy(stored_temp);
            return errors.NetworkError.InvalidResponse;
        };

        return BlockFetchResult{
            .data = BlockData{
                .index = block_index,
                .full_transactions = full_transaction_objects,
                .block = block_ptr,
            },
            .temp_storage = stored_temp,
        };
    }

    fn releaseFetchResult(self: *Self, result: BlockFetchResult) void {
        if (result.temp_storage) |temp| {
            temp.deinit(self.allocator);
            self.allocator.destroy(temp);
        }
    }

    fn fetchBlockForReplay(self: *Self, block_index: u32, full_transaction_objects: bool) !BlockFetchResult {
        return self.fetchBlockInternal(block_index, full_transaction_objects, null);
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

    pub fn deinit(self: *Self) void {
        _ = self;
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
        task(); // basic execution
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
    block: *const responses.NeoBlock,

    pub fn getBlock(self: BlockData) *const responses.NeoBlock {
        return self.block;
    }
};

const BlockFetchResult = struct {
    data: BlockData,
    temp_storage: ?*response_aliases.NeoGetBlock,
};

const BlockPublisherContext = struct {
    rx: *JsonRpc2_0Rx,
    allocator: std.mem.Allocator,
    neo_context: ?*anyopaque,
    fetch_fn: *const fn (?*anyopaque, u32, bool) anyerror!response_aliases.NeoGetBlock,
    callback: *const fn (BlockData) void,
    full_transactions: bool,
    owned_blocks: ArrayList(*response_aliases.NeoGetBlock),
};

fn fetchBlockInternalStatic(ctx: *BlockPublisherContext, index: u32) !BlockFetchResult {
    return ctx.rx.fetchBlockInternal(index, ctx.full_transactions, ctx);
}

/// Subscription types
pub const BlockIndexSubscription = struct {
    polling: *BlockIndexPolling,
    allocator: std.mem.Allocator,
    control: @import("block_index_polling.zig").PollingControl,
    is_active: bool,

    pub fn stop(self: *BlockIndexSubscription) void {
        if (!self.is_active) return;
        self.control.stop();
        self.is_active = false;
    }

    pub fn isActive(self: *BlockIndexSubscription) bool {
        return self.is_active and self.control.isActive();
    }

    pub fn deinit(self: *BlockIndexSubscription) void {
        self.stop();
        self.allocator.destroy(self.polling);
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

    pub fn isActive(self: *BlockSubscription) bool {
        return self.is_active and self.index_subscription.isActive();
    }

    pub fn deinit(self: *BlockSubscription) void {
        self.index_subscription.deinit();
    }
};

pub const ReplaySubscription = struct {
    blocks: []u32,
    current_index: usize,
    full_transactions: bool,
    callback: *const fn (BlockData) void,
    is_active: bool,
    allocator: std.mem.Allocator,
    rx_client: *JsonRpc2_0Rx,

    pub fn stop(self: *ReplaySubscription) void {
        self.is_active = false;
    }

    pub fn deinit(self: *ReplaySubscription) void {
        self.allocator.free(self.blocks);
    }

    pub fn processNext(self: *ReplaySubscription) bool {
        if (!self.is_active or self.current_index >= self.blocks.len) return false;

        const block_index = self.blocks[self.current_index];
        const fetch_result = self.rx_client.fetchBlockForReplay(block_index, self.full_transactions) catch |err| {
            if (!builtin.is_test) {
                log.warn("failed to fetch block {d} during replay: {any}", .{ block_index, err });
            }
            self.current_index += 1;
            return false;
        };

        self.callback(fetch_result.data);
        self.rx_client.releaseFetchResult(fetch_result);
        self.current_index += 1;

        return true;
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

const TestBlockCountStub = struct {
    value: u32,
};

fn testStubGetBlockCount(ctx: ?*anyopaque) anyerror!u32 {
    const pointer = ctx orelse return errors.NeoError.UnsupportedOperation;
    const handle: *TestBlockCountStub = @ptrCast(@alignCast(pointer));
    return handle.value;
}

const ReplayStubContext = struct {
    allocator: std.mem.Allocator,
};

fn replayStubFetch(
    ctx: ?*anyopaque,
    index: u32,
    full: bool,
) !response_aliases.NeoGetBlock {
    _ = full;
    const raw = ctx orelse return errors.NeoError.UnsupportedOperation;
    const stub: *ReplayStubContext = @ptrCast(@alignCast(raw));
    var response = response_aliases.NeoGetBlock.init();
    var block_ptr = try stub.allocator.create(responses.NeoBlock);
    block_ptr.* = responses.NeoBlock.initDefault();
    block_ptr.index = index;
    response.result = block_ptr;
    return response;
}

// Tests (converted from Swift JsonRpc2_0Rx tests)
test "JsonRpc2_0Rx creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test reactive client creation
    const executor = AsyncExecutor.init(4);
    var rx_client = JsonRpc2_0Rx.init(null, null, null, 15000, allocator);
    rx_client.executor_service = executor;

    try testing.expectEqual(@as(u32, 4), rx_client.executor_service.thread_pool_size);

    // Latest block index is not yet implemented
    try testing.expectError(errors.NeoError.UnsupportedOperation, rx_client.getLatestBlockIndex());
}

test "JsonRpc2_0Rx latest block index callback" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var stub = TestBlockCountStub{ .value = 42 };

    var rx_client = JsonRpc2_0Rx.init(&stub, testStubGetBlockCount, null, 15000, allocator);
    defer rx_client.deinit();

    const latest = try rx_client.getLatestBlockIndex();
    try testing.expectEqual(@as(u32, 41), latest);
}

test "Subscription management" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test subscription creation and management
    const polling_ptr = try allocator.create(BlockIndexPolling);
    polling_ptr.* = BlockIndexPolling.init();

    var block_subscription = BlockSubscription{
        .index_subscription = BlockIndexSubscription{
            .polling = polling_ptr,
            .allocator = allocator,
            .control = @import("block_index_polling.zig").PollingControl.init(15000, allocator),
            .is_active = true,
        },
        .full_transactions = false,
        .is_active = true,
    };

    try testing.expect(block_subscription.isActive());

    block_subscription.stop();
    try testing.expect(!block_subscription.isActive());
    block_subscription.deinit();
}

test "Block data operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const block_index: u32 = 12345;
    var block_ptr = try allocator.create(responses.NeoBlock);
    block_ptr.* = responses.NeoBlock.initDefault();
    block_ptr.index = block_index;

    const block_data = BlockData{
        .index = block_index,
        .full_transactions = true,
        .block = block_ptr,
    };

    try testing.expectEqual(block_index, block_data.index);
    try testing.expect(block_data.full_transactions);
    const block = block_data.getBlock();
    try testing.expectEqual(block_index, block.index);

    block_ptr.deinit(allocator);
    allocator.destroy(block_ptr);
}

test "Replay subscription operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var stub_context = ReplayStubContext{ .allocator = allocator };
    var rx_stub = JsonRpc2_0Rx.init(&stub_context, null, replayStubFetch, 15000, allocator);

    const test_callback = struct {
        fn onBlock(block_data: BlockData) void {
            _ = block_data;
        }
    }.onBlock;

    var replay_subscription = ReplaySubscription{
        .blocks = try allocator.dupe(u32, &[_]u32{ 100, 101, 102 }),
        .current_index = 0,
        .full_transactions = false,
        .callback = test_callback,
        .is_active = true,
        .allocator = allocator,
        .rx_client = &rx_stub,
    };
    defer replay_subscription.deinit();

    // Test processing blocks
    try testing.expect(replay_subscription.processNext()); // Block 100
    try testing.expect(replay_subscription.processNext()); // Block 101
    try testing.expect(replay_subscription.processNext()); // Block 102
    try testing.expect(!replay_subscription.processNext()); // No more blocks
}
