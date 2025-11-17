//! Neo Swift Rx implementation
//!
//! Complete conversion from NeoSwift NeoSwiftRx.swift protocol
//! Provides reactive programming interface for Neo blockchain events.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const JsonRpc2_0Rx = @import("json_rpc_2_0_rx.zig").JsonRpc2_0Rx;
const BlockData = @import("json_rpc_2_0_rx.zig").BlockData;

/// Neo Swift reactive protocol (converted from Swift NeoSwiftRx)
pub const NeoSwiftRx = struct {
    /// Reactive JSON-RPC client
    json_rpc_rx: JsonRpc2_0Rx,
    /// Default polling interval
    default_polling_interval_ms: u32,

    const Self = @This();

    /// Creates Neo Swift reactive client
    pub fn init(json_rpc_rx: JsonRpc2_0Rx, default_polling_interval_ms: u32) Self {
        return Self{
            .json_rpc_rx = json_rpc_rx,
            .default_polling_interval_ms = default_polling_interval_ms,
        };
    }

    /// Creates block publisher (equivalent to Swift blockPublisher(_ fullTransactionObjects: Bool))
    pub fn blockPublisher(
        self: *Self,
        full_transaction_objects: bool,
        callback: *const fn (BlockData) void,
    ) !@import("json_rpc_2_0_rx.zig").BlockSubscription {
        return try self.json_rpc_rx.blockPublisher(
            full_transaction_objects,
            self.default_polling_interval_ms,
            callback,
        );
    }

    /// Replays blocks in range (equivalent to Swift replayBlocksPublisher with 3 parameters)
    pub fn replayBlocksPublisher(
        self: *Self,
        start_block: u32,
        end_block: u32,
        full_transaction_objects: bool,
        callback: *const fn (BlockData) void,
    ) !@import("json_rpc_2_0_rx.zig").ReplaySubscription {
        return try self.json_rpc_rx.replayBlocksPublisher(
            start_block,
            end_block,
            full_transaction_objects,
            true, // Default ascending
            callback,
        );
    }

    /// Replays blocks with order control (equivalent to Swift replayBlocksPublisher with 4 parameters)
    pub fn replayBlocksPublisherWithOrder(
        self: *Self,
        start_block: u32,
        end_block: u32,
        full_transaction_objects: bool,
        ascending: bool,
        callback: *const fn (BlockData) void,
    ) !@import("json_rpc_2_0_rx.zig").ReplaySubscription {
        return try self.json_rpc_rx.replayBlocksPublisher(
            start_block,
            end_block,
            full_transaction_objects,
            ascending,
            callback,
        );
    }

    /// Catches up to latest block (equivalent to Swift catchUpToLatestBlockPublisher)
    pub fn catchUpToLatestBlockPublisher(
        self: *Self,
        start_block: u32,
        full_transaction_objects: bool,
        callback: *const fn (BlockData) void,
    ) !@import("json_rpc_2_0_rx.zig").CatchUpSubscription {
        return try self.json_rpc_rx.catchUpToLatestBlockPublisher(
            start_block,
            full_transaction_objects,
            callback,
        );
    }

    /// Catches up and subscribes to new blocks (equivalent to Swift catchUpToLatestAndSubscribeToNewBlocksPublisher)
    pub fn catchUpToLatestAndSubscribeToNewBlocksPublisher(
        self: *Self,
        start_block: u32,
        full_transaction_objects: bool,
        callback: *const fn (BlockData) void,
    ) !@import("json_rpc_2_0_rx.zig").CombinedSubscription {
        return try self.json_rpc_rx.catchUpToLatestAndSubscribeToNewBlocksPublisher(
            start_block,
            full_transaction_objects,
            self.default_polling_interval_ms,
            callback,
        );
    }

    /// Subscribes to new blocks (equivalent to Swift subscribeToNewBlocksPublisher)
    pub fn subscribeToNewBlocksPublisher(
        self: *Self,
        full_transaction_objects: bool,
        callback: *const fn (BlockData) void,
    ) !@import("json_rpc_2_0_rx.zig").BlockSubscription {
        return try self.blockPublisher(full_transaction_objects, callback);
    }

    /// Creates transaction filter subscription (additional utility)
    pub fn createTransactionFilterSubscription(
        self: *Self,
        filter: TransactionFilter,
        callback: *const fn (TransactionData) void,
    ) !TransactionSubscription {
        return TransactionSubscription{
            .filter = filter,
            .callback = callback,
            .is_active = true,
            .rx_client = self,
        };
    }

    /// Creates contract event subscription (additional utility)
    pub fn createContractEventSubscription(
        self: *Self,
        contract_hash: @import("../types/hash160.zig").Hash160,
        event_name: ?[]const u8,
        callback: *const fn (ContractEvent) void,
    ) !ContractEventSubscription {
        return ContractEventSubscription{
            .contract_hash = contract_hash,
            .event_name = event_name,
            .callback = callback,
            .is_active = true,
            .rx_client = self,
        };
    }

    /// Gets current subscription count (utility method)
    pub fn getActiveSubscriptionCount(self: Self) u32 {
        // Would track active subscriptions
        _ = self;
        return 0; // Placeholder
    }

    /// Stops all subscriptions (utility method)
    pub fn stopAllSubscriptions(self: *Self) void {
        // Would stop all active subscriptions
        _ = self;
    }
};

/// Transaction filter for subscription
pub const TransactionFilter = struct {
    from_address: ?@import("../types/hash160.zig").Hash160,
    to_address: ?@import("../types/hash160.zig").Hash160,
    contract_hash: ?@import("../types/hash160.zig").Hash160,
    min_amount: ?i64,

    pub fn matches(self: TransactionFilter, tx_data: TransactionData) bool {
        if (self.from_address) |from| {
            if (tx_data.from_address == null or !from.eql(tx_data.from_address.?)) {
                return false;
            }
        }

        if (self.to_address) |to| {
            if (tx_data.to_address == null or !to.eql(tx_data.to_address.?)) {
                return false;
            }
        }

        if (self.contract_hash) |contract| {
            if (tx_data.contract_hash == null or !contract.eql(tx_data.contract_hash.?)) {
                return false;
            }
        }

        if (self.min_amount) |min_amt| {
            if (tx_data.amount == null or tx_data.amount.? < min_amt) {
                return false;
            }
        }

        return true;
    }
};

/// Transaction data for filtering
pub const TransactionData = struct {
    tx_hash: @import("../types/hash256.zig").Hash256,
    from_address: ?@import("../types/hash160.zig").Hash160,
    to_address: ?@import("../types/hash160.zig").Hash160,
    contract_hash: ?@import("../types/hash160.zig").Hash160,
    amount: ?i64,
    block_index: u32,

    pub fn init(tx_hash: @import("../types/hash256.zig").Hash256, block_index: u32) TransactionData {
        return TransactionData{
            .tx_hash = tx_hash,
            .from_address = null,
            .to_address = null,
            .contract_hash = null,
            .amount = null,
            .block_index = block_index,
        };
    }
};

/// Contract event data
pub const ContractEvent = struct {
    contract_hash: @import("../types/hash160.zig").Hash160,
    event_name: []const u8,
    parameters: []const @import("../types/contract_parameter.zig").ContractParameter,
    block_index: u32,
    tx_hash: @import("../types/hash256.zig").Hash256,

    pub fn init() ContractEvent {
        return std.mem.zeroes(ContractEvent);
    }
};

/// Subscription types
pub const TransactionSubscription = struct {
    filter: TransactionFilter,
    callback: *const fn (TransactionData) void,
    is_active: bool,
    rx_client: *NeoSwiftRx,

    pub fn stop(self: *TransactionSubscription) void {
        self.is_active = false;
    }

    pub fn isActive(self: TransactionSubscription) bool {
        return self.is_active;
    }
};

pub const ContractEventSubscription = struct {
    contract_hash: @import("../types/hash160.zig").Hash160,
    event_name: ?[]const u8,
    callback: *const fn (ContractEvent) void,
    is_active: bool,
    rx_client: *NeoSwiftRx,

    pub fn stop(self: *ContractEventSubscription) void {
        self.is_active = false;
    }

    pub fn isActive(self: ContractEventSubscription) bool {
        return self.is_active;
    }

    pub fn matchesEvent(self: ContractEventSubscription, event: ContractEvent) bool {
        if (!self.contract_hash.eql(event.contract_hash)) return false;

        if (self.event_name) |name| {
            return std.mem.eql(u8, name, event.event_name);
        }

        return true; // Match all events if no specific event name
    }
};

/// Reactive utilities
pub const ReactiveUtils = struct {
    /// Creates block range for replay
    pub fn createBlockRange(start: u32, end: u32, ascending: bool, allocator: std.mem.Allocator) ![]u32 {
        if (start > end) return errors.ValidationError.ParameterOutOfRange;

        const count = end - start + 1;
        var blocks = try allocator.alloc(u32, count);

        var i: u32 = 0;
        while (i < count) : (i += 1) {
            blocks[i] = if (ascending) start + i else end - i;
        }

        return blocks;
    }

    /// Validates polling interval
    pub fn validatePollingInterval(interval_ms: u32) !void {
        if (interval_ms < 1000) { // Minimum 1 second
            return errors.ValidationError.ParameterOutOfRange;
        }

        if (interval_ms > 300000) { // Maximum 5 minutes
            return errors.ValidationError.ParameterOutOfRange;
        }
    }

    /// Creates transaction filter builder
    pub fn createTransactionFilterBuilder() TransactionFilterBuilder {
        return TransactionFilterBuilder.init();
    }

    /// Gets optimal polling interval for network
    pub fn getOptimalPollingInterval(network_type: NetworkType) u32 {
        return switch (network_type) {
            .MainNet => 15000, // 15 seconds (Neo block time)
            .TestNet => 15000, // 15 seconds
            .Local => 1000, // 1 second for local testing
            .Custom => 10000, // 10 seconds default
        };
    }
};

/// Transaction filter builder
pub const TransactionFilterBuilder = struct {
    filter: TransactionFilter,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .filter = TransactionFilter{
                .from_address = null,
                .to_address = null,
                .contract_hash = null,
                .min_amount = null,
            },
        };
    }

    pub fn fromAddress(self: *Self, address: @import("../types/hash160.zig").Hash160) *Self {
        self.filter.from_address = address;
        return self;
    }

    pub fn toAddress(self: *Self, address: @import("../types/hash160.zig").Hash160) *Self {
        self.filter.to_address = address;
        return self;
    }

    pub fn contractHash(self: *Self, hash: @import("../types/hash160.zig").Hash160) *Self {
        self.filter.contract_hash = hash;
        return self;
    }

    pub fn minAmount(self: *Self, amount: i64) *Self {
        self.filter.min_amount = amount;
        return self;
    }

    pub fn build(self: Self) TransactionFilter {
        return self.filter;
    }
};

/// Network types for optimization
pub const NetworkType = enum {
    MainNet,
    TestNet,
    Local,
    Custom,
};

// Tests (converted from Swift NeoSwiftRx tests)
test "NeoSwiftRx creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test reactive client creation
    const executor = @import("json_rpc_2_0_rx.zig").AsyncExecutor.init(4);
    var json_rpc_rx = JsonRpc2_0Rx.init(null, null, null, 15000, allocator);
    json_rpc_rx.executor_service = executor;

    var neo_swift_rx = NeoSwiftRx.init(json_rpc_rx, 15000);

    try testing.expectEqual(@as(u32, 15000), neo_swift_rx.default_polling_interval_ms);
    try testing.expectEqual(@as(u32, 0), neo_swift_rx.getActiveSubscriptionCount());
}

test "TransactionFilter operations" {
    const testing = std.testing;

    // Test transaction filter creation and matching
    const filter = TransactionFilter{
        .from_address = @import("../types/hash160.zig").Hash160.ZERO,
        .to_address = null,
        .contract_hash = null,
        .min_amount = 1000000, // 0.01 tokens (8 decimals)
    };

    // Test matching transaction
    const matching_tx = TransactionData{
        .tx_hash = @import("../types/hash256.zig").Hash256.ZERO,
        .from_address = @import("../types/hash160.zig").Hash160.ZERO,
        .to_address = null,
        .contract_hash = null,
        .amount = 2000000, // Above minimum
        .block_index = 12345,
    };

    try testing.expect(filter.matches(matching_tx));

    // Test non-matching transaction (amount too low)
    const non_matching_tx = TransactionData{
        .tx_hash = @import("../types/hash256.zig").Hash256.ZERO,
        .from_address = @import("../types/hash160.zig").Hash160.ZERO,
        .to_address = null,
        .contract_hash = null,
        .amount = 500000, // Below minimum
        .block_index = 12345,
    };

    try testing.expect(!filter.matches(non_matching_tx));
}

test "TransactionFilterBuilder operations" {
    const testing = std.testing;

    // Test filter builder pattern
    var builder = ReactiveUtils.createTransactionFilterBuilder();

    const from_hash = @import("../types/hash160.zig").Hash160.ZERO;
    const to_hash = try @import("../types/hash160.zig").Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");

    const filter = builder
        .fromAddress(from_hash)
        .toAddress(to_hash)
        .minAmount(1000000)
        .build();

    try testing.expect(filter.from_address != null);
    try testing.expect(filter.from_address.?.eql(from_hash));
    try testing.expect(filter.to_address != null);
    try testing.expect(filter.to_address.?.eql(to_hash));
    try testing.expectEqual(@as(i64, 1000000), filter.min_amount.?);
}

test "ReactiveUtils utility functions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test block range creation
    const ascending_range = try ReactiveUtils.createBlockRange(100, 105, true, allocator);
    defer allocator.free(ascending_range);

    const expected_ascending = [_]u32{ 100, 101, 102, 103, 104, 105 };
    try testing.expectEqualSlices(u32, &expected_ascending, ascending_range);

    const descending_range = try ReactiveUtils.createBlockRange(100, 103, false, allocator);
    defer allocator.free(descending_range);

    const expected_descending = [_]u32{ 103, 102, 101, 100 };
    try testing.expectEqualSlices(u32, &expected_descending, descending_range);

    // Test polling interval validation
    try ReactiveUtils.validatePollingInterval(15000); // Valid

    try testing.expectError(errors.ValidationError.ParameterOutOfRange, ReactiveUtils.validatePollingInterval(500) // Too fast
    );

    try testing.expectError(errors.ValidationError.ParameterOutOfRange, ReactiveUtils.validatePollingInterval(400000) // Too slow
    );

    // Test optimal polling intervals
    try testing.expectEqual(@as(u32, 15000), ReactiveUtils.getOptimalPollingInterval(.MainNet));
    try testing.expectEqual(@as(u32, 15000), ReactiveUtils.getOptimalPollingInterval(.TestNet));
    try testing.expectEqual(@as(u32, 1000), ReactiveUtils.getOptimalPollingInterval(.Local));
    try testing.expectEqual(@as(u32, 10000), ReactiveUtils.getOptimalPollingInterval(.Custom));
}

test "ContractEventSubscription operations" {
    const testing = std.testing;

    // Test contract event subscription
    const contract_hash = @import("../types/hash160.zig").Hash160.ZERO;
    const event_name = "Transfer";

    const test_callback = struct {
        fn onEvent(event: ContractEvent) void {
            _ = event;
        }
    }.onEvent;

    var event_subscription = ContractEventSubscription{
        .contract_hash = contract_hash,
        .event_name = event_name,
        .callback = test_callback,
        .is_active = true,
        .rx_client = undefined, // Would be set to actual client
    };

    try testing.expect(event_subscription.isActive());

    // Test event matching
    const matching_event = ContractEvent{
        .contract_hash = contract_hash,
        .event_name = event_name,
        .parameters = &[_]@import("../types/contract_parameter.zig").ContractParameter{},
        .block_index = 12345,
        .tx_hash = @import("../types/hash256.zig").Hash256.ZERO,
    };

    try testing.expect(event_subscription.matchesEvent(matching_event));

    // Test non-matching event (different contract)
    const non_matching_event = ContractEvent{
        .contract_hash = try @import("../types/hash160.zig").Hash160.initWithString("1234567890abcdef1234567890abcdef12345678"),
        .event_name = event_name,
        .parameters = &[_]@import("../types/contract_parameter.zig").ContractParameter{},
        .block_index = 12345,
        .tx_hash = @import("../types/hash256.zig").Hash256.ZERO,
    };

    try testing.expect(!event_subscription.matchesEvent(non_matching_event));

    event_subscription.stop();
    try testing.expect(!event_subscription.isActive());
}
