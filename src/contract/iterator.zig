//! Iterator implementation
//!
//! Complete conversion from NeoSwift Iterator.swift
//! Provides paginated result traversal for Neo smart contract operations.

const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const StackItem = @import("../types/stack_item.zig").StackItem;
const NeoSwift = @import("../rpc/neo_client.zig").NeoSwift;
const NeoProtocol = @import("../protocol/neo_protocol.zig").NeoProtocol;

/// Generic iterator for stack items (converted from Swift Iterator<T>)
pub fn Iterator(comptime T: type) type {
    return struct {
        /// Neo client instance
        neo_swift: *anyopaque, // NeoSwift reference
        /// Session ID for iterator
        session_id: []const u8,
        /// Iterator ID for traversal
        iterator_id: []const u8,
        /// Mapper function for converting stack items
        mapper: *const fn (StackItem, std.mem.Allocator) anyerror!T,

        allocator: std.mem.Allocator,

        const Self = @This();

        fn deinitMappedItem(item: T, allocator: std.mem.Allocator) void {
            const ti = @typeInfo(T);
            switch (ti) {
                .pointer => |ptr_info| {
                    if (ptr_info.size == .slice and ptr_info.child == u8) {
                        allocator.free(@constCast(item));
                    }
                },
                else => {},
            }
        }

        /// Creates iterator (equivalent to Swift init)
        pub fn init(
            allocator: std.mem.Allocator,
            neo_swift: *anyopaque,
            session_id: []const u8,
            iterator_id: []const u8,
            mapper: *const fn (StackItem, std.mem.Allocator) anyerror!T,
        ) !Self {
            return Self{
                .neo_swift = neo_swift,
                .session_id = try allocator.dupe(u8, session_id),
                .iterator_id = try allocator.dupe(u8, iterator_id),
                .mapper = mapper,
                .allocator = allocator,
            };
        }

        /// Cleanup resources
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.session_id);
            self.allocator.free(self.iterator_id);
        }

        /// Traverses iterator (equivalent to Swift traverse(_ count: Int))
        pub fn traverse(self: Self, count: u32) ![]T {
            const neo_swift: *NeoSwift = @ptrCast(@alignCast(self.neo_swift));
            var protocol = NeoProtocol.init(neo_swift.getService());
            const service_allocator = protocol.service.getAllocator();

            var request = try protocol.traverseIterator(self.session_id, self.iterator_id, count);
            var response = try request.sendUsing(protocol.service);
            defer response.deinit(service_allocator);

            const stack_items = response.getTraverseIterator() orelse &[_]StackItem{};
            var mapped_items = try self.allocator.alloc(T, stack_items.len);
            var mapped_count: usize = 0;
            errdefer {
                for (mapped_items[0..mapped_count]) |entry| {
                    deinitMappedItem(entry, self.allocator);
                }
                self.allocator.free(mapped_items);
            }

            for (stack_items, 0..) |item, i| {
                mapped_items[i] = try self.mapper(item, self.allocator);
                mapped_count += 1;
            }

            return mapped_items;
        }

        /// Terminates session (equivalent to Swift terminateSession())
        pub fn terminateSession(self: Self) !void {
            const neo_swift: *NeoSwift = @ptrCast(@alignCast(self.neo_swift));
            var protocol = NeoProtocol.init(neo_swift.getService());
            var request = try protocol.terminateSession(self.session_id);
            const response = try request.sendUsing(protocol.service);
            if (!(response.getTerminateSession() orelse false)) {
                return errors.ContractError.ContractCallFailed;
            }
        }

        /// Gets remaining item count estimate (utility method)
        pub fn estimateRemainingItems(self: Self) !u32 {
            // Would make RPC call to get iterator info
            _ = self;
            return 0; // stub
        }

        /// Traverses all remaining items (utility method)
        pub fn traverseAll(self: Self, max_items: u32) ![]T {
            var all_items = ArrayList(T).init(self.allocator);
            errdefer {
                for (all_items.items) |entry| {
                    deinitMappedItem(entry, self.allocator);
                }
            }
            defer all_items.deinit();

            const batch_size = @min(100, max_items); // Reasonable batch size
            var total_retrieved: u32 = 0;

            while (total_retrieved < max_items) {
                const remaining = max_items - total_retrieved;
                const this_batch = @min(batch_size, remaining);

                const batch_items = try self.traverse(this_batch);
                var cleanup_batch = true;
                errdefer if (cleanup_batch) {
                    for (batch_items) |entry| {
                        deinitMappedItem(entry, self.allocator);
                    }
                };
                defer self.allocator.free(batch_items);

                if (batch_items.len == 0) break; // No more items

                try all_items.appendSlice(batch_items);
                cleanup_batch = false;
                total_retrieved += @intCast(batch_items.len);

                if (batch_items.len < this_batch) break; // Fewer items than requested
            }

            return try all_items.toOwnedSlice();
        }

        /// Checks if iterator has more items (utility method)
        pub fn hasMore(self: Self) !bool {
            // Try to traverse 1 item to check availability
            const test_items = self.traverse(1) catch |err| {
                return switch (err) {
                    error.ContractCallFailed => false,
                    else => err,
                };
            };
            defer {
                for (test_items) |entry| {
                    deinitMappedItem(entry, self.allocator);
                }
                self.allocator.free(test_items);
            }

            return test_items.len > 0;
        }

        /// Gets session info (utility method)
        pub fn getSessionInfo(self: Self) SessionInfo {
            return SessionInfo{
                .session_id = self.session_id,
                .iterator_id = self.iterator_id,
                .item_type = @typeName(T),
            };
        }
    };
}

/// Session information structure
pub const SessionInfo = struct {
    session_id: []const u8,
    iterator_id: []const u8,
    item_type: []const u8,

    /// Formats session info for logging
    pub fn format(self: SessionInfo, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "Session: {s}, Iterator: {s}, Type: {s}", .{ self.session_id, self.iterator_id, self.item_type });
    }
};

/// Common iterator types
pub const CommonIterators = struct {
    /// String iterator (most common)
    pub const StringIterator = Iterator([]const u8);

    /// Integer iterator
    pub const IntegerIterator = Iterator(i64);

    /// Hash160 iterator
    pub const Hash160Iterator = Iterator(@import("../types/hash160.zig").Hash160);

    /// Contract parameter iterator
    pub const ContractParameterIterator = Iterator(@import("../types/contract_parameter.zig").ContractParameter);

    /// Stack item iterator (raw)
    pub const StackItemIterator = Iterator(StackItem);
};

/// Iterator factory
pub const IteratorFactory = struct {
    /// Creates string iterator with default mapper
    pub fn createStringIterator(
        allocator: std.mem.Allocator,
        neo_swift: *anyopaque,
        session_id: []const u8,
        iterator_id: []const u8,
    ) !CommonIterators.StringIterator {
        const string_mapper = struct {
            fn map(stack_item: StackItem, alloc: std.mem.Allocator) ![]const u8 {
                return try stack_item.getString(alloc);
            }
        }.map;

        return try CommonIterators.StringIterator.init(
            allocator,
            neo_swift,
            session_id,
            iterator_id,
            string_mapper,
        );
    }

    /// Creates integer iterator with default mapper
    pub fn createIntegerIterator(
        allocator: std.mem.Allocator,
        neo_swift: *anyopaque,
        session_id: []const u8,
        iterator_id: []const u8,
    ) !CommonIterators.IntegerIterator {
        const integer_mapper = struct {
            fn map(stack_item: StackItem, alloc: std.mem.Allocator) !i64 {
                _ = alloc;
                return try stack_item.getInteger();
            }
        }.map;

        return try CommonIterators.IntegerIterator.init(
            allocator,
            neo_swift,
            session_id,
            iterator_id,
            integer_mapper,
        );
    }

    /// Creates Hash160 iterator with default mapper
    pub fn createHash160Iterator(
        allocator: std.mem.Allocator,
        neo_swift: *anyopaque,
        session_id: []const u8,
        iterator_id: []const u8,
    ) !CommonIterators.Hash160Iterator {
        const hash160_mapper = struct {
            fn map(stack_item: StackItem, alloc: std.mem.Allocator) !@import("../types/hash160.zig").Hash160 {
                const bytes = try stack_item.getByteArray(alloc);
                defer alloc.free(bytes);

                if (bytes.len != 20) {
                    return errors.ValidationError.InvalidHash;
                }

                var hash_bytes: [20]u8 = undefined;
                @memcpy(&hash_bytes, bytes);
                return @import("../types/hash160.zig").Hash160.fromArray(hash_bytes);
            }
        }.map;

        return try CommonIterators.Hash160Iterator.init(
            allocator,
            neo_swift,
            session_id,
            iterator_id,
            hash160_mapper,
        );
    }
};

/// Iterator utilities
pub const IteratorUtils = struct {
    /// Default maximum items per batch
    pub const DEFAULT_MAX_ITEMS_PER_BATCH: u32 = 100;

    /// Default maximum total items
    pub const DEFAULT_MAX_TOTAL_ITEMS: u32 = 1000;

    /// Validates iterator parameters
    pub fn validateIteratorParams(session_id: []const u8, iterator_id: []const u8, count: u32) !void {
        if (session_id.len == 0) {
            return errors.ValidationError.RequiredParameterMissing;
        }

        if (iterator_id.len == 0) {
            return errors.ValidationError.RequiredParameterMissing;
        }

        if (count == 0 or count > 1000) { // Reasonable limits
            return errors.ValidationError.ParameterOutOfRange;
        }
    }

    /// Calculates optimal batch size
    pub fn calculateOptimalBatchSize(estimated_total_items: u32, max_batches: u32) u32 {
        if (max_batches == 0) return DEFAULT_MAX_ITEMS_PER_BATCH;

        const items_per_batch = estimated_total_items / max_batches;
        return @max(1, @min(DEFAULT_MAX_ITEMS_PER_BATCH, items_per_batch));
    }

    /// Creates iterator configuration
    pub fn createIteratorConfig(
        max_items_per_batch: u32,
        max_total_items: u32,
        auto_terminate: bool,
    ) IteratorConfig {
        return IteratorConfig{
            .max_items_per_batch = max_items_per_batch,
            .max_total_items = max_total_items,
            .auto_terminate = auto_terminate,
        };
    }

    /// Validates iterator configuration
    pub fn validateIteratorConfig(config: IteratorConfig) !void {
        if (config.max_items_per_batch == 0 or config.max_items_per_batch > 1000) {
            return errors.ValidationError.ParameterOutOfRange;
        }

        if (config.max_total_items == 0 or config.max_total_items > 100000) {
            return errors.ValidationError.ParameterOutOfRange;
        }
    }
};

/// Iterator configuration
pub const IteratorConfig = struct {
    max_items_per_batch: u32,
    max_total_items: u32,
    auto_terminate: bool,

    /// Default configuration
    pub fn default() IteratorConfig {
        return IteratorConfig{
            .max_items_per_batch = IteratorUtils.DEFAULT_MAX_ITEMS_PER_BATCH,
            .max_total_items = IteratorUtils.DEFAULT_MAX_TOTAL_ITEMS,
            .auto_terminate = true,
        };
    }

    /// Conservative configuration (smaller batches)
    pub fn conservative() IteratorConfig {
        return IteratorConfig{
            .max_items_per_batch = 20,
            .max_total_items = 500,
            .auto_terminate = true,
        };
    }

    /// Aggressive configuration (larger batches)
    pub fn aggressive() IteratorConfig {
        return IteratorConfig{
            .max_items_per_batch = 500,
            .max_total_items = 10000,
            .auto_terminate = false,
        };
    }
};

// Tests (converted from Swift Iterator tests)
test "Iterator creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var neo_swift_dummy: u8 = 0;
    const neo_swift_stub: *anyopaque = @ptrCast(&neo_swift_dummy);

    // Test string iterator creation
    var string_iterator = try IteratorFactory.createStringIterator(
        allocator,
        neo_swift_stub, // neo_swift stub
        "test_session_123",
        "test_iterator_456",
    );
    defer string_iterator.deinit();

    const session_info = string_iterator.getSessionInfo();
    try testing.expectEqualStrings("test_session_123", session_info.session_id);
    try testing.expectEqualStrings("test_iterator_456", session_info.iterator_id);

    // Test session info formatting
    const formatted_info = try session_info.format(allocator);
    defer allocator.free(formatted_info);

    try testing.expect(std.mem.indexOf(u8, formatted_info, "test_session_123") != null);
    try testing.expect(std.mem.indexOf(u8, formatted_info, "test_iterator_456") != null);
}

test "Iterator parameter validation" {
    const testing = std.testing;

    // Test parameter validation
    try IteratorUtils.validateIteratorParams("valid_session", "valid_iterator", 50);

    // Test invalid parameters
    try testing.expectError(errors.ValidationError.RequiredParameterMissing, IteratorUtils.validateIteratorParams("", "valid_iterator", 50));

    try testing.expectError(errors.ValidationError.RequiredParameterMissing, IteratorUtils.validateIteratorParams("valid_session", "", 50));

    try testing.expectError(errors.ValidationError.ParameterOutOfRange, IteratorUtils.validateIteratorParams("valid_session", "valid_iterator", 0));

    try testing.expectError(errors.ValidationError.ParameterOutOfRange, IteratorUtils.validateIteratorParams("valid_session", "valid_iterator", 2000));
}

test "Iterator configuration and utilities" {
    const testing = std.testing;

    // Test iterator configuration
    const default_config = IteratorConfig.default();
    try testing.expectEqual(IteratorUtils.DEFAULT_MAX_ITEMS_PER_BATCH, default_config.max_items_per_batch);
    try testing.expectEqual(IteratorUtils.DEFAULT_MAX_TOTAL_ITEMS, default_config.max_total_items);
    try testing.expect(default_config.auto_terminate);

    const conservative_config = IteratorConfig.conservative();
    try testing.expectEqual(@as(u32, 20), conservative_config.max_items_per_batch);
    try testing.expectEqual(@as(u32, 500), conservative_config.max_total_items);

    const aggressive_config = IteratorConfig.aggressive();
    try testing.expectEqual(@as(u32, 500), aggressive_config.max_items_per_batch);
    try testing.expectEqual(@as(u32, 10000), aggressive_config.max_total_items);
    try testing.expect(!aggressive_config.auto_terminate);

    // Test configuration validation
    try IteratorUtils.validateIteratorConfig(default_config);
    try IteratorUtils.validateIteratorConfig(conservative_config);
    try IteratorUtils.validateIteratorConfig(aggressive_config);

    // Test optimal batch size calculation
    const optimal_batch = IteratorUtils.calculateOptimalBatchSize(1000, 10);
    try testing.expectEqual(@as(u32, 100), optimal_batch);

    const small_batch = IteratorUtils.calculateOptimalBatchSize(50, 10);
    try testing.expectEqual(@as(u32, 5), small_batch);
}

test "Common iterator types" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var neo_swift_dummy: u8 = 0;
    const neo_swift_stub: *anyopaque = @ptrCast(&neo_swift_dummy);

    // Test integer iterator creation
    var integer_iterator = try IteratorFactory.createIntegerIterator(
        allocator,
        neo_swift_stub,
        "int_session",
        "int_iterator",
    );
    defer integer_iterator.deinit();

    const int_session_info = integer_iterator.getSessionInfo();
    try testing.expectEqualStrings("int_session", int_session_info.session_id);

    // Test Hash160 iterator creation
    var hash160_iterator = try IteratorFactory.createHash160Iterator(
        allocator,
        neo_swift_stub,
        "hash_session",
        "hash_iterator",
    );
    defer hash160_iterator.deinit();

    const hash_session_info = hash160_iterator.getSessionInfo();
    try testing.expectEqualStrings("hash_session", hash_session_info.session_id);
}
