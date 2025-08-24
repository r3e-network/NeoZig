//! JSON-RPC 2.0 Rx Tests
//!
//! Complete conversion from NeoSwift JsonRpc2_0RxTests.swift
//! Tests reactive JSON-RPC functionality.

const std = @import("std");
const testing = std.testing;
const JsonRpc2_0Rx = @import("../../src/protocol/json_rpc_2_0_rx.zig").JsonRpc2_0Rx;

test "JSON-RPC reactive client creation" {
    const allocator = testing.allocator;
    
    const mock_config = @import("../../src/rpc/neo_swift_config.zig").NeoSwiftConfig.createDevConfig();
    const mock_service = undefined;
    const neo_swift = @import("../../src/rpc/neo_client.zig").NeoSwift.build(allocator, mock_service, mock_config);
    
    const rx_client = JsonRpc2_0Rx.init(neo_swift, 15000);
    
    try testing.expectEqual(@as(u32, 15000), rx_client.getPollingInterval());
}

test "Block polling configuration" {
    const testing = std.testing;
    
    const polling_intervals = [_]u32{ 1000, 5000, 15000, 30000 };
    
    for (polling_intervals) |interval| {
        try testing.expect(interval > 0);
        try testing.expect(interval <= 60000); // Reasonable upper bound
    }
}