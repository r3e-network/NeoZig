//! Protocol test suite
//!
//! Aggregates protocol-level tests that validate internal protocol helpers.

comptime {
    _ = @import("protocol/contract_manifest_tests.zig");
    _ = @import("protocol/http_service_tests.zig");
    _ = @import("protocol/json_rpc_2_0_rx_tests.zig");
    _ = @import("protocol/request_tests.zig");
    _ = @import("protocol/response_tests.zig");
    _ = @import("protocol/stack_item_tests.zig");
}

test "protocol test suite" {}
