//! Types test suite
//!
//! Aggregates the type-focused tests under `tests/types/`.

comptime {
    _ = @import("types/enum_type_tests.zig");
    _ = @import("types/hash160_tests.zig");
    _ = @import("types/hash256_tests.zig");
    _ = @import("types/contract_parameter_tests.zig");
}
