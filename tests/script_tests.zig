//! Script test suite
//!
//! Aggregates the script-focused tests under `tests/script/`.

comptime {
    _ = @import("script/script_builder_tests.zig");
    _ = @import("script/script_reader_tests.zig");
    _ = @import("script/verification_script_tests.zig");
    _ = @import("script/invocation_script_tests.zig");
}
