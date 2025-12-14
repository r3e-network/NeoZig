//! Serialization test suite
//!
//! Aggregates the serialization-focused tests under `tests/serialization/`.

comptime {
    _ = @import("serialization/binary_reader_tests.zig");
    _ = @import("serialization/binary_writer_tests.zig");
    _ = @import("serialization/var_size_tests.zig");
}
