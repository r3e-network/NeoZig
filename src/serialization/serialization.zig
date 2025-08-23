//! Binary serialization framework
//!
//! Complete conversion from Swift serialization system.

const std = @import("std");

pub const BinaryWriter = @import("binary_writer.zig").BinaryWriter;
pub const BinaryReader = @import("binary_reader.zig").BinaryReader;

test "serialization module" {
    std.testing.refAllDecls(@This());
}