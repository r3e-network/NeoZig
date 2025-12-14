//! Binary serialization framework
//!
//! Complete conversion from Swift serialization system.

const std = @import("std");

pub const BinaryWriter = @import("binary_writer.zig").BinaryWriter;
pub const BinaryReader = @import("binary_reader.zig").BinaryReader;
pub const CompleteBinaryWriter = @import("binary_writer_complete.zig").CompleteBinaryWriter;
pub const CompleteBinaryReader = @import("binary_reader_complete.zig").CompleteBinaryReader;
pub const VarSizeUtils = @import("neo_serializable.zig").VarSizeUtils;
pub const SerializationUtils = @import("neo_serializable.zig").SerializationUtils;

test "serialization module" {
    std.testing.refAllDecls(@This());
}
