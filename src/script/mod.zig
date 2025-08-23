//! Script module
//!
//! Complete Neo VM script system converted from Swift.

const std = @import("std");

// Export script components
pub const ScriptBuilder = @import("script_builder.zig").ScriptBuilder;
pub const OpCode = @import("op_code.zig").OpCode;
pub const InteropService = @import("script_builder.zig").InteropService;

test "script module" {
    std.testing.refAllDecls(@This());
}