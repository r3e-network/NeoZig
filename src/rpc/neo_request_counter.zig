const std = @import("std");

/// Request counter for RPC calls
pub const Counter = struct {
    value: std.atomic.Value(u32),

    const Self = @This();

    pub fn init() Self {
        return Self{
            .value = std.atomic.Value(u32).init(0),
        };
    }

    pub fn next(self: *Self) u32 {
        return self.value.fetchAdd(1, .seq_cst);
    }

    pub fn get(self: *Self) u32 {
        return self.value.load(.seq_cst);
    }

    pub fn reset(self: *Self) void {
        self.value.store(0, .seq_cst);
    }
};
