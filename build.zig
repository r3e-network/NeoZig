const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Just try to compile the main module to validate syntax
    _ = target;
    _ = optimize;
    _ = b;
}