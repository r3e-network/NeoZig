const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library compilation check
    const lib_check = b.addExecutable(.{
        .name = "neo-zig-check",
        .root_source_file = b.path("final_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    b.installArtifact(lib_check);

    // Default step builds the demo
    const install_demo = b.addInstallArtifact(lib_check, .{});
    b.getInstallStep().dependOn(&install_demo.step);
    
    // Examples step
    const examples_step = b.step("examples", "Build and run examples");
    const run_demo = b.addRunArtifact(lib_check);
    examples_step.dependOn(&run_demo.step);
}