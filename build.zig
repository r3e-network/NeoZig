const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Primary module representing the SDK entry point.
    const sdk_module = b.addModule("neo-zig", .{
        .root_source_file = b.path("src/neo.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Optional underscore alias for consumers that prefer identifier-friendly names.
    _ = b.addModule("neo_zig", .{
        .root_source_file = b.path("src/neo.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Demo executable
    const demo = b.addExecutable(.{
        .name = "neo-zig-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("final_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "neo-zig", .module = sdk_module }},
        }),
    });
    b.installArtifact(demo);

    const run_demo = b.addRunArtifact(demo);
    const demo_step = b.step("demo", "Run core demo");
    demo_step.dependOn(&run_demo.step);

    // Examples executable
    const examples_exe = b.addExecutable(.{
        .name = "neo-zig-examples",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "neo-zig", .module = sdk_module }},
        }),
    });

    const run_examples = b.addRunArtifact(examples_exe);
    const examples_step = b.step("examples", "Build and run examples");
    examples_step.dependOn(&run_examples.step);

    // Complete demo executable
    const complete_demo_exe = b.addExecutable(.{
        .name = "neo-zig-complete-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/complete_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "neo-zig", .module = sdk_module }},
        }),
    });

    const run_complete_demo = b.addRunArtifact(complete_demo_exe);
    const complete_demo_step = b.step("complete-demo", "Run complete SDK demo");
    complete_demo_step.dependOn(&run_complete_demo.step);

    // Unit tests
    const unit_tests = b.addTest(.{
        .name = "neo-zig-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/neo.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Integration tests
    const integration_tests = b.addTest(.{
        .name = "integration-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "neo-zig", .module = sdk_module }},
        }),
    });

    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_test_step = b.step("integration-test", "Run integration tests");
    integration_test_step.dependOn(&run_integration_tests.step);
}
