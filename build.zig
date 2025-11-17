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

    // Demo executable used as a minimal smoke-test during the build.
    const demo_module = b.createModule(.{
        .root_source_file = b.path("final_demo.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{
            .name = "neo-zig",
            .module = sdk_module,
        }},
    });

    const demo = b.addExecutable(.{
        .name = "neo-zig-demo",
        .root_module = demo_module,
    });

    b.installArtifact(demo);

    const run_demo = b.addRunArtifact(demo);
    const examples_step = b.step("examples", "Build and run examples");
    examples_step.dependOn(&run_demo.step);

    const unit_tests = b.addTest(.{
        .root_module = sdk_module,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run all Neo Zig SDK tests");
    test_step.dependOn(&run_unit_tests.step);

    const docs_object = b.addObject(.{
        .name = "neo-zig-docs",
        .root_module = sdk_module,
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_object.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate API documentation");
    docs_step.dependOn(&install_docs.step);

    const bench_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{
            .name = "neo-zig",
            .module = sdk_module,
        }},
    });

    const bench_exe = b.addExecutable(.{
        .name = "neo-zig-bench",
        .root_module = bench_module,
    });
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run SDK benchmarks");
    bench_step.dependOn(&run_bench.step);
}
