const std = @import("std");

fn addSuiteTestStep(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    sdk_module: *std.Build.Module,
    artifact_name: []const u8,
    step_name: []const u8,
    description: []const u8,
    root_source: []const u8,
) void {
    const suite_tests = b.addTest(.{
        .name = artifact_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(root_source),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "neo-zig", .module = sdk_module }},
        }),
    });

    const run_suite_tests = b.addRunArtifact(suite_tests);
    const suite_step = b.step(step_name, description);
    suite_step.dependOn(&run_suite_tests.step);
}

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

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "integration-tests",
        "integration-test",
        "Run integration tests",
        "tests/integration.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "parity-tests",
        "parity-test",
        "Run Swift parity tests",
        "tests/all_swift_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "rpc-tests",
        "rpc-test",
        "Run RPC tests",
        "tests/rpc_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "crypto-tests",
        "crypto-test",
        "Run crypto tests",
        "tests/crypto_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "contract-tests",
        "contract-test",
        "Run contract tests",
        "tests/contract_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "transaction-tests",
        "transaction-test",
        "Run transaction tests",
        "tests/transaction_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "wallet-tests",
        "wallet-test",
        "Run wallet tests",
        "tests/wallet_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "protocol-tests",
        "protocol-test",
        "Run protocol tests",
        "tests/protocol_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "serialization-tests",
        "serialization-test",
        "Run serialization tests",
        "tests/serialization_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "script-tests",
        "script-test",
        "Run script tests",
        "tests/script_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "types-tests",
        "types-test",
        "Run types tests",
        "tests/types_tests.zig",
    );

    addSuiteTestStep(
        b,
        target,
        optimize,
        sdk_module,
        "witnessrule-tests",
        "witnessrule-test",
        "Run witness rule tests",
        "tests/witnessrule_tests.zig",
    );
}
