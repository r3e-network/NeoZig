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

    // Demo executable used as a minimal smoke-test during the build.
    const demo = b.addExecutable(.{
        .name = "neo-zig-demo",
        .root_source_file = b.path("final_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    demo.root_module.addImport("neo-zig", sdk_module);

    b.installArtifact(demo);

    const run_demo = b.addRunArtifact(demo);
    const demo_step = b.step("demo", "Run core demo");
    demo_step.dependOn(&run_demo.step);

    const examples_exe = b.addExecutable(.{
        .name = "neo-zig-examples",
        .root_source_file = b.path("examples/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    examples_exe.root_module.addImport("neo-zig", sdk_module);

    const run_examples = b.addRunArtifact(examples_exe);
    const examples_step = b.step("examples", "Build and run examples");
    examples_step.dependOn(&run_examples.step);

    const complete_demo_exe = b.addExecutable(.{
        .name = "neo-zig-complete-demo",
        .root_source_file = b.path("examples/complete_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    complete_demo_exe.root_module.addImport("neo-zig", sdk_module);

    const run_complete_demo = b.addRunArtifact(complete_demo_exe);
    const complete_demo_step = b.step("complete-demo", "Run complete SDK demo");
    complete_demo_step.dependOn(&run_complete_demo.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/neo.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run all Neo Zig SDK tests");
    test_step.dependOn(&run_unit_tests.step);

    // Swift parity/regression suites live under `tests/` and are not part of the
    // primary module. Wire them into the build so `zig build test` runs both.
    const parity_tests = b.addTest(.{
        .name = "parity",
        .root_source_file = b.path("tests/all_swift_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    parity_tests.root_module.addImport("neo-zig", sdk_module);
    const run_parity_tests = b.addRunArtifact(parity_tests);
    test_step.dependOn(&run_parity_tests.step);

    const parity_step = b.step("parity-test", "Run Swift parity test suite");
    parity_step.dependOn(&run_parity_tests.step);

    const rpc_tests = b.addTest(.{
        .name = "rpc-tests",
        .root_source_file = b.path("tests/rpc_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    rpc_tests.root_module.addImport("neo-zig", sdk_module);
    const run_rpc_tests = b.addRunArtifact(rpc_tests);
    test_step.dependOn(&run_rpc_tests.step);

    const rpc_step = b.step("rpc-test", "Run RPC request tests");
    rpc_step.dependOn(&run_rpc_tests.step);

    const integration_tests = b.addTest(.{
        .name = "integration",
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_tests.root_module.addImport("neo-zig", sdk_module);
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_step.dependOn(&run_integration_tests.step);

    const integration_step = b.step("integration-test", "Run integration test suite");
    integration_step.dependOn(&run_integration_tests.step);

    const crypto_tests = b.addTest(.{
        .name = "crypto-tests",
        .root_source_file = b.path("tests/crypto_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_tests.root_module.addImport("neo-zig", sdk_module);
    const run_crypto_tests = b.addRunArtifact(crypto_tests);
    test_step.dependOn(&run_crypto_tests.step);

    const crypto_step = b.step("crypto-test", "Run crypto test suite");
    crypto_step.dependOn(&run_crypto_tests.step);

    const contract_tests = b.addTest(.{
        .name = "contract-tests",
        .root_source_file = b.path("tests/contract_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    contract_tests.root_module.addImport("neo-zig", sdk_module);
    const run_contract_tests = b.addRunArtifact(contract_tests);
    test_step.dependOn(&run_contract_tests.step);

    const contract_step = b.step("contract-test", "Run contract test suite");
    contract_step.dependOn(&run_contract_tests.step);

    const transaction_tests = b.addTest(.{
        .name = "transaction-tests",
        .root_source_file = b.path("tests/transaction_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    transaction_tests.root_module.addImport("neo-zig", sdk_module);
    const run_transaction_tests = b.addRunArtifact(transaction_tests);
    test_step.dependOn(&run_transaction_tests.step);

    const transaction_step = b.step("transaction-test", "Run transaction test suite");
    transaction_step.dependOn(&run_transaction_tests.step);

    const wallet_tests = b.addTest(.{
        .name = "wallet-tests",
        .root_source_file = b.path("tests/wallet_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    wallet_tests.root_module.addImport("neo-zig", sdk_module);
    const run_wallet_tests = b.addRunArtifact(wallet_tests);
    test_step.dependOn(&run_wallet_tests.step);

    const wallet_step = b.step("wallet-test", "Run wallet test suite");
    wallet_step.dependOn(&run_wallet_tests.step);

    const protocol_tests = b.addTest(.{
        .name = "protocol-tests",
        .root_source_file = b.path("tests/protocol_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    protocol_tests.root_module.addImport("neo-zig", sdk_module);
    const run_protocol_tests = b.addRunArtifact(protocol_tests);
    test_step.dependOn(&run_protocol_tests.step);

    const protocol_step = b.step("protocol-test", "Run protocol test suite");
    protocol_step.dependOn(&run_protocol_tests.step);

    const serialization_tests = b.addTest(.{
        .name = "serialization-tests",
        .root_source_file = b.path("tests/serialization_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    serialization_tests.root_module.addImport("neo-zig", sdk_module);
    const run_serialization_tests = b.addRunArtifact(serialization_tests);
    test_step.dependOn(&run_serialization_tests.step);

    const serialization_step = b.step("serialization-test", "Run serialization test suite");
    serialization_step.dependOn(&run_serialization_tests.step);

    const script_tests = b.addTest(.{
        .name = "script-tests",
        .root_source_file = b.path("tests/script_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    script_tests.root_module.addImport("neo-zig", sdk_module);
    const run_script_tests = b.addRunArtifact(script_tests);
    test_step.dependOn(&run_script_tests.step);

    const script_step = b.step("script-test", "Run script test suite");
    script_step.dependOn(&run_script_tests.step);

    const types_tests = b.addTest(.{
        .name = "types-tests",
        .root_source_file = b.path("tests/types_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    types_tests.root_module.addImport("neo-zig", sdk_module);
    const run_types_tests = b.addRunArtifact(types_tests);
    test_step.dependOn(&run_types_tests.step);

    const types_step = b.step("types-test", "Run types test suite");
    types_step.dependOn(&run_types_tests.step);

    const witnessrule_tests = b.addTest(.{
        .name = "witnessrule-tests",
        .root_source_file = b.path("tests/witnessrule_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    witnessrule_tests.root_module.addImport("neo-zig", sdk_module);
    const run_witnessrule_tests = b.addRunArtifact(witnessrule_tests);
    test_step.dependOn(&run_witnessrule_tests.step);

    const witnessrule_step = b.step("witnessrule-test", "Run witness rule test suite");
    witnessrule_step.dependOn(&run_witnessrule_tests.step);

    const docs_object = b.addObject(.{
        .name = "neo-zig-docs",
        .root_source_file = b.path("src/neo.zig"),
        .target = target,
        .optimize = optimize,
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_object.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate API documentation");
    docs_step.dependOn(&install_docs.step);

    const bench_exe = b.addExecutable(.{
        .name = "neo-zig-bench",
        .root_source_file = b.path("benchmarks/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_exe.root_module.addImport("neo-zig", sdk_module);
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run SDK benchmarks");
    bench_step.dependOn(&run_bench.step);
}
