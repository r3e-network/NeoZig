const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module
    const neo_zig = b.addModule("neo-zig", .{
        .root_source_file = b.path("src/neo.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Static library
    const lib = b.addStaticLibrary(.{
        .name = "neo-zig",
        .root_source_file = b.path("src/neo.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // Examples
    const examples_step = b.step("examples", "Build and run examples");
    const example = b.addExecutable(.{
        .name = "neo-zig-example",
        .root_source_file = b.path("examples/complete_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    example.root_module.addImport("neo-zig", neo_zig);
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    examples_step.dependOn(&run_example.step);

    // Tests
    const tests = b.addTest(.{
        .name = "neo-zig-tests",
        .root_source_file = b.path("src/neo.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    const crypto_tests = b.addTest(.{
        .name = "crypto-tests",
        .root_source_file = b.path("tests/crypto_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_tests.root_module.addImport("neo-zig", neo_zig);
    
    const transaction_tests = b.addTest(.{
        .name = "transaction-tests",
        .root_source_file = b.path("tests/transaction_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    transaction_tests.root_module.addImport("neo-zig", neo_zig);
    
    const wallet_tests = b.addTest(.{
        .name = "wallet-tests",
        .root_source_file = b.path("tests/wallet_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    wallet_tests.root_module.addImport("neo-zig", neo_zig);
    
    const rpc_tests = b.addTest(.{
        .name = "rpc-tests",
        .root_source_file = b.path("tests/rpc_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    rpc_tests.root_module.addImport("neo-zig", neo_zig);
    
    const contract_tests = b.addTest(.{
        .name = "contract-tests",
        .root_source_file = b.path("tests/contract_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    contract_tests.root_module.addImport("neo-zig", neo_zig);
    
    const complete_test_suite = b.addTest(.{
        .name = "complete-test-suite",
        .root_source_file = b.path("tests/complete_test_suite.zig"),
        .target = target,
        .optimize = optimize,
    });
    complete_test_suite.root_module.addImport("neo-zig", neo_zig);
    
    const advanced_test_suite = b.addTest(.{
        .name = "advanced-test-suite",
        .root_source_file = b.path("tests/advanced_test_suite.zig"),
        .target = target,
        .optimize = optimize,
    });
    advanced_test_suite.root_module.addImport("neo-zig", neo_zig);
    
    const all_swift_tests = b.addTest(.{
        .name = "all-swift-tests",
        .root_source_file = b.path("tests/all_swift_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    all_swift_tests.root_module.addImport("neo-zig", neo_zig);

    const run_tests = b.addRunArtifact(tests);
    const run_crypto_tests = b.addRunArtifact(crypto_tests);
    const run_transaction_tests = b.addRunArtifact(transaction_tests);
    const run_wallet_tests = b.addRunArtifact(wallet_tests);
    const run_rpc_tests = b.addRunArtifact(rpc_tests);
    const run_contract_tests = b.addRunArtifact(contract_tests);
    const run_complete_suite = b.addRunArtifact(complete_test_suite);
    const run_advanced_suite = b.addRunArtifact(advanced_test_suite);
    const run_all_swift_tests = b.addRunArtifact(all_swift_tests);
    
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_crypto_tests.step);
    test_step.dependOn(&run_transaction_tests.step);
    test_step.dependOn(&run_wallet_tests.step);
    test_step.dependOn(&run_rpc_tests.step);
    test_step.dependOn(&run_contract_tests.step);
    test_step.dependOn(&run_complete_suite.step);
    test_step.dependOn(&run_advanced_suite.step);
    test_step.dependOn(&run_all_swift_tests.step);

    // Benchmarks
    const benchmark = b.addExecutable(.{
        .name = "neo-zig-bench",
        .root_source_file = b.path("benchmarks/main.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    benchmark.root_module.addImport("neo-zig", neo_zig);
    
    const run_benchmark = b.addRunArtifact(benchmark);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_benchmark.step);

    // Documentation
    const docs = b.addTest(.{
        .name = "docs",
        .root_source_file = b.path("src/neo.zig"),
        .target = target,
        .optimize = optimize,
    });
    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&b.addInstallDirectory(.{
        .source_dir = docs.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    }).step);
}