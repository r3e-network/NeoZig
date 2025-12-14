//! Interop Service implementation
//!
//! Complete conversion from NeoSwift InteropService.swift
//! Provides system call definitions and pricing for Neo VM operations.

const std = @import("std");

/// System call interop services for Neo VM (converted from Swift InteropService)
pub const InteropService = enum {
    SystemCryptoCheckSig,
    SystemCryptoCheckMultisig,
    SystemContractCall,
    SystemContractCallNative,
    SystemContractGetCallFlags,
    SystemContractCreateStandardAccount,
    SystemContractCreateMultiSigAccount,
    SystemContractNativeOnPersist,
    SystemContractNativePostPersist,
    SystemIteratorNext,
    SystemIteratorValue,
    SystemRuntimePlatform,
    SystemRuntimeGetTrigger,
    SystemRuntimeGetTime,
    SystemRuntimeGetScriptContainer,
    SystemRuntimeGetExecutingScriptHash,
    SystemRuntimeGetCallingScriptHash,
    SystemRuntimeGetEntryScriptHash,
    SystemRuntimeCheckWitness,
    SystemRuntimeGetInvocationCounter,
    SystemRuntimeLog,
    SystemRuntimeNotify,
    SystemRuntimeGetNotifications,
    SystemRuntimeGasLeft,
    SystemRuntimeBurnGas,
    SystemRuntimeGetNetwork,
    SystemRuntimeGetRandom,
    SystemStorageGetContext,
    SystemStorageGetReadOnlyContext,
    SystemStorageAsReadOnly,
    SystemStorageGet,
    SystemStorageFind,
    SystemStoragePut,
    SystemStorageDelete,

    /// Gets the string representation (equivalent to Swift rawValue)
    pub fn toString(self: InteropService) []const u8 {
        return switch (self) {
            .SystemCryptoCheckSig => "System.Crypto.CheckSig",
            .SystemCryptoCheckMultisig => "System.Crypto.CheckMultisig",
            .SystemContractCall => "System.Contract.Call",
            .SystemContractCallNative => "System.Contract.CallNative",
            .SystemContractGetCallFlags => "System.Contract.GetCallFlags",
            .SystemContractCreateStandardAccount => "System.Contract.CreateStandardAccount",
            .SystemContractCreateMultiSigAccount => "System.Contract.CreateMultisigAccount",
            .SystemContractNativeOnPersist => "System.Contract.NativeOnPersist",
            .SystemContractNativePostPersist => "System.Contract.NativePostPersist",
            .SystemIteratorNext => "System.Iterator.Next",
            .SystemIteratorValue => "System.Iterator.Value",
            .SystemRuntimePlatform => "System.Runtime.Platform",
            .SystemRuntimeGetTrigger => "System.Runtime.GetTrigger",
            .SystemRuntimeGetTime => "System.Runtime.GetTime",
            .SystemRuntimeGetScriptContainer => "System.Runtime.GetScriptContainer",
            .SystemRuntimeGetExecutingScriptHash => "System.Runtime.GetExecutingScriptHash",
            .SystemRuntimeGetCallingScriptHash => "System.Runtime.GetCallingScriptHash",
            .SystemRuntimeGetEntryScriptHash => "System.Runtime.GetEntryScriptHash",
            .SystemRuntimeCheckWitness => "System.Runtime.CheckWitness",
            .SystemRuntimeGetInvocationCounter => "System.Runtime.GetInvocationCounter",
            .SystemRuntimeLog => "System.Runtime.Log",
            .SystemRuntimeNotify => "System.Runtime.Notify",
            .SystemRuntimeGetNotifications => "System.Runtime.GetNotifications",
            .SystemRuntimeGasLeft => "System.Runtime.GasLeft",
            .SystemRuntimeBurnGas => "System.Runtime.BurnGas",
            .SystemRuntimeGetNetwork => "System.Runtime.GetNetwork",
            .SystemRuntimeGetRandom => "System.Runtime.GetRandom",
            .SystemStorageGetContext => "System.Storage.GetContext",
            .SystemStorageGetReadOnlyContext => "System.Storage.GetReadOnlyContext",
            .SystemStorageAsReadOnly => "System.Storage.AsReadOnly",
            .SystemStorageGet => "System.Storage.Get",
            .SystemStorageFind => "System.Storage.Find",
            .SystemStoragePut => "System.Storage.Put",
            .SystemStorageDelete => "System.Storage.Delete",
        };
    }

    /// Gets the hash for the interop service (equivalent to Swift hash property)
    pub fn getHash(self: InteropService, allocator: std.mem.Allocator) ![]u8 {
        const string_value = self.toString();
        var hash_full: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(string_value, &hash_full, .{});

        // Take first 4 bytes and convert to hex string
        const prefix = hash_full[0..4];
        return try @import("../utils/bytes_extensions.zig").BytesUtils.toHexString(prefix, allocator);
    }

    /// Gets the gas price for the interop service (equivalent to Swift price property)
    pub fn getPrice(self: InteropService) u32 {
        return switch (self) {
            .SystemRuntimePlatform, .SystemRuntimeGetTrigger, .SystemRuntimeGetTime, .SystemRuntimeGetScriptContainer, .SystemRuntimeGetNetwork => 1 << 3, // 8 gas

            .SystemIteratorValue, .SystemRuntimeGetExecutingScriptHash, .SystemRuntimeGetCallingScriptHash, .SystemRuntimeGetEntryScriptHash, .SystemRuntimeGetInvocationCounter, .SystemRuntimeGasLeft, .SystemRuntimeBurnGas, .SystemRuntimeGetRandom, .SystemStorageGetContext, .SystemStorageGetReadOnlyContext, .SystemStorageAsReadOnly => 1 << 4, // 16 gas

            .SystemContractGetCallFlags, .SystemRuntimeCheckWitness => 1 << 10, // 1024 gas

            .SystemRuntimeGetNotifications => 1 << 12, // 4096 gas

            .SystemCryptoCheckSig, .SystemContractCall, .SystemContractCreateStandardAccount, .SystemIteratorNext, .SystemRuntimeLog, .SystemRuntimeNotify, .SystemStorageGet, .SystemStorageFind, .SystemStoragePut, .SystemStorageDelete => 1 << 15, // 32768 gas

            else => 0, // Default price for unlisted services
        };
    }

    /// Creates an interop service from string (equivalent to Swift init from rawValue)
    pub fn fromString(string_value: []const u8) ?InteropService {
        const services = [_]InteropService{
            .SystemCryptoCheckSig,
            .SystemCryptoCheckMultisig,
            .SystemContractCall,
            .SystemContractCallNative,
            .SystemContractGetCallFlags,
            .SystemContractCreateStandardAccount,
            .SystemContractCreateMultiSigAccount,
            .SystemContractNativeOnPersist,
            .SystemContractNativePostPersist,
            .SystemIteratorNext,
            .SystemIteratorValue,
            .SystemRuntimePlatform,
            .SystemRuntimeGetTrigger,
            .SystemRuntimeGetTime,
            .SystemRuntimeGetScriptContainer,
            .SystemRuntimeGetExecutingScriptHash,
            .SystemRuntimeGetCallingScriptHash,
            .SystemRuntimeGetEntryScriptHash,
            .SystemRuntimeCheckWitness,
            .SystemRuntimeGetInvocationCounter,
            .SystemRuntimeLog,
            .SystemRuntimeNotify,
            .SystemRuntimeGetNotifications,
            .SystemRuntimeGasLeft,
            .SystemRuntimeBurnGas,
            .SystemRuntimeGetNetwork,
            .SystemRuntimeGetRandom,
            .SystemStorageGetContext,
            .SystemStorageGetReadOnlyContext,
            .SystemStorageAsReadOnly,
            .SystemStorageGet,
            .SystemStorageFind,
            .SystemStoragePut,
            .SystemStorageDelete,
        };

        for (services) |service| {
            if (std.mem.eql(u8, service.toString(), string_value)) {
                return service;
            }
        }

        return null;
    }

    /// Gets all available interop services
    pub fn getAllServices() []const InteropService {
        const services = [_]InteropService{
            .SystemCryptoCheckSig,
            .SystemCryptoCheckMultisig,
            .SystemContractCall,
            .SystemContractCallNative,
            .SystemContractGetCallFlags,
            .SystemContractCreateStandardAccount,
            .SystemContractCreateMultiSigAccount,
            .SystemContractNativeOnPersist,
            .SystemContractNativePostPersist,
            .SystemIteratorNext,
            .SystemIteratorValue,
            .SystemRuntimePlatform,
            .SystemRuntimeGetTrigger,
            .SystemRuntimeGetTime,
            .SystemRuntimeGetScriptContainer,
            .SystemRuntimeGetExecutingScriptHash,
            .SystemRuntimeGetCallingScriptHash,
            .SystemRuntimeGetEntryScriptHash,
            .SystemRuntimeCheckWitness,
            .SystemRuntimeGetInvocationCounter,
            .SystemRuntimeLog,
            .SystemRuntimeNotify,
            .SystemRuntimeGetNotifications,
            .SystemRuntimeGasLeft,
            .SystemRuntimeBurnGas,
            .SystemRuntimeGetNetwork,
            .SystemRuntimeGetRandom,
            .SystemStorageGetContext,
            .SystemStorageGetReadOnlyContext,
            .SystemStorageAsReadOnly,
            .SystemStorageGet,
            .SystemStorageFind,
            .SystemStoragePut,
            .SystemStorageDelete,
        };

        return &services;
    }
};

// Tests (converted from Swift InteropService tests)
test "InteropService string conversion" {
    const testing = std.testing;

    // Test toString (equivalent to Swift rawValue)
    const contract_call = InteropService.SystemContractCall;
    const contract_call_string = contract_call.toString();
    try testing.expectEqualStrings("System.Contract.Call", contract_call_string);

    const check_sig = InteropService.SystemCryptoCheckSig;
    const check_sig_string = check_sig.toString();
    try testing.expectEqualStrings("System.Crypto.CheckSig", check_sig_string);
}

test "InteropService fromString creation" {
    const testing = std.testing;

    // Test fromString (equivalent to Swift init from rawValue)
    const contract_call = InteropService.fromString("System.Contract.Call");
    try testing.expect(contract_call != null);
    try testing.expectEqual(InteropService.SystemContractCall, contract_call.?);

    const check_sig = InteropService.fromString("System.Crypto.CheckSig");
    try testing.expect(check_sig != null);
    try testing.expectEqual(InteropService.SystemCryptoCheckSig, check_sig.?);

    // Test invalid service
    const invalid = InteropService.fromString("System.Invalid.Service");
    try testing.expect(invalid == null);
}

test "InteropService gas pricing" {
    const testing = std.testing;

    // Test gas pricing (equivalent to Swift price property)
    const platform_price = InteropService.SystemRuntimePlatform.getPrice();
    try testing.expectEqual(@as(u32, 8), platform_price); // 1 << 3

    const check_sig_price = InteropService.SystemCryptoCheckSig.getPrice();
    try testing.expectEqual(@as(u32, 32768), check_sig_price); // 1 << 15

    const check_witness_price = InteropService.SystemRuntimeCheckWitness.getPrice();
    try testing.expectEqual(@as(u32, 1024), check_witness_price); // 1 << 10
}

test "InteropService hash generation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test hash generation (equivalent to Swift hash property)
    const contract_call = InteropService.SystemContractCall;
    const hash = try contract_call.getHash(allocator);
    defer allocator.free(hash);

    try testing.expect(hash.len == 8); // 4 bytes as hex string

    const check_sig = InteropService.SystemCryptoCheckSig;
    const check_sig_hash = try check_sig.getHash(allocator);
    defer allocator.free(check_sig_hash);

    try testing.expect(check_sig_hash.len == 8); // 4 bytes as hex string
    try testing.expect(!std.mem.eql(u8, hash, check_sig_hash)); // Different services have different hashes
}

test "InteropService getAllServices" {
    const testing = std.testing;

    // Test getting all services
    const all_services = InteropService.getAllServices();
    try testing.expect(all_services.len > 30); // Should have all 34+ services

    // Verify known services are present
    var found_contract_call = false;
    var found_check_sig = false;

    for (all_services) |service| {
        if (service == .SystemContractCall) found_contract_call = true;
        if (service == .SystemCryptoCheckSig) found_check_sig = true;
    }

    try testing.expect(found_contract_call);
    try testing.expect(found_check_sig);
}
