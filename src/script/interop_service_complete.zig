//! Complete Interop Service implementation
//!
//! Complete conversion from NeoSwift InteropService.swift
//! Provides all Neo VM interop services with pricing and hash information.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;

/// Complete interop service enumeration (converted from Swift InteropService)
pub const CompleteInteropService = enum {
    // Crypto services
    SystemCryptoCheckSig,
    SystemCryptoCheckMultisig,
    
    // Contract services
    SystemContractCall,
    SystemContractCallNative,
    SystemContractGetCallFlags,
    SystemContractCreateStandardAccount,
    SystemContractCreateMultiSigAccount,
    SystemContractNativeOnPersist,
    SystemContractNativePostPersist,
    
    // Iterator services
    SystemIteratorNext,
    SystemIteratorValue,
    
    // Runtime services
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
    
    // Storage services
    SystemStorageGetContext,
    SystemStorageGetReadOnlyContext,
    SystemStorageAsReadOnly,
    SystemStorageGet,
    SystemStorageFind,
    SystemStoragePut,
    SystemStorageDelete,
    
    const Self = @This();
    
    /// Gets service name (equivalent to Swift .rawValue property)
    pub fn getRawValue(self: Self) []const u8 {
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
    
    /// Gets service hash (equivalent to Swift .hash property)
    pub fn getHash(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const raw_value = self.getRawValue();
        const hash = Hash256.sha256(raw_value);
        const prefix = hash.toSlice()[0..4];
        
        return try @import("../utils/bytes_extensions.zig").BytesUtils.toHexString(prefix, allocator);
    }
    
    /// Gets service hash as integer
    pub fn getHashAsInt(self: Self) u32 {
        const raw_value = self.getRawValue();
        const hash = Hash256.sha256(raw_value);
        const prefix = hash.toSlice()[0..4];
        
        return std.mem.littleToNative(u32, std.mem.bytesToValue(u32, prefix[0..4]));
    }
    
    /// Gets service execution price (equivalent to Swift .price property)
    pub fn getPrice(self: Self) u32 {
        return switch (self) {
            // Low cost services (1 << 3 = 8)
            .SystemRuntimePlatform,
            .SystemRuntimeGetTrigger,
            .SystemRuntimeGetTime,
            .SystemRuntimeGetScriptContainer,
            .SystemRuntimeGetNetwork => 8,
            
            // Medium cost services (1 << 4 = 16)
            .SystemIteratorValue,
            .SystemRuntimeGetExecutingScriptHash,
            .SystemRuntimeGetCallingScriptHash,
            .SystemRuntimeGetEntryScriptHash,
            .SystemRuntimeGetInvocationCounter,
            .SystemRuntimeGasLeft => 16,
            
            // Higher cost services (1 << 5 = 32)
            .SystemRuntimeCheckWitness,
            .SystemRuntimeLog,
            .SystemRuntimeNotify,
            .SystemRuntimeGetNotifications,
            .SystemRuntimeBurnGas,
            .SystemRuntimeGetRandom => 32,
            
            // Storage services (1 << 6 = 64)
            .SystemStorageGetContext,
            .SystemStorageGetReadOnlyContext,
            .SystemStorageAsReadOnly,
            .SystemStorageGet => 64,
            
            // Expensive storage services (1 << 8 = 256)
            .SystemStorageFind,
            .SystemStoragePut,
            .SystemStorageDelete => 256,
            
            // Crypto services (1 << 10 = 1024)
            .SystemCryptoCheckSig => 1024,
            .SystemCryptoCheckMultisig => 4096, // 1 << 12
            
            // Contract services (1 << 12 = 4096)
            .SystemContractCall,
            .SystemContractCallNative => 4096,
            
            // Expensive contract services (1 << 15 = 32768)
            .SystemContractGetCallFlags,
            .SystemContractCreateStandardAccount,
            .SystemContractCreateMultiSigAccount,
            .SystemContractNativeOnPersist,
            .SystemContractNativePostPersist => 32768,
            
            // Iterator services (1 << 4 = 16)
            .SystemIteratorNext => 16,
        };
    }
    
    /// Gets all interop services (equivalent to Swift allCases)
    pub fn getAllCases() []const Self {
        return &[_]Self{
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
    }
    
    /// Creates from raw value string
    pub fn fromRawValue(raw_value: []const u8) ?Self {
        const all_cases = getAllCases();
        for (all_cases) |service| {
            if (std.mem.eql(u8, service.getRawValue(), raw_value)) {
                return service;
            }
        }
        return null;
    }
    
    /// Creates from hash string
    pub fn fromHash(hash_string: []const u8, allocator: std.mem.Allocator) ?Self {
        const all_cases = getAllCases();
        for (all_cases) |service| {
            const service_hash = service.getHash(allocator) catch continue;
            defer allocator.free(service_hash);
            
            if (std.mem.eql(u8, service_hash, hash_string)) {
                return service;
            }
        }
        return null;
    }
    
    /// Creates from hash integer
    pub fn fromHashInt(hash_int: u32) ?Self {
        const all_cases = getAllCases();
        for (all_cases) |service| {
            if (service.getHashAsInt() == hash_int) {
                return service;
            }
        }
        return null;
    }
    
    /// Gets service category
    pub fn getCategory(self: Self) ServiceCategory {
        return switch (self) {
            .SystemCryptoCheckSig, .SystemCryptoCheckMultisig => .Crypto,
            .SystemContractCall, .SystemContractCallNative, .SystemContractGetCallFlags,
            .SystemContractCreateStandardAccount, .SystemContractCreateMultiSigAccount,
            .SystemContractNativeOnPersist, .SystemContractNativePostPersist => .Contract,
            .SystemIteratorNext, .SystemIteratorValue => .Iterator,
            .SystemRuntimePlatform, .SystemRuntimeGetTrigger, .SystemRuntimeGetTime,
            .SystemRuntimeGetScriptContainer, .SystemRuntimeGetExecutingScriptHash,
            .SystemRuntimeGetCallingScriptHash, .SystemRuntimeGetEntryScriptHash,
            .SystemRuntimeCheckWitness, .SystemRuntimeGetInvocationCounter,
            .SystemRuntimeLog, .SystemRuntimeNotify, .SystemRuntimeGetNotifications,
            .SystemRuntimeGasLeft, .SystemRuntimeBurnGas, .SystemRuntimeGetNetwork,
            .SystemRuntimeGetRandom => .Runtime,
            .SystemStorageGetContext, .SystemStorageGetReadOnlyContext,
            .SystemStorageAsReadOnly, .SystemStorageGet, .SystemStorageFind,
            .SystemStoragePut, .SystemStorageDelete => .Storage,
        };
    }
    
    /// Gets service description
    pub fn getDescription(self: Self) []const u8 {
        return switch (self) {
            .SystemCryptoCheckSig => "Verifies ECDSA signature",
            .SystemCryptoCheckMultisig => "Verifies multi-signature",
            .SystemContractCall => "Calls smart contract method",
            .SystemContractCallNative => "Calls native contract method",
            .SystemRuntimeGetTime => "Gets current block timestamp",
            .SystemRuntimeCheckWitness => "Checks witness authorization",
            .SystemStorageGet => "Gets value from contract storage",
            .SystemStoragePut => "Stores value in contract storage",
            .SystemRuntimeNotify => "Emits contract notification event",
            .SystemRuntimeLog => "Logs debug message",
            else => "Neo VM interop service",
        };
    }
    
    /// Checks if service requires witness
    pub fn requiresWitness(self: Self) bool {
        return switch (self) {
            .SystemRuntimeCheckWitness => true,
            .SystemContractCall => true,
            .SystemStoragePut => true,
            .SystemStorageDelete => true,
            else => false,
        };
    }
    
    /// Checks if service modifies state
    pub fn modifiesState(self: Self) bool {
        return switch (self) {
            .SystemStoragePut,
            .SystemStorageDelete,
            .SystemRuntimeNotify,
            .SystemRuntimeLog,
            .SystemRuntimeBurnGas => true,
            else => false,
        };
    }
    
    /// Checks if service is read-only
    pub fn isReadOnly(self: Self) bool {
        return !self.modifiesState();
    }
};

/// Service categories for organization
pub const ServiceCategory = enum {
    Crypto,
    Contract,
    Iterator,
    Runtime,
    Storage,
    
    pub fn toString(self: ServiceCategory) []const u8 {
        return switch (self) {
            .Crypto => "Cryptographic",
            .Contract => "Contract",
            .Iterator => "Iterator",
            .Runtime => "Runtime",
            .Storage => "Storage",
        };
    }
    
    pub fn getDescription(self: ServiceCategory) []const u8 {
        return switch (self) {
            .Crypto => "Cryptographic verification operations",
            .Contract => "Smart contract interaction and management",
            .Iterator => "Result set iteration and traversal",
            .Runtime => "Runtime environment and execution context",
            .Storage => "Contract storage operations and persistence",
        };
    }
};

/// Interop service utilities
pub const InteropServiceUtils = struct {
    /// Gets services by category
    pub fn getServicesByCategory(category: ServiceCategory, allocator: std.mem.Allocator) ![]CompleteInteropService {
        var services = std.ArrayList(CompleteInteropService).init(allocator);
        defer services.deinit();
        
        const all_services = CompleteInteropService.getAllCases();
        for (all_services) |service| {
            if (service.getCategory() == category) {
                try services.append(service);
            }
        }
        
        return try services.toOwnedSlice();
    }
    
    /// Gets most expensive services
    pub fn getMostExpensiveServices(count: u32, allocator: std.mem.Allocator) ![]CompleteInteropService {
        const all_services = CompleteInteropService.getAllCases();
        
        // Create array with services and prices
        var service_prices = try allocator.alloc(ServicePrice, all_services.len);
        defer allocator.free(service_prices);
        
        for (all_services, 0..) |service, i| {
            service_prices[i] = ServicePrice{
                .service = service,
                .price = service.getPrice(),
            };
        }
        
        // Sort by price (descending)
        const lessThan = struct {
            fn compare(context: void, a: ServicePrice, b: ServicePrice) bool {
                _ = context;
                return a.price > b.price; // Descending order
            }
        }.compare;
        
        std.sort.block(ServicePrice, service_prices, {}, lessThan);
        
        // Extract top services
        const result_count = @min(count, service_prices.len);
        var result = try allocator.alloc(CompleteInteropService, result_count);
        
        for (service_prices[0..result_count], 0..) |service_price, i| {
            result[i] = service_price.service;
        }
        
        return result;
    }
    
    /// Calculates total execution cost
    pub fn calculateExecutionCost(services: []const CompleteInteropService) u64 {
        var total_cost: u64 = 0;
        for (services) |service| {
            total_cost += service.getPrice();
        }
        return total_cost;
    }
    
    /// Validates service compatibility
    pub fn validateServiceCompatibility(services: []const CompleteInteropService) !void {
        for (services) |service| {
            // Check for incompatible combinations
            if (service.modifiesState()) {
                // State-modifying services may require additional validation
                for (services) |other_service| {
                    if (other_service == .SystemStorageAsReadOnly and service.getCategory() == .Storage) {
                        return errors.ValidationError.InvalidParameter;
                    }
                }
            }
        }
    }
    
    /// Gets services requiring witness
    pub fn getServicesRequiringWitness(allocator: std.mem.Allocator) ![]CompleteInteropService {
        var witness_services = std.ArrayList(CompleteInteropService).init(allocator);
        defer witness_services.deinit();
        
        const all_services = CompleteInteropService.getAllCases();
        for (all_services) |service| {
            if (service.requiresWitness()) {
                try witness_services.append(service);
            }
        }
        
        return try witness_services.toOwnedSlice();
    }
    
    /// Gets read-only services
    pub fn getReadOnlyServices(allocator: std.mem.Allocator) ![]CompleteInteropService {
        var readonly_services = std.ArrayList(CompleteInteropService).init(allocator);
        defer readonly_services.deinit();
        
        const all_services = CompleteInteropService.getAllCases();
        for (all_services) |service| {
            if (service.isReadOnly()) {
                try readonly_services.append(service);
            }
        }
        
        return try readonly_services.toOwnedSlice();
    }
};

/// Service price for sorting
const ServicePrice = struct {
    service: CompleteInteropService,
    price: u32,
};

/// Service execution context
pub const ServiceExecutionContext = struct {
    available_gas: u64,
    witness_available: bool,
    storage_context: ?[]const u8,
    
    pub fn init(available_gas: u64, witness_available: bool) ServiceExecutionContext {
        return ServiceExecutionContext{
            .available_gas = available_gas,
            .witness_available = witness_available,
            .storage_context = null,
        };
    }
    
    /// Checks if service can execute in context
    pub fn canExecuteService(self: ServiceExecutionContext, service: CompleteInteropService) bool {
        // Check gas availability
        if (self.available_gas < service.getPrice()) {
            return false;
        }
        
        // Check witness requirement
        if (service.requiresWitness() and !self.witness_available) {
            return false;
        }
        
        // Check storage context for storage operations
        if (service.getCategory() == .Storage and self.storage_context == null) {
            return false;
        }
        
        return true;
    }
    
    /// Consumes gas for service execution
    pub fn consumeGas(self: *ServiceExecutionContext, service: CompleteInteropService) !void {
        const cost = service.getPrice();
        if (self.available_gas < cost) {
            return errors.ContractError.InsufficientGas;
        }
        
        self.available_gas -= cost;
    }
};

// Tests (converted from Swift InteropService tests)
test "CompleteInteropService properties and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test service properties (equivalent to Swift InteropService tests)
    try testing.expectEqualStrings("System.Crypto.CheckSig", CompleteInteropService.SystemCryptoCheckSig.getRawValue());
    try testing.expectEqualStrings("System.Contract.Call", CompleteInteropService.SystemContractCall.getRawValue());
    try testing.expectEqualStrings("System.Storage.Get", CompleteInteropService.SystemStorageGet.getRawValue());
    
    // Test service pricing
    try testing.expectEqual(@as(u32, 1024), CompleteInteropService.SystemCryptoCheckSig.getPrice());
    try testing.expectEqual(@as(u32, 4096), CompleteInteropService.SystemCryptoCheckMultisig.getPrice());
    try testing.expectEqual(@as(u32, 8), CompleteInteropService.SystemRuntimeGetTime.getPrice());
    
    // Test service categorization
    try testing.expectEqual(ServiceCategory.Crypto, CompleteInteropService.SystemCryptoCheckSig.getCategory());
    try testing.expectEqual(ServiceCategory.Contract, CompleteInteropService.SystemContractCall.getCategory());
    try testing.expectEqual(ServiceCategory.Storage, CompleteInteropService.SystemStorageGet.getCategory());
    try testing.expectEqual(ServiceCategory.Runtime, CompleteInteropService.SystemRuntimeGetTime.getCategory());
}

test "CompleteInteropService hash operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test hash generation (equivalent to Swift hash tests)
    const check_sig_hash = try CompleteInteropService.SystemCryptoCheckSig.getHash(allocator);
    defer allocator.free(check_sig_hash);
    
    try testing.expect(check_sig_hash.len == 8); // 4 bytes = 8 hex chars
    
    const contract_call_hash = try CompleteInteropService.SystemContractCall.getHash(allocator);
    defer allocator.free(contract_call_hash);
    
    try testing.expect(contract_call_hash.len == 8);
    try testing.expect(!std.mem.eql(u8, check_sig_hash, contract_call_hash)); // Should be different
    
    // Test hash as integer
    const check_sig_hash_int = CompleteInteropService.SystemCryptoCheckSig.getHashAsInt();
    try testing.expect(check_sig_hash_int != 0);
    
    const contract_call_hash_int = CompleteInteropService.SystemContractCall.getHashAsInt();
    try testing.expect(contract_call_hash_int != check_sig_hash_int);
}

test "CompleteInteropService conversion operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test creation from raw value
    const from_raw = CompleteInteropService.fromRawValue("System.Crypto.CheckSig");
    try testing.expectEqual(CompleteInteropService.SystemCryptoCheckSig, from_raw.?);
    
    const invalid_raw = CompleteInteropService.fromRawValue("Invalid.Service");
    try testing.expect(invalid_raw == null);
    
    // Test creation from hash
    const service_hash = try CompleteInteropService.SystemContractCall.getHash(allocator);
    defer allocator.free(service_hash);
    
    const from_hash = CompleteInteropService.fromHash(service_hash, allocator);
    try testing.expectEqual(CompleteInteropService.SystemContractCall, from_hash.?);
    
    // Test creation from hash integer
    const hash_int = CompleteInteropService.SystemStorageGet.getHashAsInt();
    const from_hash_int = CompleteInteropService.fromHashInt(hash_int);
    try testing.expectEqual(CompleteInteropService.SystemStorageGet, from_hash_int.?);
}

test "InteropServiceUtils utility functions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test services by category
    const crypto_services = try InteropServiceUtils.getServicesByCategory(.Crypto, allocator);
    defer allocator.free(crypto_services);
    
    try testing.expect(crypto_services.len >= 2); // At least CheckSig and CheckMultisig
    
    for (crypto_services) |service| {
        try testing.expectEqual(ServiceCategory.Crypto, service.getCategory());
    }
    
    // Test most expensive services
    const expensive_services = try InteropServiceUtils.getMostExpensiveServices(3, allocator);
    defer allocator.free(expensive_services);
    
    try testing.expectEqual(@as(usize, 3), expensive_services.len);
    
    // First should be most expensive
    const first_price = expensive_services[0].getPrice();
    const second_price = expensive_services[1].getPrice();
    try testing.expect(first_price >= second_price);
    
    // Test execution cost calculation
    const test_services = [_]CompleteInteropService{
        .SystemCryptoCheckSig,      // 1024
        .SystemContractCall,        // 4096
        .SystemStorageGet,          // 64
    };
    
    const total_cost = InteropServiceUtils.calculateExecutionCost(&test_services);
    try testing.expectEqual(@as(u64, 1024 + 4096 + 64), total_cost);
}

test "ServiceExecutionContext operations" {
    const testing = std.testing;
    
    // Test execution context
    var context = ServiceExecutionContext.init(10000, true); // 10K gas, witness available
    
    // Test service execution capability
    try testing.expect(context.canExecuteService(.SystemRuntimeGetTime)); // Low cost, no witness
    try testing.expect(context.canExecuteService(.SystemRuntimeCheckWitness)); // Requires witness
    try testing.expect(context.canExecuteService(.SystemCryptoCheckSig)); // High cost but affordable
    
    // Test gas consumption
    try context.consumeGas(.SystemCryptoCheckSig); // Consume 1024 gas
    try testing.expectEqual(@as(u64, 10000 - 1024), context.available_gas);
    
    // Test insufficient gas
    context.available_gas = 100; // Set low gas
    try testing.expectError(
        errors.ContractError.InsufficientGas,
        context.consumeGas(.SystemContractCall) // Requires 4096 gas
    );
    
    // Test witness requirement
    var no_witness_context = ServiceExecutionContext.init(10000, false);
    try testing.expect(!no_witness_context.canExecuteService(.SystemRuntimeCheckWitness));
    try testing.expect(no_witness_context.canExecuteService(.SystemRuntimeGetTime)); // No witness needed
}