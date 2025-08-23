//! Neo Script Builder
//!
//! Complete conversion from NeoSwift ScriptBuilder.swift
//! Essential for contract calls and transaction building.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const BinaryWriter = @import("../serialization/binary_writer.zig").BinaryWriter;

/// Script builder for Neo VM scripts (converted from Swift ScriptBuilder)
pub const ScriptBuilder = struct {
    writer: BinaryWriter,
    
    const Self = @This();
    
    /// Creates new script builder (equivalent to Swift init())
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .writer = BinaryWriter.init(allocator),
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.writer.deinit();
    }
    
    /// Appends OpCodes (equivalent to Swift opCode(_ opCodes: OpCode...))
    pub fn opCode(self: *Self, op_codes: []const OpCode) !*Self {
        for (op_codes) |op| {
            try self.writer.writeByte(@intFromEnum(op));
        }
        return self;
    }
    
    /// Appends OpCode with argument (equivalent to Swift opCode(_ opCode: OpCode, _ argument: Bytes))
    pub fn opCodeWithArg(self: *Self, op: OpCode, argument: []const u8) !*Self {
        try self.writer.writeByte(@intFromEnum(op));
        try self.writer.writeBytes(argument);
        return self;
    }
    
    /// Contract call (equivalent to Swift contractCall method)
    pub fn contractCall(
        self: *Self,
        script_hash: Hash160,
        method: []const u8,
        params: []const ContractParameter,
        call_flags: ?CallFlags,
    ) !*Self {
        // Push parameters (equivalent to Swift pushParams)
        if (params.len == 0) {
            _ = try self.opCode(&[_]OpCode{.NEWARRAY0});
        } else {
            _ = try self.pushParams(params);
        }
        
        // Push call flags (equivalent to Swift pushInteger)
        const flags = call_flags orelse CallFlags.All;
        _ = try self.pushInteger(@intFromEnum(flags));
        
        // Push method name (equivalent to Swift pushData)
        _ = try self.pushData(method);
        
        // Push contract hash (equivalent to Swift pushData with little endian)
        const little_endian_hash = script_hash.toLittleEndianArray();
        _ = try self.pushData(&little_endian_hash);
        
        // System call (equivalent to Swift sysCall(.systemContractCall))
        return try self.sysCall(.SystemContractCall);
    }
    
    /// System call (equivalent to Swift sysCall(_ operation: InteropService))
    pub fn sysCall(self: *Self, operation: InteropService) !*Self {
        _ = try self.opCode(&[_]OpCode{.SYSCALL});
        const hash_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, @intFromEnum(operation)));
        try self.writer.writeBytes(&hash_bytes);
        return self;
    }
    
    /// Push contract parameters (equivalent to Swift pushParams)
    pub fn pushParams(self: *Self, params: []const ContractParameter) !*Self {
        // Push parameters in reverse order
        var i = params.len;
        while (i > 0) {
            i -= 1;
            _ = try self.pushParam(params[i]);
        }
        
        // Push parameter count
        _ = try self.pushInteger(@intCast(params.len));
        _ = try self.opCode(&[_]OpCode{.PACK});
        
        return self;
    }
    
    /// Push single parameter (equivalent to Swift parameter handling)
    pub fn pushParam(self: *Self, param: ContractParameter) !*Self {
        switch (param) {
            .Boolean => |value| {
                const op = if (value) OpCode.PUSH1 else OpCode.PUSH0;
                _ = try self.opCode(&[_]OpCode{op});
            },
            .Integer => |value| {
                _ = try self.pushInteger(value);
            },
            .String => |str| {
                _ = try self.pushData(str);
            },
            .ByteArray => |data| {
                _ = try self.pushData(data);
            },
            .Hash160 => |hash| {
                _ = try self.pushData(&hash.toArray());
            },
            .Hash256 => |hash| {
                _ = try self.pushData(&hash.toArray());
            },
            .PublicKey => |key| {
                _ = try self.pushData(&key);
            },
            .Signature => |sig| {
                _ = try self.pushData(&sig);
            },
            .Array => |items| {
                for (items) |item| {
                    _ = try self.pushParam(item);
                }
                _ = try self.pushInteger(@intCast(items.len));
                _ = try self.opCode(&[_]OpCode{.PACK});
            },
            else => {
                return errors.TransactionError.InvalidParameters;
            },
        }
        return self;
    }
    
    /// Push integer value (equivalent to Swift pushInteger)
    pub fn pushInteger(self: *Self, value: i64) !*Self {
        if (value == 0) {
            _ = try self.opCode(&[_]OpCode{.PUSH0});
        } else if (value > 0 and value <= 16) {
            const op_value = @as(u8, @intCast(@intFromEnum(OpCode.PUSH1) + value - 1));
            const op = @as(OpCode, @enumFromInt(op_value));
            _ = try self.opCode(&[_]OpCode{op});
        } else {
            // Convert to bytes and push as data
            const bytes = std.mem.toBytes(std.mem.nativeToLittle(i64, value));
            _ = try self.pushData(&bytes);
        }
        return self;
    }
    
    /// Push data (equivalent to Swift pushData)
    pub fn pushData(self: *Self, data: []const u8) !*Self {
        if (data.len <= 75) {
            try self.writer.writeByte(@intCast(data.len));
            try self.writer.writeBytes(data);
        } else if (data.len <= 255) {
            _ = try self.opCode(&[_]OpCode{.PUSHDATA1});
            try self.writer.writeByte(@intCast(data.len));
            try self.writer.writeBytes(data);
        } else if (data.len <= 65535) {
            _ = try self.opCode(&[_]OpCode{.PUSHDATA2});
            try self.writer.writeU32(@intCast(data.len));
            try self.writer.writeBytes(data);
        } else {
            _ = try self.opCode(&[_]OpCode{.PUSHDATA4});
            try self.writer.writeU32(@intCast(data.len));
            try self.writer.writeBytes(data);
        }
        return self;
    }
    
    /// Build verification script for single public key (equivalent to Swift buildVerificationScript)
    pub fn buildVerificationScript(public_key: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        _ = try builder.pushData(public_key);
        _ = try builder.sysCall(.SystemCryptoCheckSig);
        
        return try allocator.dupe(u8, builder.toScript());
    }
    
    /// Build multi-sig verification script (equivalent to Swift buildVerificationScript for multi-sig)
    pub fn buildMultiSigVerificationScript(
        public_keys: []const []const u8,
        signing_threshold: u32,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (public_keys.len > constants.MAX_PUBLIC_KEYS_PER_MULTISIG_ACCOUNT) {
            return errors.throwIllegalArgument("Too many public keys for multi-sig");
        }
        
        if (signing_threshold == 0 or signing_threshold > public_keys.len) {
            return errors.throwIllegalArgument("Invalid signing threshold");
        }
        
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        // Push signing threshold
        _ = try builder.pushInteger(@intCast(signing_threshold));
        
        // Push public keys
        for (public_keys) |pub_key| {
            _ = try builder.pushData(pub_key);
        }
        
        // Push number of public keys
        _ = try builder.pushInteger(@intCast(public_keys.len));
        
        // CheckMultiSig
        _ = try builder.sysCall(.SystemCryptoCheckMultiSig);
        
        return try allocator.dupe(u8, builder.toScript());
    }
    
    /// Gets the built script (equivalent to Swift toArray())
    pub fn toScript(self: *Self) []const u8 {
        return self.writer.toSlice();
    }
    
    /// Gets script size (equivalent to Swift size property)
    pub fn size(self: *Self) usize {
        return self.writer.toSlice().len;
    }
    
    /// Resets the builder (equivalent to Swift reset)
    pub fn reset(self: *Self) void {
        self.writer.clear();
    }
};

const OpCode = @import("op_code.zig").OpCode;

const CallFlags = @import("../types/call_flags.zig").CallFlags;

/// Interop services (converted from Swift InteropService.swift)
pub const InteropService = enum(u32) {
    SystemContractCall = 0x627d5b52,
    SystemCryptoCheckSig = 0x41766430,
    SystemCryptoCheckMultiSig = 0x0f1c2d00,
    SystemRuntimeCheckWitness = 0x49252821,
    SystemRuntimeGetRandom = 0x627b4b4e,
    SystemRuntimeGetTime = 0xb7940be2,
    SystemRuntimeGetScriptContainer = 0x2d510db5,
    SystemRuntimeGetExecutingScriptHash = 0xa621c0db,
    SystemRuntimeGetCallingScriptHash = 0xb54b4f50,
    SystemRuntimeGetEntryScriptHash = 0x6b10cd64,
};

// Tests (converted from Swift ScriptBuilder tests)
test "ScriptBuilder basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Test OpCode appending (equivalent to Swift opCode tests)
    _ = try builder.opCode(&[_]OpCode{ .PUSH1, .PUSH2, .ADD });
    
    const script = builder.toScript();
    try testing.expect(script.len == 3);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.PUSH1)), script[0]);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.PUSH2)), script[1]);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.ADD)), script[2]);
}

test "ScriptBuilder contract call" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Test contract call (equivalent to Swift contractCall test)
    const contract_hash = neo.Hash160.ZERO;
    const params = [_]ContractParameter{
        ContractParameter.string("test"),
        ContractParameter.integer(42),
    };
    
    _ = try builder.contractCall(contract_hash, "testMethod", &params, CallFlags.All);
    
    const script = builder.toScript();
    try testing.expect(script.len > 0);
    
    // Should contain SYSCALL opcode
    try testing.expect(std.mem.indexOf(u8, script, &[_]u8{@intFromEnum(OpCode.SYSCALL)}) != null);
}

test "ScriptBuilder verification scripts" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test single-sig verification script (equivalent to Swift buildVerificationScript)
    const public_key = [_]u8{0x02} ++ [_]u8{0xAB} ** 32; // Mock compressed public key
    const verification_script = try ScriptBuilder.buildVerificationScript(&public_key, allocator);
    defer allocator.free(verification_script);
    
    try testing.expect(verification_script.len > 0);
    
    // Test multi-sig verification script
    const pub_keys = [_][]const u8{&public_key};
    const multi_sig_script = try ScriptBuilder.buildMultiSigVerificationScript(&pub_keys, 1, allocator);
    defer allocator.free(multi_sig_script);
    
    try testing.expect(multi_sig_script.len > 0);
    try testing.expect(multi_sig_script.len > verification_script.len); // Should be larger
}

test "ScriptBuilder data operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Test pushInteger (equivalent to Swift pushInteger tests)
    _ = try builder.pushInteger(0);   // Should use PUSH0
    _ = try builder.pushInteger(5);   // Should use PUSH5
    _ = try builder.pushInteger(100); // Should use PUSHDATA
    
    const script = builder.toScript();
    try testing.expect(script.len > 0);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.PUSH0)), script[0]);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.PUSH5)), script[1]);
}

test "ScriptBuilder parameter handling" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Test various parameter types (equivalent to Swift parameter tests)
    const bool_param = ContractParameter.boolean(true);
    const int_param = ContractParameter.integer(12345);
    const str_param = ContractParameter.string("Hello Neo");
    
    _ = try builder.pushParam(bool_param);
    _ = try builder.pushParam(int_param);
    _ = try builder.pushParam(str_param);
    
    const script = builder.toScript();
    try testing.expect(script.len > 0);
}