//! CryptoLib Contract implementation
//!
//! Neo N3
//! Native contract for cryptographic operations.
//! Provides SHA-256, RIPEMD-160, Murmur32, Keccak256 (HF_Cockatrice),
//! ECDSA verification (HF_Cockatrice), secp256k1 recovery (HF_Echidna),
//! and BLS12-381 operations (HF_Cockatrice).

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const SmartContract = @import("smart_contract.zig").SmartContract;

/// Named curve + hash algorithm pairs for ECDSA verification.
///
/// Maps to Neo N3 `NamedCurveHash` enum values used by `verifyWithECDsa`.
/// Introduced in HF_Cockatrice.
pub const NamedCurveHash = enum(u8) {
    /// secp256k1 curve with SHA-256 hash
    secp256k1SHA256 = 22,
    /// secp256r1 (prime256v1 / NIST P-256) curve with SHA-256 hash
    secp256r1SHA256 = 23,
    /// secp256k1 curve with Keccak-256 hash
    secp256k1Keccak256 = 122,
    /// secp256r1 (prime256v1 / NIST P-256) curve with Keccak-256 hash
    secp256r1Keccak256 = 123,
};

/// CryptoLib native contract
///
/// Provides cryptographic functions accessible on-chain. All hash methods
/// are read-only invocations that return raw byte arrays.
pub const CryptoLib = struct {
    /// Contract name
    pub const NAME = "CryptoLib";

    /// Script hash
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.CRYPTO_LIB };

    // -- Method names (matching Neo N3 reference) --
    pub const SHA256 = "sha256";
    pub const RIPEMD160 = "ripemd160";
    pub const MURMUR32 = "murmur32";
    pub const KECCAK256 = "keccak256";
    pub const VERIFY_WITH_ECDSA = "verifyWithECDsa";
    pub const RECOVER_SECP256K1 = "recoverSecp256K1";
    // BLS12-381
    pub const BLS12381_SERIALIZE = "bls12381Serialize";
    pub const BLS12381_DESERIALIZE = "bls12381Deserialize";
    pub const BLS12381_EQUAL = "bls12381Equal";
    pub const BLS12381_ADD = "bls12381Add";
    pub const BLS12381_MUL = "bls12381Mul";
    pub const BLS12381_PAIRING = "bls12381Pairing";

    /// Base smart contract
    smart_contract: SmartContract,

    const Self = @This();

    /// Creates new CryptoLib instance
    pub fn init(allocator: std.mem.Allocator, client: ?*anyopaque) Self {
        return Self{
            .smart_contract = SmartContract.init(allocator, SCRIPT_HASH, client),
        };
    }

    /// Gets script hash for this contract.
    pub fn getScriptHash(self: Self) Hash160 {
        return self.smart_contract.getScriptHash();
    }

    /// Validates the underlying contract configuration.
    pub fn validate(self: Self) !void {
        try self.smart_contract.validate();
        if (!self.smart_contract.getScriptHash().eql(SCRIPT_HASH)) {
            return errors.ContractError.InvalidContract;
        }
    }

    /// Returns true if this contract is native.
    pub fn isNativeContract(self: Self) bool {
        return self.smart_contract.isNativeContract();
    }

    // -----------------------------------------------------------------
    // Hash functions
    // -----------------------------------------------------------------

    /// Computes SHA-256 hash of the given data.
    pub fn sha256(self: Self, data: []const u8) ![]u8 {
        const params = [_]ContractParameter{ContractParameter.byteArray(data)};
        return try self.smart_contract.callFunctionReturningBytes(SHA256, &params);
    }

    /// Computes RIPEMD-160 hash of the given data.
    pub fn ripemd160(self: Self, data: []const u8) ![]u8 {
        const params = [_]ContractParameter{ContractParameter.byteArray(data)};
        return try self.smart_contract.callFunctionReturningBytes(RIPEMD160, &params);
    }

    /// Computes Murmur32 hash of the given data with a seed.
    pub fn murmur32(self: Self, data: []const u8, seed: u32) ![]u8 {
        const params = [_]ContractParameter{
            ContractParameter.byteArray(data),
            ContractParameter.integer(@intCast(seed)),
        };
        return try self.smart_contract.callFunctionReturningBytes(MURMUR32, &params);
    }

    /// Computes Keccak-256 hash of the given data (HF_Cockatrice).
    pub fn keccak256(self: Self, data: []const u8) ![]u8 {
        const params = [_]ContractParameter{ContractParameter.byteArray(data)};
        return try self.smart_contract.callFunctionReturningBytes(KECCAK256, &params);
    }

    // -----------------------------------------------------------------
    // Signature verification & recovery
    // -----------------------------------------------------------------

    /// Verifies an ECDSA signature against a message and public key.
    ///
    /// Parameters:
    /// - `message`: The signed message bytes.
    /// - `pubkey`: The public key bytes (compressed or uncompressed).
    /// - `signature`: The signature bytes.
    /// - `curve_hash`: The named curve + hash algorithm pair.
    ///
    /// Introduced in HF_Cockatrice.
    pub fn verifyWithECDsa(
        self: Self,
        message: []const u8,
        pubkey: []const u8,
        signature: []const u8,
        curve_hash: NamedCurveHash,
    ) !bool {
        const params = [_]ContractParameter{
            ContractParameter.byteArray(message),
            ContractParameter.byteArray(pubkey),
            ContractParameter.byteArray(signature),
            ContractParameter.integer(@intCast(@intFromEnum(curve_hash))),
        };
        return try self.smart_contract.callFunctionReturningBool(VERIFY_WITH_ECDSA, &params);
    }

    /// Recovers the public key from a secp256k1 signature.
    ///
    /// Parameters:
    /// - `message_hash`: The hash of the message that was signed.
    /// - `signature`: 65-byte signature (r[32] + s[32] + v[1]) or 64-byte EIP-2098.
    ///
    /// Returns the recovered compressed public key, or null if recovery fails.
    /// Introduced in HF_Echidna.
    pub fn recoverSecp256K1(
        self: Self,
        message_hash: []const u8,
        signature: []const u8,
    ) ![]u8 {
        const params = [_]ContractParameter{
            ContractParameter.byteArray(message_hash),
            ContractParameter.byteArray(signature),
        };
        return try self.smart_contract.callFunctionReturningBytes(RECOVER_SECP256K1, &params);
    }

    // -----------------------------------------------------------------
    // BLS12-381 operations (HF_Cockatrice)
    // -----------------------------------------------------------------

    /// Serializes a BLS12-381 point to bytes.
    pub fn bls12381Serialize(self: Self, point: []const u8) ![]u8 {
        const params = [_]ContractParameter{ContractParameter.byteArray(point)};
        return try self.smart_contract.callFunctionReturningBytes(BLS12381_SERIALIZE, &params);
    }

    /// Deserializes bytes to a BLS12-381 point.
    pub fn bls12381Deserialize(self: Self, data: []const u8) ![]u8 {
        const params = [_]ContractParameter{ContractParameter.byteArray(data)};
        return try self.smart_contract.callFunctionReturningBytes(BLS12381_DESERIALIZE, &params);
    }

    /// Checks equality of two BLS12-381 points.
    pub fn bls12381Equal(self: Self, x: []const u8, y: []const u8) !bool {
        const params = [_]ContractParameter{
            ContractParameter.byteArray(x),
            ContractParameter.byteArray(y),
        };
        return try self.smart_contract.callFunctionReturningBool(BLS12381_EQUAL, &params);
    }

    /// Adds two BLS12-381 points.
    pub fn bls12381Add(self: Self, x: []const u8, y: []const u8) ![]u8 {
        const params = [_]ContractParameter{
            ContractParameter.byteArray(x),
            ContractParameter.byteArray(y),
        };
        return try self.smart_contract.callFunctionReturningBytes(BLS12381_ADD, &params);
    }

    /// Multiplies a BLS12-381 point by a scalar.
    pub fn bls12381Mul(self: Self, x: []const u8, mul: []const u8, neg: bool) ![]u8 {
        const params = [_]ContractParameter{
            ContractParameter.byteArray(x),
            ContractParameter.byteArray(mul),
            ContractParameter.boolean(neg),
        };
        return try self.smart_contract.callFunctionReturningBytes(BLS12381_MUL, &params);
    }

    /// Computes a BLS12-381 pairing of G1 and G2 points.
    pub fn bls12381Pairing(self: Self, g1: []const u8, g2: []const u8) ![]u8 {
        const params = [_]ContractParameter{
            ContractParameter.byteArray(g1),
            ContractParameter.byteArray(g2),
        };
        return try self.smart_contract.callFunctionReturningBytes(BLS12381_PAIRING, &params);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CryptoLib creation and constants" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const crypto = CryptoLib.init(allocator, null);

    try testing.expectEqualStrings("CryptoLib", CryptoLib.NAME);
    try testing.expect(crypto.getScriptHash().eql(CryptoLib.SCRIPT_HASH));
    try testing.expect(crypto.isNativeContract());
}

test "CryptoLib operations require RPC" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const crypto = CryptoLib.init(allocator, null);
    const data = "test";

    // Hash functions
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.sha256(data));
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.ripemd160(data));
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.murmur32(data, 0));
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.keccak256(data));

    // Signature verification
    try testing.expectError(
        errors.NeoError.InvalidConfiguration,
        crypto.verifyWithECDsa(data, data, data, .secp256r1SHA256),
    );

    // Key recovery
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.recoverSecp256K1(data, data));

    // BLS12-381
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.bls12381Serialize(data));
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.bls12381Deserialize(data));
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.bls12381Equal(data, data));
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.bls12381Add(data, data));
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.bls12381Mul(data, data, false));
    try testing.expectError(errors.NeoError.InvalidConfiguration, crypto.bls12381Pairing(data, data));
}
