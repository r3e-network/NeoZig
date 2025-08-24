//! Swift Type Aliases
//!
//! Complete conversion from NeoSwift Aliases.swift
//! Provides Swift-compatible type aliases for seamless migration.

const std = @import("std");

/// Swift-compatible type aliases (converted from Swift Aliases.swift)

/// EC Point alias (equivalent to Swift ECPoint = Point)
pub const ECPoint = @import("../crypto/ec_point.zig").ECPoint;

/// EC Private Key alias (equivalent to Swift ECPrivateKey = SwiftECC.ECPrivateKey)
pub const ECPrivateKey = @import("../crypto/keys.zig").PrivateKey;

/// EC Public Key alias (equivalent to Swift ECPublicKey = SwiftECC.ECPublicKey)
pub const ECPublicKey = @import("../crypto/keys.zig").PublicKey;

/// Byte alias (equivalent to Swift Byte = UInt8)
pub const Byte = u8;

/// Bytes alias (equivalent to Swift Bytes = [UInt8])
pub const Bytes = []const u8;

/// Mutable bytes alias
pub const MutableBytes = []u8;

/// Additional Neo-specific aliases for Swift compatibility

/// Hash type aliases
pub const Hash160Type = @import("hash160.zig").Hash160;
pub const Hash256Type = @import("hash256.zig").Hash256;

/// Address type alias
pub const AddressType = @import("address.zig").Address;

/// Contract parameter type alias
pub const ContractParameterType = @import("contract_parameter.zig").ContractParameter;

/// Transaction type aliases
pub const TransactionType = @import("../transaction/neo_transaction.zig").NeoTransaction;
pub const TransactionBuilderType = @import("../transaction/transaction_builder.zig").TransactionBuilder;

/// Wallet type aliases
pub const WalletType = @import("../wallet/neo_wallet.zig").Wallet;
pub const AccountType = @import("../wallet/account.zig").Account;

/// RPC type aliases
pub const NeoSwiftType = @import("../rpc/neo_client.zig").NeoSwift;
pub const HttpServiceType = @import("../rpc/http_service.zig").HttpService;

/// Smart contract type aliases
pub const SmartContractType = @import("../contract/smart_contract.zig").SmartContract;
pub const FungibleTokenType = @import("../contract/fungible_token.zig").FungibleToken;
pub const NonFungibleTokenType = @import("../contract/non_fungible_token.zig").NonFungibleToken;

/// Script type aliases
pub const ScriptBuilderType = @import("../script/script_builder.zig").ScriptBuilder;
pub const OpCodeType = @import("../script/op_code.zig").OpCode;

/// Serialization type aliases
pub const BinaryWriterType = @import("../serialization/binary_writer_complete.zig").CompleteBinaryWriter;
pub const BinaryReaderType = @import("../serialization/binary_reader_complete.zig").CompleteBinaryReader;

/// Error type aliases
pub const NeoErrorType = @import("../core/errors.zig").NeoError;
pub const CryptoErrorType = @import("../core/errors.zig").CryptoError;
pub const ContractErrorType = @import("../contract/contract_error.zig").ContractError;

/// Network type aliases
pub const NetworkMagicType = u32;
pub const EndpointType = []const u8;

/// Swift migration utilities
pub const SwiftMigration = struct {
    /// Type mapping for Swift developers
    pub const TypeMapping = struct {
        // Swift -> Zig mappings
        pub const ECKeyPair = @import("../crypto/ec_key_pair.zig").ECKeyPair;
        pub const Hash160 = Hash160Type;
        pub const Hash256 = Hash256Type;
        pub const Address = AddressType;
        pub const Account = AccountType;
        pub const Wallet = WalletType;
        pub const NeoSwift = NeoSwiftType;
        pub const SmartContract = SmartContractType;
        pub const TransactionBuilder = TransactionBuilderType;
        pub const BinaryWriter = BinaryWriterType;
        pub const BinaryReader = BinaryReaderType;
        
        /// Gets type mapping documentation
        pub fn getTypeMappingDoc(allocator: std.mem.Allocator) ![]u8 {
            return try std.fmt.allocPrint(allocator,
                \\Swift Type -> Zig Type Mapping:
                \\ECKeyPair -> ECKeyPair
                \\Hash160 -> Hash160Type  
                \\Hash256 -> Hash256Type
                \\Address -> AddressType
                \\Account -> AccountType
                \\Wallet -> WalletType
                \\NeoSwift -> NeoSwiftType
                \\SmartContract -> SmartContractType
                \\TransactionBuilder -> TransactionBuilderType
                \\BinaryWriter -> BinaryWriterType
                \\BinaryReader -> BinaryReaderType
            );
        }
    };
    
    /// Common patterns for Swift migration
    pub const MigrationPatterns = struct {
        /// Swift: let keyPair = try ECKeyPair.create()
        /// Zig: const key_pair = try ECKeyPair.createRandom()
        pub fn createKeyPair() !@import("../crypto/ec_key_pair.zig").ECKeyPair {
            return try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
        }
        
        /// Swift: let address = keyPair.getAddress()
        /// Zig: const address = try key_pair.getAddress(allocator)
        pub fn getAddressFromKeyPair(key_pair: @import("../crypto/ec_key_pair.zig").ECKeyPair, allocator: std.mem.Allocator) ![]u8 {
            return try key_pair.getAddress(allocator);
        }
        
        /// Swift: let hash = Hash160("hex_string")
        /// Zig: const hash = try Hash160.initWithString("hex_string")
        pub fn createHash160FromString(hex_string: []const u8) !Hash160Type {
            return try Hash160Type.initWithString(hex_string);
        }
        
        /// Swift: let transaction = TransactionBuilder().version(0).build()
        /// Zig: var builder = TransactionBuilder.init(allocator); _ = builder.version(0); const tx = try builder.build()
        pub fn buildTransaction(allocator: std.mem.Allocator) !TransactionBuilderType {
            return TransactionBuilderType.init(allocator);
        }
    };
    
    /// Error mapping for Swift migration
    pub const ErrorMapping = struct {
        /// Maps Swift errors to Zig errors
        pub fn mapSwiftError(swift_error_name: []const u8) !type {
            if (std.mem.eql(u8, swift_error_name, "NeoSwiftError.illegalArgument")) {
                return NeoErrorType.IllegalArgument;
            }
            if (std.mem.eql(u8, swift_error_name, "NEP2Error.invalidPassphrase")) {
                return CryptoErrorType.InvalidKey;
            }
            if (std.mem.eql(u8, swift_error_name, "ContractError.invalidNeoName")) {
                return @import("../contract/contract_error.zig").ContractError;
            }
            
            return NeoErrorType.UnsupportedOperation;
        }
        
        /// Gets error migration guide
        pub fn getErrorMigrationGuide(allocator: std.mem.Allocator) ![]u8 {
            return try std.fmt.allocPrint(allocator,
                \\Swift Error -> Zig Error Migration:
                \\NeoSwiftError.illegalArgument -> NeoError.IllegalArgument
                \\NEP2Error.invalidPassphrase -> CryptoError.InvalidKey
                \\ContractError.invalidNeoName -> ContractError
                \\SignError.recoverFailed -> CryptoError.SignatureVerificationFailed
            );
        }
    };
};

/// Compatibility layer for Swift developers
pub const SwiftCompatibility = struct {
    /// Creates Swift-style convenience functions
    
    /// Swift: Bytes(hex: "hexstring")
    /// Zig: try SwiftCompatibility.bytesFromHex("hexstring", allocator)
    pub fn bytesFromHex(hex_string: []const u8, allocator: std.mem.Allocator) !Bytes {
        return try @import("../utils/string_extensions.zig").StringUtils.bytesFromHex(hex_string, allocator);
    }
    
    /// Swift: bytes.base58Encoded
    /// Zig: try SwiftCompatibility.base58Encode(bytes, allocator)
    pub fn base58Encode(bytes: Bytes, allocator: std.mem.Allocator) ![]u8 {
        return try @import("../utils/bytes_extensions.zig").BytesUtils.base58Encoded(bytes, allocator);
    }
    
    /// Swift: hash.toAddress()
    /// Zig: try SwiftCompatibility.hashToAddress(hash, allocator)
    pub fn hashToAddress(hash: Hash160Type, allocator: std.mem.Allocator) ![]u8 {
        return try hash.toAddress(allocator);
    }
    
    /// Swift: .isDefault
    /// Zig: SwiftCompatibility.isDefault(account, wallet)
    pub fn isDefault(account: AccountType, wallet: WalletType) bool {
        return wallet.isDefault(account);
    }
    
    /// Gets Swift compatibility guide
    pub fn getCompatibilityGuide(allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator,
            \\Swift -> Zig Migration Guide:
            \\
            \\1. Type Creation:
            \\   Swift: let hash = Hash160("hex")
            \\   Zig:   const hash = try Hash160.initWithString("hex")
            \\
            \\2. Memory Management:
            \\   Swift: Automatic (ARC)
            \\   Zig:   Explicit (defer allocator.free(data))
            \\
            \\3. Error Handling:
            \\   Swift: throw/try/catch
            \\   Zig:   error union types with try
            \\
            \\4. Optional Values:
            \\   Swift: Type?
            \\   Zig:   ?Type
            \\
            \\5. Method Names:
            \\   Swift: camelCase
            \\   Zig:   snake_case (but Swift methods preserved)
        );
    }
};

// Tests (converted from Swift Aliases tests)
test "Swift type aliases validation" {
    const testing = std.testing;
    
    // Test type alias consistency (equivalent to Swift type tests)
    const byte_val: Byte = 0x42;
    try testing.expectEqual(@as(u8, 0x42), byte_val);
    
    const bytes_val: Bytes = &[_]u8{ 1, 2, 3, 4 };
    try testing.expectEqual(@as(usize, 4), bytes_val.len);
    
    // Test that aliases point to correct types
    const ec_point = ECPoint.generator();
    try testing.expect(ec_point.isOnCurve());
    
    const hash160 = Hash160Type.ZERO;
    try testing.expect(hash160.eql(Hash160Type.init()));
    
    const hash256 = Hash256Type.ZERO;
    try testing.expect(hash256.eql(Hash256Type.init()));
}

test "SwiftMigration pattern examples" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Swift migration patterns (equivalent to Swift migration tests)
    const key_pair = try SwiftMigration.MigrationPatterns.createKeyPair();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    try testing.expect(key_pair.isValid());
    
    const address = try SwiftMigration.MigrationPatterns.getAddressFromKeyPair(key_pair, allocator);
    defer allocator.free(address);
    
    try testing.expect(address.len > 0);
    
    const hash160 = try SwiftMigration.MigrationPatterns.createHash160FromString("1234567890abcdef1234567890abcdef12345678");
    try testing.expect(!hash160.eql(Hash160Type.ZERO));
    
    var tx_builder = try SwiftMigration.MigrationPatterns.buildTransaction(allocator);
    defer tx_builder.deinit();
    
    _ = tx_builder.version(0);
    try testing.expectEqual(@as(u8, 0), tx_builder.version_field);
}

test "SwiftCompatibility helper functions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Swift compatibility helpers
    const hex_bytes = try SwiftCompatibility.bytesFromHex("1234abcd", allocator);
    defer allocator.free(hex_bytes);
    
    try testing.expectEqual(@as(usize, 4), hex_bytes.len);
    try testing.expectEqual(@as(u8, 0x12), hex_bytes[0]);
    
    const base58_encoded = try SwiftCompatibility.base58Encode(hex_bytes, allocator);
    defer allocator.free(base58_encoded);
    
    try testing.expect(base58_encoded.len > 0);
    
    // Test hash to address conversion
    const test_hash = try Hash160Type.initWithString("1234567890abcdef1234567890abcdef12345678");
    const address = try SwiftCompatibility.hashToAddress(test_hash, allocator);
    defer allocator.free(address);
    
    try testing.expect(address.len > 0);
}

test "Migration documentation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test documentation generation
    const type_mapping_doc = try SwiftMigration.TypeMapping.getTypeMappingDoc(allocator);
    defer allocator.free(type_mapping_doc);
    
    try testing.expect(type_mapping_doc.len > 0);
    try testing.expect(std.mem.indexOf(u8, type_mapping_doc, "ECKeyPair") != null);
    try testing.expect(std.mem.indexOf(u8, type_mapping_doc, "Hash160") != null);
    
    const error_guide = try SwiftMigration.ErrorMapping.getErrorMigrationGuide(allocator);
    defer allocator.free(error_guide);
    
    try testing.expect(error_guide.len > 0);
    try testing.expect(std.mem.indexOf(u8, error_guide, "NeoSwiftError") != null);
    
    const compatibility_guide = try SwiftCompatibility.getCompatibilityGuide(allocator);
    defer allocator.free(compatibility_guide);
    
    try testing.expect(compatibility_guide.len > 0);
    try testing.expect(std.mem.indexOf(u8, compatibility_guide, "Migration Guide") != null);
    try testing.expect(std.mem.indexOf(u8, compatibility_guide, "Memory Management") != null);
}