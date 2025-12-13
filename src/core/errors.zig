//! Error types for Neo Zig SDK
//!
//! Complete conversion from NeoSwift error handling system.
//! All error types match the original Swift implementation.
//!
//! Design principles:
//! - Each error set has domain-specific, non-overlapping error names
//! - Error names are prefixed with domain context for clarity
//! - Use throwIllegalArgument/throwIllegalState for Swift API compatibility

const std = @import("std");
const builtin = @import("builtin");

const log = std.log.scoped(.neo_errors);

/// General Neo SDK errors (converted from NeoSwiftError)
pub const NeoError = error{
    IllegalArgument,
    IllegalState,
    UnsupportedOperation,
    InvalidConfiguration,
    OperationTimeout,
    ResourceNotFound,
    AccessDenied,
    OperationCancelled,
    ServiceUnavailable,
};

/// Cryptographic operation errors
pub const CryptoError = error{
    InvalidKey,
    InvalidSignature,
    SignatureVerificationFailed,
    InvalidKeyPair,
    CryptoOperationFailed,
    InvalidCurvePoint,
    KeyGenerationFailed,
    KeyDerivationFailed,
    InvalidHash,
    RandomGenerationFailed,
    InvalidWIF,
    InvalidCompressedKey,
    ECDSAOperationFailed,
};

/// Serialization and deserialization errors
pub const SerializationError = error{
    InvalidFormat,
    DataTooLarge,
    UnexpectedEndOfData,
    InvalidLength,
    BufferOverflow,
    InvalidEncoding,
    MalformedData,
    VersionMismatch,
    InvalidType,
    DeserializationFailed,
    SerializationFailed,
};

/// Validation errors
pub const ValidationError = error{
    InvalidAddress,
    InvalidLength,
    InvalidFormat,
    InvalidHash,
    InvalidParameter,
    ParameterOutOfRange,
    RequiredParameterMissing,
    InvalidChecksum,
    InvalidNetwork,
    InvalidTransaction,
    InvalidBlock,
    InvalidScript,
    ValidationFailed,
};

/// Network and RPC errors
pub const NetworkError = error{
    ConnectionFailed,
    NetworkTimeout,
    InvalidResponse,
    ServerError,
    ProtocolError,
    AuthenticationFailed,
    RateLimitExceeded,
    NetworkUnavailable,
    InvalidEndpoint,
    RequestFailed,
};

/// Transaction errors
pub const TransactionError = error{
    InsufficientFunds,
    InvalidVersion,
    InvalidNonce,
    TransactionTooLarge,
    InvalidGasPrice,
    InvalidGasLimit,
    TransactionAlreadyExists,
    TransactionExpired,
    InvalidSigner,
    MissingSignature,
    SigningFailed,
    InvalidWitness,
    InvalidTransaction,
    InvalidParameters,
};

/// Wallet operation errors
pub const WalletError = error{
    WalletNotFound,
    InvalidPassword,
    WalletLocked,
    InvalidWalletFormat,
    AccountNotFound,
    DuplicateAccount,
    InsufficientBalance,
    InvalidAccount,
    DecryptionFailed,
    EncryptionFailed,
    KeyDerivationFailed,
};

/// Contract interaction errors
pub const ContractError = error{
    ContractNotFound,
    InvalidContract,
    ContractExecutionFailed,
    InvalidMethod,
    InvalidParameters,
    ContractCallFailed,
    InsufficientGas,
    ContractFault,
    MethodNotFound,
    InvalidContractState,
};

/// Utility function to convert Swift error messages.
/// Emits a debug log (in Debug builds) before returning the error.
/// This provides context that Zig's error system cannot carry. Enable debug logs by
/// setting `std_options.log_level = .debug` in your root file.
pub fn throwIllegalArgument(message: []const u8) NeoError {
    // Best-effort diagnostic context; no hard stdout/stderr side effects.
    if (builtin.mode == .Debug) {
        log.debug("IllegalArgument: {s}", .{message});
    }
    return NeoError.IllegalArgument;
}

/// Utility function to convert Swift error messages.
/// Emits a debug log (in Debug builds) before returning the error.
pub fn throwIllegalState(message: []const u8) NeoError {
    // Best-effort diagnostic context; no hard stdout/stderr side effects.
    if (builtin.mode == .Debug) {
        log.debug("IllegalState: {s}", .{message});
    }
    return NeoError.IllegalState;
}

test "error types validation" {
    const testing = std.testing;
    
    // Test error creation and handling
    const crypto_error: CryptoError = CryptoError.InvalidKey;
    const validation_error: ValidationError = ValidationError.InvalidAddress;
    
    try testing.expect(crypto_error == CryptoError.InvalidKey);
    try testing.expect(validation_error == ValidationError.InvalidAddress);
}
