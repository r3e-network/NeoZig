# Security Policy

## 🛡️ Security Features

The Neo Zig SDK aims to be secure-by-default, but security is a process: review, test, and threat-model your usage (especially around key management and networking).

### Cryptographic Security
- **secp256r1 ECDSA**: Production-grade elliptic curve cryptography
- **RFC 6979**: Deterministic signature generation prevents nonce reuse
- **RIPEMD-160**: Full implementation with test vector validation
- **Secure Random**: Uses OS cryptographic random number generator
- **Timing-safe comparisons**: Uses `std.crypto.timing_safe` for secret equality checks where applicable (not a blanket constant-time guarantee)

### Memory Safety
- **Bounds checks in safe code**: Zig helps prevent common memory bugs when you stay in safe code
- **Explicit allocators**: Most APIs are allocator-aware; convenience constructors may allocate using `std.heap.page_allocator`
- **Secure Zeroization**: Private keys are securely erased from memory
- **Unsafe operations reviewed**: Some low-level code uses casts/pointers for performance and protocol parsing; treat these as review hotspots

### Input Validation
- **Comprehensive Validation**: All inputs validated with proper error reporting
- **Hash Validation**: Hash formats and lengths strictly validated
- **Address Validation**: Base58Check validation with checksum verification
- **Parameter Validation**: Contract parameters validated according to Neo VM rules

### Network Security
- **TLS by configuration**: Use HTTPS endpoints for mainnet/testnet
- **Request Validation**: JSON-RPC requests properly validated
- **Error Handling**: Detailed error reporting without information leakage
- **Best-effort timeouts**: `std.http` lacks per-request socket deadlines; the SDK uses elapsed-time guards and retry limits to avoid hanging forever

## 🔒 Secure Usage Guidelines

### Private Key Management
```zig
// ✅ Good: Generate secure keys
const private_key = neo.crypto.generatePrivateKey();

// ✅ Good: Securely zeroize when done
var key_pair = try neo.crypto.generateKeyPair(true);
defer key_pair.zeroize();

// ❌ Avoid: Hardcoded keys in source code
// const key = try PrivateKey.fromHex("hardcoded_hex");
```

### Transaction Security
```zig
// ✅ Good: Validate transactions before signing
try transaction.validate();
const signed_tx = try builder.sign(&[_]PrivateKey{private_key}, network_magic);

// ✅ Good: Use proper network magic
const mainnet_magic = constants.NetworkMagic.MAINNET;
```

### Wallet Security
```zig
// ✅ Good: Use strong passwords for wallet encryption
const strong_password = "MyStrongPassword123!@#";
const account = try wallet.importAccount(private_key, strong_password, "Main Account");

// ❌ Avoid: Weak or empty passwords
// const weak_password = "";
```

## 🚨 Reporting Security Vulnerabilities

If you discover a security vulnerability in the Neo Zig SDK:

1. **DO NOT** open a public GitHub issue
2. Email security reports to: `jimmy@r3e.network`
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fixes (if any)

### Response Timeline
- **24 hours**: Initial acknowledgment
- **72 hours**: Preliminary assessment
- **7 days**: Detailed analysis and fix timeline
- **30 days**: Security patch release (if applicable)

## 🔍 Security Audit Trail

### Cryptographic Implementation Audit
- **Algorithm Compliance**: All algorithms follow industry standards
- **Test Vector Validation**: Cryptographic functions validated against known test vectors
- **Side-Channel Notes**: Timing-safe comparisons are used in some paths; this is not a formal side-channel hardening claim
- **Key Generation**: Uses cryptographically secure random number generation

### Code Security Review
- **Memory Safety**: Zig safety checks + explicit ownership; unsafe casts require review
- **Input Sanitization**: All external inputs properly validated
- **Error Handling**: Comprehensive error handling without information leakage
- **Dependency Security**: Minimal dependencies, all from trusted sources

### Network Security Assessment
- **TLS**: Use HTTPS endpoints for production
- **Certificate Validation**: Delegated to Zig stdlib HTTP/TLS behaviour and the platform certificate bundle configuration
- **Request/Response Validation**: All JSON-RPC communications validated
- **Timeouts**: Best-effort via elapsed-time checks and retry limits (not a hard socket deadline)

## 📋 Security Checklist

Before using the Neo Zig SDK in production:

- [ ] Use the latest stable version
- [ ] Enable all compiler warnings and security features
- [ ] Use strong passwords for wallet encryption
- [ ] Validate all external inputs
- [ ] Use HTTPS endpoints for mainnet/testnet
- [ ] Implement proper error handling
- [ ] Securely store and handle private keys
- [ ] Regularly update dependencies
- [ ] Monitor for security advisories
- [ ] Test all cryptographic operations

## 🏆 Security Certifications

- **Memory Safety**: Zig safety checks + explicit ownership (not a formal certification)
- **Cryptographic Compliance**: RFC standards (6979, NEP-2, NEP-6)
- **Test Coverage**: Comprehensive test suite with edge cases
- **Code Quality**: Security-first design and regression coverage

## 📚 Security Resources

- [Neo Security Best Practices](https://docs.neo.org/docs/en-us/develop/write/security.html)
- [Zig Security Guidelines](https://ziglang.org/learn/overview/#performance-and-safety-choose-two)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [RFC 6979: Deterministic Usage of DSA and ECDSA](https://tools.ietf.org/html/rfc6979)

---

**Security is our top priority. The Neo Zig SDK is designed with security-first principles throughout.**
