# Contributing to Neo Zig SDK

Thank you for your interest in contributing to the Neo Zig SDK! This guide helps you get started contributing to the Zig implementation of a Neo N3 SDK.

## 🎯 Project Overview

The Neo Zig SDK targets NeoSwift API familiarity while adopting Zig conventions:

- explicit memory management (`deinit`, allocators)
- explicit error propagation (`try`)
- test coverage for core workflows

## 🚀 Getting Started

### Prerequisites

- [Zig 0.14.0+](https://ziglang.org/download/)
- Git
- Basic understanding of Neo blockchain
- Familiarity with Zig programming language

### Development Setup

1. **Clone the repository**
   ```bash
   git clone git@github.com:r3e-network/neo-zig-sdk.git
   cd neo-zig-sdk
   ```

2. **Build the project**
   ```bash
   zig build
   ```

3. **Run tests**
   ```bash
   zig build test
   ```

4. **Run examples**
   ```bash
   zig build examples
   ```

## 📋 Development Guidelines

### Code Style

- Follow standard Zig formatting (`zig fmt`)
- Use clear, descriptive variable and function names
- Add comprehensive documentation comments for public APIs
- Ensure memory safety with explicit allocator management
- Validate all inputs and handle errors explicitly

### Security Requirements

- **Never expose private keys** in logs or error messages
- **Validate all inputs** from external sources
- **Use secure random** for all cryptographic operations
- **Implement constant-time** operations for sensitive data
- **Clear sensitive data** from memory after use

### Performance Guidelines

- **Minimize allocations** in hot paths
- **Use stack allocation** for fixed-size data
- **Implement zero-copy** operations where possible
- **Profile critical paths** and optimize bottlenecks
- **Benchmark new features** against performance targets

## 🧪 Testing

### Test Requirements

- **Add tests** for all new functionality
- **Cover edge cases** and error conditions
- **Include performance** benchmarks for critical operations
- **Validate security** implications of changes
- **Test memory safety** with leak detection

### Running Tests

```bash
# Run all tests
zig build test

# Run specific test suite
zig test src/crypto/keys.zig
zig test tests/crypto_tests.zig

# Run with summary
zig build test --summary all

# Performance benchmarks
zig build bench
```

## 📝 Documentation

### Documentation Requirements

- **Document all public APIs** with clear descriptions
- **Provide usage examples** for complex functionality
- **Explain security implications** of cryptographic operations
- **Include performance characteristics** for operations
- **Update README** for significant changes

### Documentation Style

```zig
/// Generates a new cryptographically secure private key.
///
/// This function uses the OS cryptographic random number generator
/// to create a private key that is guaranteed to be in the valid
/// range for the secp256r1 curve.
///
/// ## Security
/// The generated key is cryptographically secure and suitable for
/// production use. Always zeroize the key after use.
///
/// ## Performance
/// Key generation typically takes <10ms on modern hardware.
///
/// ## Example
/// ```zig
/// const private_key = neo.crypto.generatePrivateKey();
/// defer private_key.zeroize();
/// ```
pub fn generatePrivateKey() PrivateKey {
    // Implementation...
}
```

## 🔄 Contribution Process

### 1. Issue Discussion

- **Create an issue** to discuss significant changes
- **Search existing issues** to avoid duplicates
- **Provide clear description** of the problem or feature
- **Include examples** and use cases when relevant

### 2. Development

- **Fork the repository** and create a feature branch
- **Follow coding guidelines** and style requirements
- **Write comprehensive tests** for new functionality
- **Update documentation** as needed
- **Ensure no regressions** in existing functionality

### 3. Pull Request

- **Create descriptive PR title** summarizing the change
- **Provide detailed description** of what was changed and why
- **Include test results** and performance impact
- **Link related issues** and discussions
- **Request review** from maintainers

### Pull Request Template

```markdown
## Description
Brief description of the changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Performance benchmarks included (if applicable)
- [ ] Security review completed (if applicable)

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Documentation updated
- [ ] No sensitive information exposed
- [ ] Memory safety verified
```

## 🐛 Bug Reports

### Bug Report Template

```markdown
## Bug Description
Clear and concise description of the bug.

## To Reproduce
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. See error

## Expected Behavior
Clear description of what you expected to happen.

## Environment
- OS: [e.g. Ubuntu 22.04]
- Zig Version: [e.g. 0.12.0]
- Neo Zig SDK Version: [e.g. 1.0.1]

## Additional Context
Add any other context about the problem here.
```

## 💡 Feature Requests

### Feature Request Template

```markdown
## Feature Description
Clear and concise description of the desired feature.

## Motivation
Explain why this feature would be valuable.

## Proposed Solution
Describe how you envision the feature working.

## Alternatives Considered
Describe alternative solutions you've considered.

## Additional Context
Add any other context about the feature request.
```

## 🛡️ Security

### Security Policy

- **Report security vulnerabilities** privately to jimmy@r3e.network
- **Do not create public issues** for security vulnerabilities
- **Include detailed description** and reproduction steps
- **Allow time for assessment** and fix development

### Security Guidelines

- **Never commit secrets** or private keys
- **Validate all inputs** from external sources
- **Use secure coding practices** throughout
- **Follow cryptographic best practices**
- **Implement proper error handling** without information leakage

## 📞 Communication

### Getting Help

- **GitHub Discussions**: For general questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Email**: jimmy@r3e.network for direct communication
- **Documentation**: Check existing docs before asking questions

### Code of Conduct

- **Be respectful** and inclusive in all interactions
- **Focus on technical merit** in discussions
- **Help others learn** and contribute
- **Maintain professional** communication standards
- **Follow open source** best practices

## 🏆 Recognition

Contributors will be recognized in:
- **README acknowledgments**
- **Release notes** for significant contributions
- **Contributor lists** in documentation
- **Special recognition** for security improvements

## 📈 Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Criteria

- **All tests pass** across all platforms
- **Security review** completed for crypto changes
- **Performance benchmarks** meet targets
- **Documentation** updated and complete
- **Breaking changes** clearly documented

---

## 🎯 Areas for Contribution

### High Priority
- **Performance optimizations** for critical paths
- **Additional test coverage** for edge cases
- **Documentation improvements** and examples
- **Cross-platform testing** and validation

### Medium Priority
- **Additional utility functions** for developer convenience
- **Enhanced error messages** with better context
- **Performance monitoring** and metrics
- **Integration examples** with popular tools

### Advanced Contributions
- **Cryptographic optimizations** (with security review)
- **Protocol extensions** for future Neo features
- **Advanced tooling** for development workflows
- **Research and benchmarking** studies

---

**Thank you for contributing to the Neo Zig SDK! Together, we're building the future of Neo blockchain development.** 🚀

*For questions or support, reach out to jimmy@r3e.network or create a GitHub issue.*
