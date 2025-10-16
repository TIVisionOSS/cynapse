# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-10-16

### Added

- Initial release of Cynapse
- Cross-platform memory integrity monitoring (Linux, Windows, macOS)
- BLAKE3 and SHA-256 hashing support
- Merkle tree-based hierarchical verification
- Async background monitoring with configurable intervals
- Tamper detection callbacks
- Adaptive sampling based on risk
- JIT/self-modifying code whitelisting
- Signal and exception handling (SIGSEGV, SIGTRAP)
- Forensic snapshot capabilities (feature-gated)
- Remote attestation with Ed25519 signing (feature-gated)
- Comprehensive test suite with 80%+ coverage
- Performance benchmarks
- Full documentation and examples
- CI/CD pipeline with automated testing

### Core Features

- `Monitor` API for easy integration
- `MonitorBuilder` for advanced configuration
- `MemoryMapper` for cross-platform segment enumeration
- `HashEngine` for efficient page hashing
- `MerkleTree` for incremental verification
- `ForensicsManager` for tamper evidence collection
- `AttestationProof` for remote verification

### Examples

- `self_protect.rs` - Basic self-protection demo
- `server_daemon.rs` - Advanced server monitoring
- `forensic_analysis.rs` - Forensic snapshot demonstration

### Documentation

- Comprehensive README with quick start guide
- Security policy (SECURITY.md)
- Contributing guidelines (CONTRIBUTING.md)
- Dual MIT/Apache-2.0 licensing
- API documentation for all public items

### Platform Support

- Linux via `/proc/self/maps` and direct memory reading
- Windows via `VirtualQuery` and `ReadProcessMemory`
- macOS via Mach kernel APIs

### Security

- Minimal unsafe code with documented safety invariants
- Miri-validated for undefined behavior
- Comprehensive threat model documentation
- Responsible disclosure policy

## [0.0.1] - Development

### Added

- Initial project setup
- Core architecture design
- Platform abstraction layer

---

[Unreleased]: https://github.com/TIVisionOSS/cynapse/compare/v0.1.0...master
[0.1.0]: https://github.com/TIVisionOSS/cynapse/releases/tag/v0.1.0
