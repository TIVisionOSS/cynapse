# Contributing to Cynapse

Thank you for your interest in contributing to Cynapse! We welcome contributions from the community.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- Be respectful and considerate
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Assume good intentions

---

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Git
- A GitHub account (for pull requests)

### Setting Up Your Development Environment

```bash
# Clone the repository
git clone https://github.com/TIVisionOSS/cynapse.git
cd cynapse

# Build the project
cargo build

# Run tests
cargo test

# Run tests with all features
cargo test --all-features

# Run clippy
cargo clippy --all-targets --all-features

# Format code
cargo fmt
```

---

## Development Workflow

### 1. Find an Issue

- Check the [issue tracker](https://github.com/TIVisionOSS/cynapse/issues)
- Look for issues tagged `good-first-issue` or `help-wanted`
- Comment on the issue to let others know you're working on it

### 2. Create a Branch

```bash
# Create a new branch from master
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-number-description
```

### 3. Make Changes

- Write clean, idiomatic Rust code
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Add tests for new functionality
- Update documentation as needed

### 4. Commit Your Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add new feature X"

# Or for bug fixes
git commit -m "fix: resolve issue #123"
```

**Commit Message Format:**

- `feat: description` — New feature
- `fix: description` — Bug fix
- `docs: description` — Documentation changes
- `test: description` — Test additions or changes
- `refactor: description` — Code refactoring
- `perf: description` — Performance improvements
- `chore: description` — Maintenance tasks

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create a pull request on GitHub
# Include a clear description of changes
# Reference related issues (e.g., "Closes #123")
```

---

## Coding Standards

### Rust Style

- Follow the [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/)
- Run `cargo fmt` before committing
- Ensure `cargo clippy` passes without warnings

### Code Organization

```
src/
├── lib.rs           # Public API and re-exports
├── core/            # Core functionality
│   ├── mapper.rs    # Memory mapping
│   ├── hasher.rs    # Hashing and Merkle trees
│   ├── monitor.rs   # Monitoring logic
│   └── ...
├── platform/        # Platform-specific code
│   ├── linux.rs
│   ├── windows.rs
│   └── macos.rs
└── utils/           # Utility functions
```

### Unsafe Code

- **Minimize unsafe:** Only use when absolutely necessary
- **Document safety:** Every unsafe block must have a `// SAFETY:` comment explaining why it's safe
- **Isolate unsafe:** Keep unsafe code in small, well-tested functions
- **Test with Miri:** Run `cargo +nightly miri test` to catch undefined behavior

Example:

```rust
// SAFETY: We're reading from our own process memory at a valid address.
// The caller must ensure the address range is valid and readable.
unsafe {
    std::ptr::copy_nonoverlapping(src, dst, size);
}
```

### Error Handling

- Use `Result<T, Error>` for fallible operations
- Provide descriptive error messages
- Use `thiserror` for error types
- Avoid panics in library code (use `Result` instead)

### Documentation

- Add doc comments (`///`) for all public items
- Include examples in doc comments
- Use `#[doc(hidden)]` for implementation details
- Write module-level documentation

Example:

```rust
/// Hash a memory page using the configured algorithm.
///
/// # Arguments
///
/// * `data` - The page contents to hash
/// * `address` - The memory address of the page
///
/// # Returns
///
/// A `HashedPage` containing the hash and metadata.
///
/// # Example
///
/// ```
/// use cynapse::core::hasher::{HashEngine, HashAlgorithm};
///
/// let engine = HashEngine::new(HashAlgorithm::Blake3);
/// let data = vec![0u8; 4096];
/// let page = engine.hash_page(&data, 0x1000).unwrap();
/// ```
pub fn hash_page(&self, data: &[u8], address: usize) -> Result<HashedPage> {
    // Implementation
}
```

---

## Testing

### Test Organization

```
tests/
├── integration/      # Integration tests
│   ├── basic_monitoring.rs
│   └── memory_operations.rs
└── platform/         # Platform-specific tests
    └── platform_tests.rs
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_name() {
        // Arrange
        let input = create_test_input();

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected_output);
    }

    #[test]
    #[should_panic(expected = "error message")]
    fn test_error_condition() {
        // Test error handling
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run platform-specific tests
cargo test --test platform_tests

# Run with all features
cargo test --all-features

# Run benchmarks
cargo bench
```

### Test Coverage

- Aim for **80%+ code coverage**
- Test edge cases and error conditions
- Test platform-specific code on relevant platforms

---

## Documentation

### Building Documentation

```bash
# Build and open documentation
cargo doc --no-deps --open

# Build with all features
cargo doc --all-features --no-deps --open
```

### Documentation Checklist

- [ ] All public items have doc comments
- [ ] Examples are included and tested
- [ ] Module-level documentation explains purpose
- [ ] Links to related types and functions work
- [ ] README.md is updated if needed

---

## Submitting Changes

### Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] Code follows Rust style guidelines
- [ ] `cargo fmt` has been run
- [ ] `cargo clippy` passes without warnings
- [ ] All tests pass (`cargo test --all-features`)
- [ ] New tests are added for new functionality
- [ ] Documentation is updated
- [ ] Commit messages are clear and descriptive
- [ ] No merge conflicts with `master`

### Pull Request Template

```markdown
## Description

Brief description of changes.

## Related Issues

Closes #123

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

Describe how you tested the changes.

## Checklist

- [ ] Tests pass
- [ ] Documentation updated
- [ ] Code formatted
- [ ] Clippy passes
```

### Review Process

1. Submit pull request
2. Automated CI checks run
3. Maintainers review code
4. Address feedback if needed
5. Merge after approval

---

## Platform-Specific Contributions

### Linux

- Test on recent kernel versions (5.x+)
- Consider different distributions
- Test with SELinux/AppArmor if applicable

### Windows

- Test on Windows 10/11
- Consider both x64 and x86
- Test with different Windows Security settings

### macOS

- Test on recent macOS versions (12+)
- Test on both Intel and Apple Silicon

---

## Adding New Features

### Feature Flags

When adding optional functionality:

1. Add feature flag to `Cargo.toml`:

```toml
[features]
new-feature = ["dep:new-dependency"]
```

2. Use `#[cfg(feature = "new-feature")]` for feature-gated code

3. Update documentation to mention the feature

4. Add tests that run with and without the feature

### Breaking Changes

- Avoid breaking changes if possible
- Document breaking changes clearly
- Follow semantic versioning
- Provide migration guide

---

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR:** Breaking changes
- **MINOR:** New features (backward compatible)
- **PATCH:** Bug fixes (backward compatible)

### Release Checklist

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run full test suite
4. Build and test documentation
5. Tag release
6. Publish to crates.io
7. Announce release

---

## Community

### Getting Help

- **GitHub Issues:** Report bugs or request features
- **Discussions:** Ask questions or share ideas
- **Email:** Contact maintainers directly for sensitive topics

### Recognition

Contributors are recognized in:

- Release notes
- `CONTRIBUTORS.md` file
- Git commit history

---

## License

By contributing to Cynapse, you agree that your contributions will be licensed under the same dual MIT/Apache-2.0 license.

---

## Questions?

If you have questions about contributing, feel free to:

- Open an issue with the `question` label
- Start a discussion
- Contact the maintainers

Thank you for contributing to Cynapse! 🧠
