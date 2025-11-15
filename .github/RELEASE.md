# Release Process Documentation

This document describes how to create releases for NetUI using the automated CI/CD pipeline.

## Prerequisites

Before creating your first release, you need to configure the `CARGO_REGISTRY_TOKEN` secret in your GitHub repository:

1. **Get your crates.io API token:**
   - Log in to [crates.io](https://crates.io/)
   - Go to Account Settings → API Tokens
   - Click "New Token" and give it a name (e.g., "GitHub Actions")
   - Copy the generated token

2. **Add the token to GitHub Secrets:**
   - Go to your repository on GitHub
   - Navigate to Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `CARGO_REGISTRY_TOKEN`
   - Value: Paste your crates.io API token
   - Click "Add secret"

## Creating a Release

### Step 1: Update the version

Edit `Cargo.toml` and update the version number:

```toml
[package]
name = "netui"
version = "0.1.2"  # Update this version
```

### Step 2: Update dependencies (if needed)

Run `cargo update` to update `Cargo.lock` if you want to update dependencies.

### Step 3: Test locally

Before creating a release, ensure everything works:

```bash
# Run tests
cargo test

# Check formatting
cargo fmt --all -- --check

# Run linting
cargo clippy --all-targets --all-features -- -D warnings

# Check for security vulnerabilities
cargo audit

# Build release binary
cargo build --release
```

### Step 4: Commit changes

```bash
git add Cargo.toml Cargo.lock
git commit -m "Bump version to 0.1.2"
git push origin main
```

### Step 5: Create and push a tag

```bash
# Create a tag (must start with 'v')
git tag v0.1.2

# Push the tag to GitHub
git push origin v0.1.2
```

### Step 6: Automated release process

Once you push the tag, GitHub Actions will automatically:

1. **Create a GitHub Release** with the tag name
2. **Build binaries** for all supported platforms:
   - Linux x86_64 (GNU)
   - Linux x86_64 (MUSL - static binary)
   - Linux ARM64
   - macOS Intel (x86_64)
   - macOS Apple Silicon (aarch64)
   - Windows x86_64
3. **Upload binary artifacts** to the GitHub Release
4. **Publish to crates.io** automatically

You can monitor the progress in the "Actions" tab of your GitHub repository.

## Supported Platforms

The release workflow builds binaries for the following platforms:

| Platform | Target Triple | Binary Format |
|----------|--------------|---------------|
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| Linux x86_64 (static) | `x86_64-unknown-linux-musl` | `.tar.gz` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | `.tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `.tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `.tar.gz` |
| Windows x86_64 | `x86_64-pc-windows-msvc` | `.zip` |

## CI/CD Pipeline Overview

### CI Workflow (`rust.yml`)

Runs on every push and pull request to `main` and `releases` branches:

- **Test Job:** Builds and runs tests on Linux, macOS, and Windows
- **Clippy Job:** Runs Rust linter to catch common mistakes
- **Fmt Job:** Checks code formatting
- **Audit Job:** Checks for security vulnerabilities in dependencies

### Release Workflow (`release.yml`)

Triggered only when you push a tag starting with `v`:

1. **Create Release:** Creates a GitHub Release with release notes
2. **Build Release:** Compiles binaries for all supported platforms
3. **Publish to crates.io:** Automatically publishes the new version

## Troubleshooting

### Release workflow fails at "Publish to crates.io"

- Verify that `CARGO_REGISTRY_TOKEN` is correctly set in GitHub Secrets
- Check that you're the owner or have publish permissions for the crate on crates.io
- Ensure the version in `Cargo.toml` hasn't already been published

### Binary build fails for a specific platform

- Check the Actions logs for that specific platform
- Some dependencies might not support all platforms
- Cross-compilation issues may occur for ARM targets

### Tag already exists

If you need to re-release:

```bash
# Delete local tag
git tag -d v0.1.2

# Delete remote tag
git push origin :refs/tags/v0.1.2

# Create and push again
git tag v0.1.2
git push origin v0.1.2
```

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (x.0.0): Breaking changes
- **MINOR** (0.x.0): New features, backward compatible
- **PATCH** (0.0.x): Bug fixes, backward compatible

## Manual Publishing (Fallback)

If automated publishing fails, you can publish manually:

```bash
cargo publish --token YOUR_CRATES_IO_TOKEN
```

## Notes

- **Windows users** need [Npcap](https://npcap.com/#download) to use NetUI
- **Linux/macOS users** need root privileges to capture network packets
- The MUSL build (`x86_64-unknown-linux-musl`) is statically linked and works on any Linux distribution
