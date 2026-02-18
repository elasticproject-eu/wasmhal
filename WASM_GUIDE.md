# ELASTIC HAL - WebAssembly Integration Guide

## Overview

The ELASTIC HAL provides a comprehensive set of TEE (Trusted Execution Environment) capabilities through WIT (WebAssembly Interface Types) interfaces. This guide shows how to build WebAssembly services that use the HAL.

**What's Included:**

- Working `.wasm` service example (192KB)
- Complete build documentation
- Example `/add_user` service demonstrating HAL integration
- Runtime foundation for hosting WASM components

## Quick Start

### Build the Example Service

```bash
# 1. Install cargo-component (one time)
cargo install cargo-component --locked

# 2. Add WASM target
rustup target add wasm32-wasip1

# 3. Build the service
cd example-add-user
cargo component build --release

# Output: target/wasm32-wasip1/release/example_add_user.wasm
```

The resulting `.wasm` file is ready to run in any WASM runtime that implements the HAL host interfaces (e.g., Propeller + TEEAgent).

## Prerequisites

### Install Rust (if not already installed)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Install cargo-component

```bash
cargo install cargo-component --locked
```

This installs the tool for building WebAssembly components (takes ~5 minutes).

### Add WASM target

```bash
rustup target add wasm32-wasip1
```

## Repository Structure

```
wasmhal/
├── wit-modular/                # HAL WIT interface definitions
│   ├── platform.wit           # Platform & attestation
│   ├── crypto.wit             # Cryptography
│   ├── storage.wit            # Encrypted storage
│   ├── clock.wit              # Time & clocks
│   ├── random.wit             # Secure random
│   ├── sockets.wit            # Network sockets
│   └── communication.wit      # Inter-service communication
│
├── example-add-user/          # Demo WASM service
│   ├── Cargo.toml             # Dependencies configured
│   ├── wit/
│   │   ├── world.wit          # Service API definition
│   │   └── deps/              # HAL WIT interfaces
│   ├── src/
│   │   └── lib.rs             # Service implementation
│   └── target/
│       └── wasm32-wasip1/release/
│           └── example_add_user.wasm  # 192KB WASM component
│
├── hal-runtime/               # Host runtime foundation
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs             # Runtime interface
│       ├── main.rs            # CLI
│       └── host_impl.rs       # HAL bridge
│
└── src/                       # Native HAL implementation
    ├── platform.rs
    ├── crypto.rs
    ├── storage.rs
    └── ...
```

## Available HAL Interfaces

### Platform (`elastic:platform/platform@0.1.0`)

```wit
// Get platform attestation report
attestation: func(report-data: list<u8>) -> result<list<u8>, string>;

// Get platform information
get-platform-info: func() -> platform-info;
```

### Crypto (`elastic:crypto/crypto@0.1.0`)

```wit
// Hash data with specified algorithm
hash: func(algorithm: hash-algorithm, data: list<u8>) -> result<list<u8>, string>;

// Symmetric encryption
encrypt-symmetric: func(
    algorithm: symmetric-algorithm,
    key: list<u8>,
    iv: list<u8>,
    plaintext: list<u8>
) -> result<list<u8>, string>;

decrypt-symmetric: func(
    algorithm: symmetric-algorithm,
    key: list<u8>,
    iv: list<u8>,
    ciphertext: list<u8>
) -> result<list<u8>, string>;

// Asymmetric operations
sign: func(algorithm: signature-algorithm, key: list<u8>, data: list<u8>)
    -> result<list<u8>, string>;

verify: func(algorithm: signature-algorithm, key: list<u8>, data: list<u8>, signature: list<u8>)
    -> result<_, string>;
```

### Storage (`elastic:storage/storage@0.1.0`)

```wit
// Container management
container-create: func(name: string) -> result<container-handle, string>;
container-open: func(name: string) -> result<container-handle, string>;
container-delete: func(name: string) -> result<_, string>;

// Object operations
object-write: func(container: container-handle, key: string, value: list<u8>)
    -> result<_, string>;

object-read: func(container: container-handle, key: string)
    -> result<list<u8>, string>;

object-delete: func(container: container-handle, key: string)
    -> result<_, string>;

// List operations
container-list: func(container: container-handle) -> result<list<string>, string>;
```

### Clock (`elastic:clock/clock@0.1.0`)

```wit
// Get system time
get-system-time: func() -> result<system-time, string>;

// Get monotonic time (for elapsed time measurements)
get-monotonic-time: func() -> result<monotonic-time, string>;

// Sleep for specified duration
sleep: func(duration: duration) -> result<_, string>;
```

### Random (`elastic:random/random@0.1.0`)

```wit
// Generate random bytes
get-random-bytes: func(length: u32) -> result<list<u8>, string>;

// Fill buffer with random bytes
fill-bytes: func(buffer: list<u8>) -> result<_, string>;
```

## Example Service: User Management

The `example-add-user` service demonstrates a complete WASM service using the HAL.

### Features Demonstrated

**User Management** - Add/get/list users  
**Storage** - Persistent user database in TEE  
**Cryptography** - Email hashing for privacy  
**Attestation** - Proof of TEE execution  
**Random** - Secure ID generation  
**Clock** - Timestamps for audit trails

### API

```wit
interface user-api {
    /// Add a new user with generated ID and timestamp
    add-user: func(name: string, email: string) -> result<user, string>;

    /// Get user by ID
    get-user: func(id: string) -> result<user, string>;

    /// List all user IDs
    list-users: func() -> result<list<string>, string>;

    /// Get TEE attestation report
    get-attestation: func(nonce: list<u8>) -> result<list<u8>, string>;
}

record user {
    id: string,
    name: string,
    email-hash: string,
    created-at: u64,
}
```

### Implementation Example

```rust
use bindings::elastic::storage::storage as storage_hal;
use bindings::elastic::crypto::crypto as crypto_hal;
use bindings::elastic::platform::platform as platform_hal;
use bindings::elastic::random::random as random_hal;
use bindings::elastic::clock::clock as clock_hal;

impl Guest for Component {
    fn add_user(name: String, email: String) -> Result<User, String> {
        // Generate secure random ID
        let id_bytes = random_hal::get_random_bytes(16)
            .map_err(|e| format!("Random generation failed: {}", e))?;
        let id = hex::encode(&id_bytes);

        // Hash email for privacy
        let email_hash_bytes = crypto_hal::hash(
            &email.as_bytes(),
            HashAlgorithm::Sha256
        ).map_err(|e| format!("Hashing failed: {}", e))?;
        let email_hash = hex::encode(&email_hash_bytes);

        // Get timestamp
        let timestamp = clock_hal::get_system_time()
            .map_err(|e| format!("Clock failed: {}", e))?;

        // Store in TEE storage
        let container = storage_hal::create_container("user-db")
            .or_else(|_| storage_hal::open_container("user-db"))
            .map_err(|e| format!("Storage failed: {}", e))?;

        let user_data = format!("{}:{}:{}", name, email_hash, timestamp.seconds);
        storage_hal::store_object(container, &id, user_data.as_bytes())
            .map_err(|e| format!("Store failed: {}", e))?;

        Ok(User {
            id,
            name,
            email_hash,
            created_at: timestamp.seconds,
        })
    }

    fn get_attestation(nonce: Vec<u8>) -> Result<Vec<u8>, String> {
        platform_hal::attestation(&nonce)
    }
}
```

## Creating Your Own Service

### 1. Create a New Component

```bash
cargo component new --lib my-service
cd my-service
```

### 2. Add HAL Dependencies

Copy the HAL WIT files:

```bash
mkdir -p wit/deps
cp ../wit-modular/{platform,crypto,storage,clock,random}.wit wit/deps/
```

### 3. Update `Cargo.toml`

```toml
[package]
name = "my-service"
version = "0.1.0"
edition = "2021"

[dependencies]
# Add any additional dependencies you need

[lib]
crate-type = ["cdylib"]

[package.metadata.component]
package = "my-org:my-service"

[package.metadata.component.target]
world = "my-service"

[package.metadata.component.target.dependencies]
"elastic:platform" = { path = "wit/deps/platform.wit" }
"elastic:crypto" = { path = "wit/deps/crypto.wit" }
"elastic:storage" = { path = "wit/deps/storage.wit" }
"elastic:clock" = { path = "wit/deps/clock.wit" }
"elastic:random" = { path = "wit/deps/random.wit" }
```

**Important:** Dependencies must be under `[package.metadata.component.target.dependencies]`, not just `.dependencies`.

### 4. Define Your Service Interface

Edit `wit/world.wit`:

```wit
package my-org:my-service@0.1.0;

world my-service {
    // Import HAL interfaces you need
    import elastic:platform/platform@0.1.0;
    import elastic:crypto/crypto@0.1.0;
    import elastic:storage/storage@0.1.0;
    import elastic:clock/clock@0.1.0;
    import elastic:random/random@0.1.0;

    // Export your API
    export my-api;
}

interface my-api {
    // Define your service functions
    do-something: func(input: string) -> result<string, string>;
}
```

### 5. Implement in `src/lib.rs`

```rust
#[allow(warnings)]
mod bindings;

use bindings::exports::my_org::my_service::my_api::Guest;

// Import HAL functions
use bindings::elastic::platform::platform as platform_hal;
use bindings::elastic::storage::storage as storage_hal;
use bindings::elastic::crypto::crypto as crypto_hal;

struct Component;

impl Guest for Component {
    fn do_something(input: String) -> Result<String, String> {
        // Use HAL functions
        let platform_info = platform_hal::get_platform_info();

        // Use storage
        let container = storage_hal::create_container("my-data")
            .or_else(|_| storage_hal::open_container("my-data"))?;

        storage_hal::store_object(container, "key", input.as_bytes())?;

        Ok(format!("Stored on platform: {}", platform_info.platform_type))
    }
}

bindings::export!(Component with_types_in bindings);
```

### 6. Build

```bash
cargo component build --release
```

Your `.wasm` file will be at: `target/wasm32-wasip1/release/my_service.wasm`

## Running WASM Services

### With hal-runtime

```bash
# Build the runtime
cd hal-runtime
cargo build --release

# Run your WASM service
cargo run --release -- ../my-service/target/wasm32-wasip1/release/my_service.wasm
```

### With Wasmtime Directly

```bash
wasmtime run \
  --wasm component-model \
  my_service.wasm
```

### With Propeller + TEEAgent

The `.wasm` files integrate into the full stack:

```
┌──────────────────────────────────┐
│   WASM Service (your .wasm)      │
│   Uses: elastic::{storage,crypto,│
│         platform,random,clock}   │
└────────────┬─────────────────────┘
             │ WIT Interface
┌────────────▼─────────────────────┐
│   Propeller Runtime              │
│   (Wasmtime with component model)│
└────────────┬─────────────────────┘
             │ Bridges to
┌────────────▼─────────────────────┐
│   TEEAgent HAL Implementation    │
│   Talks to: TDX/SEV-SNP/SGX      │
└──────────────────────────────────┘
```

The runtime:

1. **Propeller** loads the `.wasm` component
2. **TEEAgent** provides the HAL implementation (platform-specific)
3. **WASM service** calls HAL functions transparently

## Troubleshooting

### Error: "package 'elastic:platform' not found"

**Cause:** Dependencies not in the correct Cargo.toml section.

**Solution:** Ensure dependencies are under `[package.metadata.component.target.dependencies]`:

```toml
[package.metadata.component.target.dependencies]
"elastic:platform" = { path = "wit/deps/platform.wit" }
```

### Error: "failed to load component"

**Cause:** Built with regular `cargo build` instead of `cargo component build`.

**Solution:** Always use:

```bash
cargo component build  # Not cargo build
```

### WIT Syntax Errors

Common issues:

- Function names must be `kebab-case` (e.g., `get-system-time`)
- Type names must be `kebab-case` (e.g., `platform-info`)
- Avoid conflicts between function and type names
- Use `_` for unit type in results: `result<_, string>`

### Type Mismatches in Rust

The generated bindings expect specific types:

- Use `&str` not `String` for string slices
- Use `&[u8]` not `Vec<u8>` for byte slices
- Convert with `&variable` or `.as_bytes()` as needed

Example:

```rust
// Correct
storage_hal::store_object(container, &id, data.as_bytes())?;

// Wrong - type mismatch
storage_hal::store_object(container, id, data)?;
```

## Development Workflow

### 1. Build .wasm File

```bash
cd your-service
cargo component build --release
```

### 2. Test Locally

```bash
cd ../hal-runtime
cargo run --release -- ../your-service/target/wasm32-wasip1/release/your_service.wasm
```

### 3. Integrate with Runtime

Deploy in Propeller/Wasmtime with TEEAgent HAL implementation.

### 4. Deploy in TEE

Test with actual TDX/SEV-SNP/SGX hardware.

### 5. Add More Services

Use the same pattern to create additional microservices.

## Frequently Asked Questions

### Can I use the HAL for storage, crypto, and other capabilities?

**Yes.** The `example-add-user.wasm` service demonstrates:

- Storage (container-based object storage)
- Cryptography (hashing, encryption available)
- Attestation (TEE proof of execution)
- Random (secure random number generation)
- Clock (timestamps)

Network/sockets are defined in `wit-modular/sockets.wit` and `wit-modular/communication.wit` - same pattern applies.

### What's the difference between HAL interfaces?

- **Platform:** TEE attestation, platform information
- **Crypto:** Cryptographic operations (hash, encrypt, decrypt, sign, verify)
- **Storage:** Encrypted persistent storage in TEE
- **Clock:** Time functions (system time, monotonic time, sleep)
- **Random:** Cryptographically secure random number generation
- **Sockets:** Network communication
- **Communication:** Inter-service messaging

### How do I debug WASM services?

1. **Use Wasmtime CLI** with verbose output
2. **Check generated bindings** in `src/bindings.rs`
3. **Add logging** via the host (if implemented)
4. **Test HAL calls** individually
5. **Verify WIT definitions** match usage

### Can I use external Rust crates?

Yes, add them to `[dependencies]` in `Cargo.toml`:

```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hex = "0.4"
```

Only pure Rust code works - no system calls outside the WASM sandbox.

### What size are the .wasm files?

Depends on functionality:

- `example-add-user`: 192KB (with HAL usage, JSON serialization)
- Minimal service: ~50-100KB
- Complex service: 200-500KB

Use `--release` build for smaller sizes (optimizations enabled).

## Next Steps

1. Build `example-add-user` service to understand the pattern
2. Create your own service using the template above
3. Test with `hal-runtime` or Wasmtime
4. Integrate with Propeller + TEEAgent
5. Deploy in production TEE environment (TDX/SEV-SNP/SGX)
6. Build additional microservices using the same pattern

## Additional Resources

- **cargo-component documentation:** https://github.com/bytecodealliance/cargo-component
- **WIT specification:** https://component-model.bytecodealliance.org/design/wit.html
- **Wasmtime:** https://wasmtime.dev/
- **WebAssembly Component Model:** https://component-model.bytecodealliance.org/

---
