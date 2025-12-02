# ELASTIC TEE HAL - Modular WIT Interfaces

This directory contains the refactored, modular WIT interface definitions for the ELASTIC TEE HAL. Each interface is now in its own package, allowing for independent development, versioning, and composition.

## Structure

The monolithic `world.wit` has been broken down into separate, composable interfaces:

### Core Interfaces

- **`platform.wit`** - Platform detection, information, and attestation
- **`capabilities.wit`** - Runtime feature discovery and capability queries
- **`crypto.wit`** - Cryptographic operations (symmetric/asymmetric, signing, hashing)
- **`random.wit`** - Cryptographically secure random number generation

### Storage & Communication

- **`storage.wit`** - Encrypted container-based object storage
- **`communication.wit`** - Secure Wasm-to-Wasm message passing
- **`sockets.wit`** - Network sockets with TCP/UDP/TLS/DTLS support

### Compute & Resources

- **`gpu.wit`** - GPU compute interface for hardware acceleration
- **`resources.wit`** - Dynamic resource allocation and tracking

### System Services

- **`events.wit`** - Priority-based event handling and subscriptions
- **`clock.wit`** - System and monotonic time operations

### Composition

- **`complete.wit`** - Composed worlds for different use cases:
  - `elastic-tee-hal` - Full HAL with all interfaces (backward compatible)
  - `elastic-tee-minimal` - Core platform, crypto, and random
  - `elastic-tee-attestation` - Attestation-focused subset
  - `elastic-tee-storage` - Storage-focused subset
  - `elastic-tee-network` - Network-focused subset
  - `elastic-tee-compute` - Compute-focused subset

## Benefits

1. **Incremental Development** - Implement interfaces one at a time without stubbing everything
2. **Independent Versioning** - Each interface can evolve at its own pace
3. **Selective Composition** - Only include the interfaces you need
4. **Wasm Implementations** - Easy to provide Wasm implementations for individual interfaces
5. **WASI Alignment** - Follows modern WASI composition patterns
6. **Clearer Boundaries** - Better separation of concerns

## Proposed API (Implementation In Progress)

**Status**: The WIT interface definitions are complete. The Rust linker API implementation is in progress and requires proper Wasmtime bindgen integration.

The following examples show the intended usage patterns once the Rust linker integration is fully implemented:

### Using Individual Interfaces

```rust
// Only link the interfaces you need (proposed API)
elastic_hal::platform::add_to_linker(&mut linker)?;
elastic_hal::crypto::add_to_linker(&mut linker)?;
```

### Using Composed Worlds

```rust
// Use a minimal world for attestation-only workloads (proposed API)
let mut linker = Linker::new(&engine);
elastic_hal::minimal::add_to_linker(&mut linker)?;
```

### Full HAL (Backward Compatible)

```rust
// Use all interfaces (equivalent to old monolithic world) (proposed API)
elastic_hal::add_to_linker(&mut linker)?;
```

**Note:** These APIs are not yet implemented. The WIT interface definitions are complete, but the Rust `add_to_linker` implementations and Wasmtime bindings still need to be created.

## Migration from Monolithic World

The old monolithic world is still available via `complete.wit` for backward compatibility. New implementations should prefer using individual interface packages or the specialized composed worlds.

## Package Structure

Each interface follows this pattern:

```wit
package elastic:<interface-name>@0.1.0;

interface <interface-name> {
  // Interface definitions
}

world <interface-name>-world {
  export <interface-name>;
}
```

This allows the interface to be:
- Used standalone
- Composed with other interfaces
- Versioned independently
- Implemented in native code or Wasm
