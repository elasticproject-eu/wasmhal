// Example: Using ELASTIC TEE HAL with Wasmtime Linker
// Demonstrates the plugin-style architecture for adding HAL interfaces

use elastic_tee_hal::wasmtime_bindings;
use wasmtime::component::*;
use wasmtime::{Config, Engine, Store};

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Initialize Wasmtime with component model support
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    // Create a linker
    let mut linker = Linker::new(&engine);

    log::info!("Adding ELASTIC TEE HAL interfaces to Wasmtime linker...\n");

    // Option 1: Add all interfaces (full HAL)
    log::info!("Option 1: Full HAL");
    wasmtime_bindings::add_to_linker(&mut linker)?;
    log::info!("✓ All 11 interfaces added\n");

    // Option 2: Add minimal interfaces only
    log::info!("Option 2: Minimal HAL (platform, capabilities, crypto, random)");
    let mut linker2 = Linker::new(&engine);
    wasmtime_bindings::add_minimal_to_linker(&mut linker2)?;
    log::info!("✓ 4 core interfaces added\n");

    // Option 3: Add attestation-focused interfaces
    log::info!("Option 3: Attestation HAL (platform, crypto, random)");
    let mut linker3 = Linker::new(&engine);
    wasmtime_bindings::add_attestation_to_linker(&mut linker3)?;
    log::info!("✓ 3 attestation interfaces added\n");

    // Option 4: Add individual interfaces as needed
    log::info!("Option 4: Custom composition (platform + crypto)");
    let mut linker4 = Linker::new(&engine);
    wasmtime_bindings::platform::add_to_linker(&mut linker4)?;
    wasmtime_bindings::crypto::add_to_linker(&mut linker4)?;
    log::info!("✓ 2 custom interfaces added\n");

    // Option 5: Storage-focused
    log::info!("Option 5: Storage HAL");
    let mut linker5 = Linker::new(&engine);
    wasmtime_bindings::add_storage_to_linker(&mut linker5)?;
    log::info!("✓ Storage interfaces added\n");

    // Option 6: Network-focused
    log::info!("Option 6: Network HAL");
    let mut linker6 = Linker::new(&engine);
    wasmtime_bindings::add_network_to_linker(&mut linker6)?;
    log::info!("✓ Network interfaces added\n");

    log::info!("All linker configurations successful!");
    log::info!("\nThe linkers are now ready to instantiate WASM components");
    log::info!("that use the corresponding ELASTIC TEE HAL interfaces.");

    Ok(())
}
