//! Build the Wasmtime linker that exposes the HAL to a component.
//!
//! The HAL crate deliberately does no Wasmtime linking itself: it is a plain
//! Rust library, and binding it to the component model means generating host
//! traits from the WIT definitions. That layer lives here, in `hal-runtime`,
//! which owns the `bindgen!` expansion over `wit/world.wit` and the host
//! implementations that bridge each interface to the native HAL.
//!
//! Constructing the runtime and linker needs no TEE hardware — no attestation
//! device is touched until a component actually calls into the HAL. Passing a
//! component path runs one, which does require a SEV-SNP or TDX guest.
//!
//! ```sh
//! cargo run --example wasmtime_linker                      # linker only
//! cargo run --example wasmtime_linker -- ./component.wasm  # run a component
//! ```

use anyhow::Result;
use hal_runtime::HalRuntime;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // The engine needs component-model and async support; HalRuntime::new
    // configures both.
    let runtime = HalRuntime::new()?;
    log::info!("Wasmtime engine ready (component model, async)");

    // Registers WASI plus every HAL interface on a fresh linker. This is the
    // single entry point: there is no per-interface variant to keep in sync,
    // because the interface list is generated from the WIT world.
    //
    // Not bound to a variable: `run_component` below builds the linker it
    // instantiates with, so holding one here would only duplicate it.
    runtime.create_linker()?;
    log::info!("Linker built: WASI + all HAL interfaces registered");

    // Bindings are generated, so the interface set cannot drift from the WIT
    // definitions at compile time.
    log::info!("  - Interfaces: platform, capabilities, crypto, storage,");
    log::info!("                sockets, gpu, resources, events,");
    log::info!("                communication, clock, random");

    let Some(component) = std::env::args().nth(1) else {
        log::info!("No component given — stopping after the linker is built.");
        log::info!(
            "Pass a path to run one: cargo run --example wasmtime_linker -- <component.wasm>"
        );
        return Ok(());
    };

    // run_component instantiates with the linker above and calls the guest's
    // `run` export, returning the report-data it produced for attestation.
    // This is where a TEE guest is required.
    log::info!("Running component {} ...", component);
    let report_data = runtime.run_component(component.into()).await?;

    log::info!(
        "Component returned {} bytes of report-data",
        report_data.len()
    );
    log::info!("Report-data (hex): {}", hex::encode(&report_data));

    Ok(())
}
