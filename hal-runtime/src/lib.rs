//! HAL Runtime - WASM Host that provides ELASTIC HAL to WASM components
//!
//! This runtime:
//! - Loads WASM components built with cargo-component
//! - Implements WIT interfaces by bridging to native HAL
//! - Provides secure execution environment for WASM services

use anyhow::{Context, Result};
use std::path::PathBuf;
use wasmtime::component::*;
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};

mod host_impl;
pub use host_impl::HalHost;

mod wit_impl;

// Generate host-side bindings from the consolidated WIT (single package).
// Targets the `hal-consumer` world: WASM guests *import* all HAL interfaces
// and *export* run (to provide report-data for attestation).
wasmtime::component::bindgen!({
    world: "hal-consumer",
    path: "wit",
    async: true,
});

/// Runtime state that implements WASI and HAL interfaces
pub struct RuntimeState {
    wasi: WasiCtx,
    table: wasmtime::component::ResourceTable,
    pub(crate) hal: HalHost,
}

impl WasiView for RuntimeState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn table(&mut self) -> &mut wasmtime::component::ResourceTable {
        &mut self.table
    }
}

/// HAL WASM Runtime
pub struct HalRuntime {
    engine: Engine,
}

impl HalRuntime {
    /// Create a new HAL runtime
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.async_support(true);

        let engine = Engine::new(&config)?;

        Ok(Self { engine })
    }

    /// Load and instantiate a WASM component
    pub async fn load_component(&self, wasm_path: PathBuf) -> Result<Component> {
        let component = Component::from_file(&self.engine, &wasm_path)
            .with_context(|| format!("Failed to load component from {:?}", wasm_path))?;

        Ok(component)
    }

    /// Create a Linker with WASI + all HAL interfaces registered
    pub fn create_linker(&self) -> Result<Linker<RuntimeState>> {
        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::add_to_linker_async(&mut linker)?;
        HalConsumer::add_to_linker(&mut linker, |state: &mut RuntimeState| state)?;
        Ok(linker)
    }

    /// Create a new store with HAL host implementation
    pub fn create_store(&self) -> Result<Store<RuntimeState>> {
        let wasi = WasiCtxBuilder::new().inherit_stdio().inherit_env().build();
        let table = wasmtime::component::ResourceTable::new();

        let hal = HalHost::new()?;

        let state = RuntimeState { wasi, table, hal };

        Ok(Store::new(&self.engine, state))
    }

    /// Instantiate a component with full HAL support and call its `run` export
    pub async fn run_component(&self, wasm_path: PathBuf) -> Result<Vec<u8>> {
        let component = self.load_component(wasm_path).await?;
        let linker = self.create_linker()?;
        let mut store = self.create_store()?;

        let instance = HalConsumer::instantiate_async(&mut store, &component, &linker).await?;
        let report_data = instance
            .elastic_hal_run()
            .call_run(&mut store)
            .await?;

        Ok(report_data)
    }
}

impl Default for HalRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create HAL runtime")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let runtime = HalRuntime::new();
        assert!(runtime.is_ok());
    }
}
