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
use host_impl::HalHost;

/// Runtime state that implements WASI and HAL interfaces
pub struct RuntimeState {
    wasi: WasiCtx,
    hal: HalHost,
}

impl WasiView for RuntimeState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn table(&mut self) -> &mut wasmtime::component::ResourceTable {
        self.wasi.table()
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

    /// Create a new store with HAL host implementation
    pub fn create_store(&self) -> Result<Store<RuntimeState>> {
        let wasi = WasiCtxBuilder::new().inherit_stdio().inherit_env().build();

        let hal = HalHost::new()?;

        let state = RuntimeState { wasi, hal };

        Ok(Store::new(&self.engine, state))
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
