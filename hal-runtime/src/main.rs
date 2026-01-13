//! HAL Runtime CLI
//! 
//! Command-line interface for running WASM components with HAL support

use anyhow::{Context, Result};
use clap::Parser;
use hal_runtime::HalRuntime;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hal-runtime")]
#[command(about = "Run WASM components with ELASTIC HAL support")]
struct Args {
    /// Path to the WASM component file (.wasm)
    #[arg(value_name = "COMPONENT")]
    component: PathBuf,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }
    
    log::info!("Starting HAL Runtime");
    log::info!("Loading component: {:?}", args.component);
    
    // Create runtime
    let runtime = HalRuntime::new()
        .context("Failed to create HAL runtime")?;
    
    // Load component
    let component = runtime.load_component(args.component.clone()).await
        .context("Failed to load WASM component")?;
    
    // Create store
    let mut store = runtime.create_store()
        .context("Failed to create runtime store")?;
    
    log::info!("Component loaded successfully");
    log::info!("Runtime ready - component has access to HAL interfaces");
    
    // TODO: Instantiate and call component exports
    // This will be implemented once we have the actual WIT bindings generated
    
    Ok(())
}
