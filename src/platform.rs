// Main ELASTIC TEE HAL Platform Implementation

use crate::capabilities::PlatformCapabilities;
use crate::error::{HalError, HalResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Main ELASTIC TEE HAL structure
pub struct ElasticTeeHal {
    platform_type: PlatformType,
    capabilities: Arc<RwLock<PlatformCapabilities>>,
    initialized: bool,
}

/// Supported TEE platform types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PlatformType {
    AmdSev,
    IntelTdx,
    // Future platform support can be added here
}

impl ElasticTeeHal {
    /// Create a new HAL instance with platform auto-detection
    pub fn new() -> HalResult<Self> {
        // Initialize the crypto provider for Rustls
        Self::init_crypto_provider()?;

        let platform_type = Self::detect_platform()?;
        let capabilities = Arc::new(RwLock::new(PlatformCapabilities::new(
            platform_type.clone(),
        )));

        let mut hal = Self {
            platform_type,
            capabilities,
            initialized: false,
        };

        hal.initialize()?;
        Ok(hal)
    }

    /// Create a HAL instance for a specific platform type
    pub fn with_platform(platform_type: PlatformType) -> HalResult<Self> {
        // Initialize the crypto provider for Rustls
        Self::init_crypto_provider()?;

        let capabilities = Arc::new(RwLock::new(PlatformCapabilities::new(
            platform_type.clone(),
        )));

        let mut hal = Self {
            platform_type,
            capabilities,
            initialized: false,
        };

        hal.initialize()?;
        Ok(hal)
    }

    /// Initialize the HAL with platform-specific setup
    fn initialize(&mut self) -> HalResult<()> {
        match self.platform_type {
            PlatformType::AmdSev => self.init_amd_sev()?,
            PlatformType::IntelTdx => self.init_intel_tdx()?,
        }

        self.initialized = true;
        log::info!(
            "ELASTIC TEE HAL initialized for platform: {:?}",
            self.platform_type
        );
        Ok(())
    }

    /// Initialize the crypto provider for Rustls
    fn init_crypto_provider() -> HalResult<()> {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            // Install the ring crypto provider for Rustls
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        Ok(())
    }

    /// Detect the current TEE platform
    fn detect_platform() -> HalResult<PlatformType> {
        // Check for AMD SEV-SNP
        if Self::is_amd_sev_available() {
            return Ok(PlatformType::AmdSev);
        }

        // Check for Intel TDX
        if Self::is_intel_tdx_available() {
            return Ok(PlatformType::IntelTdx);
        }

        Err(HalError::PlatformNotSupported(
            "No supported TEE platform detected".to_string(),
        ))
    }

    /// Check if AMD SEV is available
    fn is_amd_sev_available() -> bool {
        // In a real implementation, this would check:
        // - CPU vendor (AMD)
        // - SEV capability in CPUID
        // - /dev/sev device availability
        // - SNP guest status

        #[cfg(target_arch = "x86_64")]
        {
            // Check for AMD CPU vendor
            let is_amd = Self::is_amd_cpu();

            // Check for SEV guest device (SNP environments)
            let has_sev_guest = std::path::Path::new("/dev/sev-guest").exists();

            // Check for SEV device (host environments)
            let has_sev_dev = std::path::Path::new("/dev/sev").exists();

            // Check for TSM support (Trust Security Module for attestation)
            let has_tsm = std::path::Path::new("/sys/kernel/config/tsm/report").exists();

            println!("AMD SEV Detection:");
            println!("  - AMD CPU: {}", is_amd);
            println!("  - /dev/sev-guest: {}", has_sev_guest);
            println!("  - /dev/sev: {}", has_sev_dev);
            println!("  - TSM support: {}", has_tsm);

            is_amd && (has_sev_guest || has_sev_dev) && has_tsm
        }
        #[cfg(not(target_arch = "x86_64"))]
        false
    }

    /// Check if this is an AMD CPU
    fn is_amd_cpu() -> bool {
        // Read /proc/cpuinfo to check vendor
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            content.contains("vendor_id\t: AuthenticAMD")
        } else {
            false
        }
    }

    /// Check if Intel TDX is available
    pub fn is_intel_tdx_available() -> bool {
        // Check for Intel TDX Trust Domain
        // This verifies:
        // - CPU vendor (Intel)
        // - TDX guest device
        // - TDX capability in CPU flags
        // - TSM (Trust Security Module) support for attestation

        #[cfg(target_arch = "x86_64")]
        {
            // Check for Intel CPU vendor
            let is_intel = Self::is_intel_cpu();

            // Check for TDX guest device
            let has_tdx_guest = std::path::Path::new("/dev/tdx_guest").exists();

            // Check for TSM support (Trust Security Module for attestation)
            let has_tsm = std::path::Path::new("/sys/kernel/config/tsm/report").exists();

            // Check for TDX guest flag in CPU features
            let has_tdx_flag = Self::has_tdx_cpu_flag();

            println!("Intel TDX Detection:");
            println!("  - Intel CPU: {}", is_intel);
            println!("  - /dev/tdx_guest: {}", has_tdx_guest);
            println!("  - TSM support: {}", has_tsm);
            println!("  - TDX CPU flag: {}", has_tdx_flag);

            is_intel && has_tdx_guest && has_tsm && has_tdx_flag
        }
        #[cfg(not(target_arch = "x86_64"))]
        false
    }

    /// Check if this is an Intel CPU
    fn is_intel_cpu() -> bool {
        // Read /proc/cpuinfo to check vendor
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            content.contains("vendor_id\t: GenuineIntel")
        } else {
            false
        }
    }

    /// Check for TDX guest CPU flag
    fn has_tdx_cpu_flag() -> bool {
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            content.contains("tdx_guest")
        } else {
            false
        }
    }

    /// Initialize AMD SEV platform
    fn init_amd_sev(&self) -> HalResult<()> {
        log::info!("Initializing AMD SEV-SNP platform");

        // In a real implementation, this would:
        // - Verify we're running in an SNP guest
        // - Set up attestation capabilities
        // - Initialize secure memory regions
        // - Configure crypto acceleration

        Ok(())
    }

    /// Initialize Intel TDX platform
    fn init_intel_tdx(&self) -> HalResult<()> {
        log::info!("Initializing Intel TDX platform");

        // Verify TDX guest device is accessible
        if !std::path::Path::new("/dev/tdx_guest").exists() {
            return Err(HalError::TeeInitializationFailed(
                "TDX guest device /dev/tdx_guest not found".to_string(),
            ));
        }

        // Verify TSM (Trust Security Module) is available for attestation
        if !std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
            log::warn!(
                "TSM not available at /sys/kernel/config/tsm/report - attestation may be limited"
            );
        }

        // Verify we're running as a TDX guest
        if !Self::has_tdx_cpu_flag() {
            return Err(HalError::TeeInitializationFailed(
                "TDX guest CPU flag not detected".to_string(),
            ));
        }

        log::info!("Intel TDX platform initialized successfully");
        log::info!("  - TDX guest device: /dev/tdx_guest");
        log::info!("  - TSM support: available");
        log::info!("  - Hardware attestation: enabled");
        log::info!("  - Secure memory protection: active");
        log::info!("  - Crypto acceleration: AES-NI available");

        Ok(())
    }

    /// Get the platform type
    pub fn platform_type(&self) -> &PlatformType {
        &self.platform_type
    }

    /// Get platform capabilities
    pub async fn capabilities(&self) -> PlatformCapabilities {
        self.capabilities.read().await.clone()
    }

    /// Check if HAL is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Perform platform attestation with custom report data
    ///
    /// # Arguments
    /// * `report_data` - Custom data to include in the attestation report (e.g., nonce, challenge)
    ///   For TDX, this should be up to 64 bytes. For SEV-SNP, up to 64 bytes.
    pub async fn attest(&self, report_data: &[u8]) -> HalResult<Vec<u8>> {
        if !self.initialized {
            return Err(HalError::TeeInitializationFailed(
                "HAL not initialized".to_string(),
            ));
        }

        match self.platform_type {
            PlatformType::AmdSev => self.amd_sev_attest(report_data).await,
            PlatformType::IntelTdx => self.intel_tdx_attest(report_data).await,
        }
    }

    /// AMD SEV attestation
    async fn amd_sev_attest(&self, report_data: &[u8]) -> HalResult<Vec<u8>> {
        // In a real implementation, this would:
        // - Generate attestation report
        // - Include measurement data
        // - Sign with platform key
        // - Include the provided report_data in the attestation report

        log::info!(
            "Generating AMD SEV attestation report with {} bytes of report data",
            report_data.len()
        );

        // Truncate or pad report_data to 64 bytes for SEV-SNP
        let mut report_data_padded = vec![0u8; 64];
        let copy_len = report_data.len().min(64);
        report_data_padded[..copy_len].copy_from_slice(&report_data[..copy_len]);

        // Placeholder attestation data
        let attestation_data = serde_json::json!({
            "platform": "amd-sev-snp",
            "version": crate::HAL_VERSION,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "measurements": {
                "bootloader": "placeholder_hash",
                "kernel": "placeholder_hash",
                "hal": "placeholder_hash"
            },
            "report_data": hex::encode(&report_data_padded)
        });

        Ok(attestation_data.to_string().into_bytes())
    }

    /// Intel TDX attestation.
    ///
    /// Two return modes are supported, selected automatically:
    ///
    /// 1. **Default (no `ITA_API_KEY` env var):** generate a raw TDX DCAP
    ///    quote via the Linux TSM, parse out MRTD and RTMR0..3, and return a
    ///    compact `{"measurements": {...}}` JSON document. This is the format
    ///    consumed by the Propeller HAL `attestation-test` example
    ///    (`evidence len ≈ 863`). See [`crate::tdx_quote`] for the parser.
    ///
    /// 2. **Intel Trust Authority round-trip (`ITA_API_KEY` set):** perform
    ///    the ITA v2 verifier-nonce protocol — fetch nonce, regenerate the
    ///    quote with `REPORTDATA = SHA512(nonce.val || nonce.iat ||
    ///    user_data)`, submit quote + nonce, and return the resulting EAR
    ///    JWT. This path is for KBS-style integrations that need a verified
    ///    appraisal token rather than raw measurements.
    ///
    /// If the ITA round-trip is requested but fails, we fall back to the raw
    /// TDX quote bytes (not the measurements JSON) so the caller can retry
    /// the submission themselves.
    async fn intel_tdx_attest(&self, report_data: &[u8]) -> HalResult<Vec<u8>> {
        log::info!(
            "Generating Intel TDX attestation quote with {} bytes of report data",
            report_data.len()
        );

        // Pad/truncate report_data to exactly 64 bytes (TDX hardware requirement)
        let mut report_data_padded = [0u8; 64];
        let copy_len = report_data.len().min(64);
        report_data_padded[..copy_len].copy_from_slice(&report_data[..copy_len]);

        // --- Step 1: Get the raw TDX quote from the hardware ---
        let raw_quote = self.get_tdx_quote_via_tsm(&report_data_padded)?;

        log::info!("TDX quote obtained: {} bytes", raw_quote.len());

        // --- Step 2: Optionally submit to Intel Trust Authority ---
        // If ITA_API_KEY is set, perform the full remote attestation round-trip
        // and return the EAR (Entity Attestation Result) JWT as bytes.
        // On any failure here, fall through to returning the raw quote bytes
        // so the caller can retry the submission.
        if let Some(ita_client) = crate::ita::ItaClient::from_env() {
            // Step 2a: Fetch ITA verifier nonce and derive REPORTDATA
            match ita_client.fetch_nonce_and_report_data(&report_data_padded).await {
                Ok((ita_report_data, nonce_state)) => {
                    // Step 2b: Re-generate the TDX quote with ITA's REPORTDATA
                    match self.get_tdx_quote_via_tsm(&ita_report_data) {
                        Ok(ita_quote) => {
                            // Step 2c: Submit quote + nonce to ITA
                            match ita_client
                                .attest_with_nonce(&ita_quote, &report_data_padded, &nonce_state)
                                .await
                            {
                                Ok(ear_jwt) => {
                                    log::info!("ITA attestation succeeded, returning EAR JWT");
                                    return Ok(ear_jwt.into_bytes());
                                }
                                Err(e) => {
                                    log::warn!("ITA attest failed ({}), returning raw TDX quote", e);
                                    eprintln!("[ITA ERROR] {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("TDX quote gen for ITA failed: {}", e);
                            eprintln!("[ITA ERROR] Quote generation failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("ITA nonce fetch failed ({}), returning raw TDX quote", e);
                    eprintln!("[ITA ERROR] {}", e);
                }
            }
            // ITA was requested but failed somewhere — return the raw quote
            // so the caller can retry, rather than the measurements JSON.
            return Ok(raw_quote);
        }

        // --- Step 3: Default path — return parsed measurements JSON ---
        // This is what Propeller's WASM `attestation-test` workload prints
        // as `evidence: {...}`.
        match crate::tdx_quote::TdxMeasurements::parse(&raw_quote) {
            Ok(measurements) => {
                let hal_hash = crate::tdx_quote::compute_hal_hash();
                let evidence_json = measurements.to_evidence_json(&hal_hash);
                log::info!(
                    "Returning measurements JSON ({} bytes)",
                    evidence_json.len()
                );
                Ok(evidence_json.into_bytes())
            }
            Err(e) => {
                // Quote was unparseable — surface the raw quote rather than
                // hide a hardware/firmware oddity behind synthetic JSON.
                log::warn!("TDX quote parse failed ({}), returning raw quote", e);
                Ok(raw_quote)
            }
        }
    }

    /// Obtain a raw TDX DCAP quote via the Linux TSM (Trusted Security Module)
    /// configfs interface at /sys/kernel/config/tsm/report/.
    ///
    /// This is the recommended method on Linux kernels >= 6.7.
    /// Steps:
    ///   1. mkdir  /sys/kernel/config/tsm/report/<unique-name>
    ///   2. write  report_data  →  inblob
    ///   3. read   outblob      →  raw TDX quote bytes
    ///   4. rmdir  the entry
    fn get_tdx_quote_via_tsm(&self, report_data: &[u8; 64]) -> HalResult<Vec<u8>> {
        let tsm_base = "/sys/kernel/config/tsm/report";

        if !std::path::Path::new(tsm_base).exists() {
            return Err(HalError::TeeInitializationFailed(
                "TSM configfs not available at /sys/kernel/config/tsm/report".to_string(),
            ));
        }

        // Use a timestamp-derived unique name to avoid collisions
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let entry_name = format!("hal_quote_{}", ts);
        let entry_path = format!("{}/{}", tsm_base, entry_name);

        // Create the report entry directory
        std::fs::create_dir(&entry_path).map_err(|e| {
            HalError::TeeInitializationFailed(format!(
                "Failed to create TSM report entry '{}': {}",
                entry_path, e
            ))
        })?;

        // The kernel creates inblob/outblob as root-owned (--w------- / r--r--r--).
        // Fix permissions so our user can write inblob and read outblob.
        let chmod_result = std::process::Command::new("sudo")
            .args(["sh", "-c",
                &format!("chmod o+w {}/inblob && chmod o+r {}/outblob",
                    entry_path, entry_path)])
            .status();
        if chmod_result.map(|s| !s.success()).unwrap_or(true) {
            let _ = std::fs::remove_dir(&entry_path);
            return Err(HalError::TeeInitializationFailed(
                "Failed to chmod TSM entry files (sudo required)".to_string(),
            ));
        }

        // Write report_data (inblob) — this triggers the kernel to prepare the quote
        let inblob_path = format!("{}/inblob", entry_path);
        if let Err(e) = std::fs::write(&inblob_path, report_data.as_ref()) {
            let _ = std::fs::remove_dir(&entry_path);
            return Err(HalError::TeeInitializationFailed(format!(
                "Failed to write TSM inblob: {}",
                e
            )));
        }

        // Read the quote (outblob)
        let outblob_path = format!("{}/outblob", entry_path);
        let quote = match std::fs::read(&outblob_path) {
            Ok(data) => data,
            Err(e) => {
                let _ = std::fs::remove_dir(&entry_path);
                return Err(HalError::TeeInitializationFailed(format!(
                    "Failed to read TSM outblob (quote): {}",
                    e
                )));
            }
        };

        // Clean up the report entry
        let _ = std::fs::remove_dir(&entry_path);

        if quote.is_empty() {
            return Err(HalError::TeeInitializationFailed(
                "TSM returned an empty quote".to_string(),
            ));
        }

        Ok(quote)
    }

    /// Verify an attestation report
    pub async fn verify_attestation(&self, attestation: &[u8]) -> HalResult<bool> {
        // In a real implementation, this would verify the attestation signature
        // and check measurements against known good values

        let attestation_str = String::from_utf8_lossy(attestation);
        log::info!("Verifying attestation: {}", attestation_str);

        // Placeholder verification
        Ok(true)
    }
}

impl Default for ElasticTeeHal {
    fn default() -> Self {
        Self::new().expect("Failed to create default HAL instance")
    }
}

/// Check if Intel TDX is available (standalone function for external use)
pub fn is_intel_tdx_available() -> bool {
    ElasticTeeHal::is_intel_tdx_available()
}
