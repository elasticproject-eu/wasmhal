//! Minimal attestation guest component.
//!
//! Demonstrates the full attestation flow:
//! 1. `run()` is called by the host runtime
//! 2. Guest generates a nonce (report-data) using HAL random
//! 3. Guest calls HAL attestation with the report-data
//! 4. Guest returns the attestation evidence to the host

#[allow(warnings)]
mod bindings;

use bindings::elastic::hal::{attestation, platform, random};

struct Component;

impl bindings::exports::elastic::hal::run::Guest for Component {
    fn run() -> Vec<u8> {
        // 1. Query platform info
        let info = platform::get_platform_info();
        let _ = format!(
            "Running on {} v{}",
            info.platform_type, info.version
        );

        // 2. Generate random nonce as report-data
        let report_data = match random::get_random_bytes(32) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Fallback: use a fixed nonce if random is unavailable
                let _ = format!("Random failed: {}, using fallback nonce", e);
                vec![0x42u8; 32]
            }
        };

        // 3. Request attestation evidence from the TEE platform
        match attestation::attestation(&report_data) {
            Ok(evidence) => evidence,
            Err(e) => {
                // Return error message as bytes if attestation fails
                // (expected on non-TEE platforms)
                format!("attestation-error:{}", e).into_bytes()
            }
        }
    }
}

bindings::export!(Component with_types_in bindings);
