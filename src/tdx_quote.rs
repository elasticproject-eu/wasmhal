//! Intel TDX DCAP Quote parsing and measurement extraction.
//!
//! ## Background
//!
//! When `intel_tdx_attest()` returns to the WASM workload (via the
//! `elastic:tee-hal/platform::attestation` host call), the workload expects a
//! compact JSON document of the form:
//!
//! ```json
//! {
//!   "measurements": {
//!     "hal":   "<sha256 hex of HAL binary>",
//!     "mrtd":  "<48-byte hex>",
//!     "rtmr0": "<48-byte hex>",
//!     "rtmr1": "<48-byte hex>",
//!     "rtmr2": "<48-byte hex>",
//!     "rtmr3": "<48-byte hex>"
//!   }
//! }
//! ```
//!
//! This shape matches what the Propeller `attestation-test` example documents
//! as the expected evidence (`evidence len ≈ 863`).
//!
//! For the full Intel Trust Authority round-trip (which returns an EAR JWT
//! instead), see `crate::ita` — that path is taken only when `ITA_API_KEY` is
//! set in the environment.
//!
//! ## TDX Quote layout (DCAP v4, TDX 1.0)
//!
//! A raw quote produced by the Linux TSM `outblob` is laid out as:
//!
//! | Offset | Size | Field                                       |
//! |-------:|-----:|---------------------------------------------|
//! |      0 |   48 | Quote header                                |
//! |     48 |  584 | TD Quote Body                               |
//! |    632 |    4 | Signature data length                       |
//! |    636 |    N | Signature data                              |
//!
//! The 584-byte TD Quote Body has, among other fields:
//!
//! | Body offset | Quote offset | Size | Field      |
//! |------------:|-------------:|-----:|------------|
//! |         136 |          184 |   48 | MRTD       |
//! |         328 |          376 |   48 | RTMR0      |
//! |         376 |          424 |   48 | RTMR1      |
//! |         424 |          472 |   48 | RTMR2      |
//! |         472 |          520 |   48 | RTMR3      |
//! |         520 |          568 |   64 | REPORTDATA |
//!
//! Reference: Intel TDX DCAP Quote Generation Library, `td_quote_body_v4`
//! struct in `Intel/SGXDataCenterAttestationPrimitives`.

use sha2::{Digest, Sha256};

/// Byte length of MRTD and each RTMR (SHA-384 digests).
pub const MEASUREMENT_LEN: usize = 48;

/// Offset of MRTD inside a raw TDX DCAP v4 quote.
const OFFSET_MRTD: usize = 184;
/// Offset of RTMR0 inside a raw TDX DCAP v4 quote.
const OFFSET_RTMR0: usize = 376;
/// Offset of RTMR1 inside a raw TDX DCAP v4 quote.
const OFFSET_RTMR1: usize = 424;
/// Offset of RTMR2 inside a raw TDX DCAP v4 quote.
const OFFSET_RTMR2: usize = 472;
/// Offset of RTMR3 inside a raw TDX DCAP v4 quote.
const OFFSET_RTMR3: usize = 520;

/// Minimum quote length needed to safely read all measurements.
const MIN_QUOTE_LEN: usize = OFFSET_RTMR3 + MEASUREMENT_LEN;

/// Parsed TDX measurements (each 48 bytes, SHA-384 digests).
#[derive(Debug, Clone)]
pub struct TdxMeasurements {
    pub mrtd: [u8; MEASUREMENT_LEN],
    pub rtmr0: [u8; MEASUREMENT_LEN],
    pub rtmr1: [u8; MEASUREMENT_LEN],
    pub rtmr2: [u8; MEASUREMENT_LEN],
    pub rtmr3: [u8; MEASUREMENT_LEN],
}

impl TdxMeasurements {
    /// Parse MRTD and RTMR0..3 out of a raw TDX DCAP quote.
    ///
    /// Returns `Err` if the quote is too short to contain all five fields.
    pub fn parse(quote: &[u8]) -> Result<Self, String> {
        if quote.len() < MIN_QUOTE_LEN {
            return Err(format!(
                "TDX quote too short: got {} bytes, need at least {}",
                quote.len(),
                MIN_QUOTE_LEN
            ));
        }
        let read = |off: usize| -> [u8; MEASUREMENT_LEN] {
            let mut out = [0u8; MEASUREMENT_LEN];
            out.copy_from_slice(&quote[off..off + MEASUREMENT_LEN]);
            out
        };
        Ok(Self {
            mrtd: read(OFFSET_MRTD),
            rtmr0: read(OFFSET_RTMR0),
            rtmr1: read(OFFSET_RTMR1),
            rtmr2: read(OFFSET_RTMR2),
            rtmr3: read(OFFSET_RTMR3),
        })
    }

    /// Render as the compact `{"measurements": {...}}` JSON document expected
    /// by the Propeller HAL example.
    ///
    /// `hal_hash` should be the SHA-256 of the HAL binary
    /// (see [`compute_hal_hash`]).
    pub fn to_evidence_json(&self, hal_hash: &[u8; 32]) -> String {
        format!(
            r#"{{"measurements":{{"hal":"{}","mrtd":"{}","rtmr0":"{}","rtmr1":"{}","rtmr2":"{}","rtmr3":"{}"}}}}"#,
            hex::encode(hal_hash),
            hex::encode(self.mrtd),
            hex::encode(self.rtmr0),
            hex::encode(self.rtmr1),
            hex::encode(self.rtmr2),
            hex::encode(self.rtmr3),
        )
    }
}

/// Compute SHA-256 of the currently running HAL binary (`/proc/self/exe`).
///
/// This identifies which HAL build produced the attestation. If the binary
/// can't be read for any reason we return all-zero, which is a deliberate
/// "unknown" sentinel rather than a failure — the MRTD/RTMR values from the
/// hardware are the security-critical fields.
pub fn compute_hal_hash() -> [u8; 32] {
    match std::fs::read("/proc/self/exe") {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hasher.finalize().into()
        }
        Err(e) => {
            log::warn!("Failed to read /proc/self/exe for HAL hash: {}", e);
            [0u8; 32]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_short_quote() {
        let short = vec![0u8; 100];
        assert!(TdxMeasurements::parse(&short).is_err());
    }

    #[test]
    fn parse_extracts_at_correct_offsets() {
        let mut quote = vec![0u8; MIN_QUOTE_LEN];
        // Fill each measurement with a distinguishable byte pattern.
        quote[OFFSET_MRTD..OFFSET_MRTD + MEASUREMENT_LEN].fill(0xAA);
        quote[OFFSET_RTMR0..OFFSET_RTMR0 + MEASUREMENT_LEN].fill(0xB0);
        quote[OFFSET_RTMR1..OFFSET_RTMR1 + MEASUREMENT_LEN].fill(0xB1);
        quote[OFFSET_RTMR2..OFFSET_RTMR2 + MEASUREMENT_LEN].fill(0xB2);
        quote[OFFSET_RTMR3..OFFSET_RTMR3 + MEASUREMENT_LEN].fill(0xB3);

        let m = TdxMeasurements::parse(&quote).unwrap();
        assert_eq!(m.mrtd, [0xAA; MEASUREMENT_LEN]);
        assert_eq!(m.rtmr0, [0xB0; MEASUREMENT_LEN]);
        assert_eq!(m.rtmr1, [0xB1; MEASUREMENT_LEN]);
        assert_eq!(m.rtmr2, [0xB2; MEASUREMENT_LEN]);
        assert_eq!(m.rtmr3, [0xB3; MEASUREMENT_LEN]);
    }

    #[test]
    fn evidence_json_shape_matches_propeller_example() {
        let m = TdxMeasurements {
            mrtd: [0x11; MEASUREMENT_LEN],
            rtmr0: [0x22; MEASUREMENT_LEN],
            rtmr1: [0x33; MEASUREMENT_LEN],
            rtmr2: [0x44; MEASUREMENT_LEN],
            rtmr3: [0x55; MEASUREMENT_LEN],
        };
        let hal = [0x66u8; 32];
        let json = m.to_evidence_json(&hal);
        assert!(json.contains(r#""measurements":"#));
        assert!(json.contains(r#""hal":"6666"#));
        assert!(json.contains(r#""mrtd":"1111"#));
        assert!(json.contains(r#""rtmr0":"2222"#));
        assert!(json.contains(r#""rtmr3":"5555"#));
        // Round-trippable as JSON.
        let _: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    }
}
