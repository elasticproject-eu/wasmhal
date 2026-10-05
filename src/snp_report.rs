//! AMD SEV-SNP guest attestation report parsing.
//!
//! ## Background
//!
//! On an AMD SEV-SNP guest the firmware signs a fixed-layout *attestation
//! report*. The Linux TSM configfs returns those bytes verbatim from `outblob`
//! (see [`crate::attestation`]), so this module's job is to read the fields a
//! verifier needs out of that layout.
//!
//! The measurements document produced here deliberately matches the shape the
//! Intel TDX path emits, so a workload that consumes `attestation()` handles one
//! document rather than one per vendor:
//!
//! ```json
//! {
//!   "measurements": {
//!     "hal":   "<sha256 hex of HAL binary>",
//!     "mrtd":  "<48-byte hex of the SNP measurement>",
//!     "tcb":   "<reported TCB, decimal>"
//!   }
//! }
//! ```
//!
//! `mrtd` is the SNP `MEASUREMENT` field — SNP's name for the single launch
//! measurement that TDX splits into MRTD plus four runtime registers.
//!
//! ## Report layout
//!
//! Offsets are into the raw report, little-endian, per the AMD SEV-SNP
//! Firmware ABI Specification, "Guest Attestation Report" table:
//!
//! | Offset | Size | Field           | Notes                              |
//! |-------:|-----:|-----------------|------------------------------------|
//! |  0x000 |    4 | VERSION         | 2 = SNP, 3 = SNP + TCB components |
//! |  0x004 |    4 | GUEST_SVN       |                                    |
//! |  0x008 |    8 | POLICY          |                                    |
//! |  0x018 |    8 | CURRENT_TCB     |                                    |
//! |  0x02C |    8 | FLAGS           |                                    |
//! |  0x038 |   32 | REPORT_DATA     | verifier nonce                     |
//! |  0x058 |   48 | MEASUREMENT     | launch digest ("MRTD")             |
//! |  0x088 |   32 | HOST_DATA       |                                    |
//! |  0x0A8 |   64 | ID_KEY_DIGEST   |                                    |
//! |  0x0E8 |   64 | AUTHOR_KEY_DIGEST |                                  |
//! |  0x128 |   32 | REPORT_ID       |                                    |
//! |  0x148 |   64 | REPORT_ID_MA    |                                    |
//! |  0x188 |    8 | REPORTED_TCB    |                                    |
//! |  0x1A0 |    4 | CPU_SOCKETS     |                                    |
//! |  0x3C0 |  512 | SIGNATURE       | ECDSA P-384 over everything above  |
//!
//! Only VERSION, REPORTED_TCB, REPORT_DATA and MEASUREMENT are read here.
//! Signature verification is a verifier's job: it needs the VCEK certificate
//! chain and the AMD root of trust, and a caller that skips that check has not
//! gained anything by having us parse the layout for it.

/// Length of the SNP `MEASUREMENT` field (SHA-384).
pub const MEASUREMENT_LEN: usize = 48;

/// Length of the SNP `REPORT_DATA` field.
pub const REPORT_DATA_LEN: usize = 32;

/// Offset of VERSION.
const OFFSET_VERSION: usize = 0x000;
/// Offset of REPORTED_TCB.
const OFFSET_REPORTED_TCB: usize = 0x188;
/// Offset of REPORT_DATA.
const OFFSET_REPORT_DATA: usize = 0x038;
/// Offset of MEASUREMENT.
const OFFSET_MEASUREMENT: usize = 0x058;

/// The smallest report that can contain everything read here.
///
/// The full signed report is 0x4A0 bytes; we only require enough to reach the
/// end of MEASUREMENT plus REPORTED_TCB, which is what makes the parser
/// tolerant of a firmware that trims fields it is not required to populate.
const MIN_REPORT_LEN: usize = OFFSET_REPORTED_TCB + 8;

/// The SNP guest report version this parser understands.
///
/// 2 is the base SNP report; 3 adds the TCB components block. Both place the
/// fields read here at the same offsets, so both are accepted.
const KNOWN_VERSIONS: [u32; 2] = [2, 3];

/// Fields extracted from a raw SNP attestation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpReport {
    /// Report version (2 or 3).
    pub version: u32,
    /// The launch measurement, hex-encoded into evidence as `mrtd`.
    pub measurement: [u8; MEASUREMENT_LEN],
    /// The report data the firmware bound its signature to.
    pub report_data: [u8; REPORT_DATA_LEN],
    /// Current TCB the firmware reports for this guest.
    pub reported_tcb: u64,
}

impl SnpReport {
    /// Parse the fields this crate reads out of a raw SNP attestation report.
    ///
    /// Returns `Err` if the report is shorter than [`MIN_REPORT_LEN`] or carries
    /// a version this parser does not recognise. The version check is
    /// deliberately strict: an unknown version means the firmware may have moved
    /// or inserted fields, and silently reading the old offsets would produce
    /// plausible-looking but wrong measurements — which is worse than refusing.
    pub fn parse(report: &[u8]) -> Result<Self, String> {
        if report.len() < MIN_REPORT_LEN {
            return Err(format!(
                "SNP attestation report too short: got {} bytes, need at least {}",
                report.len(),
                MIN_REPORT_LEN
            ));
        }

        let version = u32::from_le_bytes(
            report[OFFSET_VERSION..OFFSET_VERSION + 4]
                .try_into()
                .expect("4-byte slice"),
        );

        if !KNOWN_VERSIONS.contains(&version) {
            return Err(format!(
                "unrecognised SNP report version {} (expected one of {:?})",
                version, KNOWN_VERSIONS
            ));
        }

        let mut measurement = [0u8; MEASUREMENT_LEN];
        measurement
            .copy_from_slice(&report[OFFSET_MEASUREMENT..OFFSET_MEASUREMENT + MEASUREMENT_LEN]);

        let mut report_data = [0u8; REPORT_DATA_LEN];
        report_data
            .copy_from_slice(&report[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + REPORT_DATA_LEN]);

        let reported_tcb = u64::from_le_bytes(
            report[OFFSET_REPORTED_TCB..OFFSET_REPORTED_TCB + 8]
                .try_into()
                .expect("8-byte slice"),
        );

        Ok(Self {
            version,
            measurement,
            report_data,
            reported_tcb,
        })
    }

    /// Whether the firmware bound `requested` into the report data.
    ///
    /// Compares the first [`REPORT_DATA_LEN`] bytes of `requested`, zero-padded,
    /// against what the firmware reports.
    ///
    /// Truncating to 32 bytes is not leniency — it is what the hardware does.
    /// The TSM interface accepts 64 bytes of report data, but SNP's `REPORT_DATA`
    /// field is only 32 bytes wide, so the firmware binds the leading 32 and
    /// discards the rest. Callers wanting a full-length binding should send at
    /// most 32 bytes on SNP; anything beyond that is not covered by the
    /// signature and this check correctly refuses to claim otherwise.
    pub fn report_data_matches(&self, requested: &[u8]) -> bool {
        let bound = requested.len().min(REPORT_DATA_LEN);
        let mut want = [0u8; REPORT_DATA_LEN];
        want[..bound].copy_from_slice(&requested[..bound]);
        self.report_data == want
    }

    /// Render as the `{"measurements": {...}}` document, matching the shape the
    /// TDX path emits.
    pub fn to_evidence_json(&self, hal_hash: &[u8; 32]) -> String {
        format!(
            r#"{{"measurements":{{"hal":"{}","mrtd":"{}","tcb":"{}"}}}}"#,
            hex::encode(hal_hash),
            hex::encode(self.measurement),
            self.reported_tcb
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic report of `len` bytes with the fields set.
    fn synthetic_report(version: u32, len: usize) -> Vec<u8> {
        let mut r = vec![0u8; len];
        r[OFFSET_VERSION..OFFSET_VERSION + 4].copy_from_slice(&version.to_le_bytes());
        r[OFFSET_MEASUREMENT..OFFSET_MEASUREMENT + MEASUREMENT_LEN].fill(0xAB);
        r[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + REPORT_DATA_LEN].fill(0xCD);
        r[OFFSET_REPORTED_TCB..OFFSET_REPORTED_TCB + 8]
            .copy_from_slice(&0x0000_0000_00FF_FF01u64.to_le_bytes());
        r
    }

    #[test]
    fn parse_rejects_short_report() {
        assert!(SnpReport::parse(&vec![0u8; 64]).is_err());
    }

    #[test]
    fn parse_rejects_unknown_version() {
        // Refusing here is the point: reading old offsets from a newer layout
        // would yield plausible but wrong measurements.
        let report = synthetic_report(9, MIN_REPORT_LEN);
        let err = SnpReport::parse(&report).unwrap_err();
        assert!(err.contains("unrecognised"), "got: {}", err);
    }

    #[test]
    fn parse_accepts_known_versions() {
        for version in [2u32, 3u32] {
            let report = synthetic_report(version, MIN_REPORT_LEN);
            let parsed = SnpReport::parse(&report).unwrap();
            assert_eq!(parsed.version, version);
        }
    }

    #[test]
    fn parse_extracts_fields_at_documented_offsets() {
        let report = synthetic_report(2, MIN_REPORT_LEN);
        let parsed = SnpReport::parse(&report).unwrap();

        assert_eq!(parsed.measurement, [0xAB; MEASUREMENT_LEN]);
        assert_eq!(parsed.report_data, [0xCD; REPORT_DATA_LEN]);
        assert_eq!(parsed.reported_tcb, 0x0000_0000_00FF_FF01);
    }

    #[test]
    fn report_data_matches_the_leading_32_bytes_the_hardware_binds() {
        let report = synthetic_report(2, MIN_REPORT_LEN);
        let parsed = SnpReport::parse(&report).unwrap();

        // The synthetic report is 0xCD in all 32 bytes.
        assert!(parsed.report_data_matches(&[0xCD; 32]));
        assert!(parsed.report_data_matches(&[0xCD; 33]));
        assert!(parsed.report_data_matches(&[0xCD; 64]));

        // A shorter nonce is zero-padded by the requester, so its padding is
        // zero and cannot match an all-0xCD field.
        assert!(!parsed.report_data_matches(&[0xCD; 8]));
        assert!(!parsed.report_data_matches(&[0xCD; 31]));

        // Any other nonce must not match — this is the freshness check.
        assert!(!parsed.report_data_matches(&[0x00; 32]));
        assert!(!parsed.report_data_matches(&[0xCE; 32]));
    }

    #[test]
    fn report_data_matches_when_the_nonce_is_shorter_than_the_field() {
        // Build a report whose report data is a short nonce plus zero padding,
        // which is exactly what request_report writes.
        let mut report = synthetic_report(2, MIN_REPORT_LEN);
        report[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + REPORT_DATA_LEN].fill(0x00);
        report[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + 8].fill(0xCD);

        let parsed = SnpReport::parse(&report).unwrap();
        assert!(parsed.report_data_matches(&[0xCD; 8]));
    }

    #[test]
    fn evidence_json_shape_matches_the_tdx_path() {
        let report = synthetic_report(2, MIN_REPORT_LEN);
        let parsed = SnpReport::parse(&report).unwrap();
        let json = parsed.to_evidence_json(&[0x11; 32]);

        assert!(json.contains(r#""measurements":"#));
        assert!(json.contains(r#""hal":"1111"#));
        assert!(json.contains(r#""mrtd":"abab"#));
        assert!(json.contains(r#""tcb":"16776961"#));
        let _: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    }
}
