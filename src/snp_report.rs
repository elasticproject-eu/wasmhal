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
//! | Offset | Size | Field             | Notes                              |
//! |-------:|-----:|-------------------|------------------------------------|
//! |  0x000 |    4 | VERSION           | 2–5 (see `KNOWN_VERSIONS`)         |
//! |  0x004 |    4 | GUEST_SVN         |                                    |
//! |  0x008 |    8 | POLICY            |                                    |
//! |  0x010 |   16 | FAMILY_ID         |                                    |
//! |  0x020 |   16 | IMAGE_ID          |                                    |
//! |  0x030 |    4 | VMPL              |                                    |
//! |  0x034 |    4 | SIGNATURE_ALGO    |                                    |
//! |  0x038 |    8 | CURRENT_TCB       |                                    |
//! |  0x040 |    8 | PLATFORM_INFO     |                                    |
//! |  0x048 |    4 | FLAGS             | AUTHOR_KEY_EN, MASK_CHIP_KEY, …    |
//! |  0x050 |   64 | REPORT_DATA       | verifier nonce                     |
//! |  0x090 |   48 | MEASUREMENT       | launch digest ("MRTD")             |
//! |  0x0C0 |   32 | HOST_DATA         |                                    |
//! |  0x0E0 |   48 | ID_KEY_DIGEST     |                                    |
//! |  0x110 |   48 | AUTHOR_KEY_DIGEST |                                    |
//! |  0x140 |   32 | REPORT_ID         |                                    |
//! |  0x160 |   32 | REPORT_ID_MA      |                                    |
//! |  0x180 |    8 | REPORTED_TCB      |                                    |
//! |  0x1A0 |   64 | CHIP_ID           |                                    |
//! |  0x2A0 |  512 | SIGNATURE         | ECDSA P-384 over 0x000–0x29F       |
//!
//! Checked against real reports from GCP SEV-SNP guests (version 5): the
//! nonce written through the TSM `inblob` appears at 0x050.
//!
//! Only VERSION, REPORTED_TCB, REPORT_DATA and MEASUREMENT are read here.
//! Signature verification is a verifier's job: it needs the VCEK certificate
//! chain and the AMD root of trust, and a caller that skips that check has not
//! gained anything by having us parse the layout for it.

/// Length of the SNP `MEASUREMENT` field (SHA-384).
pub const MEASUREMENT_LEN: usize = 48;

/// Length of the SNP `REPORT_DATA` field.
pub const REPORT_DATA_LEN: usize = 64;

/// Offset of VERSION.
const OFFSET_VERSION: usize = 0x000;
/// Offset of REPORTED_TCB.
const OFFSET_REPORTED_TCB: usize = 0x180;
/// Offset of REPORT_DATA.
const OFFSET_REPORT_DATA: usize = 0x050;
/// Offset of MEASUREMENT.
const OFFSET_MEASUREMENT: usize = 0x090;

/// The smallest report that can contain everything read here.
///
/// The full signed report is 0x4A0 bytes; we only require enough to reach the
/// end of MEASUREMENT plus REPORTED_TCB, which is what makes the parser
/// tolerant of a firmware that trims fields it is not required to populate.
const MIN_REPORT_LEN: usize = OFFSET_REPORTED_TCB + 8;

/// The SNP guest report version this parser understands.
///
/// 2 is the base SNP report; 3 adds the TCB components block; 4 and 5 add
/// mitigation-vector and launch-TCB fields in previously reserved space (GCP
/// SEV-SNP guests return version 5 as of 2026). All of them place the fields
/// read here at the same offsets and keep the 0x4A0 size, so all are accepted.
const KNOWN_VERSIONS: [u32; 4] = [2, 3, 4, 5];

/// Fields extracted from a raw SNP attestation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpReport {
    /// Report version (one of `KNOWN_VERSIONS`).
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
    /// `requested` is zero-padded to [`REPORT_DATA_LEN`] (64 bytes), exactly as
    /// [`crate::attestation::request_report`] pads it before writing `inblob`,
    /// and must then equal the report's `REPORT_DATA` field byte for byte.
    /// Longer input can never have been bound and does not match.
    pub fn report_data_matches(&self, requested: &[u8]) -> bool {
        if requested.len() > REPORT_DATA_LEN {
            return false;
        }
        let mut want = [0u8; REPORT_DATA_LEN];
        want[..requested.len()].copy_from_slice(requested);
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
        for version in KNOWN_VERSIONS {
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
    fn report_data_matches_the_full_64_byte_field() {
        let report = synthetic_report(2, MIN_REPORT_LEN);
        let parsed = SnpReport::parse(&report).unwrap();

        // The synthetic report is 0xCD in all 64 bytes.
        assert!(parsed.report_data_matches(&[0xCD; 64]));

        // A shorter nonce is zero-padded by the requester, so its padding is
        // zero and cannot match an all-0xCD field.
        assert!(!parsed.report_data_matches(&[0xCD; 32]));
        assert!(!parsed.report_data_matches(&[0xCD; 63]));
        assert!(!parsed.report_data_matches(&[0xCD; 65]));

        // Any other nonce must not match — this is the freshness check.
        assert!(!parsed.report_data_matches(&[0x00; 64]));
        assert!(!parsed.report_data_matches(&[0xCE; 64]));
    }

    #[test]
    fn parse_reads_report_data_after_tcb_and_platform_info() {
        // Regression: the fields before REPORT_DATA (CURRENT_TCB at 0x38,
        // PLATFORM_INFO at 0x40) must not leak into the parsed nonce.
        let mut report = synthetic_report(5, 0x4A0);
        report[0x38..0x50].fill(0xEE);
        let parsed = SnpReport::parse(&report).unwrap();
        assert_eq!(parsed.report_data, [0xCD; REPORT_DATA_LEN]);
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
