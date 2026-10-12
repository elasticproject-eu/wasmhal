//! Azure SEV-SNP attestation via the vTPM.
//!
//! Azure SEV-SNP confidential VMs sit behind a paravisor and expose neither
//! `/dev/sev-guest` nor the Linux TSM configfs, so the TSM-based SNP path
//! cannot run there. The paravisor instead presents a vTPM that carries an
//! HCL report in an NV index and can produce a TPM quote over caller-supplied
//! report data — together the two pieces of the evidence chain.
//!
//! Evidence is returned as HAL-native JSON (format v1):
//!
//! ```json
//! {
//!   "hal_format":     "1",
//!   "platform":       "az-snp-vtpm",
//!   "hcl_report_b64": "<standard base64>",
//!   "tpm_quote": {
//!     "signature_b64": "<standard base64>",
//!     "message_b64":   "<standard base64>",
//!     "pcrs_b64":      ["<standard base64>", ...]
//!   }
//! }
//! ```
//!
//! All byte fields are standard base64 (alphabet +/=).
//!
//! No VCEK certificate is fetched at collection time: the verifier derives
//! the AMD KDS URL for it from the shipped HCL report (chip_id + reported
//! TCB) and retrieves the certificate itself.

use crate::azure_vtpm;
use crate::error::{HalError, HalResult};

/// Whether the Azure SNP vTPM evidence source is usable on this host.
///
/// Detects an Azure SEV-SNP CVM by reading the vTPM HCL report NV index
/// through `/dev/tpmrm0` (tpm2-abrmd holds `/dev/tpm0`) and checking the
/// report type. Returns `false` on any error or a non-SNP HCL report (e.g. a
/// TDX guest), so the caller can fall through to the next evidence source.
pub fn is_available() -> bool {
    if !azure_vtpm::is_azure_host() {
        return false;
    }

    let has_vtpm =
        std::path::Path::new("/dev/tpm0").exists() || std::path::Path::new("/dev/tpmrm0").exists();
    if !has_vtpm {
        return false;
    }

    let result = is_azure_snp_cvm_via_tpmrm0().unwrap_or(false);
    log::debug!("Azure SNP CVM probe: {}", result);
    result
}

/// Check whether the vTPM HCL report carries an SNP report.
///
/// Returns `Ok(false)` if the HCL parse fails (an Azure CVM that is not
/// SEV-SNP) and `Err` if the device is not accessible.
fn is_azure_snp_cvm_via_tpmrm0() -> Result<bool, tss_esapi::Error> {
    use az_snp_vtpm::hcl::{HclReport, ReportType};

    let bytes = azure_vtpm::vtpm_get_report_tpmrm0()?;
    let Ok(hcl_report) = HclReport::new(bytes) else {
        return Ok(false);
    };
    Ok(hcl_report.report_type() == ReportType::Snp)
}

/// Collect Azure SEV-SNP evidence bound to `report_data`.
///
/// 1. Read the HCL report from the vTPM.
/// 2. Parse-check it into an SNP attestation report.
/// 3. Quote `report_data` with the vTPM attestation key.
pub fn attest(report_data: &[u8]) -> HalResult<Vec<u8>> {
    use az_snp_vtpm::hcl::HclReport;
    use az_snp_vtpm::report::AttestationReport;
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    azure_vtpm::check_report_data(report_data)?;

    // HCL report from the vTPM.
    let hcl_bytes = azure_vtpm::vtpm_get_report_tpmrm0().map_err(|e| {
        HalError::TeeInitializationFailed(format!(
            "Azure SNP: failed to get HCL report from vTPM: {}",
            e
        ))
    })?;

    // Parse-check: the HCL must carry a valid SNP attestation report.
    let _snp_check: AttestationReport = HclReport::new(hcl_bytes.clone())
        .map_err(|e| {
            HalError::TeeInitializationFailed(format!(
                "Azure SNP: failed to parse HCL report: {}",
                e
            ))
        })
        .and_then(|hcl| {
            hcl.try_into().map_err(|e| {
                HalError::TeeInitializationFailed(format!(
                    "Azure SNP: failed to extract SNP AttestationReport: {}",
                    e
                ))
            })
        })?;

    // TPM quote over the caller's report data.
    let (sig, msg, pcrs) = azure_vtpm::vtpm_get_quote_tpmrm0(report_data).map_err(|e| {
        HalError::TeeInitializationFailed(format!("Azure SNP: failed to get TPM Quote: {}", e))
    })?;

    // HAL-native JSON (format v1).
    let hal_output = serde_json::json!({
        "hal_format":     "1",
        "platform":       "az-snp-vtpm",
        "hcl_report_b64": b64.encode(&hcl_bytes),
        "tpm_quote": {
            "signature_b64": b64.encode(&sig),
            "message_b64":   b64.encode(&msg),
            "pcrs_b64":      pcrs.iter().map(|p| b64.encode(p.as_ref())).collect::<Vec<_>>(),
        },
    });

    log::info!(
        "Azure SNP+vTPM HAL-native evidence: hcl_bytes={} bytes",
        hcl_bytes.len()
    );

    Ok(hal_output.to_string().into_bytes())
}
