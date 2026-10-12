//! Azure TDX attestation via the vTPM.
//!
//! Azure TDX confidential VMs expose no Linux TSM, so the TSM-based TDX path
//! cannot run there. The vTPM instead carries an HCL report in an NV index;
//! parsed, it yields the TdReport whose SHA-384 digest the Azure IMDS signs
//! into a TD Quote. Together with a TPM quote over the caller's report data,
//! that is the evidence chain.
//!
//! Evidence is returned as HAL-native JSON (format v1):
//!
//! ```json
//! {
//!   "hal_format":     "1",
//!   "platform":       "az-tdx-vtpm",
//!   "hcl_report_b64": "<standard base64>",
//!   "td_quote_b64":   "<standard base64 raw TD Quote from Azure IMDS>",
//!   "tpm_quote": {
//!     "signature_b64": "<standard base64>",
//!     "message_b64":   "<standard base64>",
//!     "pcrs_b64":      ["<standard base64>", ...]
//!   }
//! }
//! ```
//!
//! All byte fields are standard base64 (alphabet +/=).

use crate::azure_vtpm;
use crate::error::{HalError, HalResult};

/// Whether the Azure TDX vTPM evidence source is usable on this host.
///
/// Detects an Azure TDX CVM by reading the vTPM HCL report NV index through
/// `/dev/tpmrm0` (tpm2-abrmd holds `/dev/tpm0`) and checking the report type.
/// Returns `false` on any error or a non-TDX HCL report (e.g. an SEV-SNP
/// guest), so the caller can fall through to the next evidence source.
pub fn is_available() -> bool {
    if !azure_vtpm::is_azure_host() {
        return false;
    }

    let has_vtpm =
        std::path::Path::new("/dev/tpm0").exists() || std::path::Path::new("/dev/tpmrm0").exists();
    if !has_vtpm {
        return false;
    }

    let result = is_azure_tdx_cvm_via_tpmrm0().unwrap_or(false);
    log::debug!("Azure TDX CVM probe: {}", result);
    result
}

/// Check whether the vTPM HCL report carries a TDX report.
///
/// Returns `Ok(false)` if the HCL parse fails (an Azure CVM that is not TDX)
/// and `Err` if the device is not accessible.
fn is_azure_tdx_cvm_via_tpmrm0() -> Result<bool, tss_esapi::Error> {
    use az_tdx_vtpm::hcl::{HclReport, ReportType};

    let bytes = azure_vtpm::vtpm_get_report_tpmrm0()?;
    let Ok(hcl_report) = HclReport::new(bytes) else {
        return Ok(false);
    };
    Ok(hcl_report.report_type() == ReportType::Tdx)
}

/// Collect Azure TDX evidence bound to `report_data`.
///
/// 1. Read the HCL report from the vTPM and parse it into a TdReport.
/// 2. Request the TD Quote for that TdReport from Azure IMDS.
/// 3. Quote `report_data` with the vTPM attestation key.
pub fn attest(report_data: &[u8]) -> HalResult<Vec<u8>> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    azure_vtpm::check_report_data(report_data)?;

    // HCL report from the vTPM, parsed into a TdReport.
    let hcl_report_bytes = azure_vtpm::vtpm_get_report_tpmrm0().map_err(|e| {
        HalError::TeeInitializationFailed(format!(
            "Azure TDX: failed to get TdReport from vTPM: {}",
            e
        ))
    })?;
    let hcl_for_td = az_tdx_vtpm::hcl::HclReport::new(hcl_report_bytes.clone()).map_err(|e| {
        HalError::TeeInitializationFailed(format!("Azure TDX: failed to parse HCL report: {}", e))
    })?;
    let td_report: az_tdx_vtpm::tdx::TdReport =
        hcl_for_td
            .try_into()
            .map_err(|e: az_tdx_vtpm::hcl::HclError| {
                HalError::TeeInitializationFailed(format!(
                    "Azure TDX: failed to parse TdReport: {}",
                    e
                ))
            })?;

    // TD Quote from Azure IMDS.
    let td_quote = az_tdx_vtpm::imds::get_td_quote(&td_report).map_err(|e| {
        HalError::TeeInitializationFailed(format!(
            "Azure TDX: failed to get TD Quote from IMDS: {}",
            e
        ))
    })?;

    // TPM quote over the caller's report data.
    let (sig, msg, pcrs) = azure_vtpm::vtpm_get_quote_tpmrm0(report_data).map_err(|e| {
        HalError::TeeInitializationFailed(format!("Azure TDX: failed to get TPM Quote: {}", e))
    })?;

    // HAL-native JSON (format v1).
    let hal_output = serde_json::json!({
        "hal_format":     "1",
        "platform":       "az-tdx-vtpm",
        "hcl_report_b64": b64.encode(&hcl_report_bytes),
        "td_quote_b64":   b64.encode(&td_quote),
        "tpm_quote": {
            "signature_b64": b64.encode(&sig),
            "message_b64":   b64.encode(&msg),
            "pcrs_b64":      pcrs.iter().map(|p| b64.encode(p.as_ref())).collect::<Vec<_>>(),
        },
    });

    log::info!(
        "Azure TDX+vTPM HAL-native evidence: td_quote={} bytes, hcl_report={} bytes",
        td_quote.len(),
        hcl_report_bytes.len()
    );

    Ok(hal_output.to_string().into_bytes())
}
