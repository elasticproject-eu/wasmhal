// AMD SEV-SNP attestation via the Linux TSM on guests that expose the
// firmware attestation interface directly.
//
// This is the path taken by every SEV-SNP guest *except* Azure: bare metal and
// GCP both run the guest with `/dev/sev-guest` present and the TSM configfs
// mounted, and the firmware produces the same signed SNP attestation report in
// both cases. (Azure confidential VMs sit behind a paravisor that hides the
// device nodes and surfaces a vTPM instead — see `crate::sev_vtpm`.)
//
// Why this needs its own module rather than a branch inside `platform.rs`: the
// Azure path returns Trustee/CoCo `az_snp_vtpm` evidence, while this path
// returns the same `{"measurements": {...}}` document as Intel TDX, because
// that is the shape the WIT `attestation` host call already promises. Keeping
// the two shapes apart is deliberate; merging them would break whichever
// consumer already handles the other.

use crate::attestation::{compute_hal_hash, request_report, tsm_available};
use crate::error::{HalError, HalResult};

/// Whether the SNP evidence source is usable on this host.
///
/// Requires the firmware attestation device plus the TSM interface to request a
/// report through. The Azure vTPM is checked first by the caller, so this does
/// not need to exclude it — an Azure guest has no `/dev/sev-guest` at all.
pub fn is_available() -> bool {
    let has_sev_guest = std::path::Path::new("/dev/sev-guest").exists();
    has_sev_guest && tsm_available()
}

/// Collect an SNP attestation report bound to `report_data`.
///
/// On success returns the measurements document described in
/// [`crate::snp_report`]. The firmware signature is *not* verified here: that
/// needs the VCEK chain and the AMD root of trust, and belongs to the relying
/// party that consumes this evidence. The report data *is* checked against the
/// caller's nonce before the document is returned, so a stale or mismatched
/// report fails loudly here rather than being forwarded as if it were fresh.
pub fn attest(report_data: &[u8]) -> HalResult<Vec<u8>> {
    if !is_available() {
        return Err(HalError::PlatformNotSupported(
            "SEV-SNP attestation via the Linux TSM requires /dev/sev-guest and \
             /sys/kernel/config/tsm/report"
                .into(),
        ));
    }

    let raw = request_report("snp", report_data)?;
    log::info!("SNP attestation report obtained: {} bytes", raw.len());

    let report = crate::snp_report::SnpReport::parse(&raw).map_err(|e| {
        HalError::AttestationFailed(format!("failed to parse SNP attestation report: {}", e))
    })?;

    // Freshness: confirm the firmware actually bound our nonce. Without this a
    // report cached (or returned) from an earlier request would look valid.
    if !report.report_data_matches(report_data) {
        return Err(HalError::AttestationFailed(format!(
            "SNP report data does not match the requested nonce: report carries {}",
            hex::encode(report.report_data)
        )));
    }

    log::debug!(
        "SNP report version {}, reported TCB {}, measurement {}",
        report.version,
        report.reported_tcb,
        hex::encode(report.measurement)
    );

    let evidence = report.to_evidence_json(&compute_hal_hash());
    log::info!("Returning SNP measurements JSON ({} bytes)", evidence.len());

    Ok(evidence.into_bytes())
}
