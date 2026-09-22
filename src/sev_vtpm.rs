// Azure SEV-SNP attestation via the guest vTPM.
//
// On Azure confidential VMs the hypervisor does not expose `/dev/sev` or
// `/dev/sev-guest`; the paravisor presents a vTPM instead. The vTPM carries an
// HCL (Host Compatibility Layer) report in an NV index, and can produce a TPM
// quote over caller-supplied report data. Together those two pieces are the
// evidence the CoCo `az-snp-vtpm` attester emits and that Trustee's
// `az_snp_vtpm` verifier consumes.
//
// The evidence is returned as JSON matching that attester's `Evidence` shape:
//
// ```json
// {
//   "version": 1,
//   "tpm_quote": { "signature": "<hex>", "message": "<hex>", "pcrs": ["<hex>", ...] },
//   "hcl_report": [ ... ],
//   "vcek": "<base64 DER>"
// }
// ```
//
// `vcek` is the AMD Versioned Chip Endorsement Key certificate, fetched from
// Azure IMDS. It is what lets a verifier check the SNP report against the AMD
// certificate chain.

use crate::error::{HalError, HalResult};

/// Whether the Azure vTPM evidence source is usable on this host.
pub fn is_available() -> bool {
    let has_vtpm =
        std::path::Path::new("/dev/tpm0").exists() || std::path::Path::new("/dev/tpmrm0").exists();
    if !has_vtpm {
        return false;
    }

    match az_snp_vtpm::is_snp_cvm() {
        Ok(is_snp) => is_snp,
        Err(e) => {
            log::debug!("vTPM present but no SNP HCL report: {}", e);
            false
        }
    }
}

/// Collect Azure SEV-SNP evidence bound to `report_data`.
pub async fn attest(report_data: &[u8]) -> HalResult<Vec<u8>> {
    if report_data.len() > 64 {
        return Err(HalError::InvalidParameter(
            "report_data must be at most 64 bytes".into(),
        ));
    }

    // The HCL report is read from the vTPM NV index.
    let hcl_report = az_snp_vtpm::vtpm::get_report().map_err(|e| {
        HalError::TeeInitializationFailed(format!("failed to read HCL report from vTPM: {}", e))
    })?;

    // A TPM quote over the supplied report data proves freshness: a verifier
    // can check that the PCR digest is bound to the nonce it issued.
    let quote = az_snp_vtpm::vtpm::get_quote(report_data).map_err(|e| {
        HalError::TeeInitializationFailed(format!("failed to obtain vTPM quote: {}", e))
    })?;

    // The VCEK certificate comes from Azure IMDS. Mirror the attester: an
    // unavailable VCEK degrades the evidence (no AMD chain validation) but is
    // not fatal, so log and carry on with an empty value.
    let vcek = match az_snp_vtpm::imds::get_certs() {
        Ok(certs) => base64_decode_pem(&certs.vcek).unwrap_or_else(|e| {
            log::warn!("failed to decode VCEK from IMDS: {}", e);
            Vec::new()
        }),
        Err(e) => {
            log::warn!("failed to fetch VCEK from IMDS: {}", e);
            Vec::new()
        }
    };

    let evidence = serde_json::json!({
        "version": 1u32,
        "tpm_quote": {
            "signature": hex::encode(quote.signature()),
            "message": hex::encode(quote.message()),
            "pcrs": quote
                .pcrs_sha256()
                .map(hex::encode)
                .collect::<Vec<String>>(),
        },
        "hcl_report": hcl_report,
        "vcek": base64_encode(&vcek),
    });

    let bytes = serde_json::to_vec(&evidence).map_err(|e| {
        HalError::TeeInitializationFailed(format!("failed to serialise SEV evidence: {}", e))
    })?;

    log::info!(
        "Collected Azure SEV-SNP evidence ({} bytes, {} PCRs)",
        bytes.len(),
        quote.pcrs_sha256().count()
    );

    Ok(bytes)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Strip PEM armour and return the DER bytes.
fn base64_decode_pem(pem: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| e.to_string())
}
