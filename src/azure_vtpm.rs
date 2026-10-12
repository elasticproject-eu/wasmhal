//! Azure vTPM helpers accessed through `/dev/tpmrm0`.
//!
//! The `az-cvm-vtpm` `vtpm` helpers open `/dev/tpm0`, which the tpm2-abrmd
//! daemon holds exclusively on Azure CVM images. The kernel TPM resource
//! manager (`/dev/tpmrm0`) multiplexes sessions natively and is safe for
//! concurrent access, so the helpers here use it instead.
//!
//! Constants are fixed by the Azure Confidential VM vTPM specification
//! (verified against az-cvm-vtpm 0.8.2):
//!   0x01400001  HCL report NV index
//!   0x81000003  vTPM attestation key persistent handle
//!   PCR slots 0-23, SHA-256

use crate::error::{HalError, HalResult};

/// HCL report NV index.
pub(crate) const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;

/// vTPM attestation key persistent handle.
pub(crate) const VTPM_AK_HANDLE: u32 = 0x81000003;

/// Raw vTPM quote parts: `(signature, attestation message, SHA-256 PCR digests)`.
pub(crate) type VtpmQuote = (Vec<u8>, Vec<u8>, Vec<[u8; 32]>);

pub(crate) use crate::platform::is_azure_host;

/// Read the raw HCL report bytes from the vTPM NV index.
///
/// Shared by the TDX and SNP attestation paths, which use the same index.
pub(crate) fn vtpm_get_report_tpmrm0() -> Result<Vec<u8>, tss_esapi::Error> {
    use std::str::FromStr;
    use tss_esapi::abstraction::nv;
    use tss_esapi::handles::NvIndexTpmHandle;
    use tss_esapi::interface_types::resource_handles::NvAuth;
    use tss_esapi::interface_types::session_handles::AuthSession;
    use tss_esapi::tcti_ldr::TctiNameConf;
    use tss_esapi::Context;

    let conf = TctiNameConf::from_str("device:/dev/tpmrm0")?;
    let mut context = Context::new(conf)?;
    context.set_sessions((Some(AuthSession::Password), None, None));
    let nv_index = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)?;
    let report = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(report)
}

/// Quote `report_data` with the vTPM attestation key over all 24 SHA-256 PCR
/// slots. Returns the raw `(signature, message, pcrs)` bytes.
pub(crate) fn vtpm_get_quote_tpmrm0(report_data: &[u8]) -> Result<VtpmQuote, tss_esapi::Error> {
    use std::str::FromStr;
    use tss_esapi::abstraction::pcr;
    use tss_esapi::handles::TpmHandle;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::interface_types::session_handles::AuthSession;
    use tss_esapi::structures::pcr_selection_list::PcrSelectionListBuilder;
    use tss_esapi::structures::pcr_slot::PcrSlot;
    use tss_esapi::structures::{AttestInfo, Data, Signature, SignatureScheme};
    use tss_esapi::tcti_ldr::TctiNameConf;
    use tss_esapi::traits::Marshall;
    use tss_esapi::Context;

    // All 24 PCR slots, SHA-256
    const PCR_SLOTS: [PcrSlot; 24] = [
        PcrSlot::Slot0,
        PcrSlot::Slot1,
        PcrSlot::Slot2,
        PcrSlot::Slot3,
        PcrSlot::Slot4,
        PcrSlot::Slot5,
        PcrSlot::Slot6,
        PcrSlot::Slot7,
        PcrSlot::Slot8,
        PcrSlot::Slot9,
        PcrSlot::Slot10,
        PcrSlot::Slot11,
        PcrSlot::Slot12,
        PcrSlot::Slot13,
        PcrSlot::Slot14,
        PcrSlot::Slot15,
        PcrSlot::Slot16,
        PcrSlot::Slot17,
        PcrSlot::Slot18,
        PcrSlot::Slot19,
        PcrSlot::Slot20,
        PcrSlot::Slot21,
        PcrSlot::Slot22,
        PcrSlot::Slot23,
    ];

    let conf = TctiNameConf::from_str("device:/dev/tpmrm0")?;
    let mut context = Context::new(conf)?;

    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;

    let quote_data: Data = report_data.try_into()?;
    let hash_algo = HashingAlgorithm::Sha256;
    let selection_list = PcrSelectionListBuilder::new()
        .with_selection(hash_algo, &PCR_SLOTS)
        .build()?;

    context.set_sessions((Some(AuthSession::Password), None, None));
    let (attest, signature) = context.quote(
        key_handle.into(),
        quote_data,
        SignatureScheme::Null,
        selection_list.clone(),
    )?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        return Err(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::InvalidParam,
        ));
    };
    let Signature::RsaSsa(rsa_sig) = signature else {
        return Err(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::InvalidParam,
        ));
    };

    let sig_bytes = rsa_sig.signature().to_vec();
    let message = attest.marshall()?;

    context.clear_sessions();
    let pcr_data = pcr::read_all(&mut context, selection_list)?;
    let pcr_bank = pcr_data
        .pcr_bank(hash_algo)
        .ok_or(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::InvalidParam,
        ))?;

    let pcrs: Vec<[u8; 32]> = pcr_bank
        .into_iter()
        .map(|(_, digest)| <[u8; 32]>::try_from(digest.clone()).unwrap_or([0u8; 32]))
        .collect();

    Ok((sig_bytes, message, pcrs))
}

/// Reject `report_data` that cannot be bound into a TPM quote: the quote
/// carries it as the `extraData` octet, sized for a 64-byte digest.
pub(crate) fn check_report_data(report_data: &[u8]) -> HalResult<()> {
    if report_data.len() > 64 {
        return Err(HalError::InvalidParameter(
            "report_data must be at most 64 bytes".into(),
        ));
    }
    Ok(())
}
