// Intel Trust Authority (ITA) client
//
// Submits a raw TDX DCAP quote to the Intel Trust Authority attestation service
// and returns the EAR (Entity Attestation Result) JWT token.
//
// Prerequisites:
//   - Set the ITA_API_KEY environment variable with your ITA API key.
//     Register at https://portal.eu.trustauthority.intel.com to obtain one.
//
// Flow (ITA v2 verifier-nonce protocol):
//   1. GET  /appraisal/v2/nonce        →  verifier nonce {val, iat, signature}
//   2. Compute REPORTDATA = SHA-512(val_bytes || iat_bytes || user_data)
//   3. Generate TDX quote with REPORTDATA bound into the hardware
//   4. POST /appraisal/v2/attest       →  EAR JWT string

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha512};

/// ITA EU region base URL (key was registered at portal.eu.trustauthority.intel.com)
const ITA_BASE_URL: &str = "https://api.eu.trustauthority.intel.com";
const ITA_NONCE_PATH: &str = "/appraisal/v2/nonce";
const ITA_ATTEST_PATH: &str = "/appraisal/v2/attest";

/// Holds the verifier nonce returned by ITA's /nonce endpoint.
/// Fields are base64-encoded as returned by the API — echoed back verbatim in the attest call.
pub struct ItaNonceState {
    pub val_b64: String,
    pub iat_b64: String,
    pub sig_b64: String,
}

/// Client for Intel Trust Authority attestation verification
pub struct ItaClient {
    api_key: String,
    base_url: String,
    http: reqwest::Client,
}

impl ItaClient {
    /// Create an ITA client using the ITA_API_KEY environment variable.
    /// Returns None if the variable is not set.
    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var("ITA_API_KEY").ok()?;
        Some(Self::new(api_key))
    }

    /// Create an ITA client with an explicit API key.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: ITA_BASE_URL.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Override the ITA base URL (useful for testing / other regions).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Step 1 of the ITA attestation flow.
    ///
    /// Fetches a verifier nonce from ITA and derives the 64-byte REPORTDATA
    /// that must be embedded into the TDX quote via the TSM interface.
    ///
    /// REPORTDATA = SHA-512(nonce.val_bytes || nonce.iat_bytes || user_data)
    ///
    /// Returns `(report_data, nonce_state)`. Pass `report_data` to the TSM
    /// quote generator, then pass `nonce_state` to `attest_with_nonce`.
    pub async fn fetch_nonce_and_report_data(
        &self,
        user_data: &[u8],
    ) -> Result<([u8; 64], ItaNonceState), String> {
        let nonce_url = format!("{}{}", self.base_url, ITA_NONCE_PATH);

        let response = self
            .http
            .get(&nonce_url)
            .header("x-api-key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("ITA nonce request failed: {}", e))?;

        let status = response.status();
        let body_text = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".to_string());

        if !status.is_success() {
            return Err(format!(
                "ITA nonce returned HTTP {}: {}",
                status, body_text
            ));
        }

        let nonce_json: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| format!("Failed to parse ITA nonce response: {}", e))?;

        let val_b64 = nonce_json["val"]
            .as_str()
            .ok_or("Missing 'val' in ITA nonce response")?
            .to_string();
        let iat_b64 = nonce_json["iat"]
            .as_str()
            .ok_or("Missing 'iat' in ITA nonce response")?
            .to_string();
        let sig_b64 = nonce_json["signature"]
            .as_str()
            .ok_or("Missing 'signature' in ITA nonce response")?
            .to_string();

        // Decode raw bytes for hashing
        let val_bytes = STANDARD
            .decode(&val_b64)
            .map_err(|e| format!("Failed to decode nonce val: {}", e))?;
        let iat_bytes = STANDARD
            .decode(&iat_b64)
            .map_err(|e| format!("Failed to decode nonce iat: {}", e))?;

        // REPORTDATA = SHA-512(val_bytes || iat_bytes || user_data)
        let mut hasher = Sha512::new();
        hasher.update(&val_bytes);
        hasher.update(&iat_bytes);
        hasher.update(user_data);
        let digest = hasher.finalize();

        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&digest);

        log::debug!("ITA nonce fetched, REPORTDATA computed (SHA-512, 64 bytes)");
        Ok((report_data, ItaNonceState { val_b64, iat_b64, sig_b64 }))
    }

    /// Step 2 of the ITA attestation flow.
    ///
    /// Submits the TDX quote (generated with the REPORTDATA from step 1) together
    /// with the verifier nonce and original user_data to ITA, and returns the EAR JWT.
    ///
    /// # Arguments
    /// * `quote`      – Raw TDX DCAP quote bytes from the TSM outblob
    /// * `user_data`  – The original user-supplied data (NOT the SHA-512 hash)
    /// * `nonce`      – The nonce state returned by `fetch_nonce_and_report_data`
    pub async fn attest_with_nonce(
        &self,
        quote: &[u8],
        user_data: &[u8],
        nonce: &ItaNonceState,
    ) -> Result<String, String> {
        let attest_url = format!("{}{}", self.base_url, ITA_ATTEST_PATH);
        let quote_b64 = STANDARD.encode(quote);
        let user_data_b64 = STANDARD.encode(user_data);

        let body = serde_json::json!({
            "tdx": {
                "quote": quote_b64,
                "runtime_data": user_data_b64,
                "verifier_nonce": {
                    "val": nonce.val_b64,
                    "iat": nonce.iat_b64,
                    "signature": nonce.sig_b64
                }
            }
        });

        log::info!("Submitting TDX quote to ITA ({} bytes)", quote.len());

        let response = self
            .http
            .post(&attest_url)
            .header("x-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("ITA attest request failed: {}", e))?;

        let status = response.status();
        let body_text = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".to_string());

        if !status.is_success() {
            return Err(format!(
                "ITA returned HTTP {}: {}",
                status, body_text
            ));
        }

        let ear = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_text) {
            if let Some(token) = json.get("token").and_then(|t| t.as_str()) {
                token.to_string()
            } else {
                body_text
            }
        } else {
            body_text
        };

        log::info!(
            "ITA attestation succeeded, EAR token received ({} bytes)",
            ear.len()
        );
        Ok(ear)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ita_client_no_key() {
        if std::env::var("ITA_API_KEY").is_err() {
            assert!(ItaClient::from_env().is_none());
        }
    }

    #[test]
    fn test_ita_client_with_key() {
        let client = ItaClient::new("test-key-123");
        assert_eq!(client.api_key, "test-key-123");
        assert_eq!(client.base_url, ITA_BASE_URL);
    }
}
