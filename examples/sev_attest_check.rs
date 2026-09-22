//! Collects real AMD SEV-SNP evidence from the running guest and prints a
//! summary. Intended to be run inside an Azure confidential VM.
use elastic_tee_hal::platform::ElasticTeeHal;

fn main() {
    let hal = match ElasticTeeHal::new() {
        Ok(h) => h,
        Err(e) => {
            println!("HAL init failed: {}", e);
            std::process::exit(1);
        }
    };

    println!("platform: {:?}", hal.platform_type());

    let report_data = b"wasmhal-sev-check";
    match futures::executor::block_on(hal.attest(report_data)) {
        Ok(evidence) => {
            println!("evidence: {} bytes", evidence.len());
            match serde_json::from_slice::<serde_json::Value>(&evidence) {
                Ok(v) => {
                    println!("version: {}", v["version"]);
                    println!(
                        "pcrs: {}",
                        v["tpm_quote"]["pcrs"]
                            .as_array()
                            .map(|a| a.len())
                            .unwrap_or(0)
                    );
                    println!(
                        "hcl_report bytes: {}",
                        v["hcl_report"].as_array().map(|a| a.len()).unwrap_or(0)
                    );
                    println!(
                        "vcek present: {}",
                        v["vcek"].as_str().map(|s| !s.is_empty()).unwrap_or(false)
                    );
                    let sig = v["tpm_quote"]["signature"].as_str().unwrap_or("");
                    println!("signature hex len: {}", sig.len());
                }
                Err(e) => println!("evidence is not JSON: {}", e),
            }
        }
        Err(e) => println!("attest failed: {}", e),
    }
}
