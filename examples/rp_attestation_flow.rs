//! End-to-end demo: attester → relying party → decrypted WASM
//!
//! Flow:
//!   1. Generate a random nonce as user_data.
//!   2. Run the Intel Trust Authority round-trip via `hal.attest_with_ita()`
//!      to obtain an EAR JWT signed by ITA.
//!   3. POST the EAR to the relying party's `/attest` endpoint.
//!   4. Receive the AES-256 key (base64) on success.
//!   5. GET the encrypted WASM from `/wasm`.
//!   6. AES-256-GCM-decrypt the payload and write it to disk.
//!   7. Execute the decrypted WASM in-process via wasmtime (preview1 WASI).
//!
//! Run on a TDX VM with:
//!   ITA_API_KEY=<key> RP_URL=http://<rp-host>:8087 \
//!     cargo run --example rp_attestation_flow
//!
//! Defaults:
//!   RP_URL    = http://127.0.0.1:8087
//!   OUTPUT    = ./decrypted.wasm
//!   SKIP_RUN  = unset (set to "1" to stop after decryption)
//!
//! ## Relying party
//!
//! The relying party (RP) used during development is a Thales-internal Go
//! service and is **not** included in this repository. Any compatible RP
//! must expose the following HTTP API on the URL pointed to by `RP_URL`:
//!
//!   * `POST /attest`  body: `{"ear":"<EAR JWT>"}`
//!                     200 : `{"ok":true,"key":"<base64 AES-256 key>",
//!                              "wasm_url":"/wasm"}`
//!     The RP must verify the EAR JWT signature against the ITA JWKS
//!     (e.g. `https://portal.eu.trustauthority.intel.com/certs`) and
//!     enforce its own policy on the EAR claims before releasing the key.
//!
//!   * `GET  /wasm`    200 : raw bytes, layout `nonce(12) || ciphertext+tag`
//!                     encrypted with AES-256-GCM under the key returned
//!                     by `/attest`.
//!
//! See `WASM_GUIDE.md` for the encryption layout and an example payload.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use elastic_tee_hal::{ElasticTeeHal, RandomInterface};
use serde_json::Value;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let rp_base = std::env::var("RP_URL").unwrap_or_else(|_| "http://127.0.0.1:8087".to_string());
    let output_path = std::env::var("OUTPUT").unwrap_or_else(|_| "./decrypted.wasm".to_string());

    println!("=== Attester → Relying Party demo ===");
    println!("Relying party : {}", rp_base);
    println!("Output WASM   : {}", output_path);

    // 1. Initialise HAL.
    let hal = ElasticTeeHal::new()?;
    println!("✓ HAL initialised on {:?}", hal.platform_type());

    // 2. Generate nonce.
    let random = RandomInterface::new();
    let nonce = random.generate_nonce(32)?;
    println!("✓ 32-byte nonce: {}", hex::encode(&nonce));

    // 3. ITA round-trip → EAR JWT.
    println!("→ Submitting TDX quote to Intel Trust Authority…");
    let ear_jwt = hal.attest_with_ita(&nonce).await?;
    println!("✓ EAR JWT received ({} bytes)", ear_jwt.len());

    // 4. POST EAR to relying party.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let attest_url = format!("{}/attest", rp_base.trim_end_matches('/'));
    println!("→ POST {}", attest_url);

    let resp = http
        .post(&attest_url)
        .json(&serde_json::json!({ "ear": ear_jwt }))
        .send()
        .await?;

    let status = resp.status();
    let body_text = resp.text().await?;
    if !status.is_success() {
        return Err(format!("relying party rejected attestation: HTTP {} — {}", status, body_text).into());
    }

    let body: Value = serde_json::from_str(&body_text)?;
    let key_b64 = body
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or("no 'key' field in RP response")?;
    let wasm_url_path = body
        .get("wasm_url")
        .and_then(|v| v.as_str())
        .unwrap_or("/wasm");
    let key_bytes = STANDARD.decode(key_b64)?;
    if key_bytes.len() != 32 {
        return Err(format!("key length is {} bytes; expected 32", key_bytes.len()).into());
    }
    println!("✓ Attestation accepted, AES-256 key released");

    // 5. Fetch encrypted WASM.
    let wasm_url = format!("{}{}", rp_base.trim_end_matches('/'), wasm_url_path);
    println!("→ GET {}", wasm_url);
    let enc = http.get(&wasm_url).send().await?.error_for_status()?.bytes().await?;
    println!("✓ Encrypted WASM downloaded ({} bytes)", enc.len());

    // 6. AES-256-GCM-decrypt.  Layout written by the relying party:
    //    enc = nonce(12) || ciphertext_with_auth_tag
    if enc.len() < 12 + 16 {
        return Err("encrypted payload too short".into());
    }
    let (nonce_bytes, ciphertext) = enc.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("AES-GCM decrypt failed: {}", e))?;

    std::fs::write(&output_path, &plaintext)?;
    println!(
        "✓ Decrypted WASM written to {} ({} bytes)",
        output_path,
        plaintext.len()
    );

    // 7. Execute the decrypted WASM in-process via wasmtime + WASI preview1.
    //    `examplejd.wasm` is a core WASI module that prints "Hello, World!"
    //    from `_start`. We run it here so the demo closes the loop:
    //      attest → release key → decrypt → execute.
    if std::env::var("SKIP_RUN").ok().as_deref() != Some("1") {
        println!("\n→ Executing decrypted WASM via wasmtime…");
        run_wasi_module(&plaintext).await?;
        println!("✓ WASM execution finished");
    } else {
        println!("(SKIP_RUN=1 set — not executing the decrypted module)");
    }

    println!("=== DONE ===");

    Ok(())
}

/// Run a core WASI (preview1) module by calling its `_start` export.
/// stdout/stderr are inherited so any output is visible directly.
async fn run_wasi_module(wasm_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    use wasmtime::{Config, Engine, Linker, Module, Store};
    use wasmtime_wasi::preview1::{self, WasiP1Ctx};
    use wasmtime_wasi::WasiCtxBuilder;

    let mut config = Config::new();
    config.async_support(true);
    let engine = Engine::new(&config)?;
    let module = Module::new(&engine, wasm_bytes)?;

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    preview1::add_to_linker_async(&mut linker, |t| t)?;

    let wasi: WasiP1Ctx = WasiCtxBuilder::new()
        .inherit_stdio()
        .inherit_env()
        .build_p1();
    let mut store = Store::new(&engine, wasi);

    let instance = linker.instantiate_async(&mut store, &module).await?;

    println!("--- BEGIN WASM stdout ---");
    if let Ok(start) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
        start.call_async(&mut store, ()).await?;
    } else if let Ok(main) = instance.get_typed_func::<(), ()>(&mut store, "main") {
        main.call_async(&mut store, ()).await?;
    } else {
        return Err("WASM has no `_start` or `main` export".into());
    }
    println!("--- END WASM stdout ---");
    Ok(())
}
