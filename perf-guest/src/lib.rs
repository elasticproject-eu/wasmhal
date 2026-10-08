//! Benchmark guest component for the ELASTIC TEE HAL.
//!
//! Exercises the HAL from inside Wasm, grouped by the use-case worlds in
//! `wit-modular/complete.wit` (minimal, attestation, storage, network,
//! compute). Each operation is timed inside the guest with the WASI
//! monotonic clock, so the numbers include the Wasm-to-host call boundary.
//!
//! Configuration (environment variables passed through by the host):
//! * `PERF_ECHO_PORT` - TCP port of a loopback echo server (network world)
//! * `PERF_REPS`      - repetitions per operation (default 15)
//!
//! `run()` returns tab-separated lines: `world\top\tmedian_ns\tp95_ns\tstatus`.

wit_bindgen::generate!({
    path: "../hal-runtime/wit",
    world: "hal-consumer",
});

use elastic::hal::{
    attestation, communication, crypto, gpu, platform, random, resources, sockets, storage,
};
use std::time::Instant;

struct Component;

struct Out(String);

impl Out {
    /// Time `f` in batches of `batch` calls, `reps` times; record per-call median and p95.
    fn measure(
        &mut self,
        world: &str,
        op: &str,
        batch: u32,
        reps: u32,
        mut f: impl FnMut() -> Result<(), String>,
    ) {
        let mut samples = Vec::with_capacity(reps as usize);
        // Warm-up
        if let Err(e) = f() {
            self.0.push_str(&format!(
                "{world}\t{op}\t0\t0\terror: {}\n",
                e.replace(['\t', '\n'], " ")
            ));
            return;
        }
        for _ in 0..reps {
            let t = Instant::now();
            for _ in 0..batch {
                if let Err(e) = f() {
                    self.0.push_str(&format!(
                        "{world}\t{op}\t0\t0\terror: {}\n",
                        e.replace(['\t', '\n'], " ")
                    ));
                    return;
                }
            }
            samples.push(t.elapsed().as_nanos() as f64 / batch as f64);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let med = samples[samples.len() / 2];
        let p95 = samples[(samples.len() - 1) * 95 / 100];
        self.0
            .push_str(&format!("{world}\t{op}\t{med:.0}\t{p95:.0}\tok\n"));
    }
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

impl exports::elastic::hal::run::Guest for Component {
    fn run() -> Vec<u8> {
        let reps = env_u32("PERF_REPS", 15);
        let mut out = Out(String::new());
        let kib = vec![0x5Au8; 1024];
        let kib64 = vec![0x5Au8; 64 * 1024];
        let key = vec![7u8; 32];

        // ---------------- minimal: platform + crypto + random ----------------
        let w = "minimal";
        out.measure(w, "platform.get-platform-info", 1000, reps, || {
            platform::get_platform_info();
            Ok(())
        });
        out.measure(w, "platform.has-capability", 1000, reps, || {
            platform::has_capability("crypto");
            Ok(())
        });
        out.measure(w, "random.get-random-bytes (32 B)", 1000, reps, || {
            random::get_random_bytes(32).map(drop)
        });
        out.measure(w, "crypto.hash SHA-256 (1 KiB)", 500, reps, || {
            crypto::hash(&kib, crypto::HashAlgorithm::Sha256).map(drop)
        });
        out.measure(w, "crypto.hash SHA-256 (64 KiB)", 20, reps, || {
            crypto::hash(&kib64, crypto::HashAlgorithm::Sha256).map(drop)
        });
        out.measure(w, "crypto.encrypt AES-256-GCM (1 KiB)", 500, reps, || {
            crypto::encrypt(&kib, &key, crypto::CipherAlgorithm::Aes256Gcm).map(drop)
        });
        let ct =
            crypto::encrypt(&kib, &key, crypto::CipherAlgorithm::Aes256Gcm).unwrap_or_default();
        out.measure(w, "crypto.decrypt AES-256-GCM (1 KiB)", 500, reps, || {
            crypto::decrypt(&ct, &key, crypto::CipherAlgorithm::Aes256Gcm).map(drop)
        });
        out.measure(w, "crypto.encrypt AES-256-GCM (64 KiB)", 20, reps, || {
            crypto::encrypt(&kib64, &key, crypto::CipherAlgorithm::Aes256Gcm).map(drop)
        });
        match crypto::generate_keypair() {
            Ok(kp) => {
                out.measure(w, "crypto.sign Ed25519 (1 KiB)", 50, reps, || {
                    crypto::sign(&kib, &kp.private_key).map(drop)
                });
            }
            Err(e) => out
                .0
                .push_str(&format!("{w}\tcrypto.generate-keypair\t0\t0\terror: {e}\n")),
        }

        // ---------------- attestation: nonce + evidence ----------------
        let w = "attestation";
        out.measure(
            w,
            "attestation flow (nonce + evidence)",
            1,
            reps.min(10),
            || {
                let nonce = random::get_random_bytes(32)?;
                attestation::attestation(&nonce).map(drop)
            },
        );

        // ---------------- storage: platform + crypto + storage ----------------
        let w = "storage";
        match storage::create_container("perf-guest") {
            Ok(c) => {
                let kib4 = vec![0xC3u8; 4 * 1024];
                let mib = vec![0xC3u8; 1024 * 1024];
                out.measure(w, "storage.store-object (4 KiB)", 50, reps, || {
                    storage::store_object(c, "obj4k", &kib4).map(drop)
                });
                out.measure(w, "storage.retrieve-object (4 KiB)", 50, reps, || {
                    storage::retrieve_object(c, "obj4k").map(drop)
                });
                out.measure(w, "storage.store-object (1 MiB)", 2, reps, || {
                    storage::store_object(c, "obj1m", &mib).map(drop)
                });
                out.measure(w, "storage.retrieve-object (1 MiB)", 2, reps, || {
                    storage::retrieve_object(c, "obj1m").map(drop)
                });
                out.measure(w, "encrypt + store (4 KiB, app-level)", 50, reps, || {
                    let ct = crypto::encrypt(&kib4, &key, crypto::CipherAlgorithm::Aes256Gcm)?;
                    storage::store_object(c, "enc4k", &ct).map(drop)
                });
            }
            Err(e) => out.0.push_str(&format!(
                "{w}\tstorage.create-container\t0\t0\terror: {e}\n"
            )),
        }

        // ---------------- network: sockets + communication ----------------
        let w = "network";
        let port = env_u32("PERF_ECHO_PORT", 0) as u16;
        let addr = sockets::Address {
            ip: "127.0.0.1".into(),
            port,
        };
        if port != 0 {
            out.measure(
                w,
                "sockets.create + connect + close (TCP)",
                20,
                reps,
                || {
                    let s = sockets::create_socket(sockets::Protocol::Tcp)?;
                    sockets::connect(s, &addr)?;
                    sockets::close(s)
                },
            );
            match sockets::create_socket(sockets::Protocol::Tcp)
                .and_then(|s| sockets::connect(s, &addr).map(|_| s))
            {
                Ok(s) => {
                    out.measure(
                        w,
                        "sockets.send + receive (1 KiB echo round trip)",
                        50,
                        reps,
                        || {
                            sockets::send(s, &kib)?;
                            let mut got = 0;
                            while got < kib.len() {
                                got += sockets::receive(s, 65536)?.len();
                            }
                            Ok(())
                        },
                    );
                    let _ = sockets::close(s);
                }
                Err(e) => out.0.push_str(&format!(
                    "{w}\tsockets.send + receive (1 KiB echo round trip)\t0\t0\terror: {e}\n"
                )),
            }
        }
        out.measure(w, "communication send + receive (1 KiB)", 200, reps, || {
            communication::send_message("wasm-guest", &kib, false)?;
            communication::receive_message().map(drop)
        });

        // ---------------- compute: gpu + resources ----------------
        let w = "compute";
        out.measure(
            w,
            "resources.allocate + deallocate (64 MiB memory)",
            200,
            reps,
            || {
                let r = resources::allocate(resources::AllocationRequest {
                    resource_type: resources::ResourceType::Memory,
                    amount: 64,
                    priority: 50,
                })?;
                resources::deallocate(&r.allocation_id)
            },
        );
        out.measure(w, "resources.query-available (memory)", 1000, reps, || {
            resources::query_available(resources::ResourceType::Memory).map(drop)
        });
        out.measure(w, "gpu.list-adapters", 10, reps, || {
            gpu::list_adapters().map(drop)
        });

        out.0.into_bytes()
    }
}

export!(Component);
