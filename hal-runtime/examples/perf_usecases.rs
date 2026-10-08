//! Use-case benchmarks for the ELASTIC TEE HAL, following the composed
//! worlds in `wit-modular/complete.wit` (minimal, attestation, storage,
//! network, compute).
//!
//! Each operation is measured twice:
//! * from a Wasm guest component (`perf-guest`) through the Wasmtime
//!   component-model boundary, as a real workload would use the HAL, and
//! * natively, by calling the same `HalHost` function directly.
//!
//! The difference is the cost of running the workload as Wasm.
//!
//! Build the guest first, then run:
//!     (cd ../perf-guest && cargo build --release --target wasm32-wasip2)
//!     cargo run --release --example perf_usecases
//!
//! On a machine without a TEE the HAL is created for an explicit platform
//! (attestation is then reported as unavailable).

use anyhow::{Context, Result};
use elastic_tee_hal::platform::PlatformType;
use hal_runtime::{CipherAlgorithm, HashAlgorithm};
use hal_runtime::{HalConsumer, HalHost, HalRuntime};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use wasmtime::component::Component;

const REPS: u32 = 31;

fn measure(
    batch: u32,
    reps: u32,
    mut f: impl FnMut() -> Result<(), String>,
) -> Result<(f64, f64), String> {
    f()?;
    let mut s = Vec::new();
    for _ in 0..reps {
        let t = Instant::now();
        for _ in 0..batch {
            f()?;
        }
        s.push(t.elapsed().as_nanos() as f64 / batch as f64);
    }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Ok((s[s.len() / 2], s[(s.len() - 1) * 95 / 100]))
}

fn fmt_ns(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{ns:.0} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1e3)
    } else {
        format!("{:.2} ms", ns / 1e6)
    }
}

fn make_host() -> Result<(HalHost, String)> {
    match HalHost::new() {
        Ok(h) => Ok((h, "detected TEE".into())),
        Err(e) => {
            let h = HalHost::with_platform(PlatformType::AmdSev)?;
            Ok((
                h,
                format!("no TEE detected ({e}); HAL created with an explicit platform"),
            ))
        }
    }
}

/// Loopback TCP echo server for the network world.
fn start_echo_server() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 65536];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

type Results = BTreeMap<(String, String), Result<(f64, f64), String>>;

fn native(host: &mut HalHost, port: u16) -> Results {
    use hal_runtime::{AllocationRequest, ResourceType};
    let mut r = Results::new();
    let mut put = |w: &str, op: &str, v| {
        r.insert((w.to_string(), op.to_string()), v);
    };
    let kib = vec![0x5Au8; 1024];
    let kib64 = vec![0x5Au8; 64 * 1024];
    let key = vec![7u8; 32];

    let w = "minimal";
    put(
        w,
        "platform.get-platform-info",
        measure(1000, REPS, || {
            host.platform_info();
            Ok(())
        }),
    );
    put(
        w,
        "platform.has-capability",
        measure(1000, REPS, || {
            host.capabilities_has("crypto");
            Ok(())
        }),
    );
    put(
        w,
        "random.get-random-bytes (32 B)",
        measure(1000, REPS, || host.random_get_bytes(32).map(drop)),
    );
    put(
        w,
        "crypto.hash SHA-256 (1 KiB)",
        measure(500, REPS, || {
            host.crypto_hash(&kib, HashAlgorithm::Sha256).map(drop)
        }),
    );
    put(
        w,
        "crypto.hash SHA-256 (64 KiB)",
        measure(20, REPS, || {
            host.crypto_hash(&kib64, HashAlgorithm::Sha256).map(drop)
        }),
    );
    put(
        w,
        "crypto.encrypt AES-256-GCM (1 KiB)",
        measure(500, REPS, || {
            host.crypto_encrypt(&kib, &key, CipherAlgorithm::Aes256Gcm)
                .map(drop)
        }),
    );
    let ct = host
        .crypto_encrypt(&kib, &key, CipherAlgorithm::Aes256Gcm)
        .unwrap();
    put(
        w,
        "crypto.decrypt AES-256-GCM (1 KiB)",
        measure(500, REPS, || {
            host.crypto_decrypt(&ct, &key, CipherAlgorithm::Aes256Gcm)
                .map(drop)
        }),
    );
    put(
        w,
        "crypto.encrypt AES-256-GCM (64 KiB)",
        measure(20, REPS, || {
            host.crypto_encrypt(&kib64, &key, CipherAlgorithm::Aes256Gcm)
                .map(drop)
        }),
    );
    let kp = host.crypto_generate_keypair().unwrap();
    put(
        w,
        "crypto.sign Ed25519 (1 KiB)",
        measure(50, REPS, || {
            host.crypto_sign(&kib, &kp.private_key).map(drop)
        }),
    );

    let w = "attestation";
    let att = {
        let mut f = || -> Result<(), String> {
            let nonce = host.random_get_bytes(32)?;
            host.attestation(nonce).map(drop)
        };
        measure(1, REPS.min(10), &mut f)
    };
    put(w, "attestation flow (nonce + evidence)", att);

    let w = "storage";
    match host.storage_create_container("perf-native") {
        Ok(c) => {
            let kib4 = vec![0xC3u8; 4 * 1024];
            let mib = vec![0xC3u8; 1024 * 1024];
            put(
                w,
                "storage.store-object (4 KiB)",
                measure(50, REPS, || {
                    host.storage_store_object(c, "obj4k", &kib4).map(drop)
                }),
            );
            put(
                w,
                "storage.retrieve-object (4 KiB)",
                measure(50, REPS, || {
                    host.storage_retrieve_object(c, "obj4k").map(drop)
                }),
            );
            put(
                w,
                "storage.store-object (1 MiB)",
                measure(2, REPS, || {
                    host.storage_store_object(c, "obj1m", &mib).map(drop)
                }),
            );
            put(
                w,
                "storage.retrieve-object (1 MiB)",
                measure(2, REPS, || {
                    host.storage_retrieve_object(c, "obj1m").map(drop)
                }),
            );
            put(
                w,
                "encrypt + store (4 KiB, app-level)",
                measure(50, REPS, || {
                    let ct = host.crypto_encrypt(&kib4, &key, CipherAlgorithm::Aes256Gcm)?;
                    host.storage_store_object(c, "enc4k", &ct).map(drop)
                }),
            );
        }
        Err(e) => put(w, "storage.create-container", Err(e)),
    }

    let w = "network";
    let addr = hal_runtime::Address {
        ip: "127.0.0.1".into(),
        port,
    };
    put(
        w,
        "sockets.create + connect + close (TCP)",
        measure(20, REPS, || {
            let s = host.sockets_create(hal_runtime::Protocol::Tcp)?;
            host.sockets_connect(s, &addr)?;
            host.sockets_close(s)
        }),
    );
    let s = host.sockets_create(hal_runtime::Protocol::Tcp).unwrap();
    put(
        w,
        "sockets.send + receive (1 KiB echo round trip)",
        host.sockets_connect(s, &addr).and_then(|_| {
            measure(50, REPS, || {
                host.sockets_send(s, &kib)?;
                let mut got = 0;
                while got < kib.len() {
                    got += host.sockets_receive(s, 65536)?.len();
                }
                Ok(())
            })
        }),
    );
    let _ = host.sockets_close(s);
    put(
        w,
        "communication send + receive (1 KiB)",
        measure(200, REPS, || {
            host.communication_send_message("wasm-guest", &kib, false)?;
            host.communication_receive_message().map(drop)
        }),
    );

    let w = "compute";
    put(
        w,
        "resources.allocate + deallocate (64 MiB memory)",
        measure(200, REPS, || {
            let a = host.resources_allocate(&AllocationRequest {
                resource_type: ResourceType::Memory,
                amount: 64,
                priority: 50,
            })?;
            host.resources_deallocate(&a.allocation_id)
        }),
    );
    put(
        w,
        "resources.query-available (memory)",
        measure(1000, REPS, || {
            host.resources_query_available(ResourceType::Memory)
                .map(drop)
        }),
    );
    put(
        w,
        "gpu.list-adapters",
        measure(10, REPS, || host.gpu_list_adapters().map(drop)),
    );
    r
}

fn parse_guest(out: &[u8]) -> Results {
    let mut r = Results::new();
    for line in String::from_utf8_lossy(out).lines() {
        let f: Vec<&str> = line.splitn(5, '\t').collect();
        if f.len() < 5 {
            continue;
        }
        let v = if f[4] == "ok" {
            Ok((f[2].parse().unwrap_or(0.0), f[3].parse().unwrap_or(0.0)))
        } else {
            Err(f[4].trim_start_matches("error: ").to_string())
        };
        r.insert((f[0].to_string(), f[1].to_string()), v);
    }
    r
}

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _guard = rt.enter();

    let guest_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../perf-guest/target/wasm32-wasip2/release/perf_guest.wasm"
            ))
        });
    let port = start_echo_server();
    // The guest reads these through WASI (the runtime inherits the environment).
    std::env::set_var("PERF_ECHO_PORT", port.to_string());
    std::env::set_var("PERF_REPS", REPS.to_string());

    let runtime = HalRuntime::new()?;
    let bytes = std::fs::read(&guest_path).with_context(|| {
        format!("guest component not found at {guest_path:?}; build perf-guest first")
    })?;

    // Deployment costs: compile the component, then instantiate it.
    let mut compile = Vec::new();
    let mut component = None;
    for _ in 0..5 {
        let t = Instant::now();
        component = Some(Component::new(runtime.engine(), &bytes)?);
        compile.push(t.elapsed());
    }
    let component = component.unwrap();
    let linker = runtime.create_linker()?;
    let mut inst = Vec::new();
    for _ in 0..20 {
        let (host, _) = make_host()?;
        let mut store = runtime.create_store_with_host(host)?;
        let t = Instant::now();
        rt.block_on(HalConsumer::instantiate_async(
            &mut store, &component, &linker,
        ))?;
        inst.push(t.elapsed());
    }
    compile.sort();
    inst.sort();

    // Wasm guest run.
    let (host, platform_note) = make_host()?;
    let mut store = runtime.create_store_with_host(host)?;
    let instance = rt.block_on(HalConsumer::instantiate_async(
        &mut store, &component, &linker,
    ))?;
    let out = rt.block_on(instance.elastic_hal_run().call_run(&mut store))?;
    let guest = parse_guest(&out);

    // Native run of the same operations.
    let (mut host, _) = make_host()?;
    let nat = native(&mut host, port);
    for ((w, op), v) in &nat {
        if let Err(e) = v {
            eprintln!("[native error] {w} / {op}: {e}");
        }
    }

    println!("Platform: {platform_note}");
    println!(
        "Guest component: {} ({:.0} KiB)\n",
        guest_path.display(),
        bytes.len() as f64 / 1024.0
    );
    println!("### Deployment\n");
    println!("| Step | Median | p95 |");
    println!("| --- | ---: | ---: |");
    let p = |v: &Vec<Duration>| (v[v.len() / 2], v[(v.len() - 1) * 95 / 100]);
    let (m, p95) = p(&compile);
    println!(
        "| Compile guest component (Cranelift, 5 runs) | {} | {} |",
        fmt_ns(m.as_nanos() as f64),
        fmt_ns(p95.as_nanos() as f64)
    );
    let (m, p95) = p(&inst);
    println!(
        "| Instantiate with full HAL linker (20 runs) | {} | {} |",
        fmt_ns(m.as_nanos() as f64),
        fmt_ns(p95.as_nanos() as f64)
    );

    let worlds = [
        (
            "minimal",
            "`elastic-tee-minimal` (platform, crypto, random)",
        ),
        (
            "attestation",
            "`elastic-tee-attestation` (attestation, platform, crypto, random)",
        ),
        (
            "storage",
            "`elastic-tee-storage` (platform, crypto, storage)",
        ),
        (
            "network",
            "`elastic-tee-network` (platform, crypto, sockets, communication)",
        ),
        (
            "compute",
            "`elastic-tee-compute` (platform, gpu, resources)",
        ),
    ];
    for (w, title) in worlds {
        println!("\n### {title}\n");
        println!("| Operation | Native HAL (median) | Wasm guest (median) | Wasm guest (p95) | Wasm overhead |");
        println!("| --- | ---: | ---: | ---: | ---: |");
        for ((gw, op), gv) in guest.iter().filter(|((gw, _), _)| gw == w) {
            let nv = nat.get(&(gw.clone(), op.clone()));
            let cell = |v: Option<&Result<(f64, f64), String>>| match v {
                Some(Ok((m, _))) => fmt_ns(*m),
                Some(Err(e)) => format!("n/a ({e})"),
                None => "—".into(),
            };
            let (gp95, ov) = match (gv, nv) {
                (Ok((gm, gp)), Some(Ok((nm, _)))) => {
                    let d = gm - nm;
                    let sign = if d >= 0.0 { "+" } else { "−" };
                    (
                        fmt_ns(*gp),
                        format!(
                            "{sign}{} ({sign}{:.0} %)",
                            fmt_ns(d.abs()),
                            d.abs() / nm * 100.0
                        ),
                    )
                }
                (Ok((_, gp)), _) => (fmt_ns(*gp), "—".into()),
                _ => ("—".into(), "—".into()),
            };
            println!(
                "| {op} | {} | {} | {gp95} | {ov} |",
                cell(nv),
                cell(Some(gv))
            );
        }
    }
    Ok(())
}
