//! Micro-benchmarks for the ELASTIC TEE HAL.
//!
//! Measures the cost of HAL operations and compares them with calling the
//! underlying library directly, so the overhead added by the HAL layer (and
//! by the enforcement layer on top of it) is visible. On a TEE guest it also
//! measures attestation report generation.
//!
//! Run (release mode is required for meaningful numbers):
//!     cargo run --release --example perf
//!
//! Output is a Markdown table suitable for PERFORMANCE.md.

use elastic_tee_hal::crypto::CryptoInterface as HalCrypto;
use elastic_tee_hal::enforcement::policy::RateLimit;
use elastic_tee_hal::enforcement::{
    CapabilitySet, EnforcementLayer, EntityId, EntityPolicy, PolicyEngine,
};
use elastic_tee_hal::interfaces::CryptoInterface as _;
use elastic_tee_hal::platform::ElasticTeeHal;
use elastic_tee_hal::providers::DefaultCryptoProvider;
use elastic_tee_hal::storage::StorageInterface;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SAMPLES: usize = 30;
const TARGET_SAMPLE: Duration = Duration::from_millis(20);

struct Stat {
    median: Duration,
    p95: Duration,
}

/// Time `f` and return per-operation median and p95 over `SAMPLES` batches.
/// The batch size is calibrated so each batch takes roughly `TARGET_SAMPLE`.
fn bench<F: FnMut()>(mut f: F) -> Stat {
    // Warm-up and calibration.
    let mut batch = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..batch {
            f();
        }
        let el = t.elapsed();
        if el >= TARGET_SAMPLE / 4 || batch >= 1 << 24 {
            let per = el.as_secs_f64() / batch as f64;
            batch = ((TARGET_SAMPLE.as_secs_f64() / per.max(1e-9)) as usize).clamp(1, 1 << 24);
            break;
        }
        batch *= 2;
    }
    let mut per_op: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..batch {
                f();
            }
            t.elapsed().as_secs_f64() / batch as f64
        })
        .collect();
    per_op.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |q: f64| Duration::from_secs_f64(per_op[((per_op.len() - 1) as f64 * q) as usize]);
    Stat {
        median: pick(0.5),
        p95: pick(0.95),
    }
}

fn fmt(d: Duration) -> String {
    let ns = d.as_secs_f64() * 1e9;
    if ns < 1_000.0 {
        format!("{ns:.0} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1e3)
    } else {
        format!("{:.2} ms", ns / 1e6)
    }
}

struct Row {
    op: String,
    baseline: Option<Stat>,
    hal: Stat,
}

fn print_table(title: &str, base_label: &str, hal_label: &str, rows: &[Row]) {
    println!("\n### {title}\n");
    println!("| Operation | {base_label} (median) | {hal_label} (median) | {hal_label} (p95) | Overhead |");
    println!("| --- | ---: | ---: | ---: | ---: |");
    for r in rows {
        let (b, ov) = match &r.baseline {
            Some(b) => {
                let diff = r.hal.median.as_secs_f64() - b.median.as_secs_f64();
                let pct = diff / b.median.as_secs_f64() * 100.0;
                let sign = if diff >= 0.0 { "+" } else { "−" };
                (
                    fmt(b.median),
                    format!(
                        "{sign}{} ({sign}{:.0} %)",
                        fmt(Duration::from_secs_f64(diff.abs())),
                        pct.abs()
                    ),
                )
            }
            None => ("—".into(), "—".into()),
        };
        println!(
            "| {} | {} | {} | {} | {} |",
            r.op,
            b,
            fmt(r.hal.median),
            fmt(r.hal.p95),
            ov
        );
    }
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let rng = SystemRandom::new();
    let hal = HalCrypto::new();

    // ------------------------------------------------------------------
    // 1. HAL crypto vs. calling `ring` directly
    // ------------------------------------------------------------------
    let mut rows = Vec::new();

    let seed = [42u8; 32];
    let msg = vec![0xABu8; 1024];
    let ring_kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let ctx = rt.block_on(hal.load_key_context("Ed25519", &seed, "signing"))?;
    rows.push(Row {
        op: "Ed25519 sign (1 KiB)".into(),
        baseline: Some(bench(|| {
            black_box(ring_kp.sign(black_box(&msg)));
        })),
        hal: bench(|| {
            black_box(rt.block_on(hal.sign_data(ctx, black_box(&msg))).unwrap());
        }),
    });

    let sig = ring_kp.sign(&msg);
    let pk = ring_kp.public_key().as_ref().to_vec();
    rows.push(Row {
        op: "Ed25519 verify (1 KiB)".into(),
        baseline: Some(bench(|| {
            let k = signature::UnparsedPublicKey::new(&signature::ED25519, &pk);
            black_box(k.verify(black_box(&msg), sig.as_ref()).is_ok());
        })),
        hal: bench(|| {
            black_box(
                rt.block_on(hal.verify_signature("Ed25519", &pk, black_box(&msg), sig.as_ref()))
                    .unwrap(),
            );
        }),
    });

    for size in [1024usize, 64 * 1024] {
        let data = vec![0x5Au8; size];
        let label = if size >= 1024 * 1024 {
            format!("{} MiB", size >> 20)
        } else {
            format!("{} KiB", size >> 10)
        };

        rows.push(Row {
            op: format!("SHA-256 ({label})"),
            baseline: Some(bench(|| {
                black_box(ring::digest::digest(
                    &ring::digest::SHA256,
                    black_box(&data),
                ));
            })),
            hal: bench(|| {
                black_box(
                    rt.block_on(hal.hash_data("SHA-256", black_box(&data)))
                        .unwrap(),
                );
            }),
        });

        let key = [7u8; 32];
        let ring_key = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        rows.push(Row {
            op: format!("AES-256-GCM encrypt ({label})"),
            baseline: Some(bench(|| {
                let mut n = [0u8; 12];
                rng.fill(&mut n).unwrap();
                let mut buf = data.clone();
                ring_key
                    .seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(n),
                        Aad::empty(),
                        &mut buf,
                    )
                    .unwrap();
                black_box(buf);
            })),
            hal: bench(|| {
                black_box(
                    rt.block_on(hal.symmetric_encrypt("AES-256-GCM", &key, black_box(&data), None))
                        .unwrap(),
                );
            }),
        });

        let ct = rt.block_on(hal.symmetric_encrypt("AES-256-GCM", &key, &data, None))?;
        let ring_ct = {
            let mut buf = data.clone();
            ring_key
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key([0u8; 12]),
                    Aad::empty(),
                    &mut buf,
                )
                .unwrap();
            buf
        };
        rows.push(Row {
            op: format!("AES-256-GCM decrypt ({label})"),
            baseline: Some(bench(|| {
                let mut buf = ring_ct.clone();
                black_box(
                    ring_key
                        .open_in_place(
                            Nonce::assume_unique_for_key([0u8; 12]),
                            Aad::empty(),
                            &mut buf,
                        )
                        .unwrap()
                        .len(),
                );
            })),
            hal: bench(|| {
                black_box(
                    rt.block_on(hal.symmetric_decrypt("AES-256-GCM", &key, black_box(&ct), None))
                        .unwrap(),
                );
            }),
        });
    }

    let hal_rand = elastic_tee_hal::random::RandomInterface::new();
    rows.push(Row {
        op: "Random bytes (32 B)".into(),
        baseline: Some(bench(|| {
            let mut b = [0u8; 32];
            rng.fill(&mut b).unwrap();
            black_box(b);
        })),
        hal: bench(|| {
            black_box(hal_rand.generate_random_bytes(32).unwrap());
        }),
    });

    print_table("Crypto: HAL vs. direct `ring` call", "Direct", "HAL", &rows);

    // ------------------------------------------------------------------
    // 2. Enforcement layer: restricted (policy-checked, audited,
    //    rate-limited) HAL vs. the plain HAL provider
    // ------------------------------------------------------------------
    let entity = EntityId::new("bench-entity");
    let mut engine = PolicyEngine::default();
    engine
        .add_policy(
            EntityPolicy::new(entity.clone(), CapabilitySet::all())
                // Effectively unlimited, so the benchmark measures the
                // bookkeeping cost and never hits the limit.
                .with_rate_limit(
                    "crypto",
                    RateLimit {
                        operations_per_second: u64::MAX / 4,
                        burst_size: u64::MAX / 4,
                    },
                ),
        )
        .unwrap();
    let layer = EnforcementLayer::new(engine);
    let restricted = layer.create_restricted_hal(&entity).unwrap();
    let rcrypto = restricted.crypto.as_ref().unwrap();
    let plain = DefaultCryptoProvider::default();

    // Fill the audit log to its 10 000-event cap first so we measure the
    // steady state (including trimming), not an empty log.
    for _ in 0..11_000 {
        rcrypto.hash(b"x", "SHA-256").unwrap();
    }

    let mut rows = Vec::new();
    let small = vec![1u8; 64];
    rows.push(Row {
        op: "SHA-256 (64 B)".into(),
        baseline: Some(bench(|| {
            black_box(plain.hash(black_box(&small), "SHA-256").unwrap());
        })),
        hal: bench(|| {
            black_box(rcrypto.hash(black_box(&small), "SHA-256").unwrap());
        }),
    });
    let key = [9u8; 32];
    let kib = vec![1u8; 1024];
    rows.push(Row {
        op: "AES-256-GCM encrypt (1 KiB)".into(),
        baseline: Some(bench(|| {
            black_box(plain.encrypt(black_box(&kib), &key, "AES-256-GCM").unwrap());
        })),
        hal: bench(|| {
            black_box(
                rcrypto
                    .encrypt(black_box(&kib), &key, "AES-256-GCM")
                    .unwrap(),
            );
        }),
    });
    rows.push(Row {
        op: "Ed25519 sign (1 KiB)".into(),
        baseline: Some(bench(|| {
            black_box(plain.sign(black_box(&kib), &seed).unwrap());
        })),
        hal: bench(|| {
            black_box(rcrypto.sign(black_box(&kib), &seed).unwrap());
        }),
    });
    rows.push(Row {
        op: "Create restricted HAL for an entity".into(),
        baseline: None,
        hal: bench(|| {
            black_box(layer.create_restricted_hal(&entity).unwrap());
        }),
    });
    rows.push(Row {
        op: "Capability check (`has_capability`)".into(),
        baseline: None,
        hal: bench(|| {
            black_box(layer.has_capability(black_box(&entity), "crypto"));
        }),
    });
    print_table(
        "Enforcement layer: restricted HAL vs. plain HAL provider",
        "Plain HAL",
        "Restricted HAL",
        &rows,
    );

    // ------------------------------------------------------------------
    // 3. Storage: HAL container objects vs. plain file I/O
    // ------------------------------------------------------------------
    let dir = std::env::temp_dir().join(format!("wasmhal-perf-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let crypto = Arc::new(HalCrypto::new());
    let storage = rt.block_on(StorageInterface::with_encryption(dir.join("hal"), crypto))?;
    let plain_c = rt.block_on(storage.open_container("plain", false))?;
    let enc_c = rt.block_on(storage.open_container("enc", true))?;
    let raw_dir = dir.join("raw");
    std::fs::create_dir_all(&raw_dir)?;

    let mut rows = Vec::new();
    for size in [4 * 1024usize, 1024 * 1024] {
        let data = vec![0xC3u8; size];
        let label = if size >= 1024 * 1024 {
            format!("{} MiB", size >> 20)
        } else {
            format!("{} KiB", size >> 10)
        };
        let raw_path = raw_dir.join("obj");
        let raw_write = bench(|| std::fs::write(&raw_path, black_box(&data)).unwrap());
        rows.push(Row {
            op: format!("Write object ({label}), unencrypted container"),
            baseline: Some(Stat {
                median: raw_write.median,
                p95: raw_write.p95,
            }),
            hal: bench(|| {
                rt.block_on(storage.write_object(plain_c, "obj", black_box(&data)))
                    .unwrap()
            }),
        });
        rows.push(Row {
            op: format!("Write object ({label}), encrypted container"),
            baseline: Some(raw_write),
            hal: bench(|| {
                rt.block_on(storage.write_object(enc_c, "obj", black_box(&data)))
                    .unwrap()
            }),
        });
        let raw_read = bench(|| {
            black_box(std::fs::read(&raw_path).unwrap());
        });
        rows.push(Row {
            op: format!("Read object ({label}), unencrypted container"),
            baseline: Some(Stat {
                median: raw_read.median,
                p95: raw_read.p95,
            }),
            hal: bench(|| {
                black_box(rt.block_on(storage.read_object(plain_c, "obj")).unwrap());
            }),
        });
        rows.push(Row {
            op: format!("Read object ({label}), encrypted container"),
            baseline: Some(raw_read),
            hal: bench(|| {
                black_box(rt.block_on(storage.read_object(enc_c, "obj")).unwrap());
            }),
        });
    }
    print_table(
        "Storage: HAL objects vs. plain `std::fs`",
        "Plain file I/O",
        "HAL",
        &rows,
    );
    let _ = std::fs::remove_dir_all(&dir);

    // ------------------------------------------------------------------
    // 4. Attestation (only on a TEE guest)
    // ------------------------------------------------------------------
    println!("\n### Attestation\n");
    match ElasticTeeHal::new() {
        Ok(tee) => {
            println!("Platform: {:?}\n", tee.platform_type());
            let report_data = [0x11u8; 64];
            let mut times = Vec::new();
            let mut err = None;
            for _ in 0..20 {
                let t = Instant::now();
                match rt.block_on(tee.attest(&report_data)) {
                    Ok(r) => {
                        black_box(r);
                        times.push(t.elapsed());
                    }
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            if let Some(e) = err {
                println!("Attestation failed: {e}");
            } else {
                times.sort();
                println!("| Operation | Median | p95 | Min | Max |");
                println!("| --- | ---: | ---: | ---: | ---: |");
                println!(
                    "| Generate attestation report (`attest`, 20 runs) | {} | {} | {} | {} |",
                    fmt(times[times.len() / 2]),
                    fmt(times[(times.len() - 1) * 95 / 100]),
                    fmt(times[0]),
                    fmt(*times.last().unwrap())
                );
            }
        }
        Err(e) => println!("Skipped: no TEE platform detected ({e})."),
    }

    Ok(())
}
