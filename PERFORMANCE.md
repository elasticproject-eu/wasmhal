# Performance

This page reports measured performance of the ELASTIC TEE HAL on AMD SEV-SNP and Intel TDX Confidential VMs, and explains how to reproduce the measurements.

## Summary

- **Cost of calling the HAL from WebAssembly:** a HAL call made by a Wasm component costs **about 0.1–0.5 µs more** than the same call made natively, plus the time to copy data across the Wasm boundary. For operations that do real work, such as hashing, signing, storage and networking, that is typically **1–10 %**.
- **Attestation** (fresh nonce plus evidence) takes **about 82–96 ms** on both platforms. From Wasm, the difference is within run-to-run variation, because the time is spent in the TEE firmware.
- **Deploying a workload:** compiling the 271 KiB benchmark component takes **about 54–60 ms**, and instantiating it with the full HAL linker takes **about 63–73 µs**.
- **The HAL's enforcement layer** (a capability-restricted HAL) adds **about 0.2–0.3 µs per call**.

## Test environment

| | AMD SEV-SNP | Intel TDX |
| --- | --- | --- |
| Instance | GCP `n2d-standard-8` (8 vCPU, 32 GB), Confidential VM | GCP `c3-standard-8` (8 vCPU, 32 GB), Confidential VM |
| CPU | AMD EPYC 7B13 | Intel Sapphire Rapids |
| OS / kernel | Ubuntu 24.04.5, Linux 7.0.0-1011-gcp | Ubuntu 24.04.5, Linux 7.0.0-1011-gcp |
| Attestation interface | `/dev/sev-guest` and the TSM configfs (SNP report v5) | `/dev/tdx_guest` and the TSM configfs |

Toolchain: Rust 1.99.0 (`--release`), Wasmtime 25.0.3, guest built with `wit-bindgen` 0.41 for `wasm32-wasip2`. Measured on 8 October 2026 in `us-central1-a`.

## Method

- **Use-case benchmark** (`hal-runtime/examples/perf_usecases.rs` plus the guest component in `perf-guest/`):
  - A Wasm component calls the HAL through Wasmtime, the way a real workload would. The host then runs the same operations natively, without Wasm.
  - The operations are grouped by the composed worlds in [`wit-modular/complete.wit`](wit-modular/complete.wit).
  - Each operation gets one warm-up call, then 31 timed batches. The guest uses WASI's monotonic clock and the host uses `std::time::Instant`.
  - The network world talks to a TCP echo server on loopback.
- **Native benchmark** (`examples/perf.rs`):
  - Compares HAL operations with calling the underlying library (`ring`, `std::fs`) directly.
  - Compares the capability-restricted HAL with the plain HAL provider.
  - Measures attestation report generation.
  - Times 30 batches of about 20 ms each.
- **Reported values:**
  - Each figure is the median per operation. Each benchmark ran **twice** per platform, and the value shown is the mean of the two runs' medians.
  - Where the two runs differ by more than 15 %, both are shown as a range.
  - "Overhead" is the mean difference between the two runs.
- Both benchmarks run under `sudo`, because the attestation devices and the TSM configfs are root-only.

## 1. Use cases (WIT worlds)

The "native" columns call the HAL host functions directly from Rust. The "Wasm" columns make the same calls from inside a Wasm component.

#### `elastic-tee-minimal` (platform, crypto, random)

| Operation | SEV-SNP native | SEV-SNP Wasm | SEV-SNP Wasm overhead | TDX native | TDX Wasm | TDX Wasm overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| crypto.decrypt AES-256-GCM (1 KiB) | 503 ns | 837 ns | +334 ns (+66 %) | 459 ns | 750 ns | +292 ns (+64 %) |
| crypto.encrypt AES-256-GCM (1 KiB) | 1.5 µs | 2.0 µs | +535 ns (+36 %) | 1.0 µs | 1.5 µs | +468 ns (+46 %) |
| crypto.encrypt AES-256-GCM (64 KiB) | 15.4 µs–35.1 µs | 18.5 µs–41.1 µs | +4.5 µs (+18 %) | 13.0 µs | 16.9 µs | +4.0 µs (+31 %) |
| crypto.hash SHA-256 (1 KiB) | 784 ns | 1.0 µs | +231 ns (+29 %) | 843 ns | 1.1 µs | +212 ns (+25 %) |
| crypto.hash SHA-256 (64 KiB) | 41.8 µs | 44.9 µs | +3.1 µs (+7 %) | 46.3 µs | 48.5 µs | +2.2 µs (+5 %) |
| crypto.sign Ed25519 (1 KiB) | 57.6 µs | 58.1 µs | +480 ns (+1 %) | 55.6 µs | 56.4 µs | +775 ns (+1 %) |
| platform.get-platform-info | 45 ns | 268 ns | +223 ns (+496 %) | 44 ns | 230 ns | +186 ns (+428 %) |
| platform.has-capability | 2 ns | 120 ns | +118 ns (+5875 %) | 3 ns | 98 ns | +96 ns (+3183 %) |
| random.get-random-bytes (32 B) | 746 ns | 1.1 µs | +328 ns (+44 %) | 400 ns | 626 ns | +225 ns (+56 %) |

#### `elastic-tee-attestation` (attestation, platform, crypto, random)

| Operation | SEV-SNP native | SEV-SNP Wasm | SEV-SNP Wasm overhead | TDX native | TDX Wasm | TDX Wasm overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| attestation flow (nonce + evidence) | 82.0 ms | 87.5 ms | +5.5 ms (+7 %) | 95.7 ms | 94.9 ms | −835 µs (−1 %) |

#### `elastic-tee-storage` (platform, crypto, storage)

| Operation | SEV-SNP native | SEV-SNP Wasm | SEV-SNP Wasm overhead | TDX native | TDX Wasm | TDX Wasm overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| encrypt + store (4 KiB, app-level) | 490 µs | 492 µs | +1.9 µs (+0 %) | 320 µs | 317 µs | −3.0 µs (−1 %) |
| storage.retrieve-object (1 MiB) | 100 µs–129 µs | 147 µs–187 µs | +52.6 µs (+46 %) | 86.5 µs | 175 µs–213 µs | +107 µs (+124 %) |
| storage.retrieve-object (4 KiB) | 52.4 µs–77.4 µs | 54.6 µs–78.5 µs | +1.6 µs (+3 %) | 39.2 µs | 43.8 µs | +4.6 µs (+12 %) |
| storage.store-object (1 MiB) | 8.3 ms | 8.3 ms | −60.0 µs (−1 %) | 6.2 ms | 4.9 ms–6.5 ms | −505 µs (−8 %) |
| storage.store-object (4 KiB) | 463 µs | 452 µs | −10.7 µs (−2 %) | 305 µs | 305 µs | −465 ns (−0 %) |

#### `elastic-tee-network` (platform, crypto, sockets, communication)

| Operation | SEV-SNP native | SEV-SNP Wasm | SEV-SNP Wasm overhead | TDX native | TDX Wasm | TDX Wasm overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| communication send + receive (1 KiB) | 12.2 µs | 13.1 µs | +885 ns (+7 %) | 15.9 µs | 16.8 µs | +855 ns (+5 %) |
| sockets.create + connect + close (TCP) | 153 µs | 158 µs | +5.1 µs (+3 %) | 74.6 µs | 77.7 µs | +3.1 µs (+4 %) |
| sockets.send + receive (1 KiB echo round trip) | 78.1 µs–98.2 µs | 83.8 µs–112 µs | +9.9 µs (+11 %) | 59.8 µs | 60.8 µs | +975 ns (+2 %) |

#### `elastic-tee-compute` (platform, gpu, resources)

| Operation | SEV-SNP native | SEV-SNP Wasm | SEV-SNP Wasm overhead | TDX native | TDX Wasm | TDX Wasm overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gpu.list-adapters | 118 ns | 286 ns | +168 ns (+143 %) | 147 ns | 271 ns | +124 ns (+84 %) |
| resources.allocate + deallocate (64 MiB memory) | 611 ns | 1.1 µs | +454 ns (+74 %) | 600 ns | 969 ns | +368 ns (+61 %) |
| resources.query-available (memory) | 67 ns | 170 ns | +102 ns (+153 %) | 78 ns | 166 ns | +88 ns (+112 %) |

#### Deployment

| Step | SEV-SNP | TDX |
| --- | ---: | ---: |
| Compile guest component (Cranelift, 5 runs) | 59.6 ms | 54.3 ms |
| Instantiate with full HAL linker (20 runs) | 73.3 µs | 62.6 µs |

**Reading the results:**
- **Small calls** (`has-capability`, `get-platform-info`, resource queries) show large percentages but small absolute costs. The 0.1–0.3 µs is the fixed cost of entering and leaving the component.
- **Crypto:** the overhead is a fixed 0.2–0.5 µs per call, plus copying the data in and out of the guest (about 2–4.5 µs for 64 KiB). Ed25519 signing is within 1 % of native, and SHA-256 over 64 KiB is within 5–7 %.
- **Storage:** writes cost the same from Wasm as natively. `retrieve-object` of 1 MiB costs an extra 50–110 µs, which is copying the object into the guest's linear memory.
- **Network:** connecting to and closing a TCP socket costs 3–4 % more from Wasm, and inter-workload messages 5–7 % more.
- **Attestation:** the time is spent in the TEE firmware, so native and Wasm are the same within run-to-run noise.

## 2. HAL layer compared with calling the library directly

These figures are native, without Wasm. They show the cost of going through the HAL API rather than calling the underlying library.

#### Crypto: HAL vs. direct `ring` call

| Operation | SEV-SNP: Direct | SEV-SNP: HAL | SEV-SNP overhead | TDX: Direct | TDX: HAL | TDX overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ed25519 sign (1 KiB) | 30.7 µs | 57.3 µs | +26.6 µs (+87 %) | 29.6 µs | 55.5 µs | +25.9 µs (+87 %) |
| Ed25519 verify (1 KiB) | 51.6 µs | 51.8 µs | +185 ns (+0 %) | 49.1 µs | 49.4 µs | +280 ns (+1 %) |
| SHA-256 (1 KiB) | 732 ns | 914 ns | +181 ns (+25 %) | 804 ns | 1.1 µs | +270 ns (+34 %) |
| AES-256-GCM encrypt (1 KiB) | 1.0 µs | 1.6 µs | +585 ns (+58 %) | 612 ns | 1.2 µs | +592 ns (+97 %) |
| AES-256-GCM decrypt (1 KiB) | 244 ns | 596 ns | +352 ns (+144 %) | 211 ns | 656 ns | +446 ns (+211 %) |
| SHA-256 (64 KiB) | 41.7 µs | 41.9 µs | +195 ns (+0 %) | 46.2 µs | 46.5 µs | +365 ns (+1 %) |
| AES-256-GCM encrypt (64 KiB) | 32.5 µs | 99.9 µs | +67.5 µs (+208 %) | 10.9 µs | 41.7 µs | +30.8 µs (+284 %) |
| AES-256-GCM decrypt (64 KiB) | 10.3 µs | 12.8 µs | +2.4 µs (+23 %) | 9.8 µs | 12.2 µs | +2.4 µs (+25 %) |
| Random bytes (32 B) | 690 ns | 723 ns | +32 ns (+5 %) | 359 ns | 381 ns | +22 ns (+6 %) |

#### Enforcement layer: restricted HAL vs. plain HAL provider

| Operation | SEV-SNP: Plain HAL | SEV-SNP: Restricted HAL | SEV-SNP overhead | TDX: Plain HAL | TDX: Restricted HAL | TDX overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SHA-256 (64 B) | 166 ns | 379 ns | +212 ns (+128 %) | 184 ns–213 ns | 420 ns | +221 ns (+111 %) |
| AES-256-GCM encrypt (1 KiB) | 1.4 µs | 1.7 µs | +280 ns (+20 %) | 951 ns | 1.2 µs | +244 ns (+26 %) |
| Ed25519 sign (1 KiB) | 57.8 µs | 58.0 µs | +205 ns (+0 %) | 55.8 µs | 56.1 µs | +280 ns (+1 %) |
| Create restricted HAL for an entity | — | 318 µs | — | — | 533 µs | — |
| Capability check (`has_capability`) | — | 31 ns | — | — | 21 ns | — |

#### Storage: HAL objects vs. plain `std::fs`

| Operation | SEV-SNP: Plain file I/O | SEV-SNP: HAL | SEV-SNP overhead | TDX: Plain file I/O | TDX: HAL | TDX overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Write object (4 KiB), unencrypted container | 451 µs | 466 µs | +14.6 µs (+3 %) | 304 µs | 317 µs | +12.9 µs (+4 %) |
| Write object (4 KiB), encrypted container | 451 µs | 515 µs | +63.9 µs (+14 %) | 304 µs | 347 µs | +43.4 µs (+14 %) |
| Read object (4 KiB), unencrypted container | 6.0 µs | 54.1 µs–76.8 µs | +59.4 µs (+989 %) | 2.0 µs | 42.2 µs | +40.2 µs (+2053 %) |
| Read object (4 KiB), encrypted container | 6.0 µs | 55.7 µs–78.9 µs | +61.3 µs (+1020 %) | 2.0 µs | 43.1 µs | +41.2 µs (+2100 %) |
| Write object (1 MiB), unencrypted container | 8.3 ms | 8.4 ms | +45.0 µs (+1 %) | 6.5 ms | 6.5 ms | +50.0 µs (+1 %) |
| Write object (1 MiB), encrypted container | 8.3 ms | 8.4 ms | +90.0 µs (+1 %) | 6.5 ms | 6.6 ms | +80.0 µs (+1 %) |
| Read object (1 MiB), unencrypted container | 47.5 µs | 96.2 µs–121 µs | +61.1 µs (+129 %) | 42.1 µs | 93.9 µs | +51.8 µs (+123 %) |
| Read object (1 MiB), encrypted container | 47.5 µs | 334 µs | +286 µs (+602 %) | 42.1 µs | 357 µs | +315 µs (+747 %) |

#### Attestation report generation (native, 20 runs per run)

| Platform | Median | p95 | Min | Max |
| --- | ---: | ---: | ---: | ---: |
| SEV-SNP | 69.4 ms | 92.1 ms–115.7 ms | 58.6 ms | 10.3 s |
| TDX | 78.5 ms | 93.5 ms | 75.7 ms | 128.7 ms |

**Reading the results:**
- **Ed25519 sign:** the HAL rebuilds the key pair from the stored seed on every call. That costs about as much as the signature itself, hence the extra ~26 µs. Caching the key pair in the crypto context would remove this cost.
- **AES-256-GCM encrypt:** the HAL also sets up the key and copies the ciphertext once more to prepend the nonce. The overhead at 64 KiB (+31–68 µs) is larger than those steps alone explain, and has not been profiled yet. Decrypt is within 2.5 µs of `ring` directly.
- **Enforcement layer:** a restricted HAL adds about 0.2–0.3 µs per call, regardless of the operation.
- **Storage reads:** they go through `tokio::fs`, which runs each file operation on Tokio's blocking thread pool. That hand-off is a fixed cost of about 40–60 µs per operation, which dominates for 4 KiB objects. For encrypted containers, reads also include AES-256-GCM decryption.
- **Storage writes:** the HAL also writes the object metadata and updates the container metadata. For 1 MiB objects that costs about 1 %.
- **SEV-SNP attestation:** both runs had one report that took about 10.3 s, while the other 19 took 58–116 ms. The cause has not been investigated. It may be the kernel retrying throttled SNP guest requests.

## Reproducing

The benchmarks run on any x86-64 Linux machine. Without a TEE, every figure except attestation is produced, and the use-case benchmark prints "no TEE detected".

```bash
# Dependencies (Ubuntu 24.04)
sudo apt-get install -y build-essential pkg-config libtss2-dev libssl-dev
rustup target add wasm32-wasip2

# Build the guest component first, then the benchmarks
(cd perf-guest  && cargo build --release --target wasm32-wasip2)
cargo build --release --example perf
(cd hal-runtime && cargo build --release --example perf_usecases)

# Run (sudo is needed for attestation on a TEE)
sudo ./target/release/examples/perf
sudo ./hal-runtime/target/release/examples/perf_usecases
```

Both programs print Markdown tables. To recreate the test VMs on GCP:

```bash
gcloud compute instances create elastic-perf-snp --zone us-central1-a \
  --machine-type n2d-standard-8 --confidential-compute-type SEV_SNP \
  --maintenance-policy TERMINATE --image-family ubuntu-2404-lts-amd64 \
  --image-project ubuntu-os-cloud --boot-disk-size 50GB
gcloud compute instances create elastic-perf-tdx --zone us-central1-a \
  --machine-type c3-standard-8 --confidential-compute-type TDX \
  --maintenance-policy TERMINATE --image-family ubuntu-2404-lts-amd64 \
  --image-project ubuntu-os-cloud --boot-disk-size 50GB
```
