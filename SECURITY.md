# Security Policy

## Reporting a vulnerability

Please **do not report security vulnerabilities in public GitHub issues.**

Report them privately through [GitHub private vulnerability reporting](https://github.com/elasticproject-eu/wasmhal/security/advisories/new). Please include:

- the affected component (HAL library, `hal-runtime`, or a WIT interface) and the commit;
- the platform: AMD SEV-SNP, Intel TDX or non-TEE, plus the cloud provider and kernel version;
- steps to reproduce it, or a proof of concept, and the impact you expect.

We aim to acknowledge reports within 5 working days. We'll agree a disclosure timeline with you, and credit you in the advisory unless you prefer otherwise.

## Supported versions

The project is research software developed within the ELASTIC project. Security fixes are made on the `main` branch only; there are no maintained release branches.

## Security model

The HAL gives WebAssembly workloads access to platform services inside a Confidential VM: attestation, crypto, storage, sockets, GPU, resources and inter-workload communication. It relies on the following.

- **The TEE protects the guest's memory, not the host it runs on.** On AMD SEV-SNP and Intel TDX, guest memory is encrypted and integrity-protected against the hypervisor. Disk, network and device I/O leave the guest and are visible to the host, unless the workload protects them itself.
- **Wasm isolation separates workloads from each other.** A Wasm component can only reach the HAL interfaces linked into its world. The composed worlds in [`wit-modular/`](wit-modular/) (minimal, attestation, storage, network, compute) let you grant a workload only the interfaces it needs. The enforcement layer (`src/enforcement/`), together with the [HAL Enforcement Service](https://github.com/syafiq/enforcement-service), adds per-entity capability checks, rate limits and auditing on top.
- **The HAL host process is trusted.** `hal-runtime` and the HAL library run with the privileges of the host process. Any workload it loads can use the interfaces that process is able to reach.

## Guidelines for deploying the HAL

**Attestation**
- The HAL returns attestation **evidence**: the SNP report or TDX quote, the measurements, and the caller's nonce bound into the report data. It does **not verify** the hardware signature on that evidence.
- The relying party must verify it:
  - the signature chain (AMD VCEK/ASK/ARK, or Intel PCS/DCAP);
  - that the nonce it sent matches;
  - the measurement and TCB values, against values it expects.

**Privileges**
- Requesting a report through `/sys/kernel/config/tsm/report` needs root, because the configfs entries are root-owned.
- Run the HAL with only the privileges it needs. Don't give untrusted users shell access to the host process or its user.

**Least privilege for workloads**
- Give each workload the smallest WIT world that serves it. For example, use `elastic-tee-minimal` for crypto-only workloads.
- Use the enforcement layer or the Enforcement Service to restrict capabilities per workload.

**Storage**
- Objects are written to the guest's file system. `hal-runtime` uses `/tmp/hal-storage`.
- Data in **unencrypted containers** is visible to anyone who can read that disk.
- Keys for **encrypted containers** are generated in memory and are **not persisted**. An application that needs its data after a restart must keep the key and load it again with `load_object_key`.

**Network**
- Plain TCP and UDP sockets are not encrypted. Protect sensitive traffic at the application layer.
- The TLS support in `sockets.rs` uses rustls with its default protocol versions (TLS 1.2 and 1.3). The TLS client starts with an empty set of trusted root certificates.

**Resource limits**
- Each socket uses a file descriptor in the host process. Set `ulimit -n` to fit the expected number of concurrent connections.
- Use the enforcement layer's rate limits to stop one workload from exhausting shared resources.

**Dependencies**
- Keep the Rust toolchain and dependencies up to date. Check them regularly with [`cargo audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit).

## Scope

In scope:
- this repository's code (the HAL library, `hal-runtime` and the WIT definitions);
- the examples, where they show insecure use of the API.

Out of scope:
- vulnerabilities in the TEE hardware or firmware, the cloud provider's host, the Linux kernel, or third-party crates. Please report these upstream. We'd still like to hear about them if they affect the HAL.
