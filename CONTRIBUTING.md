# Contributing to ELASTIC TEE HAL

Thanks for your interest in contributing! This project is developed within the ELASTIC project and is open to external contributions.

## Reporting issues

- Use [GitHub Issues](https://github.com/elasticproject-eu/wasmhal/issues) for bugs and feature requests.
- For bugs, include the platform (AMD SEV-SNP, Intel TDX or non-TEE), the Rust version, the steps to reproduce and the observed output.
- **Security vulnerabilities:** please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Making changes

1. Open an issue first for larger changes, so the design can be discussed before you write code.
2. Fork the repository and create a branch from `main`.
3. Keep changes focused; one logical change per pull request.
4. Before opening a pull request, make sure the following pass:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets
   cargo test
   ```

   The TDX integration tests need TDX hardware and are marked `#[ignore]`. Run them with `cargo test -- --ignored` on a TDX guest if your change touches platform code. `test_platform_integration` also needs a TEE, so it fails on ordinary machines.
5. Add or update tests and documentation for any change in behaviour.
6. Open a pull request against `main` with a short description of what changed and why.

## Commit messages

Use short, descriptive messages in the imperative mood, optionally with a [Conventional Commits](https://www.conventionalcommits.org/) prefix (e.g. `feat(crypto): add X25519 key exchange`, `fix(storage): ...`).

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md), which is based on the Contributor Covenant 2.1. Please report unacceptable behaviour privately to the maintainers, as described there.

## Licence

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
