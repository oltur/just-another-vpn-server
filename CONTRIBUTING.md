# Contributing

Thanks for considering a contribution to javs. This is a small, solo-maintained
project, so keep PRs focused — see [ROADMAP.md](ROADMAP.md) for what's already
tracked before starting something large, and open an issue first for anything
beyond a small fix.

## Dev workflow

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
./docker/test.sh      # end-to-end against a real openvpn client
```

`cargo test` covers codecs, crypto, PRF, and replay logic without needing a
TUN device or root. `./docker/test.sh` is the only thing that exercises a real
handshake end-to-end and is strongly recommended before any change touching
`src/protocol.rs`, `src/control_channel.rs`, `src/crypto.rs`, `src/prf.rs`, or
`src/tls*.rs`.

## What CI checks

Every PR runs:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- [ShellCheck](https://www.shellcheck.net/) on `scripts/*.sh` and `docker/*.sh`
- `cargo audit` against [RustSec](https://rustsec.org/) advisories

Please run the `cargo` commands locally before opening a PR; CI will catch
anything missed either way.

## Submitting a PR

1. Fork the repo and create a branch off `main`.
2. Keep the change scoped — one logical change per PR.
3. Add/update tests for behavior changes where practical.
4. Update [README.md](README.md) if you change user-facing behavior
   (config keys, CLI flags, defaults).
5. Open the PR against `main`. Link any related issue.

## Reporting bugs

Open a [GitHub issue](https://github.com/oltur/just-another-vpn-server/issues)
with your `server.toml` (redact secrets/IPs), the client you tested with, and
`--log info,javs=debug` output. For suspected security vulnerabilities, see
[SECURITY.md](SECURITY.md) instead.
