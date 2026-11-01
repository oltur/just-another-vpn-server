## What & why

<!-- What does this change, and what problem does it solve? Link any related issue. -->

## Testing

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `./docker/test.sh` (required for changes touching the protocol/crypto/TLS code paths)

## Checklist

- [ ] Updated `README.md` if user-facing behavior changed (config keys, CLI flags, defaults)
- [ ] Updated `ROADMAP.md` if this closes or changes a tracked item
