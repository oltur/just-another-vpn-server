# Security Policy

javs implements a security-sensitive protocol (TLS handshake, AEAD data
channel, PSK control-channel protection) but, per the [README's
Limitations](README.md#limitations), **it has not had an independent security
audit**. Treat it accordingly and run it behind appropriate network controls.

## Supported versions

Only the latest tagged [release](https://github.com/oltur/just-another-vpn-server/releases)
receives fixes. There is no long-term support branch — please upgrade before
reporting an issue tied to an older version.

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability
(cryptographic weakness, authentication bypass, memory safety issue reachable
from untrusted network input, etc.).

Instead, report it privately via
[GitHub Security Advisories](https://github.com/oltur/just-another-vpn-server/security/advisories/new)
for this repository. If that's unavailable to you, open a regular issue asking
for a private contact without describing the issue, and a maintainer will
follow up.

Please include:

- The affected version/commit.
- Steps to reproduce, or a minimal PoC packet capture/config.
- The potential impact as you see it (e.g. control-channel bypass, key
  recovery, DoS).

There is no bug bounty. We aim to acknowledge reports within a few days and
will credit reporters in the release notes unless you'd prefer otherwise.

## Scope

In scope: the `javs` binary and the protocol/crypto code under `src/`.

Out of scope: the convenience shell scripts under `scripts/` and `docker/`
(e.g. `generate-certs.sh`) — issues there are welcome as regular bug reports,
not security reports, unless they cause a key/secret to leak.
