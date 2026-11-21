# Tarvis Obscura distribution

Based on upstream v0.2.7 (0ecc41770da5c5300227dd83a15bfa1e5100d5d4), under Apache-2.0.

Tarvis adds an optional `TARVIS_APP_NETWORK_POLICY` read-only JSON mount for expiring, exact HTTPS-origin grants to approved workspace apps. Private-network access remains denied by default. Grants pin trusted gateway addresses and are rechecked for requests and redirects. Missing, malformed, expired, or revoked grants cannot authorize internal access. Do not set `OBSCURA_ALLOW_PRIVATE_NETWORK` in production.

The policy patch is maintained as source in this fork. Rendering, the V8 watchdog, and general SSRF protection remain upstream behavior.

Tags such as `v0.2.7-tarvis.1` build native Linux AMD64 and ARM64 render binaries. Both architectures must pass focused network tests, the full render test suite, and all 33 obstacle stages before publishing. Archives contain both executables, this notice, the upstream license, and the source commit. Each archive has a SHA-256 companion file. Consumers must pin the release and checksum in their image recipe; do not resolve `latest` during workspace startup.

Building belongs in release CI. Workspace machines download verified binaries and do not need Rust or V8 build dependencies.
