# Decisions and Assumptions Log

## 2026-10-25 — Complete Implementation Architecture
- **SPKI Fingerprints**: Fingerprints are derived by parsing ASN.1 DER to isolate the SubjectPublicKeyInfo sequence, matching both certificate DER structures and raw ed25519 public key encodings.
- **Stream Splicing**: Splicing utilizes 32 KiB buffers with zero-copy stream pumps. QUIC FIN events propagate directly to TCP write shutdowns, ensuring full half-close fidelity for SSH.
- **Client Stdout Preservation**: `rtunnel connect` emits only tunnel bytes to stdout; all diagnostic logs, connection banners, and errors are routed to stderr to maintain seamless OpenSSH `ProxyCommand` compatibility.
- **Token Hashing**: Enrollment tokens are stored as SHA-256 hashes and consumed within atomic SQLite transactions to eliminate replay vulnerabilities.
- **Supervision & Revocation**: The relay scans the SQLite store on a 1-second cadence, evicting connections and active streams belonging to revoked peers within 5 seconds.