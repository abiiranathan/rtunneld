# rtunnel Security Model

## 1. Identity & Mutual TLS
- Identities are ed25519 keypairs stored with 0600 file modes on Unix.
- Fingerprints are calculated as the hex-encoded SHA-256 of the SubjectPublicKeyInfo (SPKI).
- No external Certificate Authorities or DNS validation: rustls verifiers enforce public-key fingerprint pinning.

## 2. Threat Model & Boundaries
- **Malicious or Compromised Relay**: The relay only observes opaque bytes and cannot inspect SSH plaintext. It cannot impersonate authorized agents without their ed25519 private keys.
- **Stolen Client Key**: Grants limit access to authorized agents. Revocation terminates live sessions within 5 seconds.
- **Stolen Agent Key**: Agent dials only destinations explicitly listed in its local `allowed_targets`. It cannot be used as an open proxy or SSRF vector.
- **Network Adversary**: QUIC with TLS 1.3 provides confidentiality, authenticity, and replay prevention.