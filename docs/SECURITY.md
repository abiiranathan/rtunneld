# Security model

This repository implements the first production-suitable security boundaries described in `SPEC.md`, but the full live relay and enrollment system remains a scaffold rather than a complete production service.

## Threat model

- Malicious relay: the project assumes the relay is authoritative for authentication and authorization decisions. Peers must pin the relay certificate fingerprint before sending any data. A malicious relay can still observe encrypted traffic if it is part of the active data path, so the relay is never trusted with SSH plaintext.
- Stolen client key: a stolen client key allows the attacker to impersonate that client within the relay's trust model. The design calls for immediate revocation and least-privilege grants to limit blast radius.
- Stolen agent key: a stolen agent key allows the attacker to impersonate an allowed agent and potentially reach targets granted to that agent; revocation is the intended mitigation.
- Network attacker: the model relies on QUIC/TLS mutual authentication and certificate fingerprint pinning. Passive or active attackers cannot decrypt the SSH stream without a valid peer key, and the relay never sees SSH plaintext.

## Operational recommendations

- Enforce strict file permissions on private keys.
- Use short-lived enrollment tokens and pin relay fingerprints from a trusted URI.
- Keep audit logs and revocation data central to the relay state directory.
- Treat the relay as a routing layer, not as a place to trust plaintext or decode SSH payloads.
