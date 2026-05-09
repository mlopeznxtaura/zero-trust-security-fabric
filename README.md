# Zero-Trust Security Fabric

Cluster 15 of the NextAura 500 SDKs / 25 Clusters project.

Self-hosted identity, secrets, and runtime security — no SaaS required. Every secret is short-lived. Every identity is verified. Every syscall is watched.

## Architecture

- Vault (HashiCorp) for secrets management and short-lived credential issuance
- Keycloak for OIDC/OAuth2/SAML identity with MFA
- WireGuard for zero-trust network overlay between nodes
- Falco for real-time container syscall anomaly detection
- Tink + libsodium + cryptography for application-level encryption
- WebAuthn/Passkeys to replace passwords entirely
- Semgrep + Nuclei for CI security scanning
- OpenTelemetry + Prometheus for security observability

## SDKs Used

Vault SDK, Keycloak SDK, OpenSSL SDK, libsodium, Cryptography (Python), Tink, Falco SDK, Semgrep SDK, Nuclei SDK, OWASP ZAP SDK, Snyk SDK, Auth0 SDK, Passkeys SDK (WebAuthn), JWT, WireGuard SDK, Kubernetes Python Client, Docker SDK for Python, Prometheus Client, OpenTelemetry SDK, Grafana SDK

## Quickstart

```bash
pip install -r requirements.txt
docker-compose up -d  # starts Vault, Keycloak, Prometheus

# Bootstrap secrets engine
python main.py --mode vault --action bootstrap

# Issue a short-lived token
python main.py --mode vault --action token --role my-service

# Encrypt/decrypt with Tink
python main.py --mode crypto --action encrypt --plaintext "secret data"

# Run security scan
python main.py --mode scan --target http://localhost:8080

# Check runtime anomalies (requires Falco)
python main.py --mode falco --action watch
```

## Structure

```
secrets/         Vault client, AppRole auth, dynamic credentials
identity/        Keycloak OIDC client, JWT verification, WebAuthn
crypto/          Tink encryption, libsodium wrappers, key management
runtime/         Falco alert consumer, container inspection
scanning/        Semgrep SAST, Nuclei DAST, OWASP ZAP integration
network/         WireGuard mesh config, peer management
observability/   OpenTelemetry traces, Prometheus security metrics
main.py          CLI entry point
docker-compose.yml
```
