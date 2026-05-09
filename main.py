"""
zero-trust-security-fabric — Entry Point

Self-hosted zero-trust security: Vault secrets, Keycloak identity,
Tink encryption, Falco runtime monitoring, and security scanning.

Usage:
  python main.py --mode vault --action bootstrap
  python main.py --mode vault --action get --path myapp/config
  python main.py --mode vault --action token --role web-server
  python main.py --mode crypto --action encrypt --plaintext "my secret"
  python main.py --mode identity --action token --user admin --pass admin
  python main.py --mode falco --action simulate --rule "Shell in container"
  python main.py --mode scan --target http://localhost:8080
  python main.py --mode scan --code ./src
"""
import argparse
import sys


def parse_args():
    parser = argparse.ArgumentParser(description="Zero-Trust Security Fabric")
    parser.add_argument("--mode", required=True,
                        choices=["vault", "crypto", "identity", "falco", "scan"])
    parser.add_argument("--action", default=None)
    parser.add_argument("--path", default="myapp/config")
    parser.add_argument("--role", default="web-server")
    parser.add_argument("--plaintext", default="Hello, zero-trust world!")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--target", default=None, help="URL for DAST scan")
    parser.add_argument("--code", default=".", help="Path for SAST scan")
    parser.add_argument("--rule", default="Terminal shell in container")
    parser.add_argument("--priority", default="CRITICAL")
    parser.add_argument("--vault-url", default="http://localhost:8200")
    parser.add_argument("--vault-token", default="dev-root-token")
    parser.add_argument("--keycloak-url", default="http://localhost:8080")
    return parser.parse_args()


def mode_vault(args):
    from secrets.vault_client import VaultClient
    client = VaultClient(url=args.vault_url, token=args.vault_token, auto_renew=False)

    action = args.action or "bootstrap"
    if action == "bootstrap":
        client.bootstrap_dev()
        client.set_secret("myapp/config", {
            "db_host": "postgres.internal",
            "db_name": "myapp",
            "api_key": "REPLACE_ME",
        })
        print("Vault bootstrapped with example secrets")

    elif action == "get":
        data = client.get_secret(args.path)
        print(f"Secret at {args.path}:")
        for k, v in data.items():
            print(f"  {k}: {v}")

    elif action == "set":
        client.set_secret(args.path, {"value": args.plaintext})
        print(f"Secret written to {args.path}")

    elif action == "list":
        try:
            keys = client.list_secrets("")
            print(f"Secrets: {keys}")
        except Exception as e:
            print(f"List failed: {e}")


def mode_crypto(args):
    from crypto.tink_encryption import PythonCryptoService
    import secrets as sec

    crypto = PythonCryptoService()
    key = sec.token_bytes(32)
    action = args.action or "encrypt"

    if action == "encrypt":
        bundle = crypto.aes_gcm_encrypt(key, args.plaintext.encode(), b"zero-trust-aad")
        import base64
        ct_b64 = base64.b64encode(bundle["nonce"] + bundle["ciphertext"] + bundle["tag"]).decode()
        print(f"Ciphertext (base64): {ct_b64[:60]}...")
        decrypted = crypto.aes_gcm_decrypt(key, bundle)
        print(f"Decrypted: {decrypted.decode()}")
        print(f"Round-trip OK: {decrypted.decode() == args.plaintext}")

    elif action == "keygen":
        priv, pub = crypto.generate_rsa_keypair(key_size=2048)
        print(f"RSA private key: {len(priv)} bytes")
        print(f"RSA public key: {len(pub)} bytes")

    elif action == "hmac":
        sig = crypto.hmac_sign(key, args.plaintext.encode())
        ok = crypto.hmac_verify(key, args.plaintext.encode(), sig)
        import base64
        print(f"HMAC: {base64.b64encode(sig).decode()}")
        print(f"Verify: {ok}")


def mode_identity(args):
    from identity.keycloak_client import KeycloakClient
    client = KeycloakClient(server_url=args.keycloak_url)
    action = args.action or "token"

    if action == "token":
        try:
            tokens = client.get_token(args.user, args.password)
            print(f"Access token (first 60 chars): {tokens['access_token'][:60]}...")
            print(f"Expires in: {tokens['expires_in']}s")
            info = client.verify_token(tokens["access_token"])
            print(f"User: {info.preferred_username} | roles: {info.roles}")
        except Exception as e:
            print(f"Auth failed: {e}")

    elif action == "create-user":
        try:
            uid = client.create_user(args.user, f"{args.user}@example.com", args.password)
            print(f"Created user: {uid}")
        except Exception as e:
            print(f"Create user failed: {e}")


def mode_falco(args):
    from runtime.falco_monitor import FalcoMonitor
    monitor = FalcoMonitor(auto_respond=False)
    action = args.action or "simulate"

    if action == "simulate":
        alert = monitor.simulate_alert(rule=args.rule, priority=args.priority)
        print(f"
Alert processed: {alert.rule} [{alert.priority}]")
        summary = monitor.get_alert_summary()
        print(f"Summary: {summary}")

    elif action == "watch":
        print("[Falco] Watching for alerts (Ctrl+C to stop)...")
        print("[Falco] In production, configure Falco to POST to http://localhost:2801/alerts")
        import time
        try:
            while True:
                time.sleep(5)
                monitor.simulate_alert(priority="WARNING")
        except KeyboardInterrupt:
            print(f"
Total alerts: {len(monitor.alerts)}")


def mode_scan(args):
    from scanning.security_scanner import SecurityScanOrchestrator
    scanner = SecurityScanOrchestrator()
    import json

    if args.target:
        print(f"DAST scan: {args.target}")
    if args.code:
        print(f"SAST scan: {args.code}")

    report = scanner.run_full_scan(
        code_path=args.code if args.code else None,
        target_url=args.target,
    )
    print(f"
Security Report:")
    print(f"  Total findings: {report['total_findings']}")
    print(f"  By severity: {report['by_severity']}")
    print(f"  Risk score: {report['risk_score']}")
    print(f"  Pass: {report['pass']}")


def main():
    args = parse_args()
    print("=" * 60)
    print("  Zero-Trust Security Fabric")
    print(f"  Mode: {args.mode.upper()}")
    print("=" * 60)

    dispatch = {
        "vault": mode_vault,
        "crypto": mode_crypto,
        "identity": mode_identity,
        "falco": mode_falco,
        "scan": mode_scan,
    }
    dispatch[args.mode](args)


if __name__ == "__main__":
    main()
