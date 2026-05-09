"""
HashiCorp Vault client — secrets management and short-lived credential issuance.
AppRole auth, dynamic DB credentials, PKI cert issuance, token renewal.
SDKs: hvac (Python Vault SDK)
"""
import os
import time
import threading
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import hvac


@dataclass
class VaultSecret:
    path: str
    data: Dict[str, Any]
    lease_id: Optional[str] = None
    lease_duration: int = 0
    renewable: bool = False
    created_at: float = 0.0

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()

    def expires_at(self) -> float:
        return self.created_at + self.lease_duration

    def is_expired(self, buffer_sec: int = 30) -> bool:
        return self.lease_duration > 0 and time.time() > self.expires_at() - buffer_sec


class VaultClient:
    """
    HashiCorp Vault client with AppRole auth, secret caching, and auto-renewal.
    Entry point: authenticate via AppRole, then get/set secrets, issue DB creds.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        role_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        namespace: Optional[str] = None,
        auto_renew: bool = True,
        renew_interval_sec: int = 300,
    ):
        self.url = url or os.environ.get("VAULT_ADDR", "http://localhost:8200")
        self._token = token or os.environ.get("VAULT_TOKEN")
        self._role_id = role_id or os.environ.get("VAULT_ROLE_ID")
        self._secret_id = secret_id or os.environ.get("VAULT_SECRET_ID")
        self._namespace = namespace
        self._cache: Dict[str, VaultSecret] = {}
        self._client: Optional[hvac.Client] = None
        self._renew_thread: Optional[threading.Thread] = None
        self._running = False

        self._connect()
        if auto_renew:
            self._start_renewal_loop(renew_interval_sec)

    def _connect(self):
        """Connect and authenticate to Vault."""
        kwargs = {"url": self.url}
        if self._namespace:
            kwargs["namespace"] = self._namespace

        self._client = hvac.Client(**kwargs)

        if self._token:
            self._client.token = self._token
        elif self._role_id and self._secret_id:
            self._approle_login()
        else:
            # Dev mode: try env token
            self._client.token = os.environ.get("VAULT_TOKEN", "dev-root-token")

        if self._client.is_authenticated():
            print(f"[Vault] Authenticated to {self.url}")
        else:
            print(f"[Vault] WARNING: Not authenticated")

    def _approle_login(self):
        """Authenticate via AppRole (recommended for services)."""
        result = self._client.auth.approle.login(
            role_id=self._role_id,
            secret_id=self._secret_id,
        )
        self._client.token = result["auth"]["client_token"]
        self._token_ttl = result["auth"]["lease_duration"]
        print(f"[Vault] AppRole login successful. Token TTL: {self._token_ttl}s")

    def get_secret(self, path: str, mount_point: str = "secret") -> Dict[str, Any]:
        """Read a KV secret. Returns data dict. Uses cache for performance."""
        cache_key = f"{mount_point}/{path}"
        if cache_key in self._cache and not self._cache[cache_key].is_expired():
            return self._cache[cache_key].data

        try:
            result = self._client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=mount_point
            )
            data = result["data"]["data"]
            metadata = result["data"]["metadata"]
            secret = VaultSecret(path=path, data=data)
            self._cache[cache_key] = secret
            return data
        except hvac.exceptions.InvalidPath:
            raise KeyError(f"Secret not found: {mount_point}/{path}")

    def set_secret(self, path: str, data: Dict[str, Any], mount_point: str = "secret"):
        """Write a KV v2 secret."""
        self._client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=data,
            mount_point=mount_point,
        )
        cache_key = f"{mount_point}/{path}"
        self._cache.pop(cache_key, None)
        print(f"[Vault] Secret written: {mount_point}/{path}")

    def delete_secret(self, path: str, mount_point: str = "secret"):
        """Soft-delete a KV v2 secret (keeps metadata)."""
        self._client.secrets.kv.v2.delete_latest_version_of_secret(
            path=path, mount_point=mount_point
        )
        self._cache.pop(f"{mount_point}/{path}", None)

    def generate_db_creds(self, role: str, mount_point: str = "database") -> VaultSecret:
        """
        Issue dynamic short-lived database credentials.
        Vault creates a new DB user and returns username/password.
        """
        result = self._client.secrets.database.generate_credentials(
            name=role, mount_point=mount_point
        )
        secret = VaultSecret(
            path=f"database/creds/{role}",
            data=result["data"],
            lease_id=result["lease_id"],
            lease_duration=result["lease_duration"],
            renewable=result["renewable"],
        )
        print(f"[Vault] DB creds issued for role '{role}' | TTL={result['lease_duration']}s")
        return secret

    def issue_pki_cert(
        self,
        common_name: str,
        role: str = "server",
        ttl: str = "24h",
        mount_point: str = "pki",
        alt_names: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Issue a short-lived TLS certificate from Vault PKI."""
        kwargs = {
            "name": role,
            "common_name": common_name,
            "extra_params": {"ttl": ttl},
            "mount_point": mount_point,
        }
        if alt_names:
            kwargs["extra_params"]["alt_names"] = ",".join(alt_names)
        result = self._client.secrets.pki.generate_certificate(**kwargs)
        data = result["data"]
        print(f"[Vault] PKI cert issued for {common_name} | TTL={ttl}")
        return {
            "certificate": data["certificate"],
            "private_key": data["private_key"],
            "ca_chain": data.get("ca_chain", []),
            "serial_number": data["serial_number"],
            "expiration": data["expiration"],
        }

    def renew_lease(self, lease_id: str, increment: int = 3600) -> int:
        """Renew a Vault lease (DB creds, token, etc)."""
        result = self._client.sys.renew_lease(lease_id=lease_id, increment=increment)
        new_ttl = result["lease_duration"]
        print(f"[Vault] Lease renewed: {lease_id} | new TTL={new_ttl}s")
        return new_ttl

    def _start_renewal_loop(self, interval: int):
        """Background thread to renew token before expiry."""
        def _loop():
            while self._running:
                time.sleep(interval)
                try:
                    result = self._client.auth.token.renew_self()
                    print(f"[Vault] Token renewed. New TTL: {result['auth']['lease_duration']}s")
                except Exception as e:
                    print(f"[Vault] Token renewal failed: {e}")

        self._running = True
        self._renew_thread = threading.Thread(target=_loop, daemon=True)
        self._renew_thread.start()

    def bootstrap_dev(self):
        """Bootstrap a local dev Vault with KV, PKI, and database engines."""
        try:
            self._client.sys.enable_secrets_engine("kv", path="secret",
                                                    options={"version": "2"})
        except Exception:
            pass  # Already enabled
        try:
            self._client.sys.enable_secrets_engine("pki", path="pki")
            self._client.secrets.pki.set_urls({
                "issuing_certificates": [f"{self.url}/v1/pki/ca"],
                "crl_distribution_points": [f"{self.url}/v1/pki/crl"],
            })
        except Exception:
            pass
        print("[Vault] Dev bootstrap complete: KV v2, PKI enabled")

    def list_secrets(self, path: str, mount_point: str = "secret") -> List[str]:
        result = self._client.secrets.kv.v2.list_secrets(path=path, mount_point=mount_point)
        return result["data"]["keys"]

    def close(self):
        self._running = False
