"""
Keycloak OIDC client — identity, JWT verification, and user management.
Multi-provider OAuth2, MFA enforcement, and token introspection.
SDKs: python-keycloak, PyJWT, python-jose
"""
import os
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from keycloak import KeycloakOpenID, KeycloakAdmin
from jose import jwt, JWTError
import httpx


@dataclass
class TokenInfo:
    sub: str              # user ID
    email: str
    name: str
    roles: List[str]
    exp: int
    iat: int
    preferred_username: str
    email_verified: bool = False
    raw: Dict = None


class KeycloakClient:
    """
    Keycloak OIDC integration.
    Handles token issuance, verification, introspection, and user management.
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        realm: str = "master",
        client_id: str = "zero-trust-app",
        client_secret: Optional[str] = None,
        admin_username: str = "admin",
        admin_password: str = "admin",
    ):
        self.server_url = server_url or os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
        self.realm = realm
        self.client_id = client_id

        self.oidc = KeycloakOpenID(
            server_url=self.server_url,
            realm_name=realm,
            client_id=client_id,
            client_secret_key=client_secret or os.environ.get("KEYCLOAK_CLIENT_SECRET", ""),
        )

        self._admin: Optional[KeycloakAdmin] = None
        self._admin_creds = (admin_username, admin_password)
        self._jwks_cache: Optional[Dict] = None
        print(f"[Keycloak] Client initialized: {self.server_url}/realms/{realm}")

    @property
    def admin(self) -> KeycloakAdmin:
        if self._admin is None:
            self._admin = KeycloakAdmin(
                server_url=self.server_url,
                username=self._admin_creds[0],
                password=self._admin_creds[1],
                realm_name=self.realm,
                verify=True,
            )
        return self._admin

    def get_token(self, username: str, password: str) -> Dict[str, str]:
        """Authenticate user and return access + refresh tokens."""
        tokens = self.oidc.token(username=username, password=password)
        print(f"[Keycloak] Token issued for {username}")
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "expires_in": tokens["expires_in"],
            "token_type": tokens["token_type"],
        }

    def refresh_token(self, refresh_token: str) -> Dict[str, str]:
        """Exchange refresh token for new access token."""
        tokens = self.oidc.refresh_token(refresh_token)
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", refresh_token),
            "expires_in": tokens["expires_in"],
        }

    def verify_token(self, access_token: str) -> TokenInfo:
        """
        Verify JWT access token signature and claims.
        Fetches JWKS from Keycloak and verifies locally — no network call per request.
        """
        if self._jwks_cache is None:
            self._jwks_cache = self.oidc.certs()

        try:
            payload = self.oidc.decode_token(
                access_token,
                key=self._jwks_cache,
                options={"verify_signature": True, "verify_exp": True},
            )
        except Exception as e:
            raise ValueError(f"Token verification failed: {e}")

        roles = []
        realm_access = payload.get("realm_access", {})
        roles.extend(realm_access.get("roles", []))
        resource_access = payload.get("resource_access", {})
        for resource in resource_access.values():
            roles.extend(resource.get("roles", []))

        return TokenInfo(
            sub=payload["sub"],
            email=payload.get("email", ""),
            name=payload.get("name", ""),
            roles=roles,
            exp=payload["exp"],
            iat=payload["iat"],
            preferred_username=payload.get("preferred_username", ""),
            email_verified=payload.get("email_verified", False),
            raw=payload,
        )

    def introspect(self, access_token: str) -> Dict[str, Any]:
        """Token introspection — check if token is active on Keycloak side."""
        return self.oidc.introspect(access_token)

    def logout(self, refresh_token: str):
        """Revoke refresh token (invalidates session)."""
        self.oidc.logout(refresh_token)

    def get_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Fetch user info from Keycloak userinfo endpoint."""
        return self.oidc.userinfo(access_token)

    # ---- Admin operations ----

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        first_name: str = "",
        last_name: str = "",
        enabled: bool = True,
        require_mfa: bool = False,
    ) -> str:
        """Create a new user in Keycloak. Returns user ID."""
        user_data = {
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        }
        if require_mfa:
            user_data["requiredActions"] = ["CONFIGURE_TOTP"]

        user_id = self.admin.create_user(user_data)
        print(f"[Keycloak] User created: {username} ({user_id})")
        return user_id

    def assign_role(self, user_id: str, role_name: str):
        """Assign a realm role to a user."""
        role = self.admin.get_realm_role(role_name)
        self.admin.assign_realm_roles(user_id, [role])
        print(f"[Keycloak] Role '{role_name}' assigned to {user_id}")

    def enforce_mfa(self, user_id: str):
        """Force MFA enrollment for a user."""
        self.admin.update_user(user_id, {"requiredActions": ["CONFIGURE_TOTP"]})

    def list_users(self, search: str = "", max_count: int = 100) -> List[Dict]:
        """List users in the realm."""
        return self.admin.get_users({"search": search, "max": max_count})

    def delete_user(self, user_id: str):
        self.admin.delete_user(user_id)
        print(f"[Keycloak] User deleted: {user_id}")
