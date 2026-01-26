"""OIDC Client for Keycloak integration"""

import logging
import secrets
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt
from authlib.jose.errors import JoseError
import ckan.plugins.toolkit as toolkit

from .utils import (
    get_oidc_config,
    get_oidc_endpoints,
    get_redirect_uri,
    generate_state_token,
)

log = logging.getLogger(__name__)


class OIDCClient:
    """OIDC client for authentication with Keycloak."""

    def __init__(self):
        self.client_id = get_oidc_config('client_id')
        self.client_secret = get_oidc_config('client_secret')
        self.scope = get_oidc_config('scope', 'openid profile email')
        self.verify_ssl = toolkit.asbool(get_oidc_config('verify_ssl', True))
        self.endpoints = get_oidc_endpoints()

        if not self.endpoints:
            raise ValueError("OIDC endpoints not properly configured")

        self.oauth = OAuth2Session(
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope=self.scope,
            redirect_uri=get_redirect_uri()
        )

        self._jwks_cache = None

    def get_authorization_url(self, came_from: Optional[str] = None) -> tuple[str, str]:
        """
        Generate authorization URL for OIDC login.

        Args:
            came_from: URL to redirect to after login

        Returns:
            Tuple of (authorization_url, state_token)
        """
        state = generate_state_token()
        redirect_uri = get_redirect_uri()

        # Embed return URL in state for post-login redirect
        if came_from:
            state = f"{state}|{came_from}"

        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': self.scope,
            'state': state,
        }

        # Nonce prevents replay attacks
        nonce = secrets.token_urlsafe(32)
        params['nonce'] = nonce

        authorization_url = f"{self.endpoints['authorization']}?{urlencode(params)}"

        log.debug("Generated authorization URL: %s", authorization_url)
        return authorization_url, state

    def exchange_code_for_tokens(self, code: str, state: str) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens.

        Args:
            code: Authorization code from callback
            state: State parameter from callback

        Returns:
            Dict containing access_token, id_token, and optionally refresh_token
        """
        token_endpoint = self.endpoints['token']
        redirect_uri = get_redirect_uri()

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }

        try:
            response = requests.post(
                token_endpoint,
                data=data,
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            tokens = response.json()

            log.debug("Successfully exchanged code for tokens")
            return tokens

        except requests.RequestException as e:
            log.error("Failed to exchange code for tokens: %s", e)
            raise

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from userinfo endpoint.

        Args:
            access_token: Valid access token

        Returns:
            User information dict
        """
        userinfo_endpoint = self.endpoints['userinfo']

        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        try:
            response = requests.get(
                userinfo_endpoint,
                headers=headers,
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            user_info = response.json()

            log.debug("Retrieved user info for: %s", user_info.get('preferred_username', 'unknown'))
            return user_info

        except requests.RequestException as e:
            log.error("Failed to get user info: %s", e)
            raise

    def decode_id_token(self, id_token: str, nonce: Optional[str] = None) -> Dict[str, Any]:
        """
        Decode and validate ID token.

        Args:
            id_token: JWT ID token from OIDC provider
            nonce: Nonce to validate (if provided during auth)

        Returns:
            Decoded token claims
        """
        try:
            jwks = self._get_jwks()

            claims = jwt.decode(id_token, jwks)

            required_claims = ['iss', 'sub', 'aud', 'exp', 'iat']
            for claim in required_claims:
                if claim not in claims:
                    raise ValueError(f"Missing required claim: {claim}")

            if claims['aud'] != self.client_id:
                raise ValueError(f"Invalid audience: {claims['aud']}")

            if nonce and claims.get('nonce') != nonce:
                raise ValueError("Nonce mismatch")

            log.debug("Successfully validated ID token for sub: %s", claims['sub'])
            return claims

        except JoseError as e:
            log.error("Failed to decode ID token: %s", e)
            raise

    def decode_logout_token(self, logout_token: str) -> Dict[str, Any]:
        """
        Decode and validate logout token for backchannel logout.

        Args:
            logout_token: JWT logout token from OIDC provider

        Returns:
            Decoded token claims

        Raises:
            ValueError: If token validation fails
            JoseError: If token decoding fails
        """
        try:
            jwks = self._get_jwks()

            # Decode the token
            claims = jwt.decode(logout_token, jwks)

            # Validate required claims for logout token
            required_claims = ['iss', 'aud', 'iat', 'events']
            for claim in required_claims:
                if claim not in claims:
                    raise ValueError(f"Missing required claim: {claim}")

            # Validate issuer matches expected issuer
            expected_issuer = self.endpoints.get('issuer')
            if expected_issuer and claims['iss'] != expected_issuer:
                raise ValueError(f"Invalid issuer: {claims['iss']}")

            # Validate audience contains client_id
            aud = claims['aud']
            if isinstance(aud, list):
                if self.client_id not in aud:
                    raise ValueError(f"Client ID not in audience: {aud}")
            else:
                if aud != self.client_id:
                    raise ValueError(f"Invalid audience: {aud}")

            # Validate events claim contains backchannel-logout event
            events = claims.get('events', {})
            if not isinstance(events, dict):
                raise ValueError("Events claim must be an object")

            backchannel_event_key = 'http://schemas.openid.net/event/backchannel-logout'
            if backchannel_event_key not in events:
                raise ValueError("Events claim missing backchannel-logout event")

            # Logout tokens MUST NOT have a nonce claim
            if 'nonce' in claims:
                raise ValueError("Logout token must not contain nonce claim")

            # Must have either 'sub' or 'sid' (or both)
            if 'sub' not in claims and 'sid' not in claims:
                raise ValueError("Logout token must contain 'sub' or 'sid' claim")

            log.debug("Successfully validated logout token")
            return claims

        except JoseError as e:
            log.error("Failed to decode logout token: %s", e)
            raise

    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New tokens dict
        """
        token_endpoint = self.endpoints['token']

        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }

        try:
            response = requests.post(
                token_endpoint,
                data=data,
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            tokens = response.json()

            log.debug("Successfully refreshed access token")
            return tokens

        except requests.RequestException as e:
            log.error("Failed to refresh token: %s", e)
            raise

    def logout(self, id_token: str, post_logout_redirect_uri: str) -> str:
        """
        Generate logout URL for OIDC provider.

        Args:
            id_token: ID token for logout
            post_logout_redirect_uri: URL to redirect to after logout

        Returns:
            Logout URL
        """
        logout_endpoint = self.endpoints['logout']

        params = {
            'id_token_hint': id_token,
            'post_logout_redirect_uri': post_logout_redirect_uri,
            'client_id': self.client_id,
        }

        logout_url = "%s?%s" % (logout_endpoint, urlencode(params))
        log.debug("Generated logout URL: %s", logout_url)
        return logout_url

    def _get_jwks(self) -> Dict:
        """
        Get JWKS (JSON Web Key Set) from OIDC provider.

        Returns:
            JWKS dict for token validation
        """
        if self._jwks_cache:
            return self._jwks_cache

        jwks_endpoint = self.endpoints['jwks']

        try:
            response = requests.get(
                jwks_endpoint,
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            self._jwks_cache = response.json()
            return self._jwks_cache

        except requests.RequestException as e:
            log.error("Failed to fetch JWKS: %s", e)
            raise

    def introspect_token(self, token: str) -> Dict[str, Any]:
        """
        Introspect token to check if it's active.

        Args:
            token: Token to introspect

        Returns:
            Token introspection result
        """
        introspection_endpoint = self.endpoints['introspection']

        data = {
            'token': token,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }

        try:
            response = requests.post(
                introspection_endpoint,
                data=data,
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            result = response.json()

            log.debug("Token introspection result: active=%s", result.get('active'))
            return result

        except requests.RequestException as e:
            log.error("Failed to introspect token: %s", e)
            raise