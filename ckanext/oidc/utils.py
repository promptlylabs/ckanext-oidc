"""OIDC utility functions and configuration helpers"""

import os
import logging
from typing import Optional, Any, Dict
from urllib.parse import urljoin

from ckan.common import config
import ckan.plugins.toolkit as toolkit

log = logging.getLogger(__name__)


def get_oidc_config(key: str, default: Any = None) -> Any:
    """
    Get OIDC configuration value with fallback to environment variable.
    Priority: ENV > INI > default

    Args:
        key: Configuration key (without prefix)
        default: Default value if not configured

    Returns:
        Configuration value
    """
    # Priority: ENV > INI > default
    env_key = f'CKAN__CKANEXT__OIDC__{key.upper()}'
    env_value = os.environ.get(env_key)
    if env_value is not None:
        return env_value

    config_key = f'ckanext.oidc.{key}'
    return config.get(config_key, default)


def is_oidc_enabled() -> bool:
    """Check if OIDC authentication is enabled."""
    return toolkit.asbool(get_oidc_config('enabled', False))


def get_keycloak_base_url() -> Optional[str]:
    """Build the complete Keycloak OIDC base URL."""
    provider_url = get_oidc_config('provider_url')
    realm = get_oidc_config('realm')
    if provider_url and realm:
        return f"{provider_url}/realms/{realm}"
    return None


def get_oidc_endpoints() -> Dict[str, str]:
    """Get all OIDC endpoint URLs."""
    base_url = get_keycloak_base_url()
    if not base_url:
        return {}

    oidc_base = f"{base_url}/protocol/openid-connect"
    return {
        'authorization': f"{oidc_base}/auth",
        'token': f"{oidc_base}/token",
        'userinfo': f"{oidc_base}/userinfo",
        'logout': f"{oidc_base}/logout",
        'jwks': f"{oidc_base}/certs",
        'introspection': f"{oidc_base}/token/introspect",
    }


def get_redirect_uri(came_from: Optional[str] = None) -> str:
    """
    Get the OIDC redirect URI.

    Args:
        came_from: Optional URL to return to after authentication

    Returns:
        The redirect URI for OIDC callback
    """
    redirect_uri = get_oidc_config('redirect_uri')
    if redirect_uri:
        return redirect_uri

    site_url = config.get('ckan.site_url', '').rstrip('/')
    return f"{site_url}/oidc/callback"


def validate_oidc_config() -> tuple[bool, list[str]]:
    """
    Validate required OIDC configuration.

    Returns:
        Tuple of (is_valid, list_of_missing_configs)
    """
    if not is_oidc_enabled():
        return True, []

    required_configs = [
        'provider_url',
        'realm',
        'client_id',
        'client_secret'
    ]

    missing_configs = []
    for config_key in required_configs:
        if not get_oidc_config(config_key):
            missing_configs.append(config_key)

    return len(missing_configs) == 0, missing_configs


def get_post_login_url(default: str = '/') -> str:
    """
    Get the URL to redirect to after successful login.

    Args:
        default: Default URL if no came_from parameter

    Returns:
        URL to redirect to
    """
    came_from = toolkit.request.params.get('came_from',
                                          toolkit.request.args.get('came_from', default))

    # Prevent open redirect vulnerabilities
    if not came_from or not came_from.startswith('/'):
        came_from = default

    return came_from


def generate_state_token() -> str:
    """Generate a secure state token for CSRF protection."""
    import secrets
    return secrets.token_urlsafe(32)


def store_state_token(state: str, session: Any) -> None:
    """Store state token in session for verification."""
    session['oidc_state'] = state


def verify_state_token(state: str, session: Any) -> bool:
    """Verify state token matches the one in session."""
    stored_state = session.pop('oidc_state', None)
    return stored_state == state