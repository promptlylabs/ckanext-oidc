import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging
from typing import Optional
from flask import Response, session as flask_session
from werkzeug.utils import redirect

from ckan.common import logout_user, current_user

from .utils import (
    is_oidc_enabled,
    validate_oidc_config,
    get_oidc_config,
)
from .session_manager import OIDCSessionManager

log = logging.getLogger(__name__)


class OidcPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "oidc")

        if is_oidc_enabled():
            is_valid, missing_configs = validate_oidc_config()
            if not is_valid:
                log.error(
                    f"OIDC is enabled but missing required configuration: {', '.join(missing_configs)}. "
                    f"Please set these via environment variables or in your INI file."
                )
            else:
                log.info("OIDC authentication enabled with provider: %s",
                        get_oidc_config('provider_url'))

    def get_helpers(self):
        return {
            'oidc_is_enabled': is_oidc_enabled,
            'oidc_get_config': get_oidc_config,
            'oidc_button_text': lambda: get_oidc_config('button_text', 'Login with SSO'),
            'oidc_button_position': lambda: get_oidc_config('button_position', 'top'),
            'oidc_allow_local_login': lambda: toolkit.asbool(get_oidc_config('allow_local_login', True)),
        }

    def get_blueprint(self):
        """Register OIDC blueprint for authentication endpoints."""
        from .views import oidc
        return oidc

    def logout(self) -> Optional[Response]:
        """
        Handle OIDC logout when user logs out from CKAN.

        This implements RP-initiated logout: when user logs out from CKAN,
        also log them out from Keycloak if they logged in via OIDC.

        Returns:
            Response object to redirect user, or None to use default logout
        """
        # Check if OIDC is enabled
        if not is_oidc_enabled():
            log.debug("OIDC not enabled, using default logout")
            return None

        # Check if logout integration is enabled
        if not toolkit.asbool(get_oidc_config('enable_logout', True)):
            log.debug("OIDC logout integration disabled, using default logout")
            return None

        # Check if user logged in via OIDC by checking for tokens in session
        # Debug: Log session keys to diagnose missing tokens issue
        session_keys = list(flask_session.keys()) if hasattr(flask_session, 'keys') else []
        log.debug("Current session keys: %s", session_keys)

        oidc_tokens = flask_session.get('oidc_tokens')
        oidc_login_flag = flask_session.get('oidc_login', False)

        # If tokens not in session, try to get from Redis by user ID
        if not oidc_tokens and toolkit.asbool(get_oidc_config('enable_backchannel_logout', True)):
            try:
                if current_user and hasattr(current_user, 'id'):
                    session_manager = OIDCSessionManager()
                    oidc_tokens = session_manager.get_user_tokens(current_user.id)
                    if oidc_tokens:
                        log.info("Retrieved OIDC tokens from Redis for user: %s", current_user.id)
                        oidc_login_flag = True  # User definitely logged in via OIDC if tokens are in Redis
            except Exception as e:
                log.error("Failed to retrieve tokens from Redis: %s", e)

        # Check if user logged in via OIDC (either has tokens or the login flag)
        if not oidc_tokens and not oidc_login_flag:
            log.warning("User did not login via OIDC (no oidc_tokens or oidc_login flag), using default logout. Session keys: %s", session_keys)
            return None

        # If we have the flag but no tokens, log a warning
        if oidc_login_flag and not oidc_tokens:
            log.warning("OIDC login flag present but tokens missing! Proceeding with OIDC logout anyway.")

        log.info("Logging out OIDC user, found tokens: %s, login flag: %s",
                 'id_token' in oidc_tokens if isinstance(oidc_tokens, dict) else False,
                 oidc_login_flag)

        # Clean up session mapping and user tokens for backchannel logout
        if toolkit.asbool(get_oidc_config('enable_backchannel_logout', True)):
            try:
                session_manager = OIDCSessionManager()
                session_manager.remove_session_mapping(flask_session)
                log.debug("Removed OIDC session mapping")

                # Also remove user tokens from Redis
                if current_user and hasattr(current_user, 'id'):
                    session_manager.remove_user_tokens(current_user.id)
                    log.debug("Removed OIDC tokens from Redis for user: %s", current_user.id)
            except Exception as e:
                log.error("Failed to remove session mapping/tokens: %s", e)
                # Continue with logout even if cleanup fails

        # Get ID token for RP-initiated logout
        # Try to get from tokens first, then from backup storage
        id_token = None
        if oidc_tokens:
            id_token = oidc_tokens.get('id_token')
        if not id_token:
            id_token = flask_session.get('oidc_id_token')
            if id_token:
                log.debug("Using backup id_token for logout")

        # Clear OIDC tokens, login flag, and backup id_token from session
        flask_session.pop('oidc_tokens', None)
        flask_session.pop('oidc_login', None)
        flask_session.pop('oidc_id_token', None)
        flask_session.modified = True

        # Call Flask-Login's logout_user to clear Flask session
        logout_user()

        # Check if we should redirect to Keycloak for logout
        logout_from_idp = toolkit.asbool(get_oidc_config('logout_from_idp', True))

        if logout_from_idp and id_token:
            # Redirect to Keycloak RP-initiated logout endpoint
            try:
                from .client import OIDCClient
                client = OIDCClient()

                # Get post-logout redirect URI (where Keycloak redirects after logout)
                post_logout_redirect_uri = get_oidc_config(
                    'post_logout_redirect_uri',
                    toolkit.url_for('user.logged_out_page', _external=True)
                )
                log.debug("Using post-logout redirect URI: %s", post_logout_redirect_uri)
                log.debug("oidc config post_logout_uri: %s", get_oidc_config('post_logout_redirect_uri'))
                log.debug("user.logged_out_page: %s", toolkit.url_for('user.logged_out_page', _external=True))

                # Generate Keycloak logout URL
                logout_url = client.logout(id_token, post_logout_redirect_uri)

                log.debug("Redirecting to Keycloak logout: %s", logout_url)
                return redirect(logout_url)

            except Exception as e:
                log.error("Failed to generate Keycloak logout URL: %s", e)
                # Fall through to redirect to logged_out page

        # If logout_from_idp is disabled or no id_token, just redirect to logged_out page
        log.debug("Redirecting to logged out page")
        return redirect(toolkit.url_for('user.logged_out_page'))