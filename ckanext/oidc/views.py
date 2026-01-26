"""OIDC authentication views for login/callback/logout"""

import logging
from flask import Blueprint, redirect, request, session as flask_session, make_response

import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.lib.helpers as h
from ckan.common import _, g

from ..oidc.client import OIDCClient
from ..oidc.utils import (
    is_oidc_enabled,
    store_state_token,
    verify_state_token,
    get_post_login_url,
    get_oidc_config,
)
from ..oidc.authenticator import OIDCAuthenticator

log = logging.getLogger(__name__)

oidc = Blueprint('oidc', __name__)


@oidc.route('/oidc/login')
def login():
    """Initiate OIDC login flow."""
    if not is_oidc_enabled():
        h.flash_error(_('SSO authentication is not enabled'))
        return h.redirect_to('user.login')

    try:
        came_from = request.args.get('came_from', '/')

        client = OIDCClient()

        auth_url, state = client.get_authorization_url(came_from)

        store_state_token(state, flask_session)

        log.info("Redirecting user to OIDC provider for authentication")
        return redirect(auth_url)

    except Exception as e:
        log.error("Failed to initiate OIDC login: %s", e)
        h.flash_error(_('Failed to initiate SSO login. Please try again.'))
        return h.redirect_to('user.login')


@oidc.route('/oidc/callback')
def callback():
    """Handle OIDC callback after authentication."""
    if not is_oidc_enabled():
        h.flash_error(_('SSO authentication is not enabled'))
        return h.redirect_to('user.login')

    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    error_description = request.args.get('error_description')

    if error:
        log.error("OIDC callback error: %s - %s", error, error_description)
        h.flash_error(_('Authentication failed: {}').format(error_description or error))
        return h.redirect_to('user.login')

    # CSRF protection
    if not state or not verify_state_token(state, flask_session):
        log.error("Invalid state token in OIDC callback")
        h.flash_error(_('Authentication failed: Invalid state'))
        return h.redirect_to('user.login')

    came_from = '/'
    if '|' in state:
        _state_prefix, came_from = state.split('|', 1)

    try:
        client = OIDCClient()

        tokens = client.exchange_code_for_tokens(code, state)

        if 'id_token' in tokens:
            id_token_claims = client.decode_id_token(tokens['id_token'])
        else:
            id_token_claims = client.get_user_info(tokens['access_token'])

        authenticator = OIDCAuthenticator()

        user = authenticator.provision_user(
            claims=id_token_claims,
            access_token=tokens.get('access_token')
        )

        if not user:
            log.error("Failed to provision user from OIDC claims")
            h.flash_error(_('Failed to create or update user account'))
            return h.redirect_to('user.login')

        # Keep tokens for refresh and logout
        oidc_tokens_data = {
            'access_token': tokens.get('access_token'),
            'id_token': tokens.get('id_token'),
            'refresh_token': tokens.get('refresh_token'),
        }

        # Login user FIRST - this may regenerate the session
        authenticator.login_user(user)

        # NOW store tokens in the new session AND in Redis by user ID
        flask_session['oidc_tokens'] = oidc_tokens_data
        flask_session['oidc_login'] = True
        flask_session['oidc_id_token'] = tokens.get('id_token')
        flask_session.modified = True
        log.debug("Stored OIDC tokens in session after login_user for user: %s", user.name)

        # Store tokens in Redis by user ID (survives session regeneration)
        if toolkit.asbool(get_oidc_config('enable_backchannel_logout', True)):
            try:
                from .session_manager import OIDCSessionManager
                session_manager = OIDCSessionManager()

                # Store session mapping for backchannel logout
                session_manager.store_session_mapping(flask_session, id_token_claims)

                # Store tokens by user ID (persistent storage)
                session_manager.store_user_tokens(user.id, oidc_tokens_data)
                log.debug("Stored OIDC tokens in Redis for user: %s", user.id)
            except Exception as e:
                log.error("Failed to store session/user data: %s", e)
                # Don't fail login

        h.flash_success(_('Successfully logged in via SSO'))

        redirect_target = came_from if came_from and came_from.startswith('/') else '/'
        log.info("Redirecting user %s to: %s", user.name, redirect_target)

        return h.redirect_to(redirect_target)

    except Exception as e:
        log.error("Failed to complete OIDC authentication: %s", e)
        h.flash_error(_('Authentication failed. Please try again.'))
        return h.redirect_to('user.login')


@oidc.route('/oidc/logout')
def logout():
    """DEPRECATED: Redirect to standard CKAN logout.

    This endpoint is deprecated. Use /user/logout instead.
    The IAuthenticator.logout() method now handles OIDC logout.
    """
    log.warning("Direct /oidc/logout is deprecated, use /user/logout")
    return h.redirect_to('user.logout')


@oidc.route('/oidc/refresh')
def refresh_token():
    """Refresh OIDC access token."""
    if not is_oidc_enabled():
        return toolkit.abort(404)

    try:
        tokens = flask_session.get('oidc_tokens', {})
        refresh_token = tokens.get('refresh_token')

        if not refresh_token:
            log.error("No refresh token available")
            return toolkit.abort(401)

        client = OIDCClient()

        new_tokens = client.refresh_access_token(refresh_token)

        flask_session['oidc_tokens'] = {
            'access_token': new_tokens.get('access_token'),
            'id_token': new_tokens.get('id_token'),
            'refresh_token': new_tokens.get('refresh_token', refresh_token),
        }

        log.info("Successfully refreshed OIDC tokens")
        return make_response({'success': True})

    except Exception as e:
        log.error("Failed to refresh OIDC token: %s", e)
        return toolkit.abort(401)


def _validate_logout_token(claims: dict) -> str:
    """
    Validate logout token claims.

    Args:
        claims: Decoded logout token claims

    Returns:
        Error message if validation fails, empty string if valid
    """
    # Validate required claims
    required_claims = ['iss', 'aud', 'iat', 'events']
    for claim in required_claims:
        if claim not in claims:
            return f"Missing required claim: {claim}"

    # Validate issuer matches Keycloak URL
    from .utils import get_keycloak_base_url
    expected_issuer = get_keycloak_base_url()
    if expected_issuer and claims['iss'] != expected_issuer:
        return f"Invalid issuer: expected {expected_issuer}, got {claims['iss']}"

    # Validate audience contains client_id
    client_id = get_oidc_config('client_id')
    aud = claims['aud']
    if isinstance(aud, list):
        if client_id not in aud:
            return f"Client ID not in audience list"
    else:
        if aud != client_id:
            return f"Invalid audience: expected {client_id}, got {aud}"

    # Validate events claim contains backchannel-logout event
    events = claims.get('events', {})
    if not isinstance(events, dict):
        return "Events claim must be an object"

    backchannel_event_key = 'http://schemas.openid.net/event/backchannel-logout'
    if backchannel_event_key not in events:
        return "Events claim missing backchannel-logout event"

    # Must have either 'sub' or 'sid' (or both)
    if 'sub' not in claims and 'sid' not in claims:
        return "Logout token must contain 'sub' or 'sid' claim"

    # Logout tokens MUST NOT have a nonce claim
    if 'nonce' in claims:
        return "Logout token must not contain nonce claim"

    return ""  # Valid


@oidc.route('/oidc/backchannel-logout', methods=['POST'])
def backchannel_logout():
    """
    Handle OIDC backchannel logout requests from Keycloak.

    This endpoint receives logout tokens from Keycloak when a user logs out
    from Keycloak or another application in the same realm.
    """
    log.debug("Received backchannel logout request")

    # Check if OIDC is enabled
    if not is_oidc_enabled():
        log.warning("Backchannel logout: OIDC not enabled")
        return make_response("OK", 200)

    # Check if backchannel logout is enabled
    if not toolkit.asbool(get_oidc_config('enable_backchannel_logout', True)):
        log.warning("Backchannel logout: feature disabled")
        return make_response("OK", 200)

    # Get logout token from POST data
    logout_token = request.form.get('logout_token')
    if not logout_token:
        log.error("Backchannel logout: missing logout_token parameter")
        return make_response("Bad Request: missing logout_token", 400)

    try:
        # Decode and validate logout token
        client = OIDCClient()
        claims = client.decode_logout_token(logout_token)

        # Additional validation of logout token claims
        error = _validate_logout_token(claims)
        if error:
            log.error("Backchannel logout: token validation failed: %s", error)
            return make_response(f"Bad Request: {error}", 400)

        # Extract session ID from logout token
        sid = claims.get('sid')
        sub = claims.get('sub')

        log.info("Backchannel logout: received valid token for sid=%s, sub=%s", sid, sub)

        # If we have a session ID, invalidate the corresponding session
        if sid:
            from .session_manager import OIDCSessionManager
            session_manager = OIDCSessionManager()

            # Lookup Flask session ID by OIDC sid
            flask_session_id = session_manager.get_session_id_by_sid(sid)

            if flask_session_id:
                # Invalidate the session
                success = session_manager.invalidate_session(flask_session_id)
                if success:
                    log.info("Backchannel logout: successfully invalidated session for sid=%s", sid)
                else:
                    log.warning("Backchannel logout: failed to invalidate session for sid=%s", sid)
            else:
                log.debug("Backchannel logout: no session mapping found for sid=%s (may have expired)", sid)
        else:
            log.warning("Backchannel logout: no 'sid' claim in token, cannot invalidate session")

        # Always return 200 OK (idempotent per OIDC spec)
        return make_response("OK", 200)

    except Exception as e:
        log.error("Backchannel logout: error processing logout token: %s", e)
        # Return 400 for invalid tokens, but log the error
        return make_response(f"Bad Request: {str(e)}", 400)