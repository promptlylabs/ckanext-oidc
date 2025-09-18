"""OIDC authentication views for login/callback/logout"""

import logging
from flask import Blueprint, redirect, request, session as flask_session

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
        log.error(f"Failed to initiate OIDC login: {e}")
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
        log.error(f"OIDC callback error: {error} - {error_description}")
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
        flask_session['oidc_tokens'] = {
            'access_token': tokens.get('access_token'),
            'id_token': tokens.get('id_token'),
            'refresh_token': tokens.get('refresh_token'),
        }

        authenticator.login_user(user)

        h.flash_success(_('Successfully logged in via SSO'))

        redirect_target = came_from if came_from and came_from.startswith('/') else '/'
        log.info(f"Redirecting user {user.name} to: {redirect_target}")

        return h.redirect_to(redirect_target)

    except Exception as e:
        log.error(f"Failed to complete OIDC authentication: {e}")
        h.flash_error(_('Authentication failed. Please try again.'))
        return h.redirect_to('user.login')


@oidc.route('/oidc/logout')
def logout():
    """Handle OIDC logout."""
    if not is_oidc_enabled():
        return h.redirect_to('user.logout')

    try:
        tokens = flask_session.get('oidc_tokens', {})
        id_token = tokens.get('id_token')

        flask_session.pop('oidc_tokens', None)

        if g.user:
            g.user = None
            if 'user' in flask_session:
                del flask_session['user']

        if id_token:
            client = OIDCClient()
            site_url = toolkit.config.get('ckan.site_url', '').rstrip('/')
            post_logout_redirect_uri = f"{site_url}/"

            logout_url = client.logout(id_token, post_logout_redirect_uri)
            log.info("Redirecting user to OIDC provider for logout")
            return redirect(logout_url)

        h.flash_success(_('Successfully logged out'))
        return h.redirect_to('home.index')

    except Exception as e:
        log.error(f"Error during OIDC logout: {e}")
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
        return toolkit.response.make_response({'success': True})

    except Exception as e:
        log.error(f"Failed to refresh OIDC token: {e}")
        return toolkit.abort(401)