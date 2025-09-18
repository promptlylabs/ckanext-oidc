"""OIDC Authenticator for user provisioning and management"""

import logging
import secrets
from typing import Optional, Dict, Any, List
import hashlib
import re

import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.common import g, login_user as ckan_login_user
from flask import session as flask_session

from .utils import get_oidc_config

log = logging.getLogger(__name__)


class OIDCAuthenticator:
    """Handle user authentication and provisioning from OIDC claims."""

    def __init__(self):
        self.username_claim = get_oidc_config('username_claim', 'preferred_username')
        self.email_claim = get_oidc_config('email_claim', 'email')
        self.fullname_claim = get_oidc_config('fullname_claim', 'name')
        self.groups_claim = get_oidc_config('groups_claim', 'groups')
        self.sysadmin_groups = get_oidc_config('sysadmin_groups', '').split(',')
        self.default_organization = get_oidc_config('default_organization')
        # Default to False for security - require explicit enabling
        self.auto_provision_users = toolkit.asbool(
            get_oidc_config('auto_provision_users', False)
        )

    def provision_user(self, claims: Dict[str, Any], access_token: Optional[str] = None) -> Optional[model.User]:
        """
        Provision or update a user based on OIDC claims.

        Args:
            claims: ID token claims or userinfo response
            access_token: Optional access token for additional API calls

        Returns:
            User object or None if provisioning failed
        """
        log.debug(f"Received OIDC claims: {claims}")
        log.debug(f"Using username_claim: {self.username_claim}")
        username = self._get_username_from_claims(claims)
        email = claims.get(self.email_claim, '')
        fullname = claims.get(self.fullname_claim, '')
        groups = claims.get(self.groups_claim, [])

        if not username:
            log.error("No username found in OIDC claims")
            return None

        user = self._get_user(username, email)

        if user:
            user = self._update_user(user, email, fullname, groups)
        elif self.auto_provision_users:
            user = self._create_user(username, email, fullname, groups)
        else:
            log.warning(f"User {username} not found and auto-provisioning is disabled")
            return None

        if user:
            self._process_group_memberships(user, groups)
            self._update_sysadmin_status(user, groups)

        return user

    def login_user(self, user: model.User) -> None:
        """
        Log in a user to CKAN.

        Args:
            user: User object to log in
        """
        ckan_login_user(user)

        # Required for immediate use in current request
        g.user = user.name
        g.userobj = user
        flask_session['ckan_user_id'] = user.id
        flask_session.permanent = True

        log.info(f"User {user.name} logged in via OIDC")
        log.debug(f"Session after login: g.user={getattr(g, 'user', None)}, g.userobj={getattr(g, 'userobj', None)}, session_user_id={flask_session.get('ckan_user_id')}")

    def _get_username_from_claims(self, claims: Dict[str, Any]) -> Optional[str]:
        """
        Extract and sanitize username from claims.
        Note: CKAN usernames must be alphanumeric + underscore/dash only.

        Args:
            claims: OIDC claims

        Returns:
            CKAN-compatible username (sanitized)
        """
        username = claims.get(self.username_claim)
        log.debug(f"Raw username from {self.username_claim}: {username}")
        if not username:
            # Fallback when preferred claim is missing
            username = claims.get('sub')
            log.debug(f"Fallback to sub claim: {username}")

        if username:
            username = username.lower()

            # CKAN requires: lowercase alphanumeric (ascii) characters and these symbols: -_
            username = re.sub(r'[@\.]', '_', username)
            username = re.sub(r'[^a-z0-9_\-]', '_', username)
            username = re.sub(r'^[_\-]+', '', username)
            username = username[:100]

        log.debug(f"Final sanitized username: {username}")
        return username

    def _get_user(self, username: str, email: str) -> Optional[model.User]:
        """
        Get existing user by username or email.

        Args:
            username: Username to search for
            email: Email to search for

        Returns:
            User object or None
        """
        user = model.User.get(username)
        if user:
            return user
        if email:
            user = model.User.by_email(email)
            if user:
                return user

        return None

    def _create_user(self, username: str, email: str, fullname: str, groups: List[str]) -> Optional[model.User]:
        """
        Create a new user.

        Args:
            username: Username for the new user
            email: Email address
            fullname: Full name
            groups: List of group names from OIDC

        Returns:
            Created user object or None
        """
        try:
            # SSO users need a password but won't use it
            password = secrets.token_urlsafe(32)
            user_data = {
                'name': username,
                'email': email,
                'fullname': fullname or username,
                'password': password,
            }

            context = {'ignore_auth': True}
            user_dict = toolkit.get_action('user_create')(context, user_data)

            user = model.User.get(user_dict['id'])
            log.info(f"Created new user: {username}")

            return user

        except toolkit.ValidationError as e:
            log.exception(f"Validation error creating user {username}: {e}")
            return None
        except Exception as e:
            log.exception(f"Unexpected error creating user {username}: {e}")
            return None

    def _update_user(self, user: model.User, email: str, fullname: str, groups: List[str]) -> model.User:
        """
        Update an existing user's information.

        Args:
            user: User object to update
            email: New email address
            fullname: New full name
            groups: List of group names from OIDC

        Returns:
            Updated user object
        """
        try:
            update_needed = False
            user_data = {'id': user.id}

            if email and user.email != email:
                user_data['email'] = email
                update_needed = True

            if fullname and user.fullname != fullname:
                user_data['fullname'] = fullname
                update_needed = True

            if update_needed:
                context = {'ignore_auth': True, 'user': user.name}
                toolkit.get_action('user_update')(context, user_data)
                log.info(f"Updated user information for: {user.name}")

            return user

        except toolkit.ValidationError as e:
            log.exception(f"Validation error updating user {user.name}: {e}")
            return user
        except Exception as e:
            log.exception(f"Unexpected error updating user {user.name}: {e}")
            return user

    def _process_group_memberships(self, user: model.User, groups: List[str]) -> None:
        """
        Process group memberships from OIDC claims.

        Args:
            user: User object
            groups: List of group names from OIDC
        """
        if not groups:
            return

        try:
            context = {'ignore_auth': True, 'user': user.name}

            for group_name in groups:
                org_name = re.sub(r'[^a-z0-9_\-]', '_', group_name.lower())[:100]

                try:
                    org = toolkit.get_action('organization_show')(
                        context, {'id': org_name}
                    )
                except toolkit.ObjectNotFound:
                    # Auto-create organizations if enabled
                    if toolkit.asbool(get_oidc_config('auto_create_organizations', False)):
                        org_data = {
                            'name': org_name,
                            'title': group_name,
                            'description': f'Organization from OIDC group: {group_name}'
                        }
                        org = toolkit.get_action('organization_create')(context, org_data)
                        log.info(f"Created organization: {org_name}")
                    else:
                        continue

                members = toolkit.get_action('member_list')(
                    context, {'id': org['id'], 'object_type': 'user'}
                )

                user_ids = [member[0] for member in members]
                if user.id not in user_ids:
                    member_data = {
                        'id': org['id'],
                        'username': user.name,
                        'role': 'member'
                    }
                    toolkit.get_action('organization_member_create')(context, member_data)
                    log.info(f"Added user {user.name} to organization {org_name}")

            if self.default_organization:
                try:
                    org = toolkit.get_action('organization_show')(
                        context, {'id': self.default_organization}
                    )
                    members = toolkit.get_action('member_list')(
                        context, {'id': org['id'], 'object_type': 'user'}
                    )
                    user_ids = [member[0] for member in members]

                    if user.id not in user_ids:
                        member_data = {
                            'id': org['id'],
                            'username': user.name,
                            'role': 'member'
                        }
                        toolkit.get_action('organization_member_create')(context, member_data)
                        log.info(f"Added user {user.name} to default organization {self.default_organization}")

                except toolkit.ObjectNotFound:
                    log.warning(f"Default organization {self.default_organization} not found")

        except (toolkit.ObjectNotFound, toolkit.ValidationError) as e:
            log.exception(f"Error processing group memberships for user {user.name}: {e}")
        except Exception as e:
            log.exception(f"Unexpected error processing group memberships for user {user.name}: {e}")
            raise

    def _update_sysadmin_status(self, user: model.User, groups: List[str]) -> None:
        """
        Update user's sysadmin status based on OIDC groups.

        Args:
            user: User object
            groups: List of group names from OIDC
        """
        if not self.sysadmin_groups:
            return

        try:
            should_be_sysadmin = any(
                group in self.sysadmin_groups for group in groups
            )

            if should_be_sysadmin and not user.sysadmin:
                user.sysadmin = True
                model.Session.add(user)
                model.Session.commit()
                log.info(f"Granted sysadmin rights to user: {user.name}")
            elif not should_be_sysadmin and user.sysadmin:
                # Revoke if configured to sync sysadmin status with OIDC groups
                if toolkit.asbool(get_oidc_config('revoke_sysadmin_on_missing_group', False)):
                    user.sysadmin = False
                    model.Session.add(user)
                    model.Session.commit()
                    log.info(f"Revoked sysadmin rights from user: {user.name}")

        except Exception as e:
            log.exception(f"Failed to update sysadmin status for user {user.name}: {e}")
            raise