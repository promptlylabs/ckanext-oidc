"""Session management for OIDC backchannel logout.

This module provides functionality to map OIDC session IDs (sid) to Flask session IDs
to support backchannel logout from Keycloak.
"""

import logging
import uuid
from typing import Optional, Dict, Any

import redis
from flask import session as flask_session, request

from ckan.common import config

log = logging.getLogger(__name__)


class OIDCSessionManager:
    """Manages session mappings for OIDC backchannel logout."""

    # Redis key prefixes
    SID_TO_SESSION_PREFIX = "oidc:sid:"
    SESSION_TO_SID_PREFIX = "oidc:session:"
    USER_TOKENS_PREFIX = "oidc:user_tokens:"  # Store tokens by user ID

    def __init__(self):
        """Initialize the session manager with Redis connection."""
        self._redis_conn = None
        self._init_redis()

    def _init_redis(self):
        """Initialize Redis connection from CKAN config."""
        try:
            redis_url = config.get('ckan.redis.url')
            if not redis_url:
                log.error("OIDC session manager: ckan.redis.url not configured")
                return

            self._redis_conn = redis.from_url(redis_url)
            # Test connection
            self._redis_conn.ping()
            log.debug("OIDC session manager: Redis connection initialized")
        except Exception as e:
            log.error("OIDC session manager: Failed to initialize Redis: %s", e)
            self._redis_conn = None

    def _get_ttl(self) -> int:
        """Get TTL for session mappings from CKAN config.

        Returns TTL in seconds, defaults to 24 hours if not configured.
        """
        # CKAN's permanent_session_lifetime is in seconds
        ttl = config.get('permanent_session_lifetime', 86400)
        try:
            return int(ttl)
        except (ValueError, TypeError):
            log.warning("Invalid permanent_session_lifetime config, using default 24h")
            return 86400

    def _get_session_id(self, session: Dict[str, Any]) -> Optional[str]:
        """Extract Flask session ID.

        Args:
            session: Flask session object

        Returns:
            Session ID string or None if not found
        """
        log.debug("Attempting to extract session ID, session type: %s", type(session).__name__)

        # Try 1: Direct access to sid attribute (Flask-Session with Redis)
        try:
            sid = session.sid
            if sid:
                log.debug("Got session ID from .sid attribute: %s", sid)
                return str(sid)
        except (AttributeError, KeyError) as e:
            log.debug("No .sid attribute: %s", e)

        # Try 2: Access _sid attribute (some Flask session implementations)
        try:
            sid = session._sid
            if sid:
                log.debug("Got session ID from ._sid attribute: %s", sid)
                return str(sid)
        except (AttributeError, KeyError) as e:
            log.debug("No ._sid attribute: %s", e)

        # Try 3: Check for _id in session dict (Beaker sessions)
        try:
            if isinstance(session, dict) and '_id' in session:
                sid = session['_id']
                log.debug("Got session ID from _id key: %s", sid)
                return str(sid)
        except (TypeError, KeyError) as e:
            log.debug("No _id key: %s", e)

        # Try 4: Get from Flask request cookie
        try:
            from flask import has_request_context
            if has_request_context() and request:
                # Try to get session cookie value
                session_cookie_name = 'session'  # Default Flask session cookie name
                cookie_value = request.cookies.get(session_cookie_name)
                if cookie_value:
                    log.debug("Got session cookie value (will use as ID)")
                    # Use the cookie value as session ID
                    # Note: This is the signed cookie, but we can use it as a unique identifier
                    return cookie_value[:50]  # Truncate if too long
        except Exception as e:
            log.debug("Could not get session from cookie: %s", e)

        # Try 5: Generate and store a unique session identifier in the session dict
        # This is our fallback - we create our own session ID that persists in the session
        try:
            if '_oidc_session_key' not in session:
                unique_id = str(uuid.uuid4())
                session['_oidc_session_key'] = unique_id
                session.modified = True  # Mark session as modified
                log.debug("Generated new OIDC session key: %s", unique_id)
                return unique_id
            else:
                sid = session['_oidc_session_key']
                log.debug("Using existing OIDC session key: %s", sid)
                return str(sid)
        except Exception as e:
            log.error("Failed to generate/retrieve OIDC session key: %s", e)

        log.warning("Could not extract session ID from session object after all attempts")
        return None

    def store_session_mapping(self, session: Dict[str, Any], id_token_claims: Dict[str, Any]) -> bool:
        """Store bidirectional mapping between OIDC sid and Flask session ID.

        Args:
            session: Flask session object
            id_token_claims: Decoded ID token claims containing 'sid'

        Returns:
            True if successful, False otherwise
        """
        if not self._redis_conn:
            log.error("Redis not available, cannot store session mapping")
            return False

        try:
            # Extract OIDC session ID from ID token
            oidc_sid = id_token_claims.get('sid')
            if not oidc_sid:
                log.warning("No 'sid' claim in ID token, backchannel logout will not work")
                return False

            # Extract Flask session ID
            flask_session_id = self._get_session_id(session)
            if not flask_session_id:
                log.error("Could not extract Flask session ID")
                return False

            # Store bidirectional mapping
            ttl = self._get_ttl()

            # Map: oidc:sid:{sid} -> flask_session_id
            sid_key = f"{self.SID_TO_SESSION_PREFIX}{oidc_sid}"
            self._redis_conn.setex(sid_key, ttl, flask_session_id)

            # Map: oidc:session:{flask_session_id} -> sid
            session_key = f"{self.SESSION_TO_SID_PREFIX}{flask_session_id}"
            self._redis_conn.setex(session_key, ttl, oidc_sid)

            log.debug("Stored session mapping: sid=%s, session_id=%s", oidc_sid, flask_session_id)
            return True

        except Exception as e:
            log.error("Failed to store session mapping: %s", e)
            return False

    def get_session_id_by_sid(self, sid: str) -> Optional[str]:
        """Lookup Flask session ID by OIDC session ID.

        Args:
            sid: OIDC session ID from logout token

        Returns:
            Flask session ID or None if not found
        """
        if not self._redis_conn:
            log.error("Redis not available, cannot lookup session")
            return None

        try:
            sid_key = f"{self.SID_TO_SESSION_PREFIX}{sid}"
            session_id = self._redis_conn.get(sid_key)

            if session_id:
                # Redis returns bytes in Python 3
                if isinstance(session_id, bytes):
                    session_id = session_id.decode('utf-8')
                log.debug("Found session mapping: sid=%s -> session_id=%s", sid, session_id)
                return session_id
            else:
                log.debug("No session mapping found for sid=%s", sid)
                return None

        except Exception as e:
            log.error("Failed to lookup session by sid: %s", e)
            return None

    def invalidate_session(self, flask_session_id: str) -> bool:
        """Invalidate a Flask session by deleting it from Redis.

        Args:
            flask_session_id: Flask session ID to invalidate

        Returns:
            True if successful, False otherwise
        """
        if not self._redis_conn:
            log.error("Redis not available, cannot invalidate session")
            return False

        try:
            # Try multiple session key formats used by different session backends
            session_keys = [
                f"session:{flask_session_id}",           # Flask-Session format
                f"beaker.session.{flask_session_id}",    # Beaker format
                f"beaker:session:{flask_session_id}",    # Alternative Beaker format
                flask_session_id                          # Direct key
            ]

            deleted = False
            for key in session_keys:
                result = self._redis_conn.delete(key)
                if result > 0:
                    log.info("Deleted session key: %s", key)
                    deleted = True

            # If we didn't find exact matches, try scanning for the session ID
            if not deleted:
                log.debug("Exact session keys not found, trying pattern match")
                # Try to find keys containing the session ID
                try:
                    pattern = f"*{flask_session_id}*"
                    for key in self._redis_conn.scan_iter(match=pattern, count=100):
                        if isinstance(key, bytes):
                            key = key.decode('utf-8')
                        log.debug("Found potential session key via scan: %s", key)
                        result = self._redis_conn.delete(key)
                        if result > 0:
                            log.info("Deleted session via pattern match: %s", key)
                            deleted = True
                except Exception as scan_error:
                    log.warning("Pattern scan failed: %s", scan_error)

            if deleted:
                log.info("Successfully invalidated session: %s", flask_session_id)
                return True
            else:
                log.warning("No session keys found for: %s (session may have already expired)", flask_session_id)
                # Still return True as the session is effectively invalidated
                return True

        except Exception as e:
            log.error("Failed to invalidate session: %s", e)
            return False

    def remove_session_mapping(self, session: Dict[str, Any]) -> bool:
        """Remove session mapping on logout.

        Args:
            session: Flask session object

        Returns:
            True if successful, False otherwise
        """
        if not self._redis_conn:
            log.error("Redis not available, cannot remove session mapping")
            return False

        try:
            flask_session_id = self._get_session_id(session)
            if not flask_session_id:
                log.warning("Could not extract session ID for cleanup")
                return False

            # Get the OIDC sid from the reverse mapping
            session_key = f"{self.SESSION_TO_SID_PREFIX}{flask_session_id}"
            oidc_sid = self._redis_conn.get(session_key)

            if oidc_sid:
                if isinstance(oidc_sid, bytes):
                    oidc_sid = oidc_sid.decode('utf-8')

                # Delete both mappings
                sid_key = f"{self.SID_TO_SESSION_PREFIX}{oidc_sid}"
                self._redis_conn.delete(sid_key)
                self._redis_conn.delete(session_key)

                log.debug("Removed session mapping for session_id=%s", flask_session_id)
                return True
            else:
                log.debug("No session mapping found to remove for session_id=%s", flask_session_id)
                return True  # Not an error, mapping may have expired

        except Exception as e:
            log.error("Failed to remove session mapping: %s", e)
            return False

    def store_user_tokens(self, user_id: str, tokens: Dict[str, Any]) -> bool:
        """Store OIDC tokens by user ID for persistence across session changes.

        Args:
            user_id: CKAN user ID
            tokens: Dictionary containing access_token, id_token, refresh_token

        Returns:
            True if successful, False otherwise
        """
        if not self._redis_conn:
            log.error("Redis not available, cannot store user tokens")
            return False

        try:
            import json

            key = f"{self.USER_TOKENS_PREFIX}{user_id}"
            ttl = self._get_ttl()

            # Store tokens as JSON
            tokens_json = json.dumps(tokens)
            self._redis_conn.setex(key, ttl, tokens_json)

            log.debug("Stored OIDC tokens for user: %s", user_id)
            return True

        except Exception as e:
            log.error("Failed to store user tokens: %s", e)
            return False

    def get_user_tokens(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve OIDC tokens by user ID.

        Args:
            user_id: CKAN user ID

        Returns:
            Dictionary containing tokens, or None if not found
        """
        if not self._redis_conn:
            log.error("Redis not available, cannot retrieve user tokens")
            return None

        try:
            import json

            key = f"{self.USER_TOKENS_PREFIX}{user_id}"
            tokens_json = self._redis_conn.get(key)

            if tokens_json:
                if isinstance(tokens_json, bytes):
                    tokens_json = tokens_json.decode('utf-8')
                tokens = json.loads(tokens_json)
                log.debug("Retrieved OIDC tokens for user: %s", user_id)
                return tokens
            else:
                log.debug("No OIDC tokens found for user: %s", user_id)
                return None

        except Exception as e:
            log.error("Failed to retrieve user tokens: %s", e)
            return None

    def remove_user_tokens(self, user_id: str) -> bool:
        """Remove OIDC tokens for a user.

        Args:
            user_id: CKAN user ID

        Returns:
            True if successful, False otherwise
        """
        if not self._redis_conn:
            log.error("Redis not available, cannot remove user tokens")
            return False

        try:
            key = f"{self.USER_TOKENS_PREFIX}{user_id}"
            self._redis_conn.delete(key)
            log.debug("Removed OIDC tokens for user: %s", user_id)
            return True

        except Exception as e:
            log.error("Failed to remove user tokens: %s", e)
            return False
