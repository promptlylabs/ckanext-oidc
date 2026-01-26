# ckanext-oidc

CKAN extension for OpenID Connect (OIDC) authentication with Keycloak integration.

## Features

- **Single Sign-On (SSO)**: Authenticate users via OIDC/Keycloak
- **RP-Initiated Logout**: Log out from both CKAN and Keycloak when users click logout
- **Backchannel Logout**: Automatically invalidate CKAN sessions when users log out from Keycloak
- **Automatic User Provisioning**: Create and update CKAN users from OIDC claims
- **Group Synchronization**: Sync user group memberships from OIDC claims
- **Flexible Configuration**: Support both OIDC and local authentication
- **Session Management**: Redis-backed session persistence for robust logout handling

## Requirements

- **CKAN**: 2.10+ (2.11+ recommended for Flask-Login support)
- **Python**: 3.8+
- **Redis**: Required for session management and backchannel logout
- **OIDC Provider**: Keycloak 10.0+ (or compatible OIDC provider)

## Installation

### Prerequisites

1. **Redis** must be installed and configured:
   ```bash
   # In docker-compose.yml
   services:
     redis:
       image: redis:6
       ports:
         - "6379:6379"
   ```

2. **CKAN Redis URL** must be configured:
   ```bash
   CKAN_REDIS_URL=redis://redis:6379/1
   ```

### Install Extension

1. Activate your CKAN virtual environment:
   ```bash
   . /usr/lib/ckan/default/bin/activate
   ```

2. Install the extension:
   ```bash
   pip install ckanext-oidc
   # or for development:
   pip install -e git+https://github.com/promptlylabs/ckanext-oidc.git#egg=ckanext-oidc
   ```

3. Add `oidc` to the `ckan.plugins` setting:
   ```bash
   # In your .env or CKAN config
   CKAN__PLUGINS="... oidc"
   ```

4. Configure OIDC settings (see Configuration section below)

5. Restart CKAN:
   ```bash
   docker-compose restart ckan  # or your restart command
   ```

## Quick Start Example

Minimal configuration for Keycloak:

```bash
# Enable OIDC
CKAN__CKANEXT__OIDC__ENABLED=true

# Keycloak server
CKAN__CKANEXT__OIDC__PROVIDER_URL=https://keycloak.example.com
CKAN__CKANEXT__OIDC__REALM=master
CKAN__CKANEXT__OIDC__CLIENT_ID=ckan
CKAN__CKANEXT__OIDC__CLIENT_SECRET=your-secret-here

# Basic settings
CKAN__CKANEXT__OIDC__SCOPE=openid profile email
CKAN__CKANEXT__OIDC__USERNAME_CLAIM=email

# Enable logout features
CKAN__CKANEXT__OIDC__ENABLE_LOGOUT=true
CKAN__CKANEXT__OIDC__LOGOUT_FROM_IDP=true
CKAN__CKANEXT__OIDC__ENABLE_BACKCHANNEL_LOGOUT=true

# Redis (required)
CKAN_REDIS_URL=redis://redis:6379/1
```

After configuration:
1. Restart CKAN
2. Visit `/user/login` - you should see "Login with SSO" button
3. Click the button to authenticate via Keycloak
4. User will be auto-created on first login

## Configuration

Configure OIDC by setting environment variables. The pattern is: `CKAN__CKANEXT__OIDC__<SETTING_NAME>` (note the double underscores).

### Required Settings

| Environment Variable | Description | Example |
|---------------------|-------------|---------|
| `CKAN__CKANEXT__OIDC__ENABLED` | Enable OIDC authentication | `true` |
| `CKAN__CKANEXT__OIDC__PROVIDER_URL` | Keycloak server base URL | `https://keycloak.example.com` |
| `CKAN__CKANEXT__OIDC__REALM` | Keycloak realm name | `master` |
| `CKAN__CKANEXT__OIDC__CLIENT_ID` | OIDC client ID | `ckan` |
| `CKAN__CKANEXT__OIDC__CLIENT_SECRET` | OIDC client secret | `your-secret` |
| `CKAN__CKANEXT__OIDC__SCOPE` | OIDC scopes | `openid profile email` |

### User Attribute Mapping

| Environment Variable | Description | Default | Example |
|---------------------|-------------|---------|---------|
| `CKAN__CKANEXT__OIDC__USERNAME_CLAIM` | Token claim for CKAN username | `preferred_username` | `email` |
| `CKAN__CKANEXT__OIDC__EMAIL_CLAIM` | Token claim for email | `email` | `email` |
| `CKAN__CKANEXT__OIDC__FULLNAME_CLAIM` | Token claim for full name | `name` | `name` |
| `CKAN__CKANEXT__OIDC__GROUPS_CLAIM` | Token claim for groups/roles | `groups` | `roles` |

### Authorization Settings

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `CKAN__CKANEXT__OIDC__AUTO_PROVISION_USERS` | Auto-create users on first login | `true` |
| `CKAN__CKANEXT__OIDC__SYSADMIN_GROUPS` | Groups that grant sysadmin privileges (comma-separated) | ` ` |
| `CKAN__CKANEXT__OIDC__DEFAULT_ORGANIZATION` | Default organization for new users | ` ` |
| `CKAN__CKANEXT__OIDC__AUTO_CREATE_ORGANIZATIONS` | Auto-create organizations from OIDC groups | `false` |
| `CKAN__CKANEXT__OIDC__ALLOW_LOCAL_LOGIN` | Allow local username/password login | `true` |

### Logout Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `CKAN__CKANEXT__OIDC__ENABLE_LOGOUT` | Enable OIDC logout integration | `true` |
| `CKAN__CKANEXT__OIDC__LOGOUT_FROM_IDP` | Redirect to Keycloak for logout (RP-initiated) | `true` |
| `CKAN__CKANEXT__OIDC__ENABLE_BACKCHANNEL_LOGOUT` | Enable backchannel logout from Keycloak | `true` |
| `CKAN__CKANEXT__OIDC__POST_LOGOUT_REDIRECT_URI` | Post-logout redirect URL | Auto-detected |

### UI Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `CKAN__CKANEXT__OIDC__BUTTON_TEXT` | SSO login button text | `Login with SSO` |
| `CKAN__CKANEXT__OIDC__BUTTON_ICON` | Button icon (FontAwesome class) | `fa-sign-in` |
| `CKAN__CKANEXT__OIDC__BUTTON_POSITION` | Button position: `top`, `bottom`, or `both` | `top` |

### Advanced Settings

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `CKAN__CKANEXT__OIDC__VERIFY_SSL` | Verify SSL certificates | `true` |
| `CKAN__CKANEXT__OIDC__REDIRECT_URI` | Custom OIDC redirect URI | Auto-detected |
| `CKAN__CKANEXT__OIDC__END_SESSION_ENDPOINT` | Custom end_session endpoint | Auto-discovered |

### Redis Configuration

Redis is **required** for session management and backchannel logout:

```bash
CKAN_REDIS_URL=redis://redis:6379/1
```

## Keycloak Configuration

To enable backchannel logout, configure your Keycloak client:

1. **Access Keycloak Admin Console**: Navigate to your Keycloak instance
2. **Select your client**: Clients → `ckan` (or your client ID)
3. **Configure Advanced Settings**:
   - Go to the **Advanced** tab
   - Set **Backchannel Logout Session Required**: `ON`
   - Set **Backchannel Logout URL**: `https://your-ckan-domain/oidc/backchannel-logout`
4. **Verify Session ID Mapper**:
   - Go to **Client Scopes** → `openid` → **Mappers**
   - Verify `sid` (Session ID) mapper exists and is enabled
   - If missing, add a **User Session Note** mapper:
     - **Name**: `sid`
     - **User Session Note**: `sid`
     - **Token Claim Name**: `sid`
     - **Claim JSON Type**: `String`
     - **Add to ID token**: `ON`
5. **Save Configuration**

### Example Backchannel Logout URL

For the configuration shown above:
```
https://ckan-dev.ckan-docker.orb.local/oidc/backchannel-logout
```

## Logout Flows

This extension implements two complementary logout mechanisms:

### 1. RP-Initiated Logout (CKAN → Keycloak)

When a user logs out from CKAN:
1. User clicks "Log out" in CKAN
2. CKAN clears local session and session mappings
3. CKAN redirects user to Keycloak's logout endpoint (with `id_token_hint`)
4. Keycloak logs user out from all SSO sessions
5. Keycloak redirects user back to CKAN's logged-out page

**Configuration**: Enable with `CKAN__CKANEXT__OIDC__LOGOUT_FROM_IDP=true`

### 2. Backchannel Logout (Keycloak → CKAN)

When a user logs out from Keycloak (or another application):
1. User logs out from Keycloak admin console or another app
2. Keycloak sends a signed JWT logout token to CKAN's backchannel endpoint
3. CKAN validates the token signature and claims
4. CKAN extracts the session ID (`sid`) from the token
5. CKAN invalidates the corresponding session in Redis
6. User is automatically logged out from CKAN

**Configuration**: Enable with `CKAN__CKANEXT__OIDC__ENABLE_BACKCHANNEL_LOGOUT=true`

**Requirements**:
- Redis must be configured (`CKAN_REDIS_URL`)
- Keycloak client must have backchannel logout URL configured
- Session ID (`sid`) must be included in ID tokens

## Testing

### Test RP-Initiated Logout

1. Log in to CKAN via SSO
2. Click "Log out" in CKAN
3. Verify you're redirected to Keycloak logout page
4. Verify you're redirected back to CKAN logged-out page
5. Try accessing a protected page - should require re-login

### Test Backchannel Logout

1. Log in to CKAN via SSO
2. Open Keycloak Admin Console → Sessions
3. Find your user's session and click "Logout"
4. Return to CKAN and try to access a protected page
5. Verify you're redirected to login (session invalidated)

### Debugging

Check CKAN logs:
```bash
docker logs ckan-container | grep -i "oidc\|backchannel"
```

Check Redis session mappings:
```bash
redis-cli keys "oidc:*"
redis-cli get "oidc:sid:YOUR-SESSION-ID"
```

Check stored user tokens:
```bash
redis-cli keys "oidc:user_tokens:*"
```

Common issues:
- **Tokens not persisting**: Ensure Redis is configured and accessible
- **Backchannel logout not working**: Verify Keycloak client has correct backchannel URL
- **Missing `sid` claim**: Check Keycloak client scopes include `sid` mapper
- **SSL verification errors**: Set `CKAN__CKANEXT__OIDC__VERIFY_SSL=false` for development (not recommended for production)

## Development

To set up for development:

```bash
git clone https://github.com/promptlylabs/ckanext-oidc.git
cd ckanext-oidc
pip install -e .
```

### Architecture

The extension uses:
- **Flask Blueprints** for OIDC routes (`/oidc/login`, `/oidc/callback`, `/oidc/backchannel-logout`)
- **IAuthenticator interface** to hook into CKAN's logout flow
- **Redis** for session mappings and token persistence
- **python-jose** for JWT validation

Key files:
- `plugin.py` - CKAN plugin with IAuthenticator implementation
- `views.py` - OIDC endpoints (login, callback, backchannel logout)
- `client.py` - OIDC client for token exchange and validation
- `authenticator.py` - User provisioning and authentication logic
- `session_manager.py` - Redis session mapping for backchannel logout

## Security Considerations

### Production Deployment

1. **Always use HTTPS** for production deployments
2. **Enable SSL verification**: `CKAN__CKANEXT__OIDC__VERIFY_SSL=true`
3. **Secure Redis**: Use authentication and firewall rules
4. **Session Security**: Configure CKAN session settings:
   ```bash
   # Session lifetime (30 minutes recommended)
   CKAN___PERMANENT_SESSION_LIFETIME=1800
   CKAN___SESSION_PERMANENT=True
   CKAN___SESSION_REFRESH_EACH_REQUEST=True
   # Session cookie security
   CKAN___SESSION_COOKIE_HTTPONLY=True
   CKAN___SESSION_COOKIE_SECURE=True
   CKAN___SESSION_COOKIE_SAMESITE=Lax
   ```

### JWT Validation

The extension validates:
- JWT signature using Keycloak's JWKS
- Token issuer matches configured Keycloak URL
- Token audience matches client ID
- Token expiration and issued-at times
- Required claims presence
- Backchannel logout token structure

### Session Management

- Session IDs are never exposed in URLs or logs
- Session mappings expire automatically (TTL matches session lifetime)
- User tokens stored in Redis are encrypted by Redis AUTH if configured
- Backchannel logout endpoint validates all tokens before processing

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "User did not login via OIDC" on logout | Tokens not persisting - check Redis configuration |
| Backchannel logout not working | Verify Keycloak backchannel URL and `sid` mapper |
| SSL certificate errors | Set `VERIFY_SSL=false` for dev, or fix certificates for prod |
| "Missing required claim" errors | Check Keycloak client scopes and mappers |
| Session expired immediately | Check `PERMANENT_SESSION_LIFETIME` setting |
| Can't log in with local account | Set `ALLOW_LOCAL_LOGIN=true` |

### Enable Debug Logging

```python
# In CKAN config
logging.loggers.ckanext.oidc.level = DEBUG
```

Or via environment:
```bash
CKAN__LOGGING__LOGGERS__CKANEXT_OIDC__LEVEL=DEBUG
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## License

Apache License 2.0

See [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
- **GitHub Issues**: https://github.com/promptlylabs/ckanext-oidc/issues
- **Documentation**: See this README

## Credits

Developed by @promptlylabs for CKAN integration with Keycloak/OIDC providers.