# OIDC SSO Configuration Guide

This guide provides step-by-step instructions for configuring OIDC SSO authentication for CKAN with Keycloak.

## Prerequisites

- CKAN instance with ckanext-oidc extension installed
- Keycloak server running and accessible
- Administrative access to both CKAN and Keycloak

## Step 1: Keycloak Client Configuration

### 1.1 Create OIDC Client

1. **Access Keycloak Admin Console**
   - Navigate to your Keycloak admin interface
   - Select the appropriate realm (e.g., `master`)

2. **Create New Client**
   - Go to "Clients" → "Create"
   - Client ID: `ckan`
   - Client Protocol: `openid-connect`
   - Root URL: `https://your-ckan-domain.com`

3. **Configure Client Settings**
   ```
   Access Type: confidential
   Standard Flow Enabled: ON
   Implicit Flow Enabled: OFF
   Direct Access Grants Enabled: OFF
   Service Accounts Enabled: OFF
   ```

4. **Set Valid Redirect URIs**
   ```
   https://your-ckan-domain.com/oidc/callback
   https://your-ckan-domain.com/oidc/logout
   ```

5. **Configure Web Origins**
   ```
   https://your-ckan-domain.com
   ```

### 1.2 Client Credentials

1. **Get Client Secret**
   - Go to "Credentials" tab
   - Copy the "Secret" value
   - This will be used as `CKAN__CKANEXT__OIDC__CLIENT_SECRET`

### 1.3 Client Scopes Configuration

1. **Default Client Scopes**
   - Ensure these scopes are assigned:
     - `openid` (required)
     - `profile` (recommended)
     - `email` (recommended)

2. **Custom Group Mapper** (if using group-based authorization)
   - Go to "Mappers" tab → "Create"
   - Mapper Type: `Group Membership`
   - Name: `datalake_roles`
   - Token Claim Name: `datalake_roles`
   - Full group path: OFF
   - Add to ID token: ON
   - Add to access token: ON
   - Add to userinfo: ON

## Step 2: CKAN Environment Configuration

### 2.1 Update .env File

Add the following configuration to your `.env` file:

```bash
# Enable OIDC authentication
CKAN__CKANEXT__OIDC__ENABLED=true

# Keycloak server configuration
CKAN__CKANEXT__OIDC__PROVIDER_URL=https://keycloak.apps.lab.dl.min-saude.pt
CKAN__CKANEXT__OIDC__REALM=master
CKAN__CKANEXT__OIDC__CLIENT_ID=ckan
CKAN__CKANEXT__OIDC__CLIENT_SECRET=your_client_secret_here

# OIDC scopes
CKAN__CKANEXT__OIDC__SCOPE=openid profile email

# SSL verification (set to false for development environments)
CKAN__CKANEXT__OIDC__VERIFY_SSL=false

# User attribute mapping
CKAN__CKANEXT__OIDC__USERNAME_CLAIM=email
CKAN__CKANEXT__OIDC__EMAIL_CLAIM=email
CKAN__CKANEXT__OIDC__FULLNAME_CLAIM=name
CKAN__CKANEXT__OIDC__GROUPS_CLAIM=datalake_roles

# Authorization settings
CKAN__CKANEXT__OIDC__SYSADMIN_GROUPS=DevOps/SRE Admin
CKAN__CKANEXT__OIDC__DEFAULT_ORGANIZATION=
CKAN__CKANEXT__OIDC__AUTO_PROVISION_USERS=true
CKAN__CKANEXT__OIDC__AUTO_CREATE_ORGANIZATIONS=false
CKAN__CKANEXT__OIDC__ALLOW_LOCAL_LOGIN=true

# UI Configuration
CKAN__CKANEXT__OIDC__BUTTON_TEXT=Sign in with Keycloak
CKAN__CKANEXT__OIDC__BUTTON_ICON=fa-key
CKAN__CKANEXT__OIDC__BUTTON_POSITION=top
```

### 2.2 Environment Variable Reference

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `PROVIDER_URL` | Base URL of Keycloak server | `https://keycloak.example.com` |
| `REALM` | Keycloak realm name | `master` |
| `CLIENT_ID` | OIDC client identifier | `ckan` |
| `CLIENT_SECRET` | Client secret from Keycloak | `abc123...` |
| `VERIFY_SSL` | SSL certificate verification | `true` (prod), `false` (dev) |
| `USERNAME_CLAIM` | Token claim for username | `email` or `preferred_username` |
| `GROUPS_CLAIM` | Token claim for user groups | `datalake_roles` |
| `SYSADMIN_GROUPS` | Groups that grant admin rights | `DevOps/SRE Admin,Admins` |

## Step 3: CKAN Plugin Configuration

### 3.1 Enable Plugin

Ensure the `oidc` plugin is enabled in your CKAN configuration:

```bash
CKAN__PLUGINS="... oidc ..."
```

### 3.2 Site URL Configuration

Make sure your CKAN site URL is correctly configured:

```bash
CKAN_SITE_URL=https://your-ckan-domain.com
```

## Step 4: Testing the Configuration

### 4.1 Restart Services

```bash
# For development
docker-compose -f docker-compose.dev.yml down
docker-compose -f docker-compose.dev.yml up -d

# For production
docker-compose down
docker-compose up -d
```

### 4.2 Verify Configuration

1. **Check CKAN Logs**
   ```bash
   docker-compose logs -f ckan-dev | grep -i oidc
   ```

2. **Look for Startup Message**
   ```
   INFO [ckanext.oidc.plugin] OIDC authentication enabled with provider: https://keycloak.example.com
   ```

### 4.3 Test Authentication Flow

1. **Navigate to Login Page**
   - Go to `https://your-ckan-domain.com/user/login`
   - Verify SSO button appears

2. **Test SSO Login**
   - Click "Sign in with Keycloak" button
   - Should redirect to Keycloak login
   - Enter valid credentials
   - Should redirect back to CKAN and log you in

3. **Verify User Creation**
   ```bash
   docker-compose exec ckan-dev ckan user list
   ```

## Step 5: Production Configuration

### 5.1 SSL/TLS Configuration

For production environments:

```bash
# Enable SSL verification
CKAN__CKANEXT__OIDC__VERIFY_SSL=true

# Ensure HTTPS URLs
CKAN_SITE_URL=https://your-production-domain.com
CKAN__CKANEXT__OIDC__PROVIDER_URL=https://keycloak.production.com
```

### 5.2 Security Considerations

1. **Client Secret Security**
   - Store client secret securely (environment variables, secrets management)
   - Rotate secrets regularly
   - Never commit secrets to version control

2. **HTTPS Only**
   - Ensure all URLs use HTTPS
   - Configure proper SSL certificates
   - Use secure headers and HSTS

3. **Scope Limitation**
   - Only request necessary OIDC scopes
   - Review and minimize permissions

### 5.3 Monitoring Setup

1. **Log Monitoring**
   ```bash
   # Monitor authentication events
   docker-compose logs -f ckan | grep -E "(OIDC|authentication|login)"
   ```

2. **Error Alerts**
   - Set up alerts for authentication failures
   - Monitor user creation/update errors
   - Track unusual login patterns

## Troubleshooting Common Issues

### Issue 1: "OIDC authentication not enabled"

**Cause**: Plugin not properly loaded or configuration missing

**Solutions**:
1. Verify `oidc` is in the CKAN plugins list
2. Check that `OIDC__ENABLED=true` is set
3. Restart CKAN services

### Issue 2: "Failed to create or update user account"

**Cause**: Username validation or database constraints

**Solutions**:
1. Check username sanitization in logs
2. Verify email claim is available
3. Check for duplicate users

### Issue 3: SSL verification errors

**Cause**: Certificate validation issues

**Solutions**:
1. For development: Set `VERIFY_SSL=false`
2. For production: Fix certificate chain
3. Check Keycloak SSL configuration

### Issue 4: User not staying logged in

**Cause**: Session management issues

**Solutions**:
1. Check Flask session configuration
2. Verify user state is 'active'
3. Review session cookie settings

### Issue 5: Redirect URI mismatch

**Cause**: Keycloak client configuration doesn't match CKAN URLs

**Solutions**:
1. Verify redirect URIs in Keycloak client
2. Check CKAN site URL configuration
3. Ensure URLs include correct protocol (https)

## Configuration Examples

### Development Environment

```bash
# Minimal development configuration
CKAN__CKANEXT__OIDC__ENABLED=true
CKAN__CKANEXT__OIDC__PROVIDER_URL=http://localhost:8080
CKAN__CKANEXT__OIDC__REALM=master
CKAN__CKANEXT__OIDC__CLIENT_ID=ckan
CKAN__CKANEXT__OIDC__CLIENT_SECRET=dev_secret
CKAN__CKANEXT__OIDC__VERIFY_SSL=false
CKAN__CKANEXT__OIDC__USERNAME_CLAIM=email
CKAN__CKANEXT__OIDC__EMAIL_CLAIM=email
```

### Production Environment

```bash
# Production configuration with full security
CKAN__CKANEXT__OIDC__ENABLED=true
CKAN__CKANEXT__OIDC__PROVIDER_URL=https://auth.company.com
CKAN__CKANEXT__OIDC__REALM=production
CKAN__CKANEXT__OIDC__CLIENT_ID=ckan
CKAN__CKANEXT__OIDC__CLIENT_SECRET=${KEYCLOAK_CLIENT_SECRET}
CKAN__CKANEXT__OIDC__VERIFY_SSL=true
CKAN__CKANEXT__OIDC__USERNAME_CLAIM=email
CKAN__CKANEXT__OIDC__EMAIL_CLAIM=email
CKAN__CKANEXT__OIDC__FULLNAME_CLAIM=name
CKAN__CKANEXT__OIDC__GROUPS_CLAIM=groups
CKAN__CKANEXT__OIDC__SYSADMIN_GROUPS=sysadmin,admin
CKAN__CKANEXT__OIDC__AUTO_PROVISION_USERS=true
CKAN__CKANEXT__OIDC__AUTO_CREATE_ORGANIZATIONS=false
```

## Validation Checklist

Before deploying to production, verify:

- [ ] Keycloak client configured correctly
- [ ] All environment variables set
- [ ] SSL certificates valid (production)
- [ ] Redirect URIs match exactly
- [ ] User can authenticate successfully
- [ ] User information populated correctly
- [ ] Group mappings work as expected
- [ ] Sysadmin rights assigned properly
- [ ] Logout functionality works
- [ ] Error handling tested
- [ ] Logs contain no sensitive information
- [ ] Monitoring and alerts configured

## Support

For configuration assistance:
1. Review this guide thoroughly
2. Check CKAN and Keycloak logs for specific errors
3. Verify network connectivity between services
4. Test with minimal configuration first
5. Consult the main implementation documentation