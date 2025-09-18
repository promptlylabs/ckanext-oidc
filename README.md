# ckanext-oidc

CKAN extension for OpenID Connect (OIDC) authentication

## Requirements

This extension works with CKAN 2.9+ and requires Python 3.8+

## Installation

To install ckanext-oidc:

1. Install the extension:

    ```bash
    pip install ckanext-oidc
    ```

2. Add 'oidc' to the `ckan.plugins` setting in your CKAN config file

3. Configure the OIDC settings (see Configuration section)

## Configuration

Configure OIDC by setting these options in your CKAN configuration file or as environment variables:

```ini
# Enable/disable OIDC authentication
ckanext.oidc.enabled = true

# OIDC Provider Configuration
ckanext.oidc.provider_url = https://your-oidc-provider.com
ckanext.oidc.client_id = your-client-id
ckanext.oidc.client_secret = your-client-secret
ckanext.oidc.redirect_uri = http://your-ckan-site.com/oidc/callback

# Optional settings
ckanext.oidc.scope = openid profile email
ckanext.oidc.button_text = Login with SSO
ckanext.oidc.button_position = top  # top, bottom, or both
ckanext.oidc.allow_local_login = true

# User mapping (how OIDC claims map to CKAN user fields)
ckanext.oidc.username_claim = preferred_username
ckanext.oidc.email_claim = email
ckanext.oidc.fullname_claim = name
ckanext.oidc.groups_claim = groups
```

Environment variables follow the pattern: `CKANEXT__OIDC__<SETTING_NAME>`

For example:
```bash
export CKANEXT__OIDC__ENABLED=true
export CKANEXT__OIDC__PROVIDER_URL=https://your-oidc-provider.com
export CKANEXT__OIDC__CLIENT_ID=your-client-id
export CKANEXT__OIDC__CLIENT_SECRET=your-client-secret
```

## Features

- OpenID Connect authentication integration
- Automatic user creation and update from OIDC claims
- Group membership synchronization
- Configurable login button placement
- Support for both OIDC and local authentication
- Session management with OIDC logout support

## Development

To set up for development:

```bash
git clone https://github.com/promptlylabs/ckanext-oidc.git
cd ckanext-oidc
pip install -e .
```

## License

Apache License 2.0