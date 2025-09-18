import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging

from .utils import (
    is_oidc_enabled,
    validate_oidc_config,
    get_oidc_config,
)

log = logging.getLogger(__name__)


class OidcPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IBlueprint)

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