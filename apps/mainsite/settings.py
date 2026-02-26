from cryptography.fernet import Fernet
import os
from datetime import datetime
import pytz
import mainsite
from corsheaders.defaults import default_headers

from mainsite import TOP_DIR

##
#
#  Important Stuff
#
##

INSTALLED_APPS = [
    "mainsite",
    "django.contrib.auth",
    "mozilla_django_oidc",  # Load after auth
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    "django_object_actions",
    "django_prometheus",
    "markdownify",
    "badgeuser",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "badgrsocialauth",
    "badgrsocialauth.providers.facebook",
    "badgrsocialauth.providers.kony",
    "badgrsocialauth.providers.twitter",
    "allauth.socialaccount.providers.auth0",
    "allauth.socialaccount.providers.linkedin_oauth2",
    "allauth.socialaccount.providers.oauth2",
    "corsheaders",
    "rest_framework",
    "rest_framework.authtoken",
    "django_celery_results",
    "dbbackup",  # django-dbbackup
    # OAuth 2 provider
    "oauth2_provider",
    "oidc",
    "entity",
    "issuer",
    "backpack",
    "dashboard",
    # api docs
    "drf_spectacular",
    # deprecated
    "composition",
    "django_filters",
    "lti_tool",
    "mjml",
]

MIDDLEWARE = [
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # It's important that CookieToBearerMiddleware comes before
    # the Oauth2TokenMiddleware
    "mainsite.middleware.CookieToBearerMiddleware",
    "oauth2_provider.middleware.OAuth2TokenMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "mainsite.middleware.XframeExempt500Middleware",
    "mainsite.middleware.MaintenanceMiddleware",
    "badgeuser.middleware.InactiveUserMiddleware",
    # 'mainsite.middleware.TrailingSlashMiddleware',
    "django_prometheus.middleware.PrometheusAfterMiddleware",
    "lti_tool.middleware.LtiLaunchMiddleware",
    "mainsite.middleware.ExceptionLoggingMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

DBBACKUP_STORAGE = "django.core.files.storage.FileSystemStorage"
DBBACKUP_STORAGE_OPTIONS = {"location": "/backups/"}

ROOT_URLCONF = "mainsite.urls"

# Hosts/domain names that are valid for this site.
# "*" matches anything, ".example.com" matches example.com and all subdomains
# ALLOWED_HOSTS = ['<your badgr server domain>', ]

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")


##
#
#  Templates
#
##

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.request",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
                "mainsite.context_processors.extra_settings",
            ],
            "loaders": (
                "django.template.loaders.app_directories.Loader",
                "django.template.loaders.filesystem.Loader",
            ),
        },
    },
]


##
#
#  Static Files
#
##

HTTP_ORIGIN = "http://localhost:8000"

STATICFILES_FINDERS = [
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
]

STATIC_ROOT = os.path.join(TOP_DIR, "staticfiles")
STATIC_URL = HTTP_ORIGIN + "/static/"
STATICFILES_DIRS = [
    os.path.join(TOP_DIR, "apps", "mainsite", "static"),
]

##
#
#  User / Login / Auth
#
##

AUTH_USER_MODEL = "badgeuser.BadgeUser"
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/docs"

AUTHENTICATION_BACKENDS = [
    "oidc.oeb_oidc_authentication_backend.OebOIDCAuthenticationBackend",
    "oauth2_provider.backends.OAuth2Backend",
    # Object permissions for issuing badges
    "rules.permissions.ObjectPermissionBackend",
    # Needed to login by username in Django admin, regardless of `allauth`
    "badgeuser.backends.CachedModelBackend",
    # `allauth` specific authentication methods, such as login by e-mail
    "badgeuser.backends.CachedAuthenticationBackend",
]

ACCOUNT_DEFAULT_HTTP_PROTOCOL = "http"
ACCOUNT_ADAPTER = "mainsite.account_adapter.BadgrAccountAdapter"
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_CONFIRM_EMAIL_ON_GET = True
ACCOUNT_LOGOUT_ON_GET = True
ACCOUNT_AUTHENTICATION_METHOD = "email"
ACCOUNT_FORMS = {"add_email": "badgeuser.account_forms.AddEmailForm"}
ACCOUNT_SIGNUP_FORM_CLASS = "badgeuser.forms.BadgeUserCreationForm"


SOCIALACCOUNT_EMAIL_REQUIRED = False
SOCIALACCOUNT_EMAIL_VERIFICATION = "optional"
SOCIALACCOUNT_PROVIDERS = {
    "kony": {"environment": "dev"},
    "linkedin_oauth2": {"VERIFIED_EMAIL": True},
    "auth0": {
        "AUTH0_URL": "https://mybadges.eu.auth0.com",
    },
}
SOCIALACCOUNT_ADAPTER = "badgrsocialauth.adapter.BadgrSocialAccountAdapter"


AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 8,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
    {
        "NAME": "mainsite.validators.ComplexityPasswordValidator",
    },
]


##
#
#  CORS
#
##

# Needed for authentication
CORS_ALLOW_CREDENTIALS = True

CORS_EXPOSE_HEADERS = ("link",)

CORS_ALLOW_HEADERS = [*default_headers, "x-altcha-spam-filter", "x-oeb-altcha"]

##
#
#  Media Files
#
##

MEDIA_ROOT = os.path.join(TOP_DIR, "mediafiles")
MEDIA_URL = "/media/"
ADMIN_MEDIA_PREFIX = STATIC_URL + "admin/"


##
#
#   Fixtures
#
##

FIXTURE_DIRS = [
    os.path.join(TOP_DIR, "etc", "fixtures"),
]


##
#
#  Logging
#
##

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        # Only logs to the console appear in the docker / grafana logs
        "console": {
            "level": "INFO",
            "formatter": "default",
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        # Badgr.Events emits all badge related activity
        "Badgr.Events": {
            "handlers": ["console"],
            "level": "DEBUG",
        },
    },
    "formatters": {
        "default": {"format": "%(asctime)s %(levelname)s %(module)s %(message)s"}
    },
}

##
#
#  Caching
#
##

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "KEY_PREFIX": "badgr_",
        "VERSION": 10,
        "TIMEOUT": None,
    }
}

##
#
#  Maintenance Mode
#
##

MAINTENANCE_MODE = False
MAINTENANCE_URL = "/maintenance"


##
#
#  Sphinx Search
#
##

SPHINX_API_VERSION = 0x116  # Sphinx 0.9.9

##
#
# Testing
##
TEST_RUNNER = "mainsite.testrunner.BadgrRunner"


##
#
#  REST Framework
#
##

REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly"
    ],
    "DEFAULT_RENDERER_CLASSES": (
        "mainsite.renderers.JSONLDRenderer",
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    ),
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "mainsite.authentication.BadgrOAuth2Authentication",
        "mainsite.authentication.LoggedLegacyTokenAuthentication",
        "entity.authentication.ExplicitCSRFSessionAuthentication",
        "mozilla_django_oidc.contrib.drf.OIDCAuthentication",
    ),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_VERSIONING_CLASS": "rest_framework.versioning.URLPathVersioning",
    "DEFAULT_VERSION": "v1",
    "ALLOWED_VERSIONS": ["v1", "v2", "v3", "bcv1", "rfc7591"],
    "EXCEPTION_HANDLER": "entity.views.exception_handler",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 100,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Badgr API",
    "DESCRIPTION": "Badgr API documentation",
    "VERSION": "3.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
}


##
#
#  Remote document fetcher (designed to be overridden in tests)
#
##

REMOTE_DOCUMENT_FETCHER = "badgeanalysis.utils.get_document_direct"
LINKED_DATA_DOCUMENT_FETCHER = "badgeanalysis.utils.custom_docloader"


##
#
#  Misc.
#
##

LTI_STORE_IN_SESSION = False

CAIROSVG_VERSION_SUFFIX = "2"

SITE_ID = 2

USE_I18N = False
USE_L10N = False
USE_TZ = True


##
#
#  Deployment timestamp
#
##
try:
    file = open("timestamp", "r")
    mainsite.__timestamp__ = file.read()
    print("Deployment timestamp:")
    print(mainsite.__timestamp__)
except Exception as e:
    print(e)
    mainsite.__timestamp__ = datetime.now(pytz.timezone("Europe/Berlin")).strftime(
        "%d.%m.%y %T (last restart)"
    )
    print("ERROR in determining deployment timestamp; used current timestamp:")
    print(mainsite.__timestamp__)

##
#
# Markdownify
#
##

MARKDOWNIFY_WHITELIST_TAGS = [
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "a",
    "abbr",
    "acronym",
    "b",
    "blockquote",
    "em",
    "i",
    "li",
    "ol",
    "p",
    "strong",
    "ul",
    "code",
    "pre",
    "hr",
]


OAUTH2_PROVIDER = {
    "SCOPES": {
        "r:profile": "See who you are",
        "rw:profile": "Update your own user profile",
        "r:backpack": "List assertions in your backpack",
        "rw:backpack": "Upload badges into a backpack",
        "rw:issuer": "Create and update issuers, create and update badge classes, and award assertions",
        # private scopes used for integrations
        "rw:issuer:*": "Create and update badge classes, and award assertions for a single issuer",
        "rw:serverAdmin": "Superuser trusted operations on most objects",
        "r:assertions": "Batch receive assertions",
        # Badge Connect API Scopes
        "https://purl.imsglobal.org/spec/ob/v2p1/scope/assertion.readonly": "List assertions in a User's Backpack",
        "https://purl.imsglobal.org/spec/ob/v2p1/scope/assertion.create": "Add badges into a User's Backpack",
        "https://purl.imsglobal.org/spec/ob/v2p1/scope/profile.readonly": "See who you are",
    },
    "DEFAULT_SCOPES": ["r:profile"],
    "OAUTH2_VALIDATOR_CLASS": "mainsite.oauth_validator.BadgrRequestValidator",
    "ACCESS_TOKEN_EXPIRE_SECONDS": 86400,  # 1 day
    "REFRESH_TOKEN_EXPIRE_SECONDS": 604800,  # 1 week
}
OAUTH2_PROVIDER_APPLICATION_MODEL = "oauth2_provider.Application"
OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL = "oauth2_provider.AccessToken"

OAUTH2_TOKEN_SESSION_TIMEOUT_SECONDS = OAUTH2_PROVIDER["ACCESS_TOKEN_EXPIRE_SECONDS"]

API_DOCS_EXCLUDED_SCOPES = ["rw:issuer:*", "r:assertions", "rw:serverAdmin", "*"]


BADGR_PUBLIC_BOT_USERAGENTS = [
    # 'LinkedInBot/1.0 (compatible; Mozilla/5.0; Jakarta Commons-HttpClient/3.1 +http://www.linkedin.com)'
    "LinkedInBot",
    "Twitterbot",  # 'Twitterbot/1.0'
    "facebook",  # https://developers.facebook.com/docs/sharing/webmasters/crawler
    "Facebot",
    "Slackbot",
    "Embedly",
]
BADGR_PUBLIC_BOT_USERAGENTS_WIDE = [
    "LinkedInBot",
    "Twitterbot",
    "facebook",
    "Facebot",
]


# default celery to always_eager
CELERY_ALWAYS_EAGER = True

# Feature options
GDPR_COMPLIANCE_NOTIFY_ON_FIRST_AWARD = (
    True  # Notify recipients of first award on server even if issuer didn't opt to.
)
BADGR_APPROVED_ISSUERS_ONLY = False

# Email footer operator information
GDPR_INFO_URL = None
OPERATOR_STREET_ADDRESS = None
OPERATOR_NAME = None
OPERATOR_URL = None

# OVERRIDE THESE VALUES WITH YOUR OWN STABLE VALUES IN LOCAL SETTINGS
AUTHCODE_SECRET_KEY = Fernet.generate_key()

AUTHCODE_EXPIRES_SECONDS = (
    600  # needs to be long enough to fetch information from socialauth providers
)

# SAML Settings
SAML_EMAIL_KEYS = [
    "Email",
    "email",
    "mail",
    "emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
]
SAML_FIRST_NAME_KEYS = [
    "FirstName",
    "givenName",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
]
SAML_LAST_NAME_KEYS = [
    "LastName",
    "sn",
    "surname",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
]

# SVG to PNG Image Preview Generation Settings
# You may use an HTTP service to convert SVG images to PNG for higher reliability than the built-in Python option.
SVG_HTTP_CONVERSION_ENABLED = False
SVG_HTTP_CONVERSION_ENDPOINT = (
    ""  # Include scheme, e.g. 'http://example.com/convert-to-png'
)

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# OIDC Global settings
OIDC_RP_CLIENT_ID = ""
OIDC_RP_CLIENT_SECRET = ""
OIDC_OP_AUTHORIZATION_ENDPOINT = ""
OIDC_OP_TOKEN_ENDPOINT = ""
OIDC_OP_USER_ENDPOINT = ""
OIDC_OP_JWKS_ENDPOINT = ""
OIDC_OP_END_SESSION_ENDPOINT = ""
# The document specifies nbp-enmeshed-address to also be an option, but at least in the demo it doesn't work
# OIDC_RP_SCOPES = 'openid nbp-enmeshed-address'
OIDC_RP_SCOPES = "openid"
OIDC_RP_SIGN_ALGO = "RS256"
OIDC_USERNAME_ALGO = "badgeuser.utils.generate_badgr_username"
OIDC_USE_PKCE = True
# We store the access and refresh tokens because we use them
# for authentication
OIDC_STORE_ACCESS_TOKEN = True
OIDC_STORE_REFRESH_TOKEN = True
# TODO: Maybe we want to store the ID token and use it to prevent
# prompts in the logout sequence
OIDC_STORE_ID_TOKEN = False

# Make the Django session expire after 1 minute, so that the UI has 1 minute to convert the session authentication
# into an access token
SESSION_COOKIE_AGE = 60

ALTCHA_SECRET = ""
ALTCHA_MINNUMBER = 10000
ALTCHA_MAXNUMBER = 100000

# CMS contents
CMS_API_BASE_URL = ""
CMS_API_BASE_PATH = ""
CMS_API_KEY = ""

# path to webcomponents assets build in badgr-ui
WEBCOMPONENTS_ASSETS_PATH = "/"

MJML_BACKEND_MODE = "cmd"
# make sure to not load any fonts automatically
MJML_EXEC_CMD = ["mjml", "--config.fonts", "{}"]
# MJML_CHECK_CMD_ON_STARTUP = False
