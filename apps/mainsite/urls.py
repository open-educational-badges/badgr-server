from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.generic.base import RedirectView, TemplateView
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)
from apps.mainsite.views_iframes import iframe
from mainsite.views import (
    AdminIssuer,
    AdminUser,
    badgeRequestsByBadgeClass,
    downloadQrCode,
    public_assertion_pdf,
    upload,
    nounproject,
    aiskills,
    aiskills_keywords,
    requestBadge,
    deleteBadgeRequest,
    createCaptchaChallenge,
    getTimestamp,
)
from mainsite.views import (
    info_view,
    email_unsubscribe,
    AppleAppSiteAssociation,
    error404,
    error500,
)
from mainsite.views import (
    SitewideActionFormView,
    RedirectToUiLogin,
    DocsAuthorizeRedirect,
    LegacyLoginAndObtainAuthToken,
)

from mainsite.views import (
    cms_api_menu_list,
    cms_api_page_details,
    cms_api_post_details,
    cms_api_post_list,
    cms_api_style,
    cms_api_script,
    call_cms_api,
)

from mainsite.views_lti import (
    ApplicationLaunchView,
    LtiBackpack,
    LtiBadgeCreateOrEdit,
    LtiBadges,
    LtiCompetencies,
    LtiLearningpaths,
    LtiProfile,
    XFrameExemptOIDCLoginInitView,
)

from django.apps import apps
from django.conf import settings
from django.urls import include, re_path
from django.urls import path

from mainsite.admin import badgr_admin
from backpack.badge_connect_api import (
    BadgeConnectManifestView,
    BadgeConnectManifestRedirectView,
)
from mainsite.oauth2_api import (
    AuthorizationApiView,
    TokenView,
    RevokeTokenView,
    AuthCodeExchange,
    RegisterApiView,
    PublicRegisterApiView,
)
from oidc.oidc_views import OidcView

from lti_tool.views import jwks

badgr_admin.autodiscover()
# make sure that any view/model/form imports occur AFTER admin.autodiscover


def django2_include(three_tuple_urlconf):
    (urls, app_name, namespace) = three_tuple_urlconf
    return include((urls, app_name), namespace=namespace)


urlpatterns = [
    # Backup URLs in case the server isn't serving these directly
    re_path(
        r"^favicon\.png[/]?$",
        RedirectView.as_view(
            url="%simages/favicon.png" % settings.STATIC_URL, permanent=True
        ),
    ),
    re_path(
        r"^favicon\.ico[/]?$",
        RedirectView.as_view(
            url="%simages/favicon.png" % settings.STATIC_URL, permanent=True
        ),
    ),
    re_path(
        r"^robots\.txt$",
        RedirectView.as_view(url="%srobots.txt" % settings.STATIC_URL, permanent=True),
    ),
    # legacy logo url redirect
    re_path(
        r"^static/images/header-logo-120.png$",
        RedirectView.as_view(
            url="{}images/logo.png".format(settings.STATIC_URL), permanent=True
        ),
    ),
    # Apple app universal URL endpoint
    re_path(
        r"^apple-app-site-association",
        AppleAppSiteAssociation.as_view(),
        name="apple-app-site-association",
    ),
    # OAuth2 provider URLs
    re_path(
        r"^o/authorize/?$", AuthorizationApiView.as_view(), name="oauth2_api_authorize"
    ),
    re_path(
        r"^o/token/?$",
        ensure_csrf_cookie(TokenView.as_view()),
        name="oauth2_provider_token",
    ),
    re_path(
        r"^o/revoke_token/?$",
        RevokeTokenView.as_view(),
        name="oauth2_provider_revoke_token",
    ),
    re_path(r"^o/code/?$", AuthCodeExchange.as_view(), name="oauth2_code_exchange"),
    re_path(
        r"^o/register/?$",
        RegisterApiView.as_view(),
        kwargs={"version": "rfc7591"},
        name="oauth2_api_register",
    ),
    re_path(
        r"^o/publicregister/?$",
        PublicRegisterApiView.as_view(),
        kwargs={"version": "rfc7591"},
        name="oauth2_public_api_register",
    ),
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    # Badge Connect URLs
    re_path(
        r"^bcv1/manifest/(?P<domain>[^/]+)$",
        BadgeConnectManifestView.as_view(),
        name="badge_connect_manifest",
    ),
    re_path(
        r"^\.well-known/badgeconnect.json$",
        BadgeConnectManifestRedirectView.as_view(),
        name="default_bc_manifest_redirect",
    ),
    re_path(
        r"^bcv1/", include("backpack.badge_connect_urls"), kwargs={"version": "bcv1"}
    ),
    # Home
    re_path(r"^$", info_view, name="index"),
    re_path(
        r"^accounts/login/$", RedirectToUiLogin.as_view(), name="legacy_login_redirect"
    ),
    # Admin URLs
    re_path(
        r"^staff/sidewide-actions$",
        SitewideActionFormView.as_view(),
        name="badgr_admin_sitewide_actions",
    ),
    re_path(r"^staff/", django2_include(badgr_admin.urls)),
    # Service health endpoint
    re_path(r"^health", include("health.urls")),
    # Swagger Docs
    #
    # api docs
    #
    # OpenAPI schema endpoint
    re_path(r"^api/schema/$", SpectacularAPIView.as_view(), name="schema"),
    # OAuth2 authorize redirect for docs
    re_path(
        r"^docs/oauth2/authorize$",
        DocsAuthorizeRedirect.as_view(),
        name="docs_authorize_redirect",
    ),
    # Swagger UI for v2 docs
    re_path(
        r"^docs/v2/$",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui-v2",
    ),
    re_path(r"^redoc/$", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    # Default redirect to v2 docs
    re_path(r"^docs/?$", RedirectView.as_view(url="/docs/v2/", permanent=True)),
    # unversioned public endpoints
    re_path(
        r"^unsubscribe/(?P<email_encoded>[^/]+)/(?P<expiration>[^/]+)/(?P<signature>[^/]+)",
        email_unsubscribe,
        name="unsubscribe",
    ),
    re_path(r"^public/", include("issuer.public_api_urls"), kwargs={"version": "v2"}),
    # legacy share redirects
    re_path(r"", include("backpack.share_urls")),
    # Legacy Auth Token Endpoint: Deprecated and logged
    re_path(r"^api-auth/token$", LegacyLoginAndObtainAuthToken.as_view()),
    # Social Auth (oAuth2 and SAML)
    re_path(r"^account/", include("badgrsocialauth.urls")),
    # v1 API endpoints
    re_path(r"^v1/user/", include("badgeuser.v1_api_urls"), kwargs={"version": "v1"}),
    re_path(
        r"^v1/user/", include("badgrsocialauth.v1_api_urls"), kwargs={"version": "v1"}
    ),
    re_path(r"^v1/issuer/", include("issuer.v1_api_urls"), kwargs={"version": "v1"}),
    re_path(r"^v1/earner/", include("backpack.v1_api_urls"), kwargs={"version": "v1"}),
    # v2 API endpoints
    re_path(r"^v2/", include("issuer.v2_api_urls"), kwargs={"version": "v2"}),
    re_path(r"^v2/", include("badgeuser.v2_api_urls"), kwargs={"version": "v2"}),
    re_path(r"^v2/", include("badgrsocialauth.v2_api_urls"), kwargs={"version": "v2"}),
    re_path(
        r"^v2/backpack/", include("backpack.v2_api_urls"), kwargs={"version": "v2"}
    ),
    re_path(r"^upload", upload, name="image_upload"),
    re_path(
        r"^nounproject/(?P<searchterm>[^/]+)/(?P<page>[^/]+)$",
        nounproject,
        name="nounproject",
    ),
    re_path(r"^aiskills/$", aiskills, name="aiskills"),
    re_path(r"^aiskills-keywords/$", aiskills_keywords, name="aiskills_keywords"),
    re_path(r"^request-badge/(?P<qrCodeId>[^/]+)$", requestBadge, name="request-badge"),
    re_path(r"^get-server-timestamp", getTimestamp, name="get-server-timestamp"),
    re_path(
        r"^deleteBadgeRequest/(?P<requestId>[^/]+)$",
        deleteBadgeRequest,
        name="delete-badge-request",
    ),
    re_path(
        r"^download-qrcode/(?P<qrCodeId>[^/]+)/(?P<badgeSlug>[^/]+)$",
        downloadQrCode,
        name="download-qrcode",
    ),
    re_path(
        r"^assertions/(?P<entity_id>[^/]+/pdf)",
        public_assertion_pdf,
        name="assertion-pdf",
    ),
    re_path(
        r"^badgeRequests/(?P<badgeSlug>[^/]+)$",
        badgeRequestsByBadgeClass,
        name="badge-requests-by-badgeclass",
    ),
    re_path(r"^v3/", include("issuer.v3_api_urls"), kwargs={"version": "v3"}),
    re_path(
        r"^v3/backpack/", include("backpack.v3_api_urls"), kwargs={"version": "v3"}
    ),
    re_path(r"^v3/issuer/", include("issuer.v3_api_urls"), kwargs={"version": "v3"}),
    re_path(r"^v3/user/", include("badgeuser.v3_api_urls"), kwargs={"version": "v3"}),
    re_path(r"^v3/admin/users", AdminUser.as_view({"get": "list"})),
    re_path(r"^v3/admin/issuers", AdminIssuer.as_view({"get": "list"})),
    # meinBildungsraum OIDC connection
    path("oidc/", include("mozilla_django_oidc.urls")),
    re_path(
        r"^oidcview/logoutRedirect/",
        OidcView.oidcLogoutRedirect,
        name="oidcLogoutRedirect",
    ),
    re_path(r"^altcha", createCaptchaChallenge, name="create_captcha_challenge"),
    re_path(r"^cms/menu/list/?$", cms_api_menu_list, name="cms_api_menu_list"),
    re_path(r"^cms/post/list/?$", cms_api_post_list, name="cms_api_post_list"),
    re_path(r"^cms/page/slug/?$", cms_api_page_details, name="cms_api_page_details"),
    re_path(r"^cms/post/slug/?$", cms_api_post_details, name="cms_api_post_details"),
    re_path(r"^cms/style/?$", cms_api_style, name="cms_api_style"),
    re_path(r"^cms/script/?$", cms_api_script, name="cms_api_script"),
    re_path(r"^cms/(?P<path>.+)$", call_cms_api, name="call_cms_api"),
    # iframes
    path("iframes/<uuid:iframe_uuid>/", iframe, name="iframe"),
    # LTI
    path(".well-known/jwks.json", jwks, name="jwks"),
    path(
        "lti/<uuid:registration_uuid>/",
        XFrameExemptOIDCLoginInitView.as_view(),
        name="init",
    ),
    path("lti/launch/", ApplicationLaunchView.as_view()),
    path("lti/tools/profile/", LtiProfile),
    path("lti/tools/badges/", LtiBadges),
    path("lti/tools/competencies/", LtiCompetencies),
    path("lti/tools/learningpaths/", LtiLearningpaths),
    path("lti/tools/backpack/", LtiBackpack),
    path("lti/tools/badge-create-or-edit/", LtiBadgeCreateOrEdit),
    # Prometheus endpoint
    path("", include("django_prometheus.urls")),
]
# add to serve files
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Test URLs to allow you to see these pages while DEBUG is True
if getattr(settings, "DEBUG_ERRORS", False):
    urlpatterns = [
        re_path(r"^error/404/$", error404, name="404"),
        re_path(r"^error/500/$", error500, name="500"),
    ] + urlpatterns

# If DEBUG_MEDIA is set, have django serve anything in MEDIA_ROOT at MEDIA_URL
if getattr(settings, "DEBUG_MEDIA", True):
    from django.views.static import serve as static_serve

    media_url = getattr(settings, "MEDIA_URL", "/media/").lstrip("/")
    urlpatterns = [
        re_path(
            r"^media/(?P<path>.*)$",
            static_serve,
            {"document_root": settings.MEDIA_ROOT},
        ),
    ] + urlpatterns

# If DEBUG_STATIC is set, have django serve up static files even if DEBUG=False
if getattr(settings, "DEBUG_STATIC", True):
    from django.contrib.staticfiles.views import serve as staticfiles_serve

    static_url = getattr(settings, "STATIC_URL", "/static/")
    static_url = static_url.replace(
        getattr(settings, "HTTP_ORIGIN", "http://localhost:8000"), ""
    )
    static_url = static_url.lstrip("/")
    urlpatterns = [
        re_path(
            r"^%s(?P<path>.*)" % (static_url,),
            staticfiles_serve,
            kwargs={
                "insecure": True,
            },
        )
    ] + urlpatterns

# Serve pattern library view only in debug mode or if explicitly declared
if getattr(settings, "DEBUG", True) or getattr(
    settings, "SERVE_PATTERN_LIBRARY", False
):
    urlpatterns = [
        re_path(
            r"^component-library$",
            TemplateView.as_view(template_name="component-library.html"),
            name="component-library",
        )
    ] + urlpatterns

# serve django debug toolbar if present
if settings.DEBUG and apps.is_installed("debug_toolbar"):
    try:
        import debug_toolbar

        urlpatterns = urlpatterns + [
            re_path(r"^__debug__/", include(debug_toolbar.urls)),
        ]
    except ImportError:
        pass

handler404 = error404
handler500 = error500
