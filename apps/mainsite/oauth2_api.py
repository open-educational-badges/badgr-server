# encoding: utf-8

import base64
import requests
import json
import re
import uuid
from urllib.parse import urlparse
import datetime
import jwt

from django.core.cache import cache
from django.core.files.storage import default_storage
from django.conf import settings
from django.core.validators import URLValidator
from django.http import HttpResponse
from django.utils import timezone
from django.contrib.auth import logout
from django.contrib.auth.hashers import check_password
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.models import (
    get_application_model,
    get_access_token_model,
    Application,
    AccessToken,
)
from oauth2_provider.scopes import get_scopes_backend
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views import TokenView as OAuth2ProviderTokenView
from oauth2_provider.views import RevokeTokenView as OAuth2ProviderRevokeTokenView
from oauth2_provider.views.mixins import OAuthLibMixin
from oauth2_provider.signals import app_authorized
from oauthlib.oauth2.rfc6749.utils import scope_to_list
from rest_framework import serializers, permissions
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
)
from rest_framework.views import APIView

from badgeuser.authcode import accesstoken_for_authcode
from backpack.badge_connect_api import BADGE_CONNECT_SCOPES
from mainsite.models import ApplicationInfo
from mainsite.oauth_validator import BadgrRequestValidator, BadgrOauthServer
from mainsite.serializers import ApplicationInfoSerializer, AuthorizationSerializer
from mainsite.utils import (
    fetch_remote_file_to_storage,
    throttleable,
    set_url_query_params,
)
from drf_spectacular.utils import extend_schema, extend_schema_field
from drf_spectacular.types import OpenApiTypes
import logging

logger = logging.getLogger("Badgr.Events")


@extend_schema(exclude=True)
class AuthorizationApiView(OAuthLibMixin, APIView):
    permission_classes = []

    server_class = oauth2_settings.OAUTH2_SERVER_CLASS
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    oauthlib_backend_class = oauth2_settings.OAUTH2_BACKEND_CLASS

    skip_authorization_completely = False

    def get_authorization_redirect_url(self, scopes, credentials, allow=True):
        uri, headers, body, status = self.create_authorization_response(
            request=self.request, scopes=scopes, credentials=credentials, allow=allow
        )
        return set_url_query_params(uri, **{"scope": scopes})

    def post(self, request, *args, **kwargs):
        if not self.request.user.is_authenticated:
            return Response(
                {"error": "Incorrect authentication credentials."},
                status=HTTP_401_UNAUTHORIZED,
            )

        # Copy/Pasta'd from oauth2_provider.views.BaseAuthorizationView.form_valid
        try:
            serializer = AuthorizationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            credentials = {
                "client_id": serializer.data.get("client_id"),
                "redirect_uri": serializer.data.get("redirect_uri"),
                "response_type": serializer.data.get("response_type", None),
                "state": serializer.data.get("state", None),
            }
            if serializer.data.get("code_challenge", False):
                credentials["code_challenge"] = serializer.data.get("code_challenge")
                credentials["code_challenge_method"] = serializer.data.get(
                    "code_challenge_method", "S256"
                )

            if serializer.data.get("scopes"):
                scopes = " ".join(serializer.data.get("scopes"))
            else:
                scopes = serializer.data.get("scope")
            allow = serializer.data.get("allow")

            success_url = self.get_authorization_redirect_url(
                scopes, credentials, allow
            )
            return Response({"success_url": success_url})

        except OAuthToolkitError as error:
            return Response(
                {"error": error.oauthlib_error.description}, status=HTTP_400_BAD_REQUEST
            )

    def get(self, request, *args, **kwargs):
        application = None
        request.query_params.get("client_id")
        # Copy/Pasta'd from oauth2_provider.views.BaseAuthorizationView.get
        try:
            scopes, credentials = self.validate_authorization_request(request)
            # all_scopes = get_scopes_backend().get_all_scopes()
            # kwargs["scopes"] = scopes
            # kwargs["scopes_descriptions"] = [all_scopes[scope] for scope in scopes]
            # at this point we know an Application instance with such client_id exists in the database

            # TODO: Cache this!
            application = get_application_model().objects.get(
                client_id=credentials["client_id"]
            )

            kwargs["client_id"] = credentials["client_id"]
            kwargs["redirect_uri"] = credentials["redirect_uri"]
            kwargs["response_type"] = credentials["response_type"]
            kwargs["state"] = credentials["state"]
            try:
                application_info = ApplicationInfoSerializer(
                    application.applicationinfo
                )
                kwargs["application"] = application_info.data
                app_scopes = [
                    s
                    for s in re.split(
                        r"[\s\n]+", application.applicationinfo.allowed_scopes
                    )
                    if s
                ]
            except ApplicationInfo.DoesNotExist:
                app_scopes = ["r:profile"]
                kwargs["application"] = dict(name=application.name)

            filtered_scopes = set(app_scopes) & set(scopes)
            kwargs["scopes"] = list(filtered_scopes)
            all_scopes = get_scopes_backend().get_all_scopes()
            kwargs["scopes_descriptions"] = {
                scope: all_scopes[scope] for scope in scopes
            }

            self.oauth2_data = kwargs

            # Check to see if the user has already granted access and return
            # a successful response depending on "approval_prompt" url parameter
            require_approval = request.GET.get(
                "approval_prompt", oauth2_settings.REQUEST_APPROVAL_PROMPT
            )

            # If skip_authorization field is True, skip the authorization screen even
            # if this is the first use of the application and there was no previous authorization.
            # This is useful for in-house applications-> assume an in-house applications
            # are already approved.
            if application.skip_authorization and not request.user.is_anonymous:
                success_url = self.get_authorization_redirect_url(
                    " ".join(kwargs["scopes"]), credentials
                )
                return Response({"success_url": success_url})

            elif require_approval == "auto" and not request.user.is_anonymous:
                tokens = (
                    get_access_token_model()
                    .objects.filter(
                        user=request.user,
                        application=application,
                        expires__gt=timezone.now(),
                    )
                    .all()
                )

                # check past authorizations regarded the same scopes as the current one
                for token in tokens:
                    if token.allow_scopes(scopes):
                        success_url = self.get_authorization_redirect_url(
                            " ".join(kwargs["scopes"]), credentials
                        )
                        return Response({"success_url": success_url})

            return Response(kwargs)

        except OAuthToolkitError as error:
            return Response(
                {"error": error.oauthlib_error.description}, status=HTTP_400_BAD_REQUEST
            )


httpsUrlValidator = URLValidator(message="Must be a valid HTTPS URI", schemes=["https"])


class RegistrationSerializer(serializers.Serializer):
    client_name = serializers.CharField(required=True, source="name")
    client_uri = serializers.URLField(
        required=True,
        source="applicationinfo.website_url",
        validators=[httpsUrlValidator],
    )
    logo_uri = serializers.URLField(
        required=True, source="applicationinfo.logo_uri", validators=[httpsUrlValidator]
    )
    tos_uri = serializers.URLField(
        required=True,
        source="applicationinfo.terms_uri",
        validators=[httpsUrlValidator],
    )
    policy_uri = serializers.URLField(
        required=True,
        source="applicationinfo.policy_uri",
        validators=[httpsUrlValidator],
    )
    software_id = serializers.CharField(
        required=True, source="applicationinfo.software_id"
    )
    software_version = serializers.CharField(
        required=True, source="applicationinfo.software_version"
    )
    redirect_uris = serializers.ListField(
        child=serializers.URLField(validators=[httpsUrlValidator]), required=True
    )
    token_endpoint_auth_method = serializers.CharField(
        required=False, default="client_secret_basic"
    )
    grant_types = serializers.ListField(
        child=serializers.CharField(), required=False, default=["authorization_code"]
    )
    response_types = serializers.ListField(
        child=serializers.CharField(), required=False, default=["code"]
    )
    scope = serializers.CharField(
        required=False,
        source="applicationinfo.allowed_scopes",
        default=" ".join(BADGE_CONNECT_SCOPES),
    )

    client_id = serializers.CharField(read_only=True)
    client_secret = serializers.CharField(read_only=True)
    client_id_issued_at = serializers.SerializerMethodField(read_only=True)
    client_secret_expires_at = serializers.IntegerField(default=0, read_only=True)

    def get_client_id_issued_at(self, obj):
        try:
            return int(obj.created.strftime("%s"))
        except AttributeError:
            return None

    def validate_grant_types(self, val):
        if "authorization_code" not in val:
            raise serializers.ValidationError("Missing authorization_code grant type")

        for grant_type in val:
            if grant_type not in ["authorization_code", "refresh_token"]:
                raise serializers.ValidationError(
                    "Invalid grant types. Only authorization_code and refresh_token supported"
                )
        return val

    def validate_response_types(self, val):
        if val != ["code"]:
            raise serializers.ValidationError("Invalid response type")
        return val

    def validate_scope(self, val):
        if val:
            scopes = val.split(" ")
            included = []
            for scope in scopes:
                if scope in BADGE_CONNECT_SCOPES:
                    included.append(scope)

            if len(included):
                return " ".join(set(included))
            raise serializers.ValidationError(
                "No supported Badge Connect scopes requested. See manifest for supported scopes."
            )

        else:
            # If no scopes provided, we assume they want all scopes
            return " ".join(BADGE_CONNECT_SCOPES)

    def validate_token_endpoint_auth_method(self, val):
        if val != "client_secret_basic":
            raise serializers.ValidationError(
                "Invalid token authentication method. Only client_secret_basic allowed."
            )
        return val

    def validate(self, data):
        # app_model = get_application_model()
        # All domains in URIs must be HTTPS and match
        uris = set()
        schemes = set()

        def parse_uri(uri):
            parsed = urlparse(uri)
            uris.add(parsed.netloc)
            schemes.add(parsed.scheme)

        parse_uri(data["applicationinfo"]["website_url"])
        parse_uri(data["applicationinfo"]["logo_uri"])
        parse_uri(data["applicationinfo"]["terms_uri"])
        parse_uri(data["applicationinfo"]["policy_uri"])

        # if ApplicationInfo.objects.filter(website_url=data.get('client_uri')).exists():
        #     raise serializers.ValidationError("Client already registered")

        for redirect in data.get("redirect_uris"):
            # if app_model.objects.filter(redirect_uris__contains=redirect):
            #     raise serializers.ValidationError("Redirect URI already registered")
            parse_uri(redirect)
        if len(uris) > 1:
            raise serializers.ValidationError(
                "client_uri, logo_uri, tos_uri, policy_uri, redirect_uris do not match domain."
            )

        return data

    def fetch_and_process_logo_uri(self, logo_uri):
        return fetch_remote_file_to_storage(
            logo_uri,
            upload_to="remote/application",
            allowed_mime_types=["image/png", "image/svg+xml"],
            resize_to_height=512,
        )

    def create(self, validated_data):
        app_model = get_application_model()
        app = app_model.objects.create(
            name=validated_data["name"],
            redirect_uris=" ".join(validated_data["redirect_uris"]),
            authorization_grant_type=app_model.GRANT_AUTHORIZATION_CODE,
        )

        saved_logo_uri = ""
        if validated_data["applicationinfo"]["logo_uri"] is not None:
            logo_uri = validated_data["applicationinfo"]["logo_uri"]
            status_code, image = self.fetch_and_process_logo_uri(logo_uri)

        if status_code == 200:
            saved_logo_uri = getattr(settings, "HTTP_ORIGIN") + default_storage.url(
                image
            )

        app_info = ApplicationInfo(
            application=app,
            website_url=validated_data["applicationinfo"]["website_url"],
            logo_uri=saved_logo_uri,
            terms_uri=validated_data["applicationinfo"]["terms_uri"],
            policy_uri=validated_data["applicationinfo"]["policy_uri"],
            software_id=validated_data["applicationinfo"]["software_id"],
            software_version=validated_data["applicationinfo"]["software_version"],
            allowed_scopes=validated_data["applicationinfo"]["allowed_scopes"],
            issue_refresh_token="refresh_token" in validated_data.get("grant_types"),
        )

        app_info.save()

        return app

    def to_representation(self, instance):
        rep = super(RegistrationSerializer, self).to_representation(instance)
        if " " in instance.redirect_uris:
            rep["redirect_uris"] = " ".split(instance.redirect_uris)
        else:
            rep["redirect_uris"] = [instance.redirect_uris]
        return rep


@extend_schema(exclude=True)
class RegisterApiView(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=HTTP_201_CREATED)


# this method allows users that are authorized (but do not have to be admins) to register client credentials for their account, currently the user can only choose the name
class PublicRegistrationSerializer(serializers.Serializer):
    client_name = serializers.CharField(required=True, source="name")
    grant_types = serializers.ListField(
        child=serializers.CharField(), required=False, default=["client-credentials"]
    )
    response_types = serializers.ListField(
        child=serializers.CharField(), required=False, default=["code"]
    )
    scope = serializers.CharField(
        required=False,
        source="applicationinfo.allowed_scopes",
        default="rw:issuer rw:backpack rw:profile",
    )

    client_id = serializers.CharField(read_only=True)
    client_secret = serializers.CharField(read_only=True)
    client_id_issued_at = serializers.SerializerMethodField(read_only=True)
    client_secret_expires_at = serializers.IntegerField(default=0, read_only=True)

    @extend_schema_field(OpenApiTypes.INT)
    def get_client_id_issued_at(self, obj):
        try:
            return int(obj.created.strftime("%s"))
        except AttributeError:
            return None

    def validate_response_types(self, val):
        if val != ["code"]:
            raise serializers.ValidationError("Invalid response type")
        return val

    def validate_scope(self, val):
        if val:
            scopes = val.split(" ")
            included = []
            for scope in scopes:
                if scope in ["rw:issuer", "rw:backpack", "rw:profile"]:
                    included.append(scope)

            if len(included):
                return " ".join(set(included))
            raise serializers.ValidationError(
                "No supported Badge Connect scopes requested. See manifest for supported scopes."
            )

        else:
            # If no scopes provided, we assume they want all scopes
            return " ".join(BADGE_CONNECT_SCOPES)

    def validate_token_endpoint_auth_method(self, val):
        if val != "client_secret_basic":
            raise serializers.ValidationError(
                "Invalid token authentication method. Only client_secret_basic allowed."
            )
        return val

    def create(self, validated_data):
        app_model = get_application_model()
        user = self.context["request"].user
        app = app_model(
            name=validated_data["name"],
            user=user,
            authorization_grant_type=app_model.GRANT_CLIENT_CREDENTIALS,
            client_type=Application.CLIENT_CONFIDENTIAL,
        )
        # the client_secret is hashed once saved, to return it
        # it has to be stored here
        cleartext_client_secret = app.client_secret
        app.save()
        app_info = ApplicationInfo(
            application=app,
            allowed_scopes=validated_data["applicationinfo"]["allowed_scopes"],
            issue_refresh_token="refresh_token" in validated_data.get("grant_types"),
        )
        app_info.save()

        # rewrite client_secret (see above)
        app.client_secret = cleartext_client_secret

        return app

    def to_representation(self, instance):
        rep = super(PublicRegistrationSerializer, self).to_representation(instance)
        if " " in instance.redirect_uris:
            rep["redirect_uris"] = " ".split(instance.redirect_uris)
        else:
            rep["redirect_uris"] = [instance.redirect_uris]
        return rep


class PublicRegisterApiView(APIView):
    permission_classes = []
    permission_classes = (permissions.IsAuthenticated,)

    @extend_schema(exclude=True)
    def post(self, request, **kwargs):
        serializer = PublicRegistrationSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=HTTP_201_CREATED)


def extract_oidc_access_token(request, scope):
    """
    Extracts the OIDC access token from the request

    The scope is merely used for compatibility reasons;
    Actually OIDC access tokens always have acess to all scopes.
    """
    joined_scope = " ".join(scope)
    access_token = request.session["oidc_access_token"]
    refresh_token = request.session["oidc_refresh_token"]
    return build_token(
        access_token, get_expire_seconds(access_token), joined_scope, refresh_token
    )


def build_token(access_token, expires_in, scope, refresh_token):
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": scope,
        "refresh_token": refresh_token,
    }


def extract_oidc_refresh_token(request):
    """
    Extracts the OIDC refresh token from the request
    """
    if "refresh_token" in request.POST:
        return request.POST.get("refresh_token")
    return request.COOKIES["refresh_token"]


def request_renewed_oidc_access_token(self, refresh_token):
    token_refresh_payload = {
        "refresh_token": refresh_token,
        "client_id": getattr(settings, "OIDC_RP_CLIENT_ID"),
        "client_secret": getattr(settings, "OIDC_RP_CLIENT_SECRET"),
        "grant_type": "refresh_token",
    }

    try:
        response = requests.post(
            getattr(settings, "OIDC_OP_TOKEN_ENDPOINT"), data=token_refresh_payload
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error("Failed to refresh session: '%s'", e)
        return None
    return response.json()


def get_expire_seconds(access_token):
    """
    Calculates how many more seconds the access token will be valid

    It first extracts the datetime (skipping signature verifications)
    and then calculates the diff to the current datetime
    """
    expire_datetime = datetime.datetime.fromtimestamp(
        jwt.decode(access_token, options={"verify_signature": False})["exp"]
    )
    now_datetime = datetime.datetime.now()
    diff = expire_datetime - now_datetime
    return diff.total_seconds()


def setTokenHttpOnly(response):
    data = json.loads(response.content.decode("utf-8"))
    # Add tokens as cookies
    if "access_token" in data:
        response.set_cookie(
            "access_token",
            value=data["access_token"],
            httponly=True,
            secure=not settings.DEBUG,
            max_age=data["expires_in"],
        )
        # Remove access token from body
        # FIXME: keep for old clients
        # del data['access_token']
    if "refresh_token" in data:
        response.set_cookie(
            "refresh_token",
            value=data["refresh_token"],
            httponly=True,
            secure=not settings.DEBUG,
            # Refresh tokens have the same max
            # age as access tokens, since they
            # should get renewed together with
            # the access token. This is only
            # relevant for OIDC which I can't
            # test right now, so change it if
            # needed.
            max_age=data["expires_in"],
        )
        # Remove refresh token from body
        # FIXME: keep for old clients
        # del data['refresh_token']
    response.content = json.dumps(data)
    return


class RevokeTokenView(OAuth2ProviderRevokeTokenView):
    def post(self, request, *args, **kwargs):
        if "access_token" not in request.COOKIES:
            return HttpResponse(
                json.dumps({"error": "Access token must be contained in COOKIE"}),
                status=HTTP_400_BAD_REQUEST,
            )
        else:
            # Add the access token to the request, as if it had always been there,
            # since the oauth toolkit can't handle the access token in the cookie
            access_token = request.COOKIES["access_token"]
            body = request.body.decode("utf-8")
            body = f"token={access_token}&{body}"
            request._body = str.encode(body)

            request.POST._mutable = True
            request.POST["token"] = [access_token]
            request.POST._mutable = False

            request.META["CONTENT_LENGTH"] = str(len(request.body))

        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            # For some reason, (this version) does not actually delete / revoke the tokens.
            # So I delete them manually, as long as the parent said everything's fine.
            token_objects = AccessToken.objects.filter(
                token=request.POST["token"][0]
                if type(request.POST["token"]) is list
                else request.POST["token"]
            )
            token_objects.delete()
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response


class TokenView(OAuth2ProviderTokenView):
    server_class = BadgrOauthServer
    validator_class = BadgrRequestValidator

    @throttleable
    def post(self, request, *args, **kwargs):
        if len(request.GET):
            return HttpResponse(
                json.dumps(
                    {
                        "error": "Token grant parameters must be sent in post body, not query parameters"
                    }
                ),
                status=HTTP_400_BAD_REQUEST,
            )

        grant_type = request.POST.get("grant_type", "password")
        username = request.POST.get("username")
        client_id = None

        try:
            auth_header = request.META["HTTP_AUTHORIZATION"]
            credentials = auth_header.split(" ")
            if credentials[0] == "Basic":
                client_id, client_secret = (
                    base64.b64decode(credentials[1].encode("ascii"))
                    .decode("ascii")
                    .split(":")
                )
        except (KeyError, IndexError, ValueError, TypeError):
            client_id = request.POST.get("client_id", None)
            client_secret = None

        # pre-validate scopes requested

        requested_scopes = [
            s for s in scope_to_list(request.POST.get("scope", "")) if s
        ]
        oauth_app = None
        if client_id:
            try:
                oauth_app = Application.objects.get(client_id=client_id)
                if client_secret and not check_password(
                    client_secret, oauth_app.client_secret
                ):
                    return HttpResponse(
                        json.dumps({"error": "invalid client_secret"}),
                        status=HTTP_400_BAD_REQUEST,
                    )
            except Application.DoesNotExist:
                return HttpResponse(
                    json.dumps({"error": "invalid client_id"}),
                    status=HTTP_400_BAD_REQUEST,
                )

            try:
                allowed_scopes = oauth_app.applicationinfo.scope_list
            except ApplicationInfo.DoesNotExist:
                allowed_scopes = ["r:profile"]

            # handle rw:issuer:* scopes
            if "rw:issuer:*" in allowed_scopes:
                issuer_scopes = [
                    x for x in requested_scopes if x.startswith(r"rw:issuer:")
                ]
                allowed_scopes.extend(issuer_scopes)

            filtered_scopes = set(allowed_scopes) & set(requested_scopes)
            if len(filtered_scopes) < len(requested_scopes):
                return HttpResponse(
                    json.dumps({"error": "invalid scope requested"}),
                    status=HTTP_400_BAD_REQUEST,
                )

        response = None
        if grant_type == "oidc":
            if not request.user.is_authenticated:
                return HttpResponse(
                    json.dumps({"error": "User not authenticated in session!"}),
                    status=HTTP_401_UNAUTHORIZED,
                )
            token = extract_oidc_access_token(request, requested_scopes)
            app_authorized.send(
                sender=self, request=request, token=token.get("access_token")
            )
            response = HttpResponse(content=json.dumps(token), status=200)
            # Log out of the django session, since from now on we use token authentication; the session authentication was
            # only used to obtain the access token
            logout(request)
        elif grant_type == "refresh_token":
            # Refreshes OIDC access tokens.
            # Normal access tokens don't need to be refreshed,
            # since they are valid for 24h
            refresh_token = extract_oidc_refresh_token(request)
            token = request_renewed_oidc_access_token(self, refresh_token)
            if token is None:
                return HttpResponse(
                    json.dumps({"error": "Token refresh failed!"}),
                    status=HTTP_401_UNAUTHORIZED,
                )
            # Adding the scope for compatibility reasons, even though OIDC access tokens
            # have access to everything
            token["scope"] = requested_scopes
            response = HttpResponse(content=json.dumps(token), status=200)
        else:
            # All other grant types our parent can handle
            response = super(TokenView, self).post(request, *args, **kwargs)

        # 2FA interception: if password login succeeded and user has TOTP enabled,
        # revoke the issued token and return a short-lived partial token instead.
        if grant_type == "password" and response.status_code == 200:
            try:
                response_data = json.loads(response.content)
                access_token_value = response_data.get("access_token")
                if access_token_value:
                    token_obj = AccessToken.objects.select_related("user").get(
                        token=access_token_value
                    )
                    user = token_obj.user
                    if user.totp_enabled and user.totp_confirmed:
                        partial = str(uuid.uuid4())
                        cache_key = f"2fa_partial:{partial}"
                        cache.set(
                            cache_key,
                            {
                                "user_id": user.pk,
                                "client_id": client_id or "public",
                                "scope": request.POST.get(
                                    "scope", "rw:profile rw:issuer rw:backpack"
                                ),
                            },
                            timeout=300,
                        )
                        try:
                            token_obj.delete()
                        except Exception:
                            cache.delete(cache_key)
                            logger.exception(
                                "Failed to revoke access token during 2FA interception "
                                "for user %s; falling back to normal login",
                                user.pk,
                            )
                        else:
                            return HttpResponse(
                                json.dumps(
                                    {"requires_2fa": True, "partial_token": partial}
                                ),
                                status=401,
                                content_type="application/json",
                            )
            except (AccessToken.DoesNotExist, KeyError, ValueError):
                pass

        if oauth_app and not oauth_app.applicationinfo.issue_refresh_token:
            data = json.loads(response.content)
            try:
                del data["refresh_token"]
            except KeyError:
                pass
            response.content = json.dumps(data)

        if grant_type == "password" and response.status_code == 401:
            logger.info(
                "Failed login attempt from '%s' (response code: %s)",
                username,
                response.status_code,
            )

        if response.status_code == 200:
            setTokenHttpOnly(response)

        return response


@extend_schema(exclude=True)
class AuthCodeExchange(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        def _error_response():
            return Response({"error": "Invalid authcode"}, status=HTTP_400_BAD_REQUEST)

        code = request.data.get("code")
        if not code:
            return _error_response()

        accesstoken = accesstoken_for_authcode(code)
        if accesstoken is None:
            return _error_response()

        data = dict(
            access_token=accesstoken.token, token_type="Bearer", scope=accesstoken.scope
        )

        response = Response(data, status=HTTP_200_OK)
        setTokenHttpOnly(response)
        return response
