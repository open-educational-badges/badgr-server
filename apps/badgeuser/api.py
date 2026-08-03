import datetime
import json
import re
import urllib.parse

from jsonschema import ValidationError

from allauth.account.adapter import get_adapter
from allauth.account.models import EmailConfirmationHMAC
from allauth.account.utils import user_pk_to_url_str, url_str_to_user_pk
from drf_spectacular.utils import (
    extend_schema,
)
from django.contrib.auth import get_user_model
from django.db.models import Prefetch
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.urls import reverse
from django.http import Http404
from django.utils import timezone
from django.views.generic import RedirectView
from django.conf import settings
from apps.badgeuser.utils import notify_on_password_change
from issuer.models import (
    Issuer,
    IssuerStaff,
    IssuerStaffRequest,
    LearningPath,
    LearningPathBadge,
    NetworkInvite,
)
from issuer.serializers_v1 import IssuerStaffRequestSerializer, LearningPathSerializerV1
from rest_framework import permissions, serializers, status
from rest_framework.exceptions import ValidationError as RestframeworkValidationError
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer
from rest_framework.status import (
    HTTP_302_FOUND,
    HTTP_200_OK,
    HTTP_404_NOT_FOUND,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
)
from oauth2_provider.models import get_application_model

from badgeuser.authcode import decrypt_authcode
from badgeuser.models import BadgeUser, CachedEmailAddress, TermsVersion
from badgeuser.permissions import BadgeUserIsAuthenticatedUser
from badgeuser.serializers_v1 import (
    BadgeUserProfileSerializerV1,
    BadgeUserTokenSerializerV1,
    EmailSerializerV1,
)
from badgeuser.serializers_v2 import (
    BadgeUserTokenSerializerV2,
    BadgeUserSerializerV2,
    AccessTokenSerializerV2,
    TermsVersionSerializerV2,
)
from badgeuser.tasks import process_email_verification
from badgrsocialauth.utils import redirect_to_frontend_error_toast
from entity.api import BaseEntityDetailView, BaseEntityListView
from entity.serializers import BaseSerializerV2
from issuer.permissions import BadgrOAuthTokenHasScope
from mainsite.models import BadgrApp, AccessTokenProxy, ApplicationInfo
from mainsite.utils import (
    backoff_cache_key,
    OriginSetting,
    set_url_query_params,
    throttleable,
    verifyIssuerAutomatically,
)
from mainsite.serializers import ApplicationInfoSerializer

import logging

logger = logging.getLogger("Badgr.Events")

RATE_LIMIT_DELTA = datetime.timedelta(minutes=5)


class BadgeUserDetail(BaseEntityDetailView):
    model = BadgeUser
    v1_serializer_class = BadgeUserProfileSerializerV1
    v2_serializer_class = BadgeUserSerializerV2
    permission_classes = (permissions.AllowAny, BadgrOAuthTokenHasScope)
    valid_scopes = {
        "post": ["*"],
        "get": ["r:profile", "rw:profile"],
        "put": ["rw:profile"],
        "delete": ["rw:profile"],
    }

    @extend_schema(
        summary="Post a single BadgeUser profile",
        description="Make an account",
        tags=["BadgeUsers"],
    )
    @throttleable
    def post(self, request, **kwargs):
        """
        Signup for a new account
        """
        if request.version == "v1":
            # email = request.data.get("email")
            # TODO: investigate how we can use this to improve the spam filter
            # only send email domain to spamfilter API to protect users privacy
            # _, email_domain = email.split("@", 1)
            # firstname = request.data.get("first_name")
            # lastname = request.data.get("last_name")

            # apiKey = getattr(settings, "ALTCHA_API_KEY")
            # endpoint = getattr(settings, "ALTCHA_SPAMFILTER_ENDPOINT")
            # payload = {
            #     "text": [firstname, lastname],
            # the following options seem to classify too much data as spam, i commented them out for now
            # "email": email_domain,
            # "expectedLanguages": ["en", "de"],
            # }
            # params = {"apiKey": apiKey}
            # headers = {
            #     "Content-Type": "application/json",
            #     "referer": getattr(settings, "HTTP_ORIGIN"),
            # }
            # response = requests.post(
            #     endpoint, params=params, data=json.dumps(payload), headers=headers
            # )
            # if response.status_code == 200:
            #     data = response.json()
            #     classification = data["classification"]
            #     if classification == "BAD":
            #         # TODO: show reasons why data was classified as spam
            #         return JsonResponse(
            #             {
            #                 "error": "Spam filter detected spam. Your account was not created."
            #             },
            #             status=status.HTTP_403_FORBIDDEN,
            #         )

            serializer_cls = self.get_serializer_class()
            captcha = request.data.get("captcha")
            serializer = serializer_cls(
                data=request.data, context={"request": request, "captcha": captcha}
            )
            serializer.is_valid(raise_exception=True)
            try:
                serializer.save()
            except DjangoValidationError as e:
                raise RestframeworkValidationError(e.message)
            return Response(serializer.data, status=HTTP_201_CREATED)

        return Response(status=HTTP_404_NOT_FOUND)

    @extend_schema(
        summary="Get a single BadgeUser profile",
        description="Use the entityId 'self' to retrieve the authenticated user's profile",
        tags=["BadgeUsers"],
    )
    def get(self, request, **kwargs):
        return super(BadgeUserDetail, self).get(request, **kwargs)

    @extend_schema(
        summary="Update a BadgeUser",
        description="Use the entityId 'self' to update the authenticated user's profile",
        tags=["BadgeUsers"],
    )
    def put(self, request, **kwargs):
        return super(BadgeUserDetail, self).put(request, allow_partial=True, **kwargs)

    @extend_schema(
        summary="Delete a BadgeUser",
        description="Use the entityId 'self' to delete the authenticated user's profile",
        tags=["BadgeUsers"],
    )
    def delete(self, request, **kwargs):
        return super(BadgeUserDetail, self).delete(request, **kwargs)

    def get_object(self, request, **kwargs):
        version = getattr(request, "version", "v1")
        if version == "v2":
            entity_id = kwargs.get("entity_id")
            if entity_id == "self":
                self.object = request.user
                return self.object
            try:
                self.object = BadgeUser.cached.get(entity_id=entity_id)
            except BadgeUser.DoesNotExist:
                pass
            else:
                return self.object
        elif version == "v1":
            if request.user.is_authenticated:
                self.object = request.user
                return self.object
        raise Http404

    def has_object_permissions(self, request, obj):
        method = request.method.lower()
        if method == "post":
            return True

        if isinstance(obj, BadgeUser):
            if method == "get":
                if request.user.id == obj.id:
                    # always have access to your own user
                    return True
                if obj in request.user.peers:
                    # you can see some info about users you know about
                    return True

            if method == "put" or method == "delete":
                # only current user can update their own profile
                return request.user.id == obj.id
        return False

    def get_context_data(self, **kwargs):
        context = super(BadgeUserDetail, self).get_context_data(**kwargs)
        context["isSelf"] = self.object.id == self.request.user.id
        return context


class BadgeUserToken(BaseEntityDetailView):
    model = BadgeUser
    permission_classes = (BadgeUserIsAuthenticatedUser,)
    v1_serializer_class = BadgeUserTokenSerializerV1
    v2_serializer_class = BadgeUserTokenSerializerV2

    def get_object(self, request, **kwargs):
        return request.user

    # deprecate from public API docs in favor of oauth2
    # @apispec_get_operation('BadgeUserToken',
    #     summary="Get the authenticated user's auth token",
    #     description="A new auth token will be created if none already exist for this user",
    #     tags=['Authentication'],
    # )
    def get(self, request, **kwargs):
        return super(BadgeUserToken, self).get(request, **kwargs)

    # deprecate from public API docs in favor of oauth2
    # @apispec_operation(
    #     summary="Invalidate the old token and create a new one",
    #     tags=['Authentication'],
    # )
    def put(self, request, **kwargs):
        request.user.replace_token()  # generate new token first
        self.token_replaced = True
        return super(BadgeUserToken, self).put(request, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(BadgeUserToken, self).get_context_data(**kwargs)
        context["tokenReplaced"] = getattr(self, "token_replaced", False)
        return context


class BaseUserRecoveryView(BaseEntityDetailView):
    def _get_user(self, uidb36):
        User = get_user_model()
        try:
            pk = url_str_to_user_pk(uidb36)
            return User.objects.get(pk=pk)
        except (ValueError, User.DoesNotExist):
            return None

    def get_response(self, obj={}, status=HTTP_200_OK):
        context = self.get_context_data()
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(obj, context=context)
        return Response(serializer.data, status=status)


class BadgeUserForgotPassword(BaseUserRecoveryView):
    schema = None
    authentication_classes = ()
    permission_classes = (permissions.AllowAny,)
    v1_serializer_class = serializers.Serializer
    v2_serializer_class = BaseSerializerV2

    def get(self, request, *args, **kwargs):
        badgr_app = None
        badgrapp_id = self.request.GET.get("a")
        if badgrapp_id:
            try:
                badgr_app = BadgrApp.objects.get(id=badgrapp_id)
            except BadgrApp.DoesNotExist:
                pass
        if badgr_app is None:
            badgr_app = BadgrApp.objects.get_current(request)

        redirect_url = badgr_app.forgot_password_redirect
        token = request.GET.get("token", "")
        tokenized_url = "{}{}".format(redirect_url, token)
        return Response(status=HTTP_302_FOUND, headers={"Location": tokenized_url})

    # @apispec_operation(
    #     summary="Request an account recovery email",
    #     tags=["Authentication"],
    #     parameters=[
    #         {
    #             "in": "body",
    #             "name": "body",
    #             "required": True,
    #             "schema": {
    #                 "type": "object",
    #                 "properties": {
    #                     "email": {
    #                         "type": "string",
    #                         "format": "email",
    #                         "description": "The email address on file to send recovery email to",
    #                     }
    #                 },
    #             },
    #         }
    #     ],
    # )
    def post(self, request, **kwargs):
        email = request.data.get("email")
        try:
            email_address = CachedEmailAddress.cached.get(email=email)
        except CachedEmailAddress.DoesNotExist:
            # return 200 here because we don't want to expose information about which emails we know about
            return self.get_response()

        # email rate limiting
        send_email = False
        current_time = datetime.datetime.now()
        last_request_time = email_address.get_last_forgot_password_sent_time()

        if last_request_time is None:
            send_email = True
        else:
            time_delta = current_time - last_request_time
            if time_delta > RATE_LIMIT_DELTA:
                send_email = True

        if not send_email:
            return Response(
                "Forgot password request limit exceeded. Please check your"
                + " inbox for an existing message or wait to retry.",
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        email_address.set_last_forgot_password_sent_time(datetime.datetime.now())

        #
        # taken from allauth.account.forms.ResetPasswordForm
        #

        # fetch user from database directly to avoid cache
        UserCls = get_user_model()
        try:
            user = UserCls.objects.get(pk=email_address.user_id)
        except UserCls.DoesNotExist:
            return self.get_response()

        temp_key = default_token_generator.make_token(user)
        token = "{uidb36}-{key}".format(uidb36=user_pk_to_url_str(user), key=temp_key)

        badgrapp = BadgrApp.objects.get_current(request=request)

        api_path = reverse(
            "{version}_api_auth_forgot_password".format(version=request.version)
        )
        reset_url = "{origin}{path}?token={token}&a={badgrapp}".format(
            origin=OriginSetting.HTTP, path=api_path, token=token, badgrapp=badgrapp.id
        )

        email_context = {
            "site": get_current_site(request),
            "user": user,
            "password_reset_url": reset_url,
            "badgr_app": badgrapp,
        }
        get_adapter().send_mail(
            "account/email/password_reset_key", email, email_context
        )

        return self.get_response()

    # @apispec_operation(
    #     summary="Recover an account and set a new password",
    #     tags=["Authentication"],
    #     parameters=[
    #         {
    #             "in": "body",
    #             "name": "body",
    #             "required": True,
    #             "schema": {
    #                 "type": "object",
    #                 "properties": {
    #                     "token": {
    #                         "type": "string",
    #                         "format": "string",
    #                         "description": "The token recieved in the recovery email",
    #                         "required": True,
    #                     },
    #                     "password": {
    #                         "type": "string",
    #                         "description": "The new password to use",
    #                         "required": True,
    #                     },
    #                 },
    #             },
    #         }
    #     ],
    # )
    def put(self, request, **kwargs):
        token = request.data.get("token")
        password = request.data.get("password")

        matches = re.search(r"([0-9A-Za-z]+)-(.*)", token)
        if not matches:
            return Response(status=HTTP_404_NOT_FOUND)
        uidb36 = matches.group(1)
        key = matches.group(2)
        if not (uidb36 and key):
            return Response(status=HTTP_404_NOT_FOUND)

        user = self._get_user(uidb36)
        if user is None:
            return Response(status=HTTP_404_NOT_FOUND)

        if not default_token_generator.check_token(user, key):
            return Response(status=HTTP_404_NOT_FOUND)

        try:
            validate_password(password)
        except DjangoValidationError as e:
            return Response(dict(password=e.messages), status=HTTP_400_BAD_REQUEST)

        cache.delete(backoff_cache_key(user.email))

        user.set_password(password)
        user.save()
        notify_on_password_change(user)

        return self.get_response()


class BaseRedirectView:
    """
    A base view for handling conditional redirects with flexible configuration.
    """

    def _prepare_redirect(self, request, badgrapp, intended_redirect):
        """
        Prepare redirect URL and response based on authentication status.

        :param request: HTTP request object
        :param badgrapp: BadgrApp instance
        :param intended_redirect: The target redirect path
        :return: Response object with appropriate redirect
        """
        # Prepare frontend base URL
        frontend_base_url = badgrapp.cors.rstrip("/") if badgrapp.cors else ""
        if frontend_base_url and not frontend_base_url.startswith(
            ("http://", "https://")
        ):
            frontend_base_url = f"https://{frontend_base_url}"

        # If user is authenticated, redirect to the intended page
        if request.user.is_authenticated:
            detail_url = f"{frontend_base_url}{intended_redirect}"
            return Response(status=HTTP_302_FOUND, headers={"Location": detail_url})

        # If not authenticated, prepare redirect to login
        redirect_url = badgrapp.ui_login_redirect.rstrip("/")
        response = Response(status=HTTP_302_FOUND, headers={"Location": redirect_url})

        # Set cookie for intended redirect
        response.set_cookie(
            "intended_redirect",
            intended_redirect,
            max_age=3600,  # 1 hour
            httponly=True,
            secure=settings.SECURE_SSL_REDIRECT,
            samesite="Lax",
            domain=badgrapp.cors.split("://")[-1] if badgrapp.cors else None,
        )

        return response


class BadgeUserEmailConfirm(BaseUserRecoveryView, BaseRedirectView):
    schema = None
    permission_classes = (permissions.AllowAny,)
    v1_serializer_class = BaseSerializer
    v2_serializer_class = BaseSerializerV2

    def get(self, request, **kwargs):
        """
        Confirm an email address with a token provided in an email
        ---
        parameters:
            - name: token
              type: string
              paramType: form
              description: The token received in the recovery email
              required: true
        """
        token = request.query_params.get("token", "")
        badgrapp_id = request.query_params.get("a")

        # Get BadgrApp instance
        badgrapp = BadgrApp.objects.get_by_id_or_default(badgrapp_id)

        # Get EmailConfirmation instance
        emailconfirmation = EmailConfirmationHMAC.from_key(kwargs.get("confirm_id"))
        if emailconfirmation is None:
            logger.warning(
                "No email confirmation found for confirm id '%s'",
                kwargs.get("confirm_id"),
            )
            return redirect_to_frontend_error_toast(
                request,
                "Your email confirmation link is invalid. Please attempt to "
                "create an account with this email address, again.",
            )  # 202
        # Get EmailAddress instance
        else:
            try:
                email_address = CachedEmailAddress.cached.get(
                    pk=emailconfirmation.email_address.pk
                )
            except CachedEmailAddress.DoesNotExist:
                logger.warning(
                    "No email confirmation email address found for confirm id '%s'",
                    kwargs.get("confirm_id"),
                )
                return redirect_to_frontend_error_toast(
                    request,
                    "Your email confirmation link is invalid. Please attempt "
                    "to create an account with this email address, again.",
                )  # 202

        if email_address.verified:
            logger.info(
                "Email address for confirm id '%s' was already verified",
                kwargs.get("confirm_id"),
            )
            return redirect_to_frontend_error_toast(
                request, "Your email address is already verified. You may now log in."
            )

        # Validate 'token' syntax from query param
        matches = re.search(r"([0-9A-Za-z]+)-(.*)", token)
        if not matches:
            logger.warning(
                "The token '%s' for the email confirmation id '%s' is invalid",
                token,
                kwargs.get("confirm_id"),
            )
            email_address.send_confirmation(request=request, signup=False)
            return redirect_to_frontend_error_toast(
                request,
                "Your email confirmation token is invalid. You have been sent "
                "a new link. Please check your email and try again.",
            )  # 2
        uidb36 = matches.group(1)
        key = matches.group(2)
        if not (uidb36 and key):
            logger.warning(
                "The token '%s' for the email confirmation id '%s' is invalid",
                token,
                kwargs.get("confirm_id"),
            )
            email_address.send_confirmation(request=request, signup=False)
            return redirect_to_frontend_error_toast(
                request,
                "Your email confirmation token is invalid. You have been sent "
                "a new link. Please check your email and try again.",
            )  # 2

        # Get User instance from literal 'token' value
        user = self._get_user(uidb36)
        if user is None or not default_token_generator.check_token(user, key):
            logger.warning(
                "The confirmation link for the confirm id '%s' has expired or is invalid",
                kwargs.get("confirm_id"),
            )
            email_address.send_confirmation(request=request, signup=False)
            return redirect_to_frontend_error_toast(
                request,
                "Your authorization link has expired. You have been sent a new "
                "link. Please check your email and try again.",
            )

        if email_address.user != user:
            logger.warning(
                "The email confirmation token '%s' of confirm id '%s' belongs to another user",
                token,
                kwargs.get("confirm_id"),
            )
            return redirect_to_frontend_error_toast(
                request,
                "Your email confirmation token is associated with an unexpected "
                "user. You may try again",
            )

        # Perform main operation, set EmaiAddress .verified and .primary True
        old_primary = CachedEmailAddress.objects.get_primary(user)
        if old_primary is None:
            email_address.primary = True
        email_address.verified = True
        email_address.save()

        # check whether the user has unverified institutions that should be verified with the new email
        for issuer in user.cached_issuers():
            if not issuer.verified:
                if verifyIssuerAutomatically(issuer.url, str(email_address)):
                    issuer.verified = True
                    issuer.save()

        process_email_verification.delay(email_address.pk)

        # Create an OAuth AccessTokenProxy instance for this user
        # accesstoken = AccessTokenProxy.objects.generate_new_token_for_user(
        #     user,
        #     application=(
        #         badgrapp.oauth_application if badgrapp.oauth_application_id else None
        #     ),
        #     scope="rw:backpack rw:profile rw:issuer",
        # )

        redirect_url = badgrapp.ui_login_redirect.rstrip("/")

        response = Response(status=HTTP_302_FOUND, headers={"Location": redirect_url})

        intended_redirect = "/auth/welcome"

        response.set_cookie(
            "intended_redirect",
            intended_redirect,
            max_age=3600,
            httponly=True,
            secure=request.is_secure(),
            samesite="Lax",
        )

        return response


class BadgeUserAccountConfirm(RedirectView):
    badgrapp = None

    def error_redirect_url(self):
        if self.badgrapp is None:
            self.badgrapp = BadgrApp.objects.get_by_id_or_default()

        return set_url_query_params(
            self.badgrapp.ui_login_redirect.rstrip("/"),
            authError="Error validating request.",
        )

    def get_redirect_url(self, *args, **kwargs):
        authcode = kwargs.get("authcode", None)
        if not authcode:
            return self.error_redirect_url()

        user_info = decrypt_authcode(authcode)
        try:
            user_info = json.loads(user_info)
        except (
            TypeError,
            ValueError,
        ):
            user_info = None
        if not user_info:
            return self.error_redirect_url()

        badgrapp_id = user_info.get("badgrapp_id", None)
        self.badgrapp = BadgrApp.objects.get_by_id_or_default(badgrapp_id)

        try:
            email_address = CachedEmailAddress.cached.get(email=user_info.get("email"))
        except CachedEmailAddress.DoesNotExist:
            return self.error_redirect_url()

        user = email_address.user
        user.first_name = user_info.get("first_name", user.first_name)
        user.last_name = user_info.get("last_name", user.last_name)
        user.badgrapp = self.badgrapp
        user.marketing_opt_in = user_info.get("marketing_opt_in", user.marketing_opt_in)
        user.agreed_terms_version = TermsVersion.cached.latest_version()
        user.email_verified = True
        if user_info.get("plaintext_password"):
            user.set_password(user_info["plaintext_password"])
        user.save()

        redirect_url = urllib.parse.urljoin(
            self.badgrapp.email_confirmation_redirect.rstrip("/") + "/",
            urllib.parse.quote(user.first_name.encode("utf8")),
        )
        redirect_url = set_url_query_params(
            redirect_url, email=email_address.email.encode("utf8")
        )
        return redirect_url


class AccessTokenList(BaseEntityListView):
    model = AccessTokenProxy
    serializer_class = AccessTokenSerializerV2
    v2_serializer_class = AccessTokenSerializerV2
    permission_classes = (permissions.IsAuthenticated, BadgrOAuthTokenHasScope)
    valid_scopes = ["rw:profile"]

    def get_objects(self, request, **kwargs):
        return AccessTokenProxy.objects.filter(
            user=request.user, expires__gt=timezone.now()
        )

    @extend_schema(
        summary="Get a list of access tokens for authenticated user",
        tags=["Authentication"],
    )
    def get(self, request, **kwargs):
        return super(AccessTokenList, self).get(request, **kwargs)


class ApplicationList(BaseEntityListView):
    model = get_application_model()
    serializer_class = ApplicationInfoSerializer
    v2_serializer_class = ApplicationInfoSerializer
    permission_classes = (permissions.IsAuthenticated, BadgrOAuthTokenHasScope)
    valid_scopes = ["rw:profile"]

    def get_objects(self, request, **kwargs):
        return ApplicationInfo.objects.filter(application__user=request.user)

    @extend_schema(
        summary="Get a list of application registered for the authenticated user",
        tags=["Authentication"],
    )
    def get(self, request, **kwargs):
        return super(ApplicationList, self).get(request, **kwargs)


class ApplicationDetails(BaseEntityDetailView):
    model = ApplicationInfo
    serializer_class = ApplicationInfoSerializer
    v2_serializer_class = ApplicationInfoSerializer
    permission_classes = (permissions.IsAuthenticated, BadgrOAuthTokenHasScope)
    valid_scopes = ["rw:profile"]

    @extend_schema(
        summary="Delete one registed set of access tokens", tags=["Authentication"]
    )
    def delete(self, request, application_id, **kwargs):
        model = get_application_model()

        obj = model.objects.filter(client_id=application_id, user=request.user)
        obj.delete()
        return Response(status=204)


class AccessTokenDetail(BaseEntityDetailView):
    model = AccessTokenProxy
    serializer_class = AccessTokenSerializerV2
    v2_serializer_class = AccessTokenSerializerV2
    permission_classes = (permissions.IsAuthenticated, BadgrOAuthTokenHasScope)
    valid_scopes = ["rw:profile"]

    def get_object(self, request, **kwargs):
        try:
            self.object = AccessTokenProxy.objects.get_from_entity_id(
                kwargs.get("entity_id")
            )
        except AccessTokenProxy.DoesNotExist:
            raise Http404

        if not self.has_object_permissions(request, self.object):
            raise Http404
        return self.object

    @extend_schema(summary="Get a single AccessToken", tags=["Authentication"])
    def get(self, request, **kwargs):
        return super(AccessTokenDetail, self).get(request, **kwargs)

    @extend_schema(summary="Revoke an AccessToken", tags=["Authentication"])
    def delete(self, request, **kwargs):
        obj = self.get_object(request, **kwargs)
        if not self.has_object_permissions(request, obj):
            return Response(status=HTTP_404_NOT_FOUND)
        obj.revoke()
        return Response(status=204)


class LatestTermsVersionDetail(BaseEntityDetailView):
    model = TermsVersion
    serializer_class = TermsVersionSerializerV2
    v2_serializer_class = TermsVersionSerializerV2
    permission_classes = (permissions.AllowAny,)

    def get_object(self, request, **kwargs):
        latest = TermsVersion.cached.cached_latest()
        if latest:
            return latest

        raise Http404(
            "No TermsVersion has been defined. Please contact server administrator."
        )


class BadgeUserResendEmailConfirmation(BaseUserRecoveryView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = EmailSerializerV1
    v1_serializer_class = EmailSerializerV1

    def put(self, request, **kwargs):
        email = request.data.get("email")

        try:
            email_address = CachedEmailAddress.cached.get(email=email)
        except CachedEmailAddress.DoesNotExist:
            # return 200 here because we don't want to expose information about which emails we know about
            return self.get_response()

        if email_address.verified:
            return Response(
                {"Your email address is already confirmed. You can login."},
                status=status.HTTP_409_CONFLICT,
            )
        else:
            # email rate limiting
            resend_confirmation = False
            current_time = datetime.datetime.now()
            last_request_time = email_address.get_last_verification_sent_time()

            if last_request_time is None:
                email_address.set_last_verification_sent_time(datetime.datetime.now())
                resend_confirmation = True
            else:
                time_delta = current_time - last_request_time
                if time_delta > RATE_LIMIT_DELTA:
                    resend_confirmation = True

            if resend_confirmation:
                email_address.send_confirmation(signup=True)
                email_address.set_last_verification_sent_time(datetime.datetime.now())
            else:
                return Response(
                    "You have reached a limit for resending verification email. Please check your"
                    + " inbox for an existing message or retry after 5 minutes.",
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

        serializer = EmailSerializerV1(email_address, context={"request": request})
        serialized = serializer.data
        return Response(serialized, status=status.HTTP_200_OK)


class LearningPathList(BaseEntityListView):
    """
    GET a list of learning paths for the authenticated user
    """

    model = LearningPath
    permission_classes = permission_classes = (
        permissions.IsAuthenticated,
        BadgrOAuthTokenHasScope,
    )
    valid_scopes = ["rw:profile"]
    v1_serializer_class = LearningPathSerializerV1

    def get_objects(self, request, **kwargs):
        badgeinstances = request.user.cached_badgeinstances().all()
        badges = list(
            {
                badgeinstance.badgeclass
                for badgeinstance in badgeinstances
                if badgeinstance.revoked is False
            }
        )
        lp_badges = LearningPathBadge.objects.filter(badge__in=badges)
        lps = (
            LearningPath.objects.filter(activated=True, learningpathbadge__in=lp_badges)
            .distinct()
            .select_related("issuer", "participationBadge")
            .prefetch_related(
                Prefetch(
                    "learningpathbadge_set",
                    queryset=LearningPathBadge.objects.select_related("badge").order_by(
                        "order"
                    ),
                ),
            )
        )

        return lps

    @extend_schema(
        summary="Get a list of LearningPaths for authenticated user",
        tags=["LearningPaths"],
    )
    def get(self, request, **kwargs):
        return super(LearningPathList, self).get(request, **kwargs)


class BaseRedirectView:
    """
    A base view for handling conditional redirects with flexible configuration.
    """

    def _prepare_redirect(self, request, badgrapp, intended_redirect):
        """
        Prepare redirect URL and response based on authentication status.

        :param request: HTTP request object
        :param badgrapp: BadgrApp instance
        :param intended_redirect: The target redirect path
        :return: Response object with appropriate redirect
        """
        # Prepare frontend base URL
        frontend_base_url = badgrapp.cors.rstrip("/") if badgrapp.cors else ""
        if frontend_base_url and not frontend_base_url.startswith(
            ("http://", "https://")
        ):
            frontend_base_url = f"https://{frontend_base_url}"

        # If user is authenticated, redirect to the intended page
        if request.user.is_authenticated:
            detail_url = f"{frontend_base_url}{intended_redirect}"
            return Response(status=HTTP_302_FOUND, headers={"Location": detail_url})

        # If not authenticated, prepare redirect to login
        redirect_url = badgrapp.ui_login_redirect.rstrip("/")
        response = Response(status=HTTP_302_FOUND, headers={"Location": redirect_url})

        # Set cookie for intended redirect
        response.set_cookie(
            "intended_redirect",
            intended_redirect,
            max_age=3600,  # 1 hour
            httponly=True,
            secure=settings.SECURE_SSL_REDIRECT,
            samesite="Lax",
            domain=badgrapp.cors.split("://")[-1] if badgrapp.cors else None,
        )

        return response


class BadgeUserSaveMicroDegree(BaseEntityDetailView, BaseRedirectView):
    schema = None
    permission_classes = (permissions.AllowAny,)
    v1_serializer_class = BaseSerializer
    v2_serializer_class = BaseSerializerV2

    def get(self, request, **kwargs):
        """
        Redirect to the micro degree detail page after the user logs in
        """
        badgrapp_id = request.query_params.get("a")
        badgrapp = BadgrApp.objects.get_by_id_or_default(badgrapp_id)

        microdegree_id = kwargs.get("entity_id")
        intended_redirect = f"/public/learningpaths/{microdegree_id}"

        return self._prepare_redirect(request, badgrapp, intended_redirect)


class BadgeUserCollectBadgesInBackpack(BaseEntityDetailView, BaseRedirectView):
    schema = None
    permission_classes = (permissions.AllowAny,)
    v1_serializer_class = BaseSerializer
    v2_serializer_class = BaseSerializerV2

    def get(self, request, **kwargs):
        """
        Redirect to the user's backpack page after the user logs in
        """
        badgrapp_id = request.query_params.get("a")
        badgrapp = BadgrApp.objects.get_by_id_or_default(badgrapp_id)

        intended_redirect = "/recipient/badges/"

        return self._prepare_redirect(request, badgrapp, intended_redirect)


@extend_schema(exclude=True)
class GetRedirectPath(BaseEntityDetailView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, **kwargs):
        redirect_path = request.COOKIES.get("intended_redirect")

        response = Response(
            {"success": True, "redirectPath": redirect_path or "/issuer"}
        )

        response.delete_cookie("intended_redirect")

        return response


class BadgeUserStaffRequestList(BaseEntityListView):
    """List and create staff requests for the authenticated user"""

    model = IssuerStaffRequest
    v1_serializer_class = IssuerStaffRequestSerializer
    permission_classes = (permissions.IsAuthenticated,)
    valid_scopes = {
        "post": ["rw:profile"],
        "get": ["r:profile", "rw:profile"],
    }

    @extend_schema(
        summary="Get my staff membership requests",
        description="Get all staff requests created by the authenticated user",
        tags=["BadgeUser StaffRequests"],
    )
    def get(self, request, issuer_id=None, **kwargs):
        return super().get(request, **kwargs)

    def get_objects(self, request, issuer_id=None, **kwargs):
        queryset = IssuerStaffRequest.objects.filter(
            user=request.user,
            revoked=False,
        )

        if issuer_id:
            queryset = queryset.filter(issuer__entity_id=issuer_id)

        return queryset

    @extend_schema(
        summary="Create a new issuer staff request",
        description="Request membership to an institution's staff",
        tags=["BadgeUser StaffRequests"],
    )
    def post(self, request, issuer_id, **kwargs):
        try:
            issuer = Issuer.objects.get(entity_id=issuer_id)
        except Issuer.DoesNotExist:
            return Response(
                {"response": "Issuer not found"}, status=status.HTTP_404_NOT_FOUND
            )

        existing_request = IssuerStaffRequest.objects.filter(
            issuer=issuer,
            user=request.user,
            status__in=[
                IssuerStaffRequest.Status.PENDING,
            ],
        ).first()

        if existing_request:
            return Response(
                {
                    "response": "Für diese Institution liegt noch eine offene Anfrage von dir vor!"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        for member in issuer.cached_issuerstaff():
            if request.user == member.cached_user:
                return Response(
                    {"response": "Du bist bereits Teil dieser Institution!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        try:
            staff_request = IssuerStaffRequest.objects.create(
                issuer=issuer,
                user=request.user,
                status=IssuerStaffRequest.Status.PENDING,
                revoked=False,
            )
        except Exception as e:
            return Response({"response": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer_class()(
            staff_request, context={"request": request}
        )

        email_context = {
            "site": get_current_site(request),
            "user": request.user,
            "issuer": issuer,
            "activate_url": OriginSetting.HTTP
            + reverse(
                "v1_api_user_confirm_staffrequest",
                kwargs={"entity_id": issuer.entity_id},
            ),
            "call_to_action_label": "Anfrage bestätigen",
        }

        for member in issuer.cached_issuerstaff():
            if member.role == IssuerStaff.ROLE_OWNER:
                email = member.cached_user.email
                get_adapter().send_mail(
                    "account/email/email_staff_request", email, email_context
                )

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class BadgeUserStaffRequestDetail(BaseEntityDetailView):
    """View and manage user's own staff requests"""

    model = IssuerStaffRequest
    v1_serializer_class = IssuerStaffRequestSerializer
    permission_classes = (permissions.IsAuthenticated,)
    valid_scopes = ["rw:profile"]

    def get_object(self, request, **kwargs):
        try:
            self.object = IssuerStaffRequest.objects.filter(
                entity_id=kwargs.get("request_id"),
            ).first()
        except IssuerStaffRequest.DoesNotExist:
            raise Http404

        if not self.has_object_permissions(request, self.object):
            raise Http404
        return self.object

    @extend_schema(
        summary="Get a specific staff request",
        description="Get details of a staff request created by the authenticated user",
        tags=["BadgeUser StaffRequests"],
    )
    def get(self, request, **kwargs):
        staff_request = self.get_object(request, **kwargs)
        if not self.has_object_permissions(request, staff_request):
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer_class()(
            staff_request, context={"request": request}
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        summary="Revoke a request for an issuer membership",
        description="Revoke your own pending staff membership request",
        tags=["BadgeUser StaffRequests"],
    )
    def delete(self, request, **kwargs):
        staff_request = self.get_object(request, **kwargs)
        if not self.has_object_permissions(request, staff_request):
            return Response(status=HTTP_404_NOT_FOUND)

        try:
            staff_request.revoke()
        except DjangoValidationError as e:
            raise ValidationError(e.message)

        serializer = self.get_serializer_class()(
            staff_request, context={"request": request}
        )

        return Response(status=HTTP_200_OK, data=serializer.data)


class BadgeUserConfirmStaffRequest(BaseEntityDetailView, BaseRedirectView):
    schema = None
    permission_classes = (permissions.AllowAny,)
    v1_serializer_class = BaseSerializer
    v2_serializer_class = BaseSerializerV2

    def get(self, request, **kwargs):
        """
        Redirect to the issuer staff member page after the user logs in
        """
        badgrapp_id = request.query_params.get("a")
        badgrapp = BadgrApp.objects.get_by_id_or_default(badgrapp_id)

        issuer_id = kwargs.get("entity_id")
        intended_redirect = f"/issuer/issuers/{issuer_id}/staff"

        return self._prepare_redirect(request, badgrapp, intended_redirect)


class ConfirmNetworkInvitation(BaseEntityDetailView, BaseRedirectView):
    schema = None
    permission_classes = (permissions.AllowAny,)
    v1_serializer_class = BaseSerializer
    v2_serializer_class = BaseSerializerV2

    def get(self, request, **kwargs):
        """
        Redirect to frontend to confirm network invitation
        """
        badgrapp_id = request.query_params.get("a")
        badgrapp = BadgrApp.objects.get_by_id_or_default(badgrapp_id)
        inviteSlug = kwargs.get("inviteSlug")
        try:
            invitation = NetworkInvite.objects.get(entity_id=inviteSlug)
        except NetworkInvite.DoesNotExist:
            pass
        if invitation.status == invitation.Status.APPROVED:
            intended_redirect = f"/issuer/networks/invite/{inviteSlug}?confirmed=true"
        else:
            intended_redirect = f"/issuer/networks/invite/{inviteSlug}"

        return self._prepare_redirect(request, badgrapp, intended_redirect)
