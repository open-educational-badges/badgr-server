import base64
import datetime
import hashlib
import io
import json
import logging
import os

import pyotp
import qrcode
from allauth.account.adapter import get_adapter
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from oauth2_provider.models import get_application_model, get_access_token_model
from oauthlib.common import generate_token
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)


def _generate_backup_codes(count=10):
    codes = []
    hashed = []
    for _ in range(count):
        code = base64.b32encode(os.urandom(5)).decode("utf-8").lower()[:8]
        codes.append(code)
        hashed.append(hashlib.sha256(code.encode()).hexdigest())
    return codes, hashed


def _make_qr_base64(uri):
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


class TwoFactorSetupView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, **kwargs):
        user = request.user

        if user.totp_enabled:
            return Response(
                {
                    "error": "2FA is already enabled. Disable it first before setting up again."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        secret = pyotp.random_base32()
        issuer = getattr(settings, "OPERATOR_NAME", None) or "OEB Badges"
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user.primary_email, issuer_name=issuer
        )

        user.totp_secret = secret
        user.totp_confirmed = False
        user.totp_enabled = False
        user.save()

        return Response({"qr_code": _make_qr_base64(uri), "secret": secret})


class TwoFactorConfirmView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, **kwargs):
        user = request.user
        code = request.data.get("code", "")

        if not user.totp_secret:
            return Response(
                {"error": "No 2FA setup in progress. Call /2fa/setup first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not pyotp.TOTP(user.totp_secret).verify(code):
            return Response(
                {"error": "Invalid code. Please try again."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        plaintext_codes, hashed_codes = _generate_backup_codes(10)
        user.totp_enabled = True
        user.totp_confirmed = True
        user.backup_codes = json.dumps(hashed_codes)
        user.save()

        return Response({"backup_codes": plaintext_codes})


class TwoFactorVerifyView(APIView):
    authentication_classes = ()
    permission_classes = (permissions.AllowAny,)

    def post(self, request, **kwargs):
        partial_token = request.data.get("partial_token", "")
        code = request.data.get("code", "")

        cache_data = cache.get(f"2fa_partial:{partial_token}")
        if not cache_data:
            return Response(
                {"error": "Invalid or expired session. Please log in again."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Consume the partial token immediately — prevents two concurrent requests
        # both passing the cache.get check and receiving valid tokens.
        cache.delete(f"2fa_partial:{partial_token}")

        from badgeuser.models import BadgeUser

        try:
            user = BadgeUser.objects.get(pk=cache_data["user_id"])
        except BadgeUser.DoesNotExist:
            return Response(
                {"error": "User not found."}, status=status.HTTP_400_BAD_REQUEST
            )

        totp_valid = (
            pyotp.TOTP(user.totp_secret).verify(code) if user.totp_secret else False
        )

        if not totp_valid:
            with transaction.atomic():
                user = BadgeUser.objects.select_for_update().get(pk=user.pk)
                if user.backup_codes:
                    code_hash = hashlib.sha256(code.encode()).hexdigest()
                    hashed_codes = json.loads(user.backup_codes)
                    if code_hash in hashed_codes:
                        hashed_codes.remove(code_hash)
                        user.backup_codes = json.dumps(hashed_codes)
                        user.save()
                        totp_valid = True

        if not totp_valid:
            return Response(
                {"error": "Invalid code. Please try again."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        Application = get_application_model()
        AccessToken = get_access_token_model()
        client_id = cache_data.get("client_id", "public")
        scope = cache_data.get("scope", "rw:profile rw:issuer rw:backpack")
        expires_in = 86400

        try:
            app = Application.objects.get(client_id=client_id)
        except Application.DoesNotExist:
            return Response(
                {"error": "Invalid client."}, status=status.HTTP_400_BAD_REQUEST
            )

        token = AccessToken.objects.create(
            user=user,
            application=app,
            token=generate_token(),
            expires=timezone.now() + datetime.timedelta(seconds=expires_in),
            scope=scope,
        )

        data = {
            "access_token": token.token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": scope,
        }

        response = HttpResponse(
            json.dumps(data),
            content_type="application/json",
            status=200,
        )
        response.set_cookie(
            "access_token",
            value=token.token,
            httponly=True,
            secure=not settings.DEBUG,
            max_age=expires_in,
        )
        return response


class TwoFactorDisableView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, **kwargs):
        user = request.user
        password = request.data.get("password", "")

        if not user.check_password(password):
            return Response(
                {"error": "Incorrect password. Please try again."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not user.totp_enabled:
            return Response(
                {"error": "2FA is not enabled for this account."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.totp_secret = None
        user.totp_enabled = False
        user.totp_confirmed = False
        user.backup_codes = None
        user.save()

        try:
            primary_email = next(
                (e.email for e in user.cached_emails() if e.primary), user.email
            )
            get_adapter().send_mail(
                "account/email/2fa_disabled",
                primary_email,
                {"user": user},
            )
        except Exception:
            logger.exception(
                "Failed to send 2FA disabled confirmation email to user %s", user.pk
            )

        return Response({"success": True})
