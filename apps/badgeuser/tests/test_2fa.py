import hashlib
import json

import pyotp
from django.core.cache import cache
from mainsite.tests.base import BadgrTestCase
from oauth2_provider.models import get_application_model
from oauthlib.common import generate_token


class TwoFactorSetupTests(BadgrTestCase):
    def test_setup_returns_qr_and_secret(self):
        # Successful setup returns a QR code image and raw secret for manual entry
        self.setup_user(authenticate=True)
        response = self.client.post("/v1/user/2fa/setup")
        self.assertEqual(response.status_code, 200)
        self.assertIn("qr_code", response.data)
        self.assertIn("secret", response.data)

    def test_setup_requires_authentication(self):
        # Unauthenticated requests are rejected
        response = self.client.post("/v1/user/2fa/setup")
        self.assertEqual(response.status_code, 401)

    def test_setup_stores_secret_on_user(self):
        # Setup persists an unconfirmed secret without yet enabling 2FA
        user = self.setup_user(authenticate=True)
        self.client.post("/v1/user/2fa/setup")
        user.refresh_from_db()
        self.assertIsNotNone(user.totp_secret)
        self.assertFalse(user.totp_enabled)

    def test_setup_rejected_when_2fa_already_enabled(self):
        # Cannot restart setup while 2FA is active — must disable first
        user = self.setup_user(authenticate=True)
        user.totp_secret = pyotp.random_base32()
        user.totp_enabled = True
        user.totp_confirmed = True
        user.save()
        response = self.client.post("/v1/user/2fa/setup")
        self.assertEqual(response.status_code, 400)


class TwoFactorConfirmTests(BadgrTestCase):
    def _setup_totp(self):
        user = self.setup_user(authenticate=True)
        response = self.client.post("/v1/user/2fa/setup")
        secret = response.data["secret"]
        return user, secret

    def test_confirm_with_valid_code_enables_2fa(self):
        # Valid TOTP code activates 2FA and returns 10 one-time backup codes
        user, secret = self._setup_totp()
        code = pyotp.TOTP(secret).now()
        response = self.client.post("/v1/user/2fa/confirm", {"code": code})
        self.assertEqual(response.status_code, 200)
        self.assertIn("backup_codes", response.data)
        self.assertEqual(len(response.data["backup_codes"]), 10)
        user.refresh_from_db()
        self.assertTrue(user.totp_enabled)

    def test_confirm_with_invalid_code_returns_400(self):
        # Wrong TOTP code does not enable 2FA
        self._setup_totp()
        response = self.client.post("/v1/user/2fa/confirm", {"code": "000000"})
        self.assertEqual(response.status_code, 400)

    def test_confirm_without_setup_returns_400(self):
        # Confirm is rejected if setup was never initiated (no pending secret)
        self.setup_user(authenticate=True)
        response = self.client.post("/v1/user/2fa/confirm", {"code": "123456"})
        self.assertEqual(response.status_code, 400)

    def test_confirm_requires_authentication(self):
        # Unauthenticated requests are rejected
        response = self.client.post("/v1/user/2fa/confirm", {"code": "123456"})
        self.assertEqual(response.status_code, 401)


class TwoFactorVerifyTests(BadgrTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.setup_user()
        Application = get_application_model()
        Application.objects.create(
            client_id="public",
            authorization_grant_type="client-credentials",
            user=self.user,
        )

    def _create_partial_token(self, client_id="public"):
        partial_token = generate_token()
        cache.set(
            f"2fa_partial:{partial_token}",
            {"user_id": self.user.pk, "client_id": client_id, "scope": "rw:profile"},
            timeout=300,
        )
        return partial_token

    def _enable_2fa(self):
        secret = pyotp.random_base32()
        self.user.totp_secret = secret
        self.user.totp_enabled = True
        self.user.totp_confirmed = True
        self.user.save()
        return secret

    def test_verify_with_valid_totp_returns_access_token(self):
        # Valid TOTP code exchanges the partial token for a real access token.
        # Uses json.loads(response.content) because TwoFactorVerifyView returns
        # HttpResponse rather than a DRF Response, so response.data is unavailable.
        secret = self._enable_2fa()
        partial_token = self._create_partial_token()
        code = pyotp.TOTP(secret).now()
        response = self.client.post(
            "/v1/user/2fa/verify", {"partial_token": partial_token, "code": code}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("access_token", data)

    def test_verify_with_invalid_code_returns_400(self):
        # Wrong TOTP code does not grant a token
        self._enable_2fa()
        partial_token = self._create_partial_token()
        response = self.client.post(
            "/v1/user/2fa/verify", {"partial_token": partial_token, "code": "000000"}
        )
        self.assertEqual(response.status_code, 400)

    def test_verify_with_expired_partial_token_returns_400(self):
        # Missing or expired partial token is rejected before any code check
        response = self.client.post(
            "/v1/user/2fa/verify",
            {"partial_token": "nonexistent", "code": "123456"},
        )
        self.assertEqual(response.status_code, 400)

    def test_verify_partial_token_is_consumed_after_use(self):
        # Partial token is deleted on first use — a second request with the same
        # token must fail even if the TOTP code is still within its validity window
        secret = self._enable_2fa()
        partial_token = self._create_partial_token()
        code = pyotp.TOTP(secret).now()
        self.client.post(
            "/v1/user/2fa/verify", {"partial_token": partial_token, "code": code}
        )
        response = self.client.post(
            "/v1/user/2fa/verify", {"partial_token": partial_token, "code": code}
        )
        self.assertEqual(response.status_code, 400)

    def test_verify_with_valid_backup_code(self):
        # A backup code can be used in place of a TOTP code
        self._enable_2fa()
        backup_code = "abcdefgh"
        code_hash = hashlib.sha256(backup_code.encode()).hexdigest()
        self.user.backup_codes = json.dumps([code_hash])
        self.user.save()

        partial_token = self._create_partial_token()
        response = self.client.post(
            "/v1/user/2fa/verify",
            {"partial_token": partial_token, "code": backup_code},
        )
        self.assertEqual(response.status_code, 200)

    def test_verify_backup_code_is_consumed_after_use(self):
        # Backup codes are one-time-use — the consumed code is removed from the stored list
        self._enable_2fa()
        backup_code = "abcdefgh"
        code_hash = hashlib.sha256(backup_code.encode()).hexdigest()
        self.user.backup_codes = json.dumps([code_hash])
        self.user.save()

        partial_token = self._create_partial_token()
        response = self.client.post(
            "/v1/user/2fa/verify",
            {"partial_token": partial_token, "code": backup_code},
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        remaining = json.loads(self.user.backup_codes)
        self.assertNotIn(code_hash, remaining)


class TwoFactorDisableTests(BadgrTestCase):
    def _enable_2fa(self, user):
        user.totp_secret = pyotp.random_base32()
        user.totp_enabled = True
        user.totp_confirmed = True
        user.save()

    def test_disable_with_correct_password(self):
        # Correct password clears all 2FA fields from the user record
        user = self.setup_user(password="secret", authenticate=True)
        self._enable_2fa(user)
        response = self.client.post("/v1/user/2fa/disable", {"password": "secret"})
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertFalse(user.totp_enabled)
        self.assertFalse(user.totp_confirmed)
        self.assertIsNone(user.totp_secret)
        self.assertIsNone(user.backup_codes)

    def test_disable_with_wrong_password_returns_400(self):
        # Wrong password is rejected and 2FA state is left unchanged
        user = self.setup_user(password="secret", authenticate=True)
        self._enable_2fa(user)
        response = self.client.post("/v1/user/2fa/disable", {"password": "wrongpass"})
        self.assertEqual(response.status_code, 400)
        user.refresh_from_db()
        self.assertTrue(user.totp_enabled)

    def test_disable_when_2fa_not_enabled_returns_400(self):
        # Cannot disable 2FA that was never enabled
        self.setup_user(password="secret", authenticate=True)
        response = self.client.post("/v1/user/2fa/disable", {"password": "secret"})
        self.assertEqual(response.status_code, 400)

    def test_disable_requires_authentication(self):
        # Unauthenticated requests are rejected
        response = self.client.post("/v1/user/2fa/disable", {"password": "secret"})
        self.assertEqual(response.status_code, 401)
