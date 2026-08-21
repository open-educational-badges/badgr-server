import json
import os
from unittest import mock

from django.test import override_settings

from issuer import jsonld_loader
from issuer.models import BadgeClass, Issuer, QrCode, RequestedBadge
from mainsite import TOP_DIR
from mainsite.tests.base import BadgrTestCase

COMPETENCY_CONTEXT_URL = (
    "http://example.test/extensions/CompetencyExtension/context.json"
)


@override_settings(
    MEDIA_ROOT=os.path.join(TOP_DIR, "apps/mainsite/tests/testfiles"),
)
class QrCodeAutoIssuanceTests(BadgrTestCase):
    def setUp(self):
        super().setUp()

        # auto-issuance notifies the earner immediately, which renders a PDF
        # that reads the badgeclass's CompetencyExtension; serve the repo's
        # own context file instead of hitting the network for its @context
        with open(
            os.path.join(
                TOP_DIR,
                "apps/mainsite/static/extensions/CompetencyExtension/context.json",
            )
        ) as f:
            jsonld_loader._doc_cache[COMPETENCY_CONTEXT_URL] = {
                "contextUrl": None,
                "documentUrl": COMPETENCY_CONTEXT_URL,
                "document": json.load(f),
            }

        self.user = self.setup_user(
            email="issuer@example.test", token_scope="rw:issuer"
        )
        self.issuer = Issuer.objects.create(
            name="Test Issuer",
            verified=True,
            email="issuer@example.test",
            url="http://example.test",
            linkedinId="",
            created_by=self.user,
        )
        self.badgeclass = BadgeClass.objects.create(
            name="Test Badge",
            issuer=self.issuer,
            image="badge.png",
            description="test",
            imageFrame=False,
        )
        self.badgeclass.badgeclassextension_set.create(
            name="extensions:CompetencyExtension",
            original_json=json.dumps([]),
        )
        self.badgeclass.badgeclassextension_set.create(
            name="extensions:CategoryExtension",
            original_json=json.dumps({"Category": "singlebadge"}),
        )

    def submit_request(self, qr_code, **overrides):
        payload = {
            "firstname": "Janice",
            "lastname": "M",
            "email": "janice@example.test",
            "ageConfirmation": True,
        }
        payload.update(overrides)
        return self.client.post(
            "/request-badge/{}".format(qr_code.entity_id),
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_auto_issuance_issues_badge_immediately(self):
        qr_code = QrCode.objects.create(
            badgeclass=self.badgeclass,
            issuer=self.issuer,
            title="Auto issuance QR",
            createdBy=self.user.email,
            created_by_user=self.user,
            auto_issuance=True,
        )

        response = self.submit_request(qr_code)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            self.badgeclass.badgeinstances.filter(
                recipient_identifier="janice@example.test"
            ).exists()
        )
        self.assertFalse(RequestedBadge.objects.filter(qrcode=qr_code).exists())

    def test_auto_issuance_carries_submitted_name(self):
        from mainsite.utils import get_name

        qr_code = QrCode.objects.create(
            badgeclass=self.badgeclass,
            issuer=self.issuer,
            title="Auto issuance QR",
            createdBy=self.user.email,
            created_by_user=self.user,
            auto_issuance=True,
        )

        self.submit_request(qr_code)

        assertion = self.badgeclass.badgeinstances.get(
            recipient_identifier="janice@example.test"
        )
        self.assertEqual(get_name(assertion), "Janice M")

    def test_auto_issuance_falls_back_to_email_when_name_strips_to_empty(self):
        from mainsite.utils import get_name

        qr_code = QrCode.objects.create(
            badgeclass=self.badgeclass,
            issuer=self.issuer,
            title="Auto issuance QR",
            createdBy=self.user.email,
            created_by_user=self.user,
            auto_issuance=True,
        )

        # firstname/lastname are non-empty (pass the required-field check)
        # but strip_tags() reduces them to nothing, so no recipientProfile
        # name extension gets attached, and there's no BadgeUser account
        # for this email to fall back on either.
        self.submit_request(qr_code, firstname="<script>", lastname="</script>")

        assertion = self.badgeclass.badgeinstances.get(
            recipient_identifier="janice@example.test"
        )
        self.assertEqual(get_name(assertion), "janice@example.test")

    def test_double_encoded_json_body_is_rejected(self):
        # badgr-ui used to double-JSON-encode this request body to work
        # around requestBadge() expecting a raw string; that workaround is
        # gone, so this legacy shape is no longer a valid request.
        qr_code = QrCode.objects.create(
            badgeclass=self.badgeclass,
            issuer=self.issuer,
            title="Legacy double encoding QR",
            createdBy=self.user.email,
            created_by_user=self.user,
            auto_issuance=False,
        )
        payload = {
            "firstname": "Janice",
            "lastname": "M",
            "email": "janice@example.test",
            "ageConfirmation": True,
        }

        response = self.client.post(
            "/request-badge/{}".format(qr_code.entity_id),
            data=json.dumps(json.dumps(payload)),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    def test_manual_review_still_creates_pending_request(self):
        qr_code = QrCode.objects.create(
            badgeclass=self.badgeclass,
            issuer=self.issuer,
            title="Manual review QR",
            createdBy=self.user.email,
            created_by_user=self.user,
            auto_issuance=False,
        )

        response = self.submit_request(qr_code)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            self.badgeclass.badgeinstances.filter(
                recipient_identifier="janice@example.test"
            ).exists()
        )
        self.assertTrue(RequestedBadge.objects.filter(qrcode=qr_code).exists())

    def test_blacklisted_email_returns_clean_error_instead_of_crashing(self):
        # The blacklist check BadgeInstance.save() runs is api_query_is_in_blacklist(),
        # an external service call (mainsite/blacklist.py) - not the local
        # EmailBlacklist table. Mock it to simulate a blacklisted recipient
        # without needing that external service configured.
        qr_code = QrCode.objects.create(
            badgeclass=self.badgeclass,
            issuer=self.issuer,
            title="Auto issuance QR",
            createdBy=self.user.email,
            created_by_user=self.user,
            auto_issuance=True,
        )

        with mock.patch(
            "mainsite.blacklist.api_query_is_in_blacklist", return_value=True
        ):
            response = self.submit_request(qr_code)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            self.badgeclass.badgeinstances.filter(
                recipient_identifier="janice@example.test"
            ).exists()
        )

    def test_issuance_failure_returns_clean_error_instead_of_crashing(self):
        # Any unexpected failure inside badgeclass.issue() (e.g. the
        # blacklist service being unreachable, which raises a bare
        # Exception rather than ValidationError) must not 500 this public,
        # unauthenticated endpoint.
        qr_code = QrCode.objects.create(
            badgeclass=self.badgeclass,
            issuer=self.issuer,
            title="Auto issuance QR",
            createdBy=self.user.email,
            created_by_user=self.user,
            auto_issuance=True,
        )

        with mock.patch(
            "mainsite.blacklist.api_query_is_in_blacklist",
            side_effect=Exception("Blacklist failed to respond"),
        ):
            response = self.submit_request(qr_code)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            self.badgeclass.badgeinstances.filter(
                recipient_identifier="janice@example.test"
            ).exists()
        )
