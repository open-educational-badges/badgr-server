import datetime
import os

from django.test import override_settings

from issuer.models import BadgeClass, Issuer
from mainsite import TOP_DIR
from mainsite.tests.base import BadgrTestCase


@override_settings(
    MEDIA_ROOT=os.path.join(TOP_DIR, "apps/mainsite/tests/testfiles"),
    # notifying the earner renders the badge PDF, which needs badgeclass
    # extensions this test's minimal badgeclass does not have
    GDPR_COMPLIANCE_NOTIFY_ON_FIRST_AWARD=False,
)
class DateOfBirthTests(BadgrTestCase):
    def setUp(self):
        super().setUp()

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

    def issue_url(self, version="v1"):
        if version == "v1":
            return "/v1/issuer/issuers/{}/badges/{}/assertions".format(
                self.issuer.entity_id, self.badgeclass.entity_id
            )
        return "/v2/badgeclasses/{}/assertions".format(self.badgeclass.entity_id)

    def test_issue_stores_date_of_birth(self):
        assertion = self.badgeclass.issue(
            recipient_id="recipient@example.test",
            date_of_birth=datetime.date(1990, 1, 2),
        )
        assertion.refresh_from_db()
        self.assertEqual(assertion.date_of_birth, datetime.date(1990, 1, 2))

    def test_date_of_birth_defaults_to_none(self):
        assertion = self.badgeclass.issue(recipient_id="recipient@example.test")
        assertion.refresh_from_db()
        self.assertIsNone(assertion.date_of_birth)

    def test_ob3_json_includes_date_of_birth(self):
        assertion = self.badgeclass.issue(
            recipient_id="recipient@example.test",
            date_of_birth=datetime.date(1990, 1, 2),
        )
        credential_subject = assertion.get_json_3_0()["credentialSubject"]
        self.assertEqual(credential_subject["dateOfBirth"], "1990-01-02")

    def test_ob3_json_omits_date_of_birth_when_absent(self):
        assertion = self.badgeclass.issue(recipient_id="recipient@example.test")
        credential_subject = assertion.get_json_3_0()["credentialSubject"]
        self.assertNotIn("dateOfBirth", credential_subject)

    def test_v1_issue_with_date_of_birth(self):
        response = self.client.post(
            self.issue_url("v1"),
            {
                "recipient_identifier": "recipient@example.test",
                "recipient_type": "email",
                "create_notification": False,
                "date_of_birth": "1990-01-02",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["date_of_birth"], "1990-01-02")

        assertion = self.badgeclass.badgeinstances.get(
            entity_id=response.data["slug"]
        )
        self.assertEqual(assertion.date_of_birth, datetime.date(1990, 1, 2))

    def test_v1_issue_without_date_of_birth(self):
        response = self.client.post(
            self.issue_url("v1"),
            {
                "recipient_identifier": "recipient@example.test",
                "recipient_type": "email",
                "create_notification": False,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201)

        assertion = self.badgeclass.badgeinstances.get(
            entity_id=response.data["slug"]
        )
        self.assertIsNone(assertion.date_of_birth)

    def test_v1_issue_with_invalid_date_of_birth(self):
        response = self.client.post(
            self.issue_url("v1"),
            {
                "recipient_identifier": "recipient@example.test",
                "recipient_type": "email",
                "create_notification": False,
                "date_of_birth": "02.01.1990",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_v2_issue_and_read_date_of_birth(self):
        response = self.client.post(
            self.issue_url("v2"),
            {
                "recipient": {
                    "identity": "recipient@example.test",
                    "type": "email",
                },
                "dateOfBirth": "1990-01-02",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["result"][0]["dateOfBirth"], "1990-01-02")

        entity_id = response.data["result"][0]["entityId"]
        assertion = self.badgeclass.badgeinstances.get(entity_id=entity_id)
        self.assertEqual(assertion.date_of_birth, datetime.date(1990, 1, 2))

        response = self.client.get("/v2/assertions/{}".format(entity_id))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["result"][0]["dateOfBirth"], "1990-01-02")

    def test_v2_issue_without_date_of_birth(self):
        response = self.client.post(
            self.issue_url("v2"),
            {
                "recipient": {
                    "identity": "recipient@example.test",
                    "type": "email",
                },
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data["result"][0]["dateOfBirth"])
