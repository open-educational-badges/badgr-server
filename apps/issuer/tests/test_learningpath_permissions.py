import os

from django.test import override_settings

from issuer.models import (
    BadgeClass,
    IssuerStaff,
    LearningPath,
    NetworkMembership,
    Issuer,
)
from mainsite import TOP_DIR
from mainsite.tests.base import BadgrTestCase


@override_settings(MEDIA_ROOT=os.path.join(TOP_DIR, "apps/mainsite/tests/testfiles"))
class LearningPathPermissionTests(BadgrTestCase):
    def setUp(self):
        super().setUp()

        self.network_owner = self.setup_user(email="owner@network.com")
        self.network = Issuer.objects.create(
            name="Test Network",
            is_network=True,
            verified=True,
            email="network@test.com",
            url="http://test.com",
            linkedinId="",
            created_by=self.network_owner,
        )  # ensure_owner() in save() automatically creates IssuerStaff for created_by

        self.partner = Issuer.objects.create(
            name="Partner Issuer",
            is_network=False,
            verified=True,
            email="partner@test.com",
            url="http://partner.com",
            linkedinId="",
            created_by=self.network_owner,
        )
        NetworkMembership.objects.create(network=self.network, issuer=self.partner)

        self.partner_staff = self.setup_user(email="staff@partner.com")
        IssuerStaff.objects.create(
            issuer=self.partner, user=self.partner_staff, role=IssuerStaff.ROLE_STAFF
        )

        self.participation_badge = BadgeClass.objects.create(
            name="Test LP Badge",
            issuer=self.network,
            image="badge.png",
            description="test",
        )
        self.lp = LearningPath.objects.create(
            name="Test LP",
            issuer=self.network,
            participationBadge=self.participation_badge,
            activated=True,
            required_badges_count=1,
            description="test",
        )

    def test_partner_issuer_staff_can_access_network_learning_path(self):
        self.client.force_authenticate(user=self.partner_staff)
        response = self.client.get(
            f"/v1/issuer/issuers/{self.network.entity_id}/learningpath/{self.lp.entity_id}"
        )
        self.assertEqual(response.status_code, 200)

    def test_direct_network_staff_can_access_network_learning_path(self):
        self.client.force_authenticate(user=self.network_owner)
        response = self.client.get(
            f"/v1/issuer/issuers/{self.network.entity_id}/learningpath/{self.lp.entity_id}"
        )
        self.assertEqual(response.status_code, 200)

    def test_random_user_cannot_access_network_learning_path(self):
        random_user = self.setup_user(email="random@test.com")
        self.client.force_authenticate(user=random_user)
        response = self.client.get(
            f"/v1/issuer/issuers/{self.network.entity_id}/learningpath/{self.lp.entity_id}"
        )
        self.assertEqual(response.status_code, 404)
