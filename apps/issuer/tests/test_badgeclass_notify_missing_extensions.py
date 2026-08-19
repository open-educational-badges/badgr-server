import os

from django.test import override_settings

from issuer.models import BadgeClass, Issuer
from mainsite import TOP_DIR
from mainsite.tests.base import BadgrTestCase


@override_settings(
    MEDIA_ROOT=os.path.join(TOP_DIR, "apps/mainsite/tests/testfiles"),
)
class NotifyMissingExtensionsTests(BadgrTestCase):
    """
    GDPR_COMPLIANCE_NOTIFY_ON_FIRST_AWARD defaults to True, so any badge
    class lacking CompetencyExtension/CategoryExtension crashes on a
    recipient's very first award, regardless of the issuer's notify choice.
    Older badge classes predate these extensions being always-set by the
    badgeclass form, so this is a live path, not a hypothetical one.
    """

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
            name="Legacy Badge",
            issuer=self.issuer,
            image="badge.png",
            description="test",
            imageFrame=False,
        )

    def test_notify_does_not_crash_without_competency_or_category_extension(self):
        assertion = self.badgeclass.issue(
            recipient_id="recipient@example.test",
            notify=True,
        )
        self.assertIsNotNone(assertion.pk)
