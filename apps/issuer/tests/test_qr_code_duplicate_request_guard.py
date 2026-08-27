import json
import os
import threading
from unittest import mock

from django.db import OperationalError, connection
from django.test import Client, override_settings

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
class QrCodeDuplicateRequestGuardTests(BadgrTestCase):
    def setUp(self):
        super().setUp()

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
        self.badgeclass = self._badgeclass("Test Badge")
        self.other_badgeclass = self._badgeclass("Other Badge")

    def _badgeclass(self, name):
        badgeclass = BadgeClass.objects.create(
            name=name,
            issuer=self.issuer,
            image="badge.png",
            description="test",
            imageFrame=False,
        )
        badgeclass.badgeclassextension_set.create(
            name="extensions:CompetencyExtension",
            original_json=json.dumps([]),
        )
        badgeclass.badgeclassextension_set.create(
            name="extensions:CategoryExtension",
            original_json=json.dumps({"Category": "singlebadge"}),
        )
        return badgeclass

    def _qr_code(self, badgeclass, auto_issuance, title="QR"):
        return QrCode.objects.create(
            badgeclass=badgeclass,
            issuer=self.issuer,
            title=title,
            createdBy=self.user.email,
            created_by_user=self.user,
            auto_issuance=auto_issuance,
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

    def test_repeat_request_under_auto_issuance_does_not_issue_twice(self):
        qr_code = self._qr_code(self.badgeclass, auto_issuance=True)

        first = self.submit_request(qr_code)
        second = self.submit_request(qr_code)

        self.assertEqual(first.json()["status"], "issued")
        self.assertEqual(second.json()["status"], "duplicate_issued")
        self.assertEqual(
            self.badgeclass.badgeinstances.filter(
                recipient_identifier="janice@example.test"
            ).count(),
            1,
        )

    def test_repeat_request_under_manual_review_does_not_create_second_pending(self):
        qr_code = self._qr_code(self.badgeclass, auto_issuance=False)

        first = self.submit_request(qr_code)
        second = self.submit_request(qr_code)

        self.assertEqual(first.json()["status"], "pending")
        self.assertEqual(second.json()["status"], "duplicate_pending")
        self.assertEqual(
            RequestedBadge.objects.filter(
                badgeclass=self.badgeclass, email="janice@example.test"
            ).count(),
            1,
        )

    def test_same_email_different_badge_works_normally(self):
        qr_code_a = self._qr_code(self.badgeclass, auto_issuance=True)
        qr_code_b = self._qr_code(self.other_badgeclass, auto_issuance=True)

        first = self.submit_request(qr_code_a)
        second = self.submit_request(qr_code_b)

        self.assertEqual(first.json()["status"], "issued")
        self.assertEqual(second.json()["status"], "issued")

    def test_dedup_is_scoped_by_badge_not_by_qr_code(self):
        qr_code_a = self._qr_code(self.badgeclass, auto_issuance=False, title="QR A")
        qr_code_b = self._qr_code(self.badgeclass, auto_issuance=False, title="QR B")

        first = self.submit_request(qr_code_a)
        second = self.submit_request(qr_code_b)

        self.assertEqual(first.json()["status"], "pending")
        self.assertEqual(second.json()["status"], "duplicate_pending")
        self.assertEqual(
            RequestedBadge.objects.filter(
                badgeclass=self.badgeclass, email="janice@example.test"
            ).count(),
            1,
        )

    def test_already_issued_after_manual_approval_blocks_a_repeat_request(self):
        # Mirrors what the issuer's "Badge vergeben" button actually does:
        # award the badge (BatchAssertionsIssue -> badgeclass.issue()), then
        # bulk-delete the now-fulfilled RequestedBadge row (BadgeRequestList).
        qr_code = self._qr_code(self.badgeclass, auto_issuance=False)

        first = self.submit_request(qr_code)
        self.assertEqual(first.json()["status"], "pending")

        self.badgeclass.issue(recipient_id="janice@example.test", notify=False)
        RequestedBadge.objects.filter(
            badgeclass=self.badgeclass, email__iexact="janice@example.test"
        ).delete()

        third = self.submit_request(qr_code)

        self.assertEqual(third.json()["status"], "duplicate_issued")
        self.assertFalse(
            RequestedBadge.objects.filter(
                badgeclass=self.badgeclass, email="janice@example.test"
            ).exists()
        )

    def test_already_issued_via_real_batch_assertions_endpoint_blocks_a_repeat_request(
        self,
    ):
        # Hits the actual endpoint "Badge vergeben" calls (BatchAssertionsIssue,
        # CELERY_ALWAYS_EAGER=True in tests so it runs synchronously), then the
        # actual bulk-delete endpoint (BadgeRequestList), to rule out any
        # discrepancy between the real award path and calling .issue() directly.
        qr_code = self._qr_code(self.badgeclass, auto_issuance=False)

        first = self.submit_request(qr_code)
        self.assertEqual(first.json()["status"], "pending")

        requested_badge = RequestedBadge.objects.get(
            badgeclass=self.badgeclass, email="janice@example.test"
        )

        batch_response = self.client.post(
            "/v1/issuer/issuers/{}/badges/{}/batchAssertions".format(
                self.issuer.entity_id, self.badgeclass.entity_id
            ),
            {
                "assertions": [
                    {
                        "recipient_identifier": "janice@example.test",
                        "recipient_type": "email",
                        "request_entity_id": requested_badge.entity_id,
                    }
                ],
                "create_notification": False,
            },
            format="json",
        )
        self.assertEqual(batch_response.status_code, 202)

        delete_response = self.client.post(
            "/v1/issuer/issuers/{}/badges/{}/requests".format(
                self.issuer.entity_id, self.badgeclass.entity_id
            ),
            {"ids": [requested_badge.entity_id]},
            format="json",
        )
        self.assertEqual(delete_response.status_code, 200)

        third = self.submit_request(qr_code)

        self.assertEqual(third.json()["status"], "duplicate_issued")

    def test_already_issued_blocks_request_via_a_different_manual_qr_code(self):
        auto_qr = self._qr_code(self.badgeclass, auto_issuance=True, title="Auto QR")
        manual_qr = self._qr_code(
            self.badgeclass, auto_issuance=False, title="Manual QR"
        )

        self.submit_request(auto_qr)
        second = self.submit_request(manual_qr)

        self.assertEqual(second.json()["status"], "duplicate_issued")
        self.assertFalse(
            RequestedBadge.objects.filter(
                badgeclass=self.badgeclass, email="janice@example.test"
            ).exists()
        )

    def test_concurrent_requests_do_not_create_duplicate_pending_requests(self):
        # The check-then-act duplicate guard has no DB constraint or locking
        # behind it; two requests racing each other must still only result
        # in one RequestedBadge, not one per request.
        qr_code = self._qr_code(self.badgeclass, auto_issuance=False)
        barrier = threading.Barrier(2)
        results = []

        def worker():
            client = Client()
            barrier.wait()
            response = client.post(
                "/request-badge/{}".format(qr_code.entity_id),
                data=json.dumps(
                    {
                        "firstname": "Janice",
                        "lastname": "M",
                        "email": "janice@example.test",
                        "ageConfirmation": True,
                    }
                ),
                content_type="application/json",
            )
            results.append(response.json()["status"])
            connection.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sorted(results), ["duplicate_pending", "pending"])
        self.assertEqual(
            RequestedBadge.objects.filter(
                badgeclass=self.badgeclass, email="janice@example.test"
            ).count(),
            1,
        )

    def test_concurrent_requests_do_not_issue_duplicate_badges(self):
        qr_code = self._qr_code(self.badgeclass, auto_issuance=True)
        barrier = threading.Barrier(2)
        results = []

        def worker():
            client = Client()
            barrier.wait()
            response = client.post(
                "/request-badge/{}".format(qr_code.entity_id),
                data=json.dumps(
                    {
                        "firstname": "Janice",
                        "lastname": "M",
                        "email": "janice@example.test",
                        "ageConfirmation": True,
                    }
                ),
                content_type="application/json",
            )
            results.append(response.json()["status"])
            connection.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sorted(results), ["duplicate_issued", "issued"])
        self.assertEqual(
            self.badgeclass.badgeinstances.filter(
                recipient_identifier="janice@example.test"
            ).count(),
            1,
        )

    def test_revoked_badge_does_not_block_a_fresh_request(self):
        qr_code = self._qr_code(self.badgeclass, auto_issuance=True)

        first = self.submit_request(qr_code)
        self.assertEqual(first.json()["status"], "issued")

        assertion = self.badgeclass.badgeinstances.get(
            recipient_identifier="janice@example.test"
        )
        assertion.revoke(revocation_reason="test revocation")

        second = self.submit_request(qr_code)

        self.assertEqual(second.json()["status"], "issued")
        self.assertEqual(
            self.badgeclass.badgeinstances.filter(
                recipient_identifier="janice@example.test"
            ).count(),
            2,
        )

    def test_lock_wait_timeout_returns_clean_error_instead_of_crashing(self):
        # If a concurrent request is holding the badge class row lock long
        # enough that MySQL gives up waiting (e.g. a slow external
        # dependency inside that other request), this request must not
        # crash with a raw 500.
        qr_code = self._qr_code(self.badgeclass, auto_issuance=True)

        locked_queryset = mock.Mock()
        locked_queryset.get.side_effect = OperationalError("Lock wait timeout exceeded")
        with mock.patch.object(
            BadgeClass.objects, "select_for_update", return_value=locked_queryset
        ):
            response = self.submit_request(qr_code)

        self.assertEqual(response.status_code, 503)
        self.assertFalse(
            self.badgeclass.badgeinstances.filter(
                recipient_identifier="janice@example.test"
            ).exists()
        )
