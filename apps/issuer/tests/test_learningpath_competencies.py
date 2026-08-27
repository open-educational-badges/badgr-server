import json
import os

from django.test import override_settings

from issuer import jsonld_loader
from issuer.models import BadgeClass, Issuer, LearningPath, LearningPathBadge
from mainsite import TOP_DIR
from mainsite.badge_pdf import BadgePDFCreator
from mainsite.tests.base import BadgrTestCase

COMPETENCY_CONTEXT_URL = (
    "http://example.test/extensions/CompetencyExtension/context.json"
)


def competency(name, framework_identifier="", study_load=60):
    return {
        "@context": COMPETENCY_CONTEXT_URL,
        "type": ["Extension", "extensions:CompetencyExtension"],
        "name": name,
        "description": "%s description" % name,
        "framework": "esco" if framework_identifier else "",
        "framework_identifier": framework_identifier,
        "source": "manual",
        "studyLoad": study_load,
        "category": "skill",
    }


ESCO_URI = "http://data.europa.eu/esco/skill/test-skill"


@override_settings(
    MEDIA_ROOT=os.path.join(TOP_DIR, "apps/mainsite/tests/testfiles"),
    # notifying the earner renders the badge PDF, which needs badgeclass
    # extensions this test's minimal badgeclasses do not have
    GDPR_COMPLIANCE_NOTIFY_ON_FIRST_AWARD=False,
)
class LearningPathCompetencyTests(BadgrTestCase):
    def setUp(self):
        super().setUp()

        # the OB 3.0 JSON-LD normalization resolves the extension's @context;
        # serve the repo's own context file instead of hitting the network
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

        self.badge_one = self._badgeclass(
            "Badge One",
            [competency("Skill A", ESCO_URI, 60), competency("Skill B", "", 30)],
        )
        self.badge_two = self._badgeclass(
            "Badge Two",
            [competency("Skill A", ESCO_URI, 45), competency("Skill C", "", 15)],
        )

        self.participation_badge = self._badgeclass("Test MD Badge", [])

        self.lp = LearningPath.objects.create(
            name="Test LP",
            issuer=self.issuer,
            participationBadge=self.participation_badge,
            activated=True,
            required_badges_count=2,
            description="test",
        )
        LearningPathBadge.objects.create(
            learning_path=self.lp, badge=self.badge_one, order=0
        )
        LearningPathBadge.objects.create(
            learning_path=self.lp, badge=self.badge_two, order=1
        )

    def _badgeclass(self, name, competencies):
        badgeclass = BadgeClass.objects.create(
            name=name,
            issuer=self.issuer,
            image="badge.png",
            description="test",
            imageFrame=False,
        )
        badgeclass.badgeclassextension_set.create(
            name="extensions:CompetencyExtension",
            original_json=json.dumps(competencies),
        )
        return badgeclass

    def test_competencies_are_aggregated_and_deduplicated(self):
        items = self.lp.competency_extension_items()

        self.assertEqual(
            sorted(item["name"] for item in items),
            ["Skill A", "Skill B", "Skill C"],
        )

        skill_a = next(item for item in items if item["name"] == "Skill A")
        self.assertEqual(skill_a["studyLoad"], 105)
        self.assertEqual(skill_a["hours"], 1)
        self.assertEqual(skill_a["minutes"], 45)

    def test_auto_issued_micro_degree_carries_competencies(self):
        recipient = "recipient@example.test"
        self.badge_one.issue(recipient_id=recipient)
        self.badge_two.issue(recipient_id=recipient)

        assertion = self.participation_badge.badgeinstances.get(
            recipient_identifier=recipient
        )
        extension = assertion.badgeinstanceextension_set.get(
            name="extensions:CompetencyExtension"
        )
        competencies = json.loads(extension.original_json)
        self.assertEqual(
            sorted(item["name"] for item in competencies),
            ["Skill A", "Skill B", "Skill C"],
        )

        assertion_json = assertion.get_json(obi_version="2_0")
        self.assertEqual(
            sorted(
                item["name"]
                for item in assertion_json["extensions:CompetencyExtension"]
            ),
            ["Skill A", "Skill B", "Skill C"],
        )

    def test_add_learningpath_badges_does_not_crash_without_leaf_category_extension(
        self,
    ):
        # generate_pdf() reaches add_learningpath_badges() for a badge class
        # whose CategoryExtension is "learningpath" (as set by badgr-ui when
        # a learning path is created), passing it the leaf badge instances.
        # Those leaf badges (badge_one/badge_two here) don't carry a
        # CategoryExtension themselves -- this must not crash. Calling the
        # method directly (rather than through generate_pdf -> doc.build())
        # isolates this from unrelated PDF-rendering/static-asset concerns.
        recipient = "recipient@example.test"
        instance_one = self.badge_one.issue(recipient_id=recipient)
        instance_two = self.badge_two.issue(recipient_id=recipient)

        creator = BadgePDFCreator()
        story = []
        creator.add_learningpath_badges(
            story,
            [instance_one, instance_two],
            "Recipient Name",
            "Test MD Badge",
            competencies=[],
        )

        self.assertTrue(len(story) > 0)

    def test_sync_participation_badge_competencies(self):
        self.lp.sync_participation_badge_competencies()

        extension = self.participation_badge.badgeclassextension_set.get(
            name="extensions:CompetencyExtension"
        )
        competencies = json.loads(extension.original_json)
        self.assertEqual(len(competencies), 3)
