import json

from django.core.management import BaseCommand
from django.db import transaction

from issuer.models import LearningPath


class Command(BaseCommand):
    help = (
        "Backfill the competency extension for micro degrees: syncs the aggregated "
        "path competencies onto each participation badge class and onto already "
        "issued participation badge assertions"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", action="store_true", help="Simulate the changes"
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        badgeclasses_updated = 0
        assertions_updated = 0

        with transaction.atomic():
            for learningpath in LearningPath.objects.all():
                competencies = learningpath.competency_extension_items()
                if not competencies:
                    continue
                original_json = json.dumps(competencies)

                if dry_run:
                    self.stdout.write(
                        f"DRY-RUN: would sync {len(competencies)} competencies for "
                        f"learning path '{learningpath.name}'"
                    )
                else:
                    learningpath.sync_participation_badge_competencies()
                badgeclasses_updated += 1

                assertions = learningpath.participationBadge.badgeinstances.filter(
                    revoked=False
                )
                for assertion in assertions:
                    if dry_run:
                        assertions_updated += 1
                        continue
                    extension, created = (
                        assertion.badgeinstanceextension_set.get_or_create(
                            name="extensions:CompetencyExtension",
                            defaults={"original_json": original_json},
                        )
                    )
                    if not created:
                        existing = json.loads(extension.original_json)
                        if existing:
                            # assertion already carries competencies; leave it alone
                            continue
                        extension.original_json = original_json
                        extension.save()
                    assertion.get_json(obi_version="3_0", force_recreate=True)
                    assertions_updated += 1

            if dry_run:
                transaction.set_rollback(True)

        self.stdout.write(
            self.style.SUCCESS(
                f"{'DRY-RUN: would update' if dry_run else 'Updated'} "
                f"{badgeclasses_updated} participation badge classes and "
                f"{assertions_updated} assertions"
            )
        )
