from django.core.management import BaseCommand
from django.db import transaction

from issuer.models import BadgeInstanceExtension, LearningPath


class Command(BaseCommand):
    help = (
        "Backfill the recipientProfile extension on micro degree assertions issued "
        "to unregistered recipients, carrying the name over from their component "
        "badge assertions. Optionally resend the notification email."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simulate the changes without writing",
        )
        parser.add_argument(
            "--resend-emails", action="store_true", help="Resend notification emails"
        )
        parser.add_argument(
            "--learning-path",
            dest="lp_slug",
            default=None,
            help="Limit to a specific learning path entity_id",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        resend_emails = options["resend_emails"]
        lp_slug = options["lp_slug"]

        assertions_updated = 0
        emails_sent = 0
        skipped = 0

        learningpaths = LearningPath.objects.all()
        if lp_slug:
            learningpaths = learningpaths.filter(entity_id=lp_slug)

        with transaction.atomic():
            for lp in learningpaths:
                badgeclasses = [lpb.badge for lpb in lp.learningpath_badges]
                if not badgeclasses:
                    continue

                assertions = lp.participationBadge.badgeinstances.filter(revoked=False)

                for assertion in assertions:
                    # skip if already has a recipientProfile
                    if assertion.badgeinstanceextension_set.filter(
                        name="extensions:recipientProfile"
                    ).exists():
                        skipped += 1
                        if resend_emails:
                            if dry_run:
                                self.stdout.write(
                                    f"DRY-RUN: would resend email to {assertion.recipient_identifier}"
                                )
                            else:
                                assertion.notify_earner()
                            emails_sent += 1
                        continue

                    profile_ext = BadgeInstanceExtension.objects.filter(
                        badgeinstance__recipient_identifier=assertion.recipient_identifier,
                        badgeinstance__badgeclass__in=badgeclasses,
                        name="extensions:recipientProfile",
                    ).first()

                    if not profile_ext:
                        self.stdout.write(
                            f"No recipientProfile found for {assertion.recipient_identifier} "
                            f"in LP '{lp.name}' — skipping"
                        )
                        skipped += 1
                        continue

                    if dry_run:
                        self.stdout.write(
                            f"DRY-RUN: would backfill name for {assertion.recipient_identifier} "
                            f"in LP '{lp.name}'"
                        )
                    else:
                        assertion.badgeinstanceextension_set.create(
                            name="extensions:recipientProfile",
                            original_json=profile_ext.original_json,
                        )
                        assertion.get_json(obi_version="3_0", force_recreate=True)

                    assertions_updated += 1

                    if resend_emails:
                        if dry_run:
                            self.stdout.write(
                                f"DRY-RUN: would resend email to {assertion.recipient_identifier}"
                            )
                        else:
                            assertion.notify_earner()
                        emails_sent += 1

            if dry_run:
                transaction.set_rollback(True)

        self.stdout.write(
            self.style.SUCCESS(
                f"{'DRY-RUN: ' if dry_run else ''}"
                f"Updated {assertions_updated} assertions, "
                f"skipped {skipped}, "
                f"{'would send' if dry_run else 'sent'} {emails_sent} emails"
            )
        )
