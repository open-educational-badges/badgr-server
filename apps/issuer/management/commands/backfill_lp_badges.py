from django.core.management import BaseCommand
from django.db.models import Count

from issuer.models import BadgeInstance, LearningPath


class Command(BaseCommand):
    help = (
        "Issue learning path badges to recipients who have earned enough component "
        "badges but never received the LP badge — covers registered and unregistered "
        "users missed by the activation task."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print what would be issued without writing anything",
        )
        parser.add_argument(
            "--issuer",
            dest="issuer_entity_id",
            default=None,
            help="Limit to a specific issuer entity_id",
        )
        parser.add_argument(
            "--learning-path",
            dest="lp_entity_id",
            default=None,
            help="Limit to a specific learning path entity_id",
        )
        parser.add_argument(
            "--notify",
            action="store_true",
            help="Send notification emails to recipients (default: off)",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        notify = options["notify"]

        issued = 0
        skipped = 0
        errors = 0

        learningpaths = LearningPath.objects.filter(
            archived=False, participationBadge__isnull=False
        ).select_related("participationBadge")

        if options["issuer_entity_id"]:
            learningpaths = learningpaths.filter(
                issuer__entity_id=options["issuer_entity_id"]
            )
        if options["lp_entity_id"]:
            learningpaths = learningpaths.filter(entity_id=options["lp_entity_id"])

        for lp in learningpaths:
            lp_badge_ids = lp.learningpathbadge_set.values_list("badge_id", flat=True)
            if not lp_badge_ids:
                continue

            # find every unique recipient that has earned enough component badges
            qualifying = (
                BadgeInstance.objects.filter(
                    badgeclass_id__in=lp_badge_ids, revoked=False
                )
                .values("recipient_identifier")
                .annotate(badge_count=Count("id"))
                .filter(badge_count__gte=lp.required_badges_count)
                .values_list("recipient_identifier", flat=True)
            )

            for recipient in qualifying:
                if not lp.user_should_have_badge(recipient):
                    skipped += 1
                    continue

                if dry_run:
                    self.stdout.write(
                        f"DRY-RUN: would issue LP badge for '{lp.name}' → {recipient}"
                    )
                    issued += 1
                else:
                    try:
                        lp.issue_participation_badge(recipient, notify=notify)
                        self.stdout.write(
                            f"Issued LP badge for '{lp.name}' → {recipient}"
                        )
                        issued += 1
                    except Exception as e:
                        self.stderr.write(
                            f"ERROR issuing for '{lp.name}' → {recipient}: {e}"
                        )
                        errors += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"{'DRY-RUN: ' if dry_run else ''}"
                f"Issued {issued}, skipped {skipped} (already have badge), "
                f"errors {errors}"
            )
        )
