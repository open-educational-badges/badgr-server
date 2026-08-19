from celery import shared_task
from django.db.models import Count

from issuer.models import BadgeInstance, LearningPath
from badgeuser.models import BadgeUser

import logging

logger = logging.getLogger("Badgr.Events")


@shared_task
def process_learning_path_activation(pk):
    """
    Process Micro-Degree-Badge issuance for all users when a learning path is activated.
    """

    try:
        learning_path = LearningPath.objects.get(pk=pk)

        # registered users
        for user in BadgeUser.objects.all():
            for identifier in user.all_verified_recipient_identifiers:
                if learning_path.user_should_have_badge(identifier):
                    learning_path.issue_participation_badge(identifier, notify=True)

        # unregistered recipients (email-only, no BadgeUser account)
        lp_badge_ids = learning_path.learningpathbadge_set.values_list(
            "badge_id", flat=True
        )
        unregistered_qualifiers = (
            BadgeInstance.objects.filter(
                badgeclass_id__in=lp_badge_ids, revoked=False, user__isnull=True
            )
            .values("recipient_identifier")
            .annotate(badge_count=Count("id"))
            .filter(badge_count__gte=learning_path.required_badges_count)
            .values_list("recipient_identifier", flat=True)
        )
        for identifier in unregistered_qualifiers:
            if learning_path.user_should_have_badge(identifier):
                learning_path.issue_participation_badge(identifier, notify=True)

        return f"Successfully processed learning path activation for {pk}"

    except LearningPath.DoesNotExist:
        return f"LearningPath with pk {pk} not found"
    except Exception as e:
        logger.error(f"Error processing learning path activation {pk}: {str(e)}")
        raise
