from celery import shared_task
from issuer.models import LearningPath
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

        for user in BadgeUser.objects.all():
            for identifier in user.all_verified_recipient_identifiers:
                if learning_path.user_should_have_badge(identifier):
                    learning_path.issue_participation_badge(identifier, notify=True)

        return f"Successfully processed learning path activation for {pk}"

    except LearningPath.DoesNotExist:
        return f"LearningPath with pk {pk} not found"
    except Exception as e:
        logger.error(f"Error processing learning path activation {pk}: {str(e)}")
        raise
