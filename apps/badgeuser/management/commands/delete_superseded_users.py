import datetime

from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.core.management.base import BaseCommand
from django.db.models import Count

from badgeuser.models import BadgeUser, CachedEmailAddress


class Command(BaseCommand):
    def handle(self, *args, **options):
        self.log(
            "started delete_superseded_users at {}".format(datetime.datetime.now())
        )
        # All verified emails
        cached = CachedEmailAddress.objects.filter(verified=True)

        chunk_size = 1000
        start_index = 0
        processing_index = 1

        continue_processing = True
        while continue_processing:
            start = start_index
            end = start_index + chunk_size

            # All non-unique emails
            dup_emails = (
                BadgeUser.objects.values("email")
                .annotate(Count("email"))
                .filter(email__count__gt=1)
            )[start:end]

            self.log("----------------------------------------")
            self.log(
                "Processing chunk {}. Duplicates: {}".format(
                    processing_index, len(dup_emails)
                )
            )
            self.log("----------------------------------------")

            for dup in dup_emails:
                try:
                    # Find the verified cached email for this user email
                    verified = cached.get(email=dup["email"])
                    self.log("Verified user ID: {}".format(verified.user_id))

                    # get all the users with this email expect the verified id, delete them
                    users = BadgeUser.objects.filter(email=verified.email).exclude(
                        id=verified.user_id
                    )

                    for user in users:
                        if not user.cached_emails():
                            self.log(
                                "   Deleting duplicate user ID: {}".format(user.id)
                            )
                            BadgeUser.delete(user)

                except MultipleObjectsReturned:
                    self.log(
                        "[ERROR] More than one verified CachedEmail found for a duplicate entry."
                    )
                except ObjectDoesNotExist:
                    self.log(
                        "[ERROR] No verified CachedEmail found for a duplicate entry."
                    )

            processing_index = processing_index + 1
            continue_processing = len(dup_emails) >= chunk_size
            start_index += chunk_size

        self.log(
            "finished delete_superseded_users at {}".format(datetime.datetime.now())
        )

    def log(self, message):
        self.stdout.write(message)
