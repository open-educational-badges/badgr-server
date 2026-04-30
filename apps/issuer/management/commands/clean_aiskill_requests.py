# encoding: utf-8


from django.core.management import BaseCommand
from django.utils import timezone

from dateutil.relativedelta import relativedelta

from issuer.models import Issuer


class Command(BaseCommand):
    help = "Delete old AiSkillRequest objects"

    def handle(self, *args, **options):

        # find issuers with aiskill_requests
        issuers = Issuer.objects.filter(aiskill_requests__isnull=False).distinct()

        count = 0
        for issuer in issuers:
            dt_end_mo = issuer.quota_period_start
            while(dt_end_mo < timezone.now()):
                dt_end_mo = dt_end_mo + relativedelta(months=1)

            # set filter date one month before the current period start
            dt_start_mo = dt_end_mo - relativedelta(months=2)

            # filter requests and delete
            old_aiskillrequests = issuer.aiskill_requests.filter(created_at__date__lte=dt_start_mo)
            count += len(old_aiskillrequests)

            old_aiskillrequests.delete()

        print(f'Deleted {count} AiSkillRequests')

