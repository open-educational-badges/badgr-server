# encoding: utf-8


from datetime import timedelta
import json
import os
import six
import urllib.parse

from django.conf import settings
import dateutil.parser
from django.core.files.storage import DefaultStorage
from django.db import models, transaction
from django.urls import resolve, Resolver404
from django.utils import timezone

from issuer.utils import sanitize_id
from mainsite.utils import fetch_remote_file_to_storage, list_of, OriginSetting


def resolve_source_url_referencing_local_object(source_url):
    if source_url.startswith(OriginSetting.HTTP):
        try:
            match = resolve(urllib.parse.urlparse(source_url).path)
            return match
        except Resolver404:
            pass


class BaseOpenBadgeObjectManager(models.Manager):
    def get_local_object(self, source_url):
        match = resolve_source_url_referencing_local_object(source_url)
        if match:
            try:
                return self.get(entity_id=match.kwargs.get("entity_id"))
            except self.model.DoesNotExist:
                return None


class IssuerManager(BaseOpenBadgeObjectManager):
    ALLOWED_MINE_TYPES = [
        "image/png",
        "image/gif",
        "image/jpeg",
        "image/svg+xml",
    ]

    def update_from_ob2(self, issuer_obo, original_json=None):
        image = self.image_from_ob2(issuer_obo)
        return self.update_or_create(
            source_url=issuer_obo.get("id"),
            defaults=dict(
                name=issuer_obo.get("name"),
                description=issuer_obo.get("description", None),
                url=issuer_obo.get("url", None),
                email=issuer_obo.get("email", None),
                image=image,
                original_json=original_json,
            ),
        )

    def image_from_ob2(self, issuer_obo):
        image_url = issuer_obo.get("image", None)
        image = None
        if image_url:
            if isinstance(image_url, dict):
                image_url = image_url.get("id")
            image = _fetch_image_and_get_file(
                image_url, self.ALLOWED_MINE_TYPES, upload_to="remote/issuer"
            )
        return image

    def get_or_create_from_ob2(
        self, issuer_obo, source=None, original_json=None, image=None
    ):
        source_url = issuer_obo.get("id")
        local_object = self.get_local_object(source_url)
        if local_object:
            return local_object, False

        return self.get_or_create(
            source_url=source_url,
            defaults=dict(
                source=source if source is not None else "local",
                name=issuer_obo.get("name"),
                description=issuer_obo.get("description", None),
                url=issuer_obo.get("url", None),
                email=issuer_obo.get("email", None),
                image=image,
                original_json=original_json,
            ),
        )


class BadgeClassManager(BaseOpenBadgeObjectManager):
    ALLOWED_MINE_TYPES = [
        "image/png",
        "image/svg+xml",
    ]

    @transaction.atomic
    def create(self, **kwargs):
        obj = self.model(**kwargs)
        obj.save()
        return obj

    def update_from_ob2(self, issuer, badgeclass_obo, original_json=None):
        criteria_url = None
        criteria_text = None
        criteria = badgeclass_obo.get("criteria", None)
        if isinstance(criteria, str):
            criteria_url = criteria
        elif criteria.get("type", "Criteria") == "Criteria":
            criteria_url = criteria.get("id", None)
            criteria_text = criteria.get("narrative", None)

        image = self.image_from_ob2(badgeclass_obo)

        return self.update_or_create(
            source_url=badgeclass_obo.get("id"),
            defaults=dict(
                issuer=issuer,
                name=badgeclass_obo.get("name"),
                description=badgeclass_obo.get("description", None),
                image=image,
                criteria_url=criteria_url,
                criteria_text=criteria_text,
                original_json=original_json,
            ),
        )

    def image_from_ob2(self, badgeclass_obo):
        image_url = badgeclass_obo.get("image")
        if isinstance(image_url, dict):
            image_url = image_url.get("id")

        return _fetch_image_and_get_file(
            image_url, self.ALLOWED_MINE_TYPES, upload_to="remote/badgeclass"
        )

    def get_or_create_from_ob2(
        self, issuer, badgeclass_obo, source=None, original_json=None, image=None
    ):
        source_url = badgeclass_obo.get("id")
        local_object = self.get_local_object(source_url)
        if local_object:
            return local_object, False

        criteria_url = None
        criteria_text = None
        criteria = badgeclass_obo.get("criteria", None)
        if isinstance(criteria, str):
            criteria_url = criteria
        elif criteria.get("type", "Criteria") == "Criteria":
            criteria_url = criteria.get("id", None)
            criteria_text = criteria.get("narrative", None)

        return self.get_or_create(
            source_url=source_url,
            defaults=dict(
                issuer=issuer,
                source=source if source is not None else "local",
                name=badgeclass_obo.get("name"),
                description=badgeclass_obo.get("description", None),
                image=image,
                criteria_url=criteria_url,
                criteria_text=criteria_text,
                original_json=original_json,
            ),
        )


class BadgeInstanceEvidenceManager(models.Manager):
    @transaction.atomic
    def create_from_ob2(self, badgeinstance, evidence_obo):
        if isinstance(evidence_obo, six.string_types):
            return self.create(
                badgeinstance=badgeinstance,
                evidence_url=evidence_obo,
                narrative=None,
                original_json="",
            )
        return self.create(
            badgeinstance=badgeinstance,
            evidence_url=evidence_obo.get("id", None),
            narrative=evidence_obo.get("narrative", None),
            original_json=json.dumps(evidence_obo),
        )


def _fetch_image_and_get_file(url, allowed_mime_types, upload_to=""):
    status_code, storage_name = fetch_remote_file_to_storage(
        url, upload_to=upload_to, allowed_mime_types=allowed_mime_types
    )
    if status_code == 200:
        image = DefaultStorage().open(storage_name)
        image.name = storage_name
        return image


class BadgeInstanceManager(BaseOpenBadgeObjectManager):
    ALLOWED_MINE_TYPES = [
        "image/png",
        "image/svg+xml",
    ]

    def update_from_ob2(
        self,
        badgeclass,
        assertion_obo,
        recipient_identifier,
        recipient_type="email",
        original_json=None,
    ):
        image = None
        image_url = assertion_obo.get("image", None)
        if isinstance(image_url, dict):
            image_url = image_url.get("id")
        if image_url:
            image = _fetch_image_and_get_file(
                image_url, self.ALLOWED_MINE_TYPES, upload_to="remote/assertion"
            )

        issued_on = None
        if "issuedOn" in assertion_obo:
            issued_on = dateutil.parser.parse(assertion_obo.get("issuedOn"))

        updated, created = self.update_or_create(
            source_url=assertion_obo.get("id"),
            defaults=dict(
                recipient_identifier=recipient_identifier,
                recipient_type=recipient_type,
                hashed=assertion_obo.get("recipient", {}).get("hashed", True),
                original_json=original_json,
                badgeclass=badgeclass,
                issuer=badgeclass.cached_issuer,
                image=image,
                acceptance=self.model.ACCEPTANCE_ACCEPTED,
                narrative=assertion_obo.get("narrative", None),
                issued_on=issued_on,
            ),
        )
        evidence = list_of(assertion_obo.get("evidence", None))
        evidence_items = []
        for item in evidence:
            if isinstance(item, six.string_types):
                evidence_items.append(
                    {"evidence_url": item}
                )  # convert string/url type evidence to consistent format
            elif hasattr(item, "get"):
                evidence_items.append(
                    {"evidence_url": item.get("id"), "narrative": item.get("narrative")}
                )
        updated.evidence_items = evidence_items

        return updated, created

    def image_from_ob2(self, badgeclass_image, assertion_obo):
        image_url = assertion_obo.get("image", None)
        image = None
        if image_url is None:
            image = badgeclass_image
            image.name = os.path.split(image.name)[1]
        else:
            if isinstance(image_url, dict):
                image_url = image_url.get("id")
            image = _fetch_image_and_get_file(
                image_url, self.ALLOWED_MINE_TYPES, upload_to="remote/assertion"
            )
        return image

    @transaction.atomic
    def get_or_create_from_ob2(
        self,
        badgeclass,
        assertion_obo,
        recipient_identifier,
        recipient_type="email",
        source=None,
        original_json=None,
        image=None,
    ):
        source_url = assertion_obo.get("id")
        local_object = self.get_local_object(source_url)
        if local_object:
            return local_object, False

        issued_on = None
        if "issuedOn" in assertion_obo:
            issued_on = dateutil.parser.parse(assertion_obo.get("issuedOn"))

        badgeinstance, created = self.get_or_create(
            source_url=assertion_obo.get("id"),
            defaults=dict(
                recipient_identifier=recipient_identifier,
                recipient_type=recipient_type,
                hashed=assertion_obo.get("recipient", {}).get("hashed", True),
                source=source if source is not None else "local",
                original_json=original_json,
                badgeclass=badgeclass,
                issuer=badgeclass.cached_issuer,
                image=image,
                acceptance=self.model.ACCEPTANCE_ACCEPTED,
                narrative=assertion_obo.get("narrative", None),
                issued_on=issued_on,
            ),
        )
        if created:
            evidence = list_of(assertion_obo.get("evidence", None))
            if evidence:
                from issuer.models import BadgeInstanceEvidence

                for evidence_item in evidence:
                    if isinstance(evidence_item, str):
                        # we got an IRI as 'evidence' value
                        BadgeInstanceEvidence.objects.create(
                            badgeinstance=badgeinstance, evidence_url=evidence_item
                        )
                    else:
                        # we got a single evidence item dict
                        BadgeInstanceEvidence.objects.create_from_ob2(
                            badgeinstance, evidence_item
                        )

        return badgeinstance, created

    def create(
        self,
        evidence=None,
        extensions=None,
        notify=False,
        allow_uppercase=False,
        badgr_app=None,
        microdegree_id=None,
        issuerSlug=None,
        **kwargs,
    ):
        """
        Convenience method to award a badge to a recipient_id
        :param allow_uppercase: bool
        :type badgeclass: BadgeClass
        :type issuer: Issuer
        :type notify: bool
        :type evidence: list of dicts(url=string, narrative=string)
        """
        recipient_identifier = kwargs.pop("recipient_identifier")
        recipient_identifier = sanitize_id(
            recipient_identifier,
            kwargs.get("recipient_type", "email"),
            allow_uppercase=allow_uppercase,
        )

        from issuer.models import Issuer

        badgeclass = kwargs.pop("badgeclass", None)
        if issuerSlug:
            issuer = Issuer.objects.get(entity_id=issuerSlug)
        else:
            issuer = kwargs.pop("issuer", badgeclass.issuer)

        if badgeclass and badgeclass.expiration:
            issued_on = kwargs.get("issued_on", timezone.now())
            kwargs["expires_at"] = issued_on + timedelta(days=badgeclass.expiration)

        # self.model would be a BadgeInstance
        new_instance = self.model(
            recipient_identifier=recipient_identifier,
            badgeclass=badgeclass,
            issuer=issuer,
            **kwargs,
        )

        with transaction.atomic():
            new_instance.save()

            if badgeclass and badgeclass.imageFrame:
                badge_extensions = badgeclass.cached_extensions()
                categoryExtension = badge_extensions.get(
                    name="extensions:CategoryExtension"
                )
                category = json.loads(categoryExtension.original_json)["Category"]

                try:
                    issuer_image = None
                    network_image = None

                    if badgeclass.cached_issuer.is_network:
                        issuer_image = (
                            issuer.image
                            if issuer and category != "learningpath"
                            else None
                        )
                        network_image = badgeclass.cached_issuer.image

                    else:
                        share = (
                            badgeclass.network_shares.filter(is_active=True)
                            .select_related("network")
                            .first()
                        )
                        if share:
                            network_image = share.network.image
                            issuer_image = issuer.image

                    if issuer_image and network_image and category != "learningpath":
                        new_instance.generate_assertion_image(
                            issuer_image,
                            network_image,
                        )
                        new_instance.save(update_fields=["image"])
                except Exception as e:
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.error(
                        f"Failed to generate badge instance image for {new_instance.entity_id}: {str(e)}",
                        exc_info=True,
                    )

            if evidence is not None:
                from issuer.models import BadgeInstanceEvidence

                for evidence_obj in evidence:
                    evidence_url = evidence_obj.get("evidence_url")
                    narrative = evidence_obj.get("narrative")
                    new_evidence = BadgeInstanceEvidence(
                        badgeinstance=new_instance, evidence_url=evidence_url
                    )
                    if narrative:
                        new_evidence.narrative = narrative
                    new_evidence.save()

            if extensions is not None:
                for name, ext in list(extensions.items()):
                    new_instance.badgeinstanceextension_set.create(
                        name=name, original_json=json.dumps(ext)
                    )

            # force recreation to include extensions and evidence in the json
            new_instance.get_json(obi_version="3_0", force_recreate=True)

        if not notify and getattr(settings, "GDPR_COMPLIANCE_NOTIFY_ON_FIRST_AWARD"):
            # always notify if this is the first time issuing to a recipient if configured for GDPR compliance
            if self.filter(recipient_identifier=recipient_identifier).count() == 1:
                notify = True

        if notify:
            new_instance.notify_earner(
                badgr_app=badgr_app, microdegree_id=microdegree_id
            )

        # dynamic to prevent circular import
        from issuer.models import LearningPath

        # check if badgeclass is used in learning paths
        learningpathes = LearningPath.objects.filter(
            learningpathbadge__badge=badgeclass
        )
        for learningpath in learningpathes:
            # all learningpath badges collected but participationBadge not yet issued
            if learningpath.activated and learningpath.user_should_have_badge(
                recipient_identifier
            ):
                # issue learningpath badge
                learningpath.participationBadge.issue(
                    recipient_id=recipient_identifier,
                    notify=notify,
                    microdegree_id=learningpath.entity_id,
                )

        return new_instance
