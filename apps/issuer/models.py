import datetime
import io
import math
import os
import urllib.parse
import uuid
import base64
import base58
from hashlib import sha256
from collections import OrderedDict
from json import dumps as json_dumps, loads as json_loads

from cryptography.hazmat.primitives import serialization
from pyld import jsonld

import cachemodel
from allauth.account.adapter import get_adapter
from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.db.models import ProtectedError
from django.urls import reverse
from django.utils import timezone
from apps.issuer.services.image_composer import ImageComposer
from entity.models import BaseVersionedEntity
from issuer.managers import (
    BadgeClassManager,
    BadgeInstanceEvidenceManager,
    BadgeInstanceManager,
    IssuerManager,
)
from jsonfield import JSONField
from mainsite import blacklist
from mainsite.managers import SlugOrJsonIdCacheModelManager
from mainsite.mixins import (
    HashUploadedImage,
    PngImagePreview,
    ResizeUploadedImage,
    ScrubUploadedSvgImage,
)
from mainsite.models import BadgrApp, EmailBlacklist
from mainsite.utils import OriginSetting, generate_entity_uri, get_name
from openbadges_bakery import bake

from .utils import (
    CURRENT_OBI_VERSION,
    UNVERSIONED_BAKED_VERSION,
    add_obi_version_ifneeded,
    generate_rebaked_filename,
    generate_sha256_hashstring,
    get_obi_context,
    parse_original_datetime,
    generate_private_key_pem,
    geocode,
)
import logging

logger = logging.getLogger("Badgr.Events")

AUTH_USER_MODEL = getattr(settings, "AUTH_USER_MODEL", "auth.User")

RECIPIENT_TYPE_EMAIL = "email"
RECIPIENT_TYPE_ID = "openBadgeId"
RECIPIENT_TYPE_TELEPHONE = "telephone"
RECIPIENT_TYPE_URL = "url"


class BaseAuditedModel(cachemodel.CacheModel):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    created_by = models.ForeignKey(
        "badgeuser.BadgeUser",
        blank=True,
        null=True,
        related_name="+",
        on_delete=models.SET_NULL,
    )
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    updated_by = models.ForeignKey(
        "badgeuser.BadgeUser",
        blank=True,
        null=True,
        related_name="+",
        on_delete=models.SET_NULL,
    )

    class Meta:
        abstract = True

    @property
    def cached_creator(self):
        from badgeuser.models import BadgeUser

        return BadgeUser.cached.get(id=self.created_by_id)


class BaseAuditedModelDeletedWithUser(cachemodel.CacheModel):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    created_by = models.ForeignKey(
        "badgeuser.BadgeUser",
        blank=True,
        null=True,
        related_name="+",
        on_delete=models.CASCADE,
    )
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    updated_by = models.ForeignKey(
        "badgeuser.BadgeUser",
        blank=True,
        null=True,
        related_name="+",
        on_delete=models.CASCADE,
    )

    class Meta:
        abstract = True

    @property
    def cached_creator(self):
        from badgeuser.models import BadgeUser

        return BadgeUser.cached.get(id=self.created_by_id)


class OriginalJsonMixin(models.Model):
    original_json = models.TextField(blank=True, null=True, default=None)

    class Meta:
        abstract = True

    def get_original_json(self):
        if self.original_json:
            try:
                return json_loads(self.original_json)
            except (TypeError, ValueError):
                pass

    def get_filtered_json(self, excluded_fields=()):
        original = self.get_original_json()
        if original is not None:
            return {
                key: original[key]
                for key in [
                    k for k in list(original.keys()) if k not in excluded_fields
                ]
            }


class BaseOpenBadgeObjectModel(OriginalJsonMixin, cachemodel.CacheModel):
    source = models.CharField(max_length=254, default="local")
    source_url = models.CharField(
        max_length=254, blank=True, null=True, default=None, unique=True
    )

    class Meta:
        abstract = True

    def get_extensions_manager(self):
        raise NotImplementedError()

    def __hash__(self):
        return hash((self.source, self.source_url))

    def __eq__(self, other):
        UNUSABLE_DEFAULT = uuid.uuid4()

        comparable_properties = getattr(self, "COMPARABLE_PROPERTIES", None)
        if comparable_properties is None:
            return super(BaseOpenBadgeObjectModel, self).__eq__(other)

        for prop in self.COMPARABLE_PROPERTIES:
            if getattr(self, prop) != getattr(other, prop, UNUSABLE_DEFAULT):
                return False
        return True

    @cachemodel.cached_method(auto_publish=True)
    def cached_extensions(self):
        if not self.pk:
            return []
        return self.get_extensions_manager().all()

    @property
    def extension_items(self):
        return {e.name: json_loads(e.original_json) for e in self.cached_extensions()}

    @extension_items.setter
    def extension_items(self, value):
        if value is None:
            value = {}
        touched_idx = []

        with transaction.atomic():
            if not self.pk and value:
                self.save()

            # add new
            for ext_name, ext in list(value.items()):
                ext_json = json_dumps(ext)
                ext, ext_created = self.get_extensions_manager().get_or_create(
                    name=ext_name, defaults=dict(original_json=ext_json)
                )
                if not ext_created:
                    ext.original_json = ext_json
                    ext.save()
                touched_idx.append(ext.pk)

            # remove old
            for extension in self.cached_extensions():
                if extension.pk not in touched_idx:
                    extension.delete()


class BaseOpenBadgeExtension(cachemodel.CacheModel):
    name = models.CharField(max_length=254)
    original_json = models.TextField(blank=True, null=True, default=None)

    def __str__(self):
        return self.name

    class Meta:
        abstract = True


class Issuer(
    ResizeUploadedImage,
    ScrubUploadedSvgImage,
    PngImagePreview,
    BaseAuditedModel,
    BaseVersionedEntity,
    BaseOpenBadgeObjectModel,
):
    entity_class_name = "Issuer"
    COMPARABLE_PROPERTIES = (
        "badgrapp_id",
        "description",
        "email",
        "entity_id",
        "entity_version",
        "name",
        "pk",
        "updated_at",
        "url",
    )

    staff = models.ManyToManyField(AUTH_USER_MODEL, through="IssuerStaff")

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(
        max_length=255, db_index=True, blank=True, null=True, default=None
    )
    # slug = AutoSlugField(max_length=255, populate_from='name', unique=True, blank=False, editable=True)

    badgrapp = models.ForeignKey(
        "mainsite.BadgrApp",
        blank=True,
        null=True,
        default=None,
        on_delete=models.SET_NULL,
    )

    networks = models.ManyToManyField(
        "self",
        through="NetworkMembership",
        related_name="partner_issuers",
    )

    is_network = models.BooleanField(default=False)

    name = models.CharField(max_length=1024)
    image = models.FileField(upload_to="uploads/issuers", blank=True, null=True)
    description = models.TextField(blank=True, null=True, default=None)
    url = models.CharField(max_length=254, blank=True, null=True, default=None)
    email = models.CharField(max_length=254, blank=True, null=True, default=None)
    old_json = JSONField()

    verified = models.BooleanField(null=False, default=False)

    objects = IssuerManager()
    cached = SlugOrJsonIdCacheModelManager(
        slug_kwarg_name="entity_id", slug_field_name="entity_id"
    )

    category = models.CharField(max_length=255, null=False, default="n/a")

    # address fields
    street = models.CharField(max_length=255, null=True, blank=True)
    streetnumber = models.CharField(max_length=255, null=True, blank=True)
    zip = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=255, null=True, blank=True)
    country = models.CharField(max_length=255, null=True, blank=True)
    state = models.CharField(max_length=255, null=True, blank=True)

    intendedUseVerified = models.BooleanField(null=False, default=False)
    linkedinId = models.CharField(max_length=255, default=None)
    lat = models.FloatField(null=True, blank=True)
    lon = models.FloatField(null=True, blank=True)

    private_key = models.CharField(
        max_length=512, blank=True, null=True, default=generate_private_key_pem
    )

    def publish(self, publish_staff=True, *args, **kwargs):
        fields_cache = (
            self._state.fields_cache
        )  # stash the fields cache to avoid publishing related objects here
        self._state.fields_cache = dict()

        super(Issuer, self).publish(*args, **kwargs)
        if publish_staff:
            for member in self.cached_issuerstaff():
                member.cached_user.publish()

        self._state.fields_cache = fields_cache  # restore the fields cache

    def has_nonrevoked_assertions(self):
        return self.badgeinstance_set.filter(revoked=False).exists()

    def delete(self, *args, **kwargs):
        if self.has_nonrevoked_assertions():
            raise ProtectedError(
                "Issuer can not be deleted because it has previously issued badges.",
                self,
            )

        # remove any unused badgeclasses owned by issuer
        for bc in self.cached_badgeclasses():
            bc.delete()

        staff = self.cached_issuerstaff()
        # remove membership records
        for membership in staff:
            membership.delete(publish_issuer=False)
        ret = super(Issuer, self).delete(*args, **kwargs)

        if apps.is_installed("badgebook"):
            # badgebook shim
            try:
                from badgebook.models import LmsCourseInfo

                # update LmsCourseInfo's that were using this issuer as the default_issuer
                for course_info in LmsCourseInfo.objects.filter(default_issuer=self):
                    course_info.default_issuer = None
                    course_info.save()
            except ImportError:
                pass

        return ret

    def save(self, *args, **kwargs):
        original_verified = None
        should_geocode = False
        # original_image = None

        if not self.pk:
            self.notify_admins(self)
            should_geocode = True
            if not self.verified:
                badgr_app = BadgrApp.objects.get_current(None)
                try:
                    email_context = {
                        # removes all special characters from the issuer name
                        # (keeps whitespces, digits and alphabetical characters )
                        "issuer_name": self.name,
                        "issuer_url": self.url,
                        "issuer_email": self.email,
                        "badgr_app": badgr_app,
                    }
                except KeyError as e:
                    # A property isn't stored right in json
                    raise e
                template_name = "issuer/email/notify_issuer_unverified"
                adapter = get_adapter()
                adapter.send_mail(
                    template_name,
                    self.email,
                    context=email_context,
                    from_email="support@openbadges.education",
                )
        else:
            original_object = Issuer.objects.get(pk=self.pk)
            original_verified = original_object.verified
            # original_image = original_object.image

            if (
                self.street != original_object.street
                or self.streetnumber != original_object.streetnumber
                or self.city != original_object.city
                or self.zip != original_object.zip
                or self.country != original_object.country
            ):
                should_geocode = True

        # geocoding if issuer is newly created or address in model changed
        if should_geocode:
            addr_string = (
                (self.street if self.street is not None else "")
                + " "
                + (str(self.streetnumber) if self.streetnumber is not None else "")
                + " "
                + (str(self.zip) if self.zip is not None else "")
                + " "
                + (str(self.city) if self.city is not None else "")
                + " Deutschland"
            )
            geoloc = geocode(addr_string)
            if geoloc:
                self.lon = geoloc.longitude
                self.lat = geoloc.latitude

        ensureOwner = kwargs.pop("ensureOwner", True)
        ret = super(Issuer, self).save(*args, **kwargs)

        # The user who created the issuer should always be an owner
        if ensureOwner:
            self.ensure_owner()

        # if original_image.name != self.image.name:
        #     for bc in self.cached_badgeclasses():
        #         bc.generate_badge_image(self.image)

        if self.verified and not original_verified:
            badgr_app = BadgrApp.objects.get_current(None)
            try:
                email_context = {
                    "issuer_name": self.name,
                    "issuer_url": self.url,
                    "issuer_email": self.email,
                    "badgr_app": badgr_app,
                }
            except KeyError as e:
                # A property isn't stored right in json
                raise e

            template_name = "issuer/email/notify_issuer_verified"
            adapter = get_adapter()
            adapter.send_mail(template_name, self.email, context=email_context)

        return ret

    def ensure_owner(self):
        """Makes sure the issuer has a staff with role owner

        An issuer staff relation is either created with role owner
        (if none existed), or updated to contain the role
        ROLE_OWNER.
        Earlier this also made sure that the creator was the owner;
        since this doesn't seem to be required anymore though,
        this now merely makes sure that both a creator and an
        owner exist (if possible)
        """

        # If there exists both a creator and an owner, there's nothing to do
        # (I think; it's not clearly specified)
        if (
            self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)
            and self.created_by
        ):
            return

        # If there already is an IssuerStaff entry I have to edit it
        if (
            self.created_by
            and IssuerStaff.objects.filter(user=self.created_by, issuer=self).exists()
        ):
            issuerStaff = IssuerStaff.objects.get(user=self.created_by, issuer=self)
            issuerStaff.role = IssuerStaff.ROLE_OWNER
            issuerStaff.save()
            return

        # If I don't have a creator, this means they were deleted.
        # If there are other users associated, I can chose the one with the highest privileges
        if not self.created_by:
            owners = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)
            editors = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_EDITOR)
            staff = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_STAFF)
            if owners.exists():
                self.created_by = owners.first()
                self.save(ensureOwner=False)
                # Is already owner
                return
            elif editors.exists():
                self.created_by = editors.first()
                self.save(ensureOwner=False)
            elif staff.exists():
                self.created_by = staff.first()
                self.save(ensureOwner=False)
            else:
                # With no other staff, there's nothing we can do. So we unverify the issuer
                self.verified = False
                self.save(ensureOwner=False)
                return
            # The new "creator" should also be the owner
            issuerStaff = IssuerStaff.objects.get(user=self.created_by, issuer=self)
            issuerStaff.role = IssuerStaff.ROLE_OWNER
            issuerStaff.save()
            return

        # The last remaining case is that the created_by user still exists, but got removed as owner
        # In this case there must be no owner assigned currently, so we chose a new owner
        editors = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_EDITOR)
        staff = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_STAFF)
        if editors.exists():
            new_owner = editors.first()
        elif staff.exists():
            new_owner = staff.first()
        else:
            # If there is no other user, we (re-)assign the creator as owner.
            # This is also the case for the initial creation
            new_owner = IssuerStaff.objects.create(
                issuer=self, user=self.created_by, role=IssuerStaff.ROLE_OWNER
            )
            return
        new_owner.role = IssuerStaff.ROLE_OWNER
        new_owner.save()

    def new_contact_email(self):
        # If this method is called, this may mean that the owner got deleted.
        # This implicates that we have to take measures to ensure a new owner is applied.
        self.ensure_owner()
        # We set the contact email to the first email of the first owner we find
        owners = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)
        if not owners.exists():
            # Without an owner, there's nothing we can do
            return
        owner = owners.first()
        self.email = owner.primary_email
        self.save()

    def get_absolute_url(self):
        return reverse("issuer_json", kwargs={"entity_id": self.entity_id})

    @property
    def public_url(self):
        return OriginSetting.HTTP + self.get_absolute_url()

    def image_url(self, public=False):
        if bool(self.image):
            if public:
                return OriginSetting.HTTP + reverse(
                    "issuer_image", kwargs={"entity_id": self.entity_id}
                )
            if getattr(settings, "MEDIA_URL").startswith("http"):
                return default_storage.url(self.image.name)
            else:
                return getattr(settings, "HTTP_ORIGIN") + default_storage.url(
                    self.image.name
                )
        else:
            return None

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def editors(self):
        return self.staff.filter(
            issuerstaff__role__in=(IssuerStaff.ROLE_EDITOR, IssuerStaff.ROLE_OWNER)
        )

    @property
    def owners(self):
        return self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)

    @cachemodel.cached_method(auto_publish=True)
    def cached_issuerstaff(self):
        return IssuerStaff.objects.filter(issuer=self)

    @property
    def staff_items(self):
        return self.cached_issuerstaff()

    @staff_items.setter
    def staff_items(self, value):
        """
        Update this issuers IssuerStaff from a list of IssuerStaffSerializerV2 data
        """
        existing_staff_idx = {s.cached_user: s for s in self.staff_items}
        new_staff_idx = {s["cached_user"]: s for s in value}

        with transaction.atomic():
            # add missing staff records
            for staff_data in value:
                if staff_data["cached_user"] not in existing_staff_idx:
                    staff_record, created = IssuerStaff.cached.get_or_create(
                        issuer=self,
                        user=staff_data["cached_user"],
                        defaults={"role": staff_data["role"]},
                    )
                    if not created:
                        staff_record.role = staff_data["role"]
                        staff_record.save()

            # remove old staff records -- but never remove the only OWNER role
            for staff_record in self.staff_items:
                if staff_record.cached_user not in new_staff_idx:
                    if (
                        staff_record.role != IssuerStaff.ROLE_OWNER
                        or len(self.owners) > 1
                    ):
                        staff_record.delete()

    def get_extensions_manager(self):
        return self.issuerextension_set

    @cachemodel.cached_method(auto_publish=True)
    def cached_editors(self):
        UserModel = get_user_model()
        return UserModel.objects.filter(
            issuerstaff__issuer=self, issuerstaff__role=IssuerStaff.ROLE_EDITOR
        )

    @cachemodel.cached_method(auto_publish=True)
    def cached_badgeclasses(self):
        return self.badgeclasses.all().order_by("created_at")

    @cachemodel.cached_method(auto_publish=True)
    def cached_learningpaths(self):
        return self.learningpaths.all().order_by("created_at")

    @property
    def image_preview(self):
        return self.image

    def get_json(
        self,
        obi_version=CURRENT_OBI_VERSION,
        include_extra=True,
        use_canonical_id=False,
    ):
        obi_version, context_iri = get_obi_context(obi_version)

        id = (
            self.jsonld_id
            if use_canonical_id
            else add_obi_version_ifneeded(self.jsonld_id, obi_version)
        )

        # spread 3_0 context_iri to create a copy because we might modify it later on
        json = OrderedDict(
            {"@context": [*context_iri] if obi_version == "3_0" else context_iri}
        )

        json.update(
            OrderedDict(
                type="Issuer",
                id=id,
                name=self.name,
                url=self.url,
                email=self.email,
                description=self.description,
                category=self.category,
                slug=self.entity_id,
            )
        )

        image_url = self.image_url(public=True)
        json["image"] = image_url
        if self.original_json:
            image_info = self.get_original_json().get("image", None)
            if isinstance(image_info, dict):
                json["image"] = image_info
                json["image"]["id"] = image_url

        # source url
        if self.source_url:
            if obi_version == "1_1":
                json["source_url"] = self.source_url
                json["hosted_url"] = OriginSetting.HTTP + self.get_absolute_url()
            elif obi_version == "2_0":
                json["sourceUrl"] = self.source_url
                json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                json[extension.name] = json_loads(extension.original_json)

        # pass through imported json
        if include_extra:
            extra = self.get_filtered_json()
            if extra is not None:
                for k, v in list(extra.items()):
                    if k not in json:
                        json[k] = v

        if obi_version == "2_0":
            # link to v3 version of profile
            json["related"] = [
                {
                    "type": [
                        "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Profile"
                    ],
                    "id": add_obi_version_ifneeded(self.jsonld_id, "3_0"),
                    "version": "Open Badges v3p0",
                }
            ]

        # add verificationMethod
        if obi_version == "3_0":
            json["@context"].append("https://www.w3.org/ns/did/v1")

            # link to v2 version of profile
            # https://www.imsglobal.org/spec/ob/v3p0/impl#example-issuer-profile-relation-between-open-badges-3-0-and-open-badges-2-0
            json["alsoKnownAs"] = [add_obi_version_ifneeded(self.jsonld_id, "2_0")]

            private_key = serialization.load_pem_private_key(
                self.private_key.encode(), settings.SECRET_KEY.encode()
            )
            public_key = private_key.public_key()

            # for multicodec
            ed01_prefix = b"\xed\x01"

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            public_key_base58 = base58.b58encode(
                ed01_prefix + public_key_bytes
            ).decode()

            # z prefix for multibase 58
            public_key_multibase = f"z{public_key_base58}"

            # FIXME: needed for current version of https://github.com/1EdTech/digital-credentials-public-validator/ to work..
            json["controller"] = ""

            # FIXME: this should be a list of dicts according to the spec, but the verificator only supports it this way for now
            json["verificationMethod"] = OrderedDict(
                {
                    "id": f"{id}#key-0",
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-rdf-2022",
                    "controller": id,
                    "publicKeyMultibase": public_key_multibase,
                }
            )

        return json

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(
        self,
        excluded_fields=(
            "@context",
            "id",
            "type",
            "name",
            "url",
            "description",
            "image",
            "email",
        ),
    ):
        return super(Issuer, self).get_filtered_json(excluded_fields=excluded_fields)

    @property
    def cached_badgrapp(self):
        id = self.badgrapp_id if self.badgrapp_id else None
        return BadgrApp.objects.get_by_id_or_default(badgrapp_id=id)

    @property
    def partner_issuers(self):
        """Get all issuers that are partners of this network"""
        if not self.is_network:
            return Issuer.objects.none()
        return Issuer.objects.filter(network_memberships__network=self)

    def notify_admins(self, badgr_app=None, renotify=False):
        """
        Sends an email notification to the badge recipient.
        """

        if badgr_app is None:
            badgr_app = self.cached_issuer.cached_badgrapp
        if badgr_app is None:
            badgr_app = BadgrApp.objects.get_current(None)

        UserModel = get_user_model()
        users = UserModel.objects.filter(is_staff=True)

        email_context = {
            # 'badge_name': self.badgeclass.name,
            # 'badge_id': self.entity_id,
            # 'badge_description': self.badgeclass.description,
            # 'help_email': getattr(settings, 'HELP_EMAIL', 'help@badgr.io'),
            "issuer_name": self.name,
            "users": users,
            # 'issuer_email': self.issuer.email,
            # 'issuer_detail': self.issuer.public_url,
            # 'issuer_image_url': issuer_image_url,
            # 'badge_instance_url': self.public_url,
            # 'image_url': self.public_url + '/image?type=png',
            # 'download_url': self.public_url + "?action=download",
            "site_name": "Open Educational Badges",
            # 'badgr_app': badgr_app
        }

        # Notify admin whether issuer was automatically verified or needs to be verified manually
        if self.verified:
            template_name = "issuer/email/notify_admins_issuer_verified"
        else:
            template_name = "issuer/email/notify_admins"

        adapter = get_adapter()
        for user in users:
            adapter.send_mail(template_name, user.email, context=email_context)


class NetworkMembership(models.Model):
    network = models.ForeignKey(
        Issuer,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    issuer = models.ForeignKey(
        Issuer,
        on_delete=models.CASCADE,
        related_name="network_memberships",
    )

    class Meta:
        unique_together = ("network", "issuer")


class NetworkInvite(BaseVersionedEntity):
    class Status(models.TextChoices):
        PENDING = "Pending", "Pending"
        APPROVED = "Approved", "Approved"
        REJECTED = "Rejected", "Rejected"
        REVOKED = "Revoked", "Revoked"

    network = models.ForeignKey(
        Issuer,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="invites",
    )
    issuer = models.ForeignKey(Issuer, blank=True, null=True, on_delete=models.CASCADE)
    invitedOn = models.DateTimeField(blank=False, null=False, default=timezone.now)
    acceptedOn = models.DateTimeField(blank=True, null=True, default=None)
    status = models.CharField(
        max_length=254, choices=Status.choices, default=Status.PENDING
    )
    revoked = models.BooleanField(default=False, db_index=True)

    def revoke(self):
        if self.revoked:
            raise ValidationError("Invitation is already revoked")

        self.revoked = True
        self.status = self.Status.REVOKED
        self.save()


class IssuerStaff(cachemodel.CacheModel):
    ROLE_OWNER = "owner"
    ROLE_EDITOR = "editor"
    ROLE_STAFF = "staff"
    ROLE_CHOICES = (
        (ROLE_OWNER, "Owner"),
        (ROLE_EDITOR, "Editor"),
        (ROLE_STAFF, "Staff"),
    )
    issuer = models.ForeignKey(Issuer, on_delete=models.CASCADE)
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=254, choices=ROLE_CHOICES, default=ROLE_STAFF)

    class Meta:
        unique_together = ("issuer", "user")

    def publish(self):
        super(IssuerStaff, self).publish()
        self.issuer.publish(publish_staff=False)
        self.user.publish()

    def delete(self, *args, **kwargs):
        publish_issuer = kwargs.pop("publish_issuer", True)
        new_contact = self.is_staff_contact()
        super(IssuerStaff, self).delete()
        if publish_issuer:
            self.issuer.publish(publish_staff=False)
        self.user.publish()
        # Note that this delete method is not called if the user is deleted,
        # since the cascade is done on the database level. That means that this logic
        # *also* has to be contained in the delete method of the user
        if new_contact:
            self.issuer.new_contact_email()

    def is_staff_contact(self) -> bool:
        # Get verified emails of associated user
        user_emails = self.user.verified_emails
        # Get email of issuer
        issuer_email = self.issuer.email
        # Check if overlap exists
        if issuer_email is None:
            return False
        return any(user_email.email == issuer_email for user_email in user_emails)

    @property
    def cached_user(self):
        from badgeuser.models import BadgeUser

        return BadgeUser.cached.get(pk=self.user_id)

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)


def get_user_or_none(recipient_id, recipient_type):
    from badgeuser.models import CachedEmailAddress, UserRecipientIdentifier

    user = None
    if recipient_type == "email":
        verified_email = CachedEmailAddress.objects.filter(
            verified=True, email=recipient_id
        ).first()
        if verified_email:
            user = verified_email.user
    else:
        verified_recipient_id = UserRecipientIdentifier.objects.filter(
            verified=True, identifier=recipient_id
        ).first()
        if verified_recipient_id:
            user = verified_recipient_id.user

    return user


class IssuerStaffRequest(BaseVersionedEntity):
    class Status(models.TextChoices):
        PENDING = "Pending", "Pending"
        APPROVED = "Approved", "Approved"
        REJECTED = "Rejected", "Rejected"
        REVOKED = "Revoked", "Revoked"

    issuer = models.ForeignKey(
        Issuer,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="staffrequests",
    )
    user = models.ForeignKey(
        "badgeuser.BadgeUser", blank=True, null=True, on_delete=models.CASCADE
    )
    requestedOn = models.DateTimeField(blank=False, null=False, default=timezone.now)
    status = models.CharField(
        max_length=254, choices=Status.choices, default=Status.PENDING
    )
    revoked = models.BooleanField(default=False, db_index=True)

    def revoke(self):
        if self.revoked:
            raise ValidationError("Membership request is already revoked")

        self.revoked = True
        self.status = self.Status.REVOKED
        self.save()


class BadgeClass(
    ResizeUploadedImage,
    ScrubUploadedSvgImage,
    HashUploadedImage,
    PngImagePreview,
    BaseAuditedModel,
    BaseVersionedEntity,
    BaseOpenBadgeObjectModel,
):
    entity_class_name = "BadgeClass"
    COMPARABLE_PROPERTIES = (
        "criteria_text",
        "criteria_url",
        "description",
        "entity_id",
        "entity_version",
        "expiration",
        "name",
        "pk",
        "slug",
        "updated_at",
    )

    issuer = models.ForeignKey(
        Issuer,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="badgeclasses",
    )

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(
        max_length=255, db_index=True, blank=True, null=True, default=None
    )
    # slug = AutoSlugField(max_length=255, populate_from='name', unique=True, blank=False, editable=True)

    name = models.CharField(max_length=255)
    image = models.FileField(upload_to="uploads/badges", blank=True)
    imageFrame = models.BooleanField(default=True)
    image_preview = models.FileField(upload_to="uploads/badges", blank=True, null=True)
    description = models.TextField(blank=True, null=True, default=None)

    # TODO: criteria_url and criteria_text are deprecated and should be removed once the migration to the criteria field was done
    criteria_url = models.CharField(max_length=254, blank=True, null=True, default=None)
    criteria_text = models.TextField(blank=True, null=True)
    course_url = models.CharField(max_length=255, blank=True, null=True, default=None)
    expiration = models.IntegerField(
        blank=True,
        null=True,
        default=None,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(36500),  # 100 years
        ],
        help_text="Number of days the badge is valid after being issued.",
    )

    # permissions saved as integer in binary representation
    # issuer should always be set
    COPY_PERMISSIONS_ISSUER = 0b1  # 1
    COPY_PERMISSIONS_OTHERS = 0b10  # 2
    COPY_PERMISSIONS_NONE = 0b100  # 4

    COPY_PERMISSIONS_CHOICES = (
        (COPY_PERMISSIONS_ISSUER, "Issuer"),
        (COPY_PERMISSIONS_OTHERS, "Everyone"),
        (COPY_PERMISSIONS_NONE, "None"),
    )
    COPY_PERMISSIONS_KEYS = ("issuer", "others", "none")
    copy_permissions = models.PositiveSmallIntegerField(default=COPY_PERMISSIONS_ISSUER)

    criteria = models.JSONField(blank=True, null=True)

    old_json = JSONField()

    objects = BadgeClassManager()
    cached = SlugOrJsonIdCacheModelManager(
        slug_kwarg_name="entity_id", slug_field_name="entity_id"
    )

    class Meta:
        verbose_name_plural = "Badge classes"

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)

    def clean(self):
        # Check if the issuer for this badge is verified, otherwise throw an error
        if not self.issuer.verified:
            raise ValidationError(
                "Only verified issuers can create / update badges", code="invalid"
            )

    def generate_badge_image(
        self,
        category,
        badge_image,
        issuer_image=None,
        network_image=None,
    ):
        """Generate composed badge image from original image"""

        composer = ImageComposer(category=category)

        image_b64 = composer.compose_badge_from_uploaded_image(
            badge_image, issuer_image, network_image, draw_frame=self.imageFrame
        )

        if not image_b64:
            raise ValueError("Badge image generation failed")

        if image_b64.startswith("data:image/png;base64,"):
            image_b64 = image_b64.split(",", 1)[1]

        image_data = base64.b64decode(image_b64)

        filename = f"issuer_badgeclass_{uuid.uuid4()}.png"
        content_file = ContentFile(image_data, name=filename)

        self.image.save(filename, content_file, save=False)

    def publish(self):
        fields_cache = (
            self._state.fields_cache
        )  # stash the fields cache to avoid publishing related objects here
        self._state.fields_cache = dict()
        super(BadgeClass, self).publish()
        self.issuer.publish(publish_staff=False)
        if self.created_by:
            self.created_by.publish()

        self._state.fields_cache = fields_cache  # restore the fields cache

    def delete(self, *args, **kwargs):
        # if there are some assertions that have not expired
        if (
            self.badgeinstances.filter(revoked=False)
            .filter(
                models.Q(expires_at__isnull=True)
                | models.Q(expires_at__gt=timezone.now())
            )
            .exists()
        ):
            raise ProtectedError(
                "BadgeClass may only be deleted if all BadgeInstances have been revoked.",
                self,
            )

        issuer = self.issuer
        super(BadgeClass, self).delete(*args, **kwargs)
        issuer.publish(publish_staff=False)

    def schedule_image_update_task(self):
        from issuer.tasks import rebake_all_assertions_for_badge_class

        batch_size = getattr(settings, "BADGE_ASSERTION_AUTO_REBAKE_BATCH_SIZE", 100)
        rebake_all_assertions_for_badge_class.delay(
            self.pk, limit=batch_size, replay=True
        )

    def get_absolute_url(self):
        return reverse("badgeclass_json", kwargs={"entity_id": self.entity_id})

    @property
    def public_url(self):
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def issuer_jsonld_id(self):
        return self.cached_issuer.jsonld_id

    def get_criteria_url(self):
        if self.criteria_url:
            return self.criteria_url
        return OriginSetting.HTTP + reverse(
            "badgeclass_criteria", kwargs={"entity_id": self.entity_id}
        )

    @property
    def description_nonnull(self):
        return self.description if self.description else ""

    @description_nonnull.setter
    def description_nonnull(self, value):
        self.description = value

    @property
    def owners(self):
        return self.cached_issuer.owners

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)

    def has_nonrevoked_assertions(self):
        return self.badgeinstances.filter(revoked=False).exists()

    """
    Included for legacy purposes. It is inefficient to routinely call this for
    badge classes with large numbers of assertions.
    """

    @property
    def v1_api_recipient_count(self):
        return self.badgeinstances.filter(revoked=False).count()

    @property
    def v1_api_recipient_count_issuer(self):
        return self.badgeinstances.filter(revoked=False, issuer=self.issuer).count()

    @cachemodel.cached_method(auto_publish=True)
    def cached_alignments(self):
        return self.badgeclassalignment_set.all()

    @property
    def alignment_items(self):
        return self.cached_alignments()

    @alignment_items.setter
    def alignment_items(self, value):
        if value is None:
            value = []
        keys = [
            "target_name",
            "target_url",
            "target_description",
            "target_framework",
            "target_code",
        ]

        def _identity(align):
            """build a unique identity from alignment json"""
            return "&".join("{}={}".format(k, align.get(k, None)) for k in keys)

        def _obj_identity(alignment):
            """build a unique identity from alignment json"""
            return "&".join("{}={}".format(k, getattr(alignment, k)) for k in keys)

        existing_idx = {_obj_identity(a): a for a in self.alignment_items}
        new_idx = {_identity(a): a for a in value}

        with transaction.atomic():
            # HACKY, but force a save to self otherwise we can't create related objects here
            if not self.pk:
                self.save()

            # add missing records
            for align in value:
                if _identity(align) not in existing_idx:
                    alignment = self.badgeclassalignment_set.create(**align)

            # remove old records
            for alignment in self.alignment_items:
                if _obj_identity(alignment) not in new_idx:
                    alignment.delete()

    @cachemodel.cached_method(auto_publish=True)
    def cached_tags(self):
        return self.badgeclasstag_set.all()

    @property
    def tag_items(self):
        return self.cached_tags()

    @tag_items.setter
    def tag_items(self, value):
        if value is None:
            value = []
        existing_idx = [t.name for t in self.tag_items]
        new_idx = value

        with transaction.atomic():
            if not self.pk:
                self.save()

            # add missing
            for t in value:
                if t not in existing_idx:
                    tag = self.badgeclasstag_set.create(name=t)

            # remove old
            for tag in self.tag_items:
                if tag.name not in new_idx:
                    tag.delete()

    def get_extensions_manager(self):
        return self.badgeclassextension_set

    def issue(
        self,
        recipient_id=None,
        evidence=None,
        narrative=None,
        notify=False,
        created_by=None,
        allow_uppercase=False,
        badgr_app=None,
        recipient_type=RECIPIENT_TYPE_EMAIL,
        microdegree_id=None,
        issuerSlug=None,
        activity_start_date=None,
        activity_end_date=None,
        activity_zip=None,
        activity_city=None,
        activity_online=False,
        course_url="",
        **kwargs,
    ):
        return BadgeInstance.objects.create(
            badgeclass=self,
            recipient_identifier=recipient_id,
            recipient_type=recipient_type,
            narrative=narrative,
            evidence=evidence,
            notify=notify,
            created_by=created_by,
            allow_uppercase=allow_uppercase,
            badgr_app=badgr_app,
            microdegree_id=microdegree_id,
            issuerSlug=issuerSlug,
            user=get_user_or_none(recipient_id, recipient_type),
            activity_start_date=activity_start_date,
            activity_end_date=activity_end_date,
            activity_zip=activity_zip,
            activity_city=activity_city,
            activity_online=activity_online,
            course_url=course_url,
            **kwargs,
        )

    def image_url(self, public=False):
        if public:
            return OriginSetting.HTTP + reverse(
                "badgeclass_image", kwargs={"entity_id": self.entity_id}
            )

        if getattr(settings, "MEDIA_URL").startswith("http"):
            return default_storage.url(self.image.name)
        else:
            return getattr(settings, "HTTP_ORIGIN") + default_storage.url(
                self.image.name
            )

    def get_criteria(self):
        try:
            categoryExtension = self.cached_extensions().get(
                name="extensions:CategoryExtension"
            )
        except Exception:
            return None

        category = json_loads(categoryExtension.original_json)
        if self.criteria:
            return self.criteria
        elif category["Category"] == "competency":
            competencyExtensions = {}

            if len(self.cached_extensions()) > 0:
                for extension in self.cached_extensions():
                    if extension.name == "extensions:CompetencyExtension":
                        competencyExtensions[extension.name] = json_loads(
                            extension.original_json
                        )

            competencies = []

            for competency in competencyExtensions.get(
                "extensions:CompetencyExtension", []
            ):
                competencies.append(competency.get("name"))

            md = f"""
                    *Folgende Kriterien sind auf Basis deiner Eingaben als Metadaten im Badge hinterlegt*:
                    Du hast erfolgreich an **{self.name}** teilgenommen.
                    Dabei hast du folgende Kompetenzen gestärkt:
                    """
            for comp in competencies:
                md += f"- {comp}\n"

            return md.strip()
        else:
            return f"""
                    *Folgende Kriterien sind auf Basis deiner Eingaben als Metadaten im Badge hinterlegt*:
                    Du hast erfolgreich an **{self.name}** teilgenommen.
                   """

    def get_json(
        self,
        obi_version=CURRENT_OBI_VERSION,
        include_extra=True,
        use_canonical_id=False,
        include_orgImg=False,
    ):
        obi_version, context_iri = get_obi_context(obi_version)
        json = OrderedDict(
            {"@context": [*context_iri] if obi_version == "3_0" else context_iri}
        )
        json.update(
            OrderedDict(
                type="BadgeClass",
                id=(
                    self.jsonld_id
                    if use_canonical_id
                    else add_obi_version_ifneeded(self.jsonld_id, obi_version)
                ),
                name=self.name,
                description=self.description_nonnull,
                copy_permissions=self.copy_permissions_list,
                issuer=(
                    self.cached_issuer.jsonld_id
                    if use_canonical_id
                    else add_obi_version_ifneeded(
                        self.cached_issuer.jsonld_id, obi_version
                    )
                ),
                created_at=self.created_at,
            )
        )

        json["slug"] = self.entity_id

        # image
        if self.image:
            image_url = self.image_url(public=True)
            json["image"] = image_url
            if self.original_json:
                original_json = self.get_original_json()
                if original_json is not None:
                    image_info = original_json.get("image", None)
                    if isinstance(image_info, dict):
                        json["image"] = image_info
                        json["image"]["id"] = image_url

        # criteria
        if obi_version == "1_1":
            json["criteria"] = self.get_criteria_url()
        elif obi_version == "2_0" or obi_version == "3_0":
            json["criteria"] = {}
            if self.criteria_url:
                json["criteria"]["id"] = self.criteria_url
            json["criteria"]["narrative"] = self.get_criteria()

        # source_url
        if self.source_url:
            if obi_version == "1_1":
                json["source_url"] = self.source_url
                json["hosted_url"] = OriginSetting.HTTP + self.get_absolute_url()
            elif obi_version == "2_0":
                json["sourceUrl"] = self.source_url
                json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # alignment / tags
        if obi_version == "2_0" or obi_version == "3_0":
            json["alignment"] = [
                a.get_json(obi_version=obi_version) for a in self.cached_alignments()
            ]
            json["tags"] = list(t.name for t in self.cached_tags())

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                if (
                    not include_orgImg
                    and extension.name != "extensions:OrgImageExtension"
                ):
                    json[extension.name] = json_loads(extension.original_json)

        # pass through imported json
        if include_extra:
            extra = self.get_filtered_json()
            if extra is not None:
                for k, v in list(extra.items()):
                    if k not in json:
                        json[k] = v

        if obi_version == "2_0":
            # add relation to version 3.0
            json["related"] = [
                {
                    "type": [
                        "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Achievement"
                    ],
                    "id": add_obi_version_ifneeded(self.jsonld_id, "3_0"),
                    "version": "Open Badges v3p0",
                }
            ]

        if obi_version == "3_0":
            json["type"] = ["Achievement", "https://w3id.org/openbadges#BadgeClass"]

            # link to version v2
            # https://www.imsglobal.org/spec/ob/v3p0/impl#example-openbadges-3-0-achievement-with-linked-openbadges-2-0-badgeclass-via-related-association
            json["related"] = [
                {
                    "type": ["Related", "https://w3id.org/openbadges#BadgeClass"],
                    "id": add_obi_version_ifneeded(self.jsonld_id, "2_0"),
                    "version": "Open Badges v2p0",
                }
            ]

        return json

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(
        self,
        excluded_fields=(
            "@context",
            "id",
            "type",
            "name",
            "description",
            "image",
            "criteria",
            "issuer",
        ),
    ):
        return super(BadgeClass, self).get_filtered_json(
            excluded_fields=excluded_fields
        )

    @property
    def cached_badgrapp(self):
        return self.cached_issuer.cached_badgrapp

    def generate_expires_at(self, issued_on=None):
        if not self.expiration:
            return None

        if issued_on is None:
            issued_on = timezone.now()

        return issued_on + timezone.timedelta(days=self.expiration)

    @property
    def copy_permissions_list(self):
        # turn db value into string[] using keys
        binary = bin(self.copy_permissions)[:1:-1]
        return [self.COPY_PERMISSIONS_KEYS[i] for i, x in enumerate(binary) if int(x)]

    @copy_permissions_list.setter
    def copy_permissions_list(self, value):
        if not value:
            self.copy_permissions = 0
        else:
            # turn string[] of KEYS into db value
            binary_map = [
                (1 if x in value else 0) << i
                for i, x in enumerate(self.COPY_PERMISSIONS_KEYS)
            ]
            print(binary_map)
            self.copy_permissions = sum(map(int, binary_map))


class ImportedBadgeAssertion(
    BaseVersionedEntity, BaseAuditedModel, BaseOpenBadgeObjectModel
):
    """
    Model for storing imported badges separately from the system's own badges.
    This keeps external badge data isolated from internal data models.
    """

    user = models.ForeignKey(
        "badgeuser.BadgeUser", blank=True, null=True, on_delete=models.SET_NULL
    )

    badge_name = models.CharField(max_length=255)
    badge_description = models.TextField(blank=True, null=True)
    badge_criteria_url = models.URLField(blank=True, null=True)
    badge_image_url = models.URLField(blank=True, null=True)

    image = models.FileField(upload_to="uploads/badges", blank=True)

    issuer_name = models.CharField(max_length=255)
    issuer_url = models.URLField()
    issuer_email = models.EmailField(blank=True, null=True)
    issuer_image_url = models.URLField(blank=True, null=True)

    issued_on = models.DateTimeField()
    expires_at = models.DateTimeField(blank=True, null=True)

    RECIPIENT_TYPE_EMAIL = "email"
    RECIPIENT_TYPE_ID = "openBadgeId"
    RECIPIENT_TYPE_TELEPHONE = "telephone"
    RECIPIENT_TYPE_URL = "url"

    RECIPIENT_TYPE_CHOICES = (
        (RECIPIENT_TYPE_EMAIL, "email"),
        (RECIPIENT_TYPE_ID, "openBadgeId"),
        (RECIPIENT_TYPE_TELEPHONE, "telephone"),
        (RECIPIENT_TYPE_URL, "url"),
    )

    recipient_identifier = models.CharField(max_length=320, db_index=True)
    recipient_type = models.CharField(
        max_length=255, choices=RECIPIENT_TYPE_CHOICES, default=RECIPIENT_TYPE_EMAIL
    )

    ACCEPTANCE_UNACCEPTED = "Unaccepted"
    ACCEPTANCE_ACCEPTED = "Accepted"
    ACCEPTANCE_REJECTED = "Rejected"
    ACCEPTANCE_CHOICES = (
        (ACCEPTANCE_UNACCEPTED, "Unaccepted"),
        (ACCEPTANCE_ACCEPTED, "Accepted"),
        (ACCEPTANCE_REJECTED, "Rejected"),
    )
    acceptance = models.CharField(
        max_length=254, choices=ACCEPTANCE_CHOICES, default=ACCEPTANCE_ACCEPTED
    )

    revoked = models.BooleanField(default=False)
    revocation_reason = models.CharField(max_length=255, blank=True, null=True)

    original_json = JSONField()

    hashed = models.BooleanField(default=True)
    salt = models.CharField(max_length=254, blank=True, null=True, default=None)

    narrative = models.TextField(blank=True, null=True)

    verification_url = models.URLField(blank=True, null=True)

    class Meta:
        verbose_name = "Imported Badge Assertion"

    def image_url(self):
        if self.image:
            return self.image.url
        return self.badge_image_url

    def get_extensions_manager(self):
        return self.importedbadgeassertionextension_set


class BadgeInstance(BaseAuditedModel, BaseVersionedEntity, BaseOpenBadgeObjectModel):
    entity_class_name = "Assertion"
    COMPARABLE_PROPERTIES = (
        "badgeclass_id",
        "entity_id",
        "entity_version",
        "issued_on",
        "pk",
        "narrative",
        "recipient_identifier",
        "recipient_type",
        "revoked",
        "revocation_reason",
        "updated_at",
    )

    issued_on = models.DateTimeField(blank=False, null=False, default=timezone.now)

    badgeclass = models.ForeignKey(
        BadgeClass,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="badgeinstances",
    )
    issuer = models.ForeignKey(
        Issuer, blank=False, null=False, on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        "badgeuser.BadgeUser", blank=True, null=True, on_delete=models.SET_NULL
    )

    RECIPIENT_TYPE_CHOICES = (
        (RECIPIENT_TYPE_EMAIL, "email"),
        (RECIPIENT_TYPE_ID, "openBadgeId"),
        (RECIPIENT_TYPE_TELEPHONE, "telephone"),
        (RECIPIENT_TYPE_URL, "url"),
    )
    recipient_identifier = models.CharField(
        max_length=320, blank=False, null=False, db_index=True
    )
    recipient_type = models.CharField(
        max_length=255,
        choices=RECIPIENT_TYPE_CHOICES,
        default=RECIPIENT_TYPE_EMAIL,
        blank=False,
        null=False,
    )

    image = models.FileField(upload_to="uploads/badges", blank=True)
    course_url = models.CharField(max_length=255, blank=True, null=True, default=None)

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(
        max_length=255, db_index=True, blank=True, null=True, default=None
    )

    revoked = models.BooleanField(default=False, db_index=True)
    revocation_reason = models.CharField(
        max_length=255, blank=True, null=True, default=None
    )

    expires_at = models.DateTimeField(blank=True, null=True, default=None)

    ACCEPTANCE_UNACCEPTED = "Unaccepted"
    ACCEPTANCE_ACCEPTED = "Accepted"
    ACCEPTANCE_REJECTED = "Rejected"
    ACCEPTANCE_CHOICES = (
        (ACCEPTANCE_UNACCEPTED, "Unaccepted"),
        (ACCEPTANCE_ACCEPTED, "Accepted"),
        (ACCEPTANCE_REJECTED, "Rejected"),
    )
    acceptance = models.CharField(
        max_length=254, choices=ACCEPTANCE_CHOICES, default=ACCEPTANCE_UNACCEPTED
    )

    hashed = models.BooleanField(default=True)
    salt = models.CharField(max_length=254, blank=True, null=True, default=None)

    narrative = models.TextField(blank=True, null=True, default=None)

    old_json = JSONField()

    objects = BadgeInstanceManager()
    cached = SlugOrJsonIdCacheModelManager(
        slug_kwarg_name="entity_id", slug_field_name="entity_id"
    )

    activity_start_date = models.DateTimeField(
        blank=True,
        null=True,
        default=None,
        help_text="The datetime the activity/course started",
    )
    activity_end_date = models.DateTimeField(
        blank=True,
        null=True,
        default=None,
        help_text="The datetime the activity/course ended",
    )

    activity_zip = models.CharField(max_length=255, null=True, blank=True, default=None)
    activity_city = models.CharField(
        max_length=255, null=True, blank=True, default=None
    )
    activity_online = models.BooleanField(blank=True, null=False, default=False)

    ob_json_2_0 = models.TextField(blank=True, null=True, default=None)
    ob_json_3_0 = models.TextField(blank=True, null=True, default=None)

    class Meta:
        indexes = [
            models.Index(fields=["recipient_identifier", "badgeclass", "revoked"])
        ]

    @property
    def extended_json(self):
        extended_json = self.json
        extended_json["badge"] = self.badgeclass.json
        extended_json["badge"]["issuer"] = self.issuer.json

        return extended_json

    def image_url(self, public=False):
        if public:
            return OriginSetting.HTTP + reverse(
                "badgeinstance_image", kwargs={"entity_id": self.entity_id}
            )
        if getattr(settings, "MEDIA_URL").startswith("http"):
            return default_storage.url(self.image.name)
        else:
            return getattr(settings, "HTTP_ORIGIN") + default_storage.url(
                self.image.name
            )

    def get_share_url(self, include_identifier=False):
        url = self.share_url
        if include_identifier:
            url = "%s?identity__%s=%s" % (
                url,
                self.recipient_type,
                urllib.parse.quote(self.recipient_identifier),
            )
        return url

    @property
    def share_url(self):
        return self.public_url
        # return OriginSetting.HTTP+reverse('backpack_shared_assertion', kwargs={'share_hash': self.entity_id})

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)

    @property
    def cached_badgeclass(self):
        return BadgeClass.cached.get(pk=self.badgeclass_id)

    def get_absolute_url(self):
        return reverse("badgeinstance_json", kwargs={"entity_id": self.entity_id})

    def get_absolute_backpack_url(self):
        return reverse(
            "v1_api_localbadgeinstance_detail", kwargs={"slug": self.entity_id}
        )

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def badgeclass_jsonld_id(self):
        return self.cached_badgeclass.jsonld_id

    @property
    def issuer_jsonld_id(self):
        return self.cached_issuer.jsonld_id

    @property
    def public_url(self):
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def owners(self):
        return self.issuer.owners

    @property
    def pending(self):
        """
        If the associated identifier for this BadgeInstance
        does not exist or is unverified the BadgeInstance is
        considered "pending"
        """
        from badgeuser.models import CachedEmailAddress, UserRecipientIdentifier

        try:
            if self.recipient_type == RECIPIENT_TYPE_EMAIL:
                existing_identifier = CachedEmailAddress.cached.get(
                    email=self.recipient_identifier
                )
            else:
                existing_identifier = UserRecipientIdentifier.cached.get(
                    identifier=self.recipient_identifier
                )
        except (
            UserRecipientIdentifier.DoesNotExist,
            CachedEmailAddress.DoesNotExist,
        ):
            return False

        if not self.source_url:
            return False

        return not existing_identifier.verified

    def save(self, *args, **kwargs):
        if self.pk is None:
            # First check if recipient is in the blacklist
            if blacklist.api_query_is_in_blacklist(
                self.recipient_type, self.recipient_identifier
            ):
                logger.warning(
                    "The recipient '%s' is in the blacklist for this ('%s') badge class",
                    self.recipient_identifier,
                    self.badgeclass.entity_id,
                )
                raise ValidationError("You may not award this badge to this recipient.")

            self.salt = uuid.uuid4().hex
            self.created_at = datetime.datetime.now()

            # do this now instead of in AbstractVersionedEntity.save() so we can use it for image name
            if self.entity_id is None:
                self.entity_id = generate_entity_uri()

            if not self.image:
                badgeclass_name, ext = os.path.splitext(self.badgeclass.image.file.name)
                new_image = io.BytesIO()
                bake(
                    image_file=self.cached_badgeclass.image.file,
                    assertion_json_string=json_dumps(
                        self.get_json(obi_version=UNVERSIONED_BAKED_VERSION), indent=2
                    ),
                    output_file=new_image,
                )
                self.image.save(
                    name="assertion-{id}{ext}".format(id=self.entity_id, ext=ext),
                    content=ContentFile(new_image.read()),
                    save=False,
                )

            try:
                from badgeuser.models import CachedEmailAddress

                existing_email = CachedEmailAddress.cached.get(
                    email=self.recipient_identifier
                )
                if (
                    self.recipient_identifier != existing_email.email
                    and self.recipient_identifier
                    not in [e.email for e in existing_email.cached_variants()]
                ):
                    existing_email.add_variant(self.recipient_identifier)
            except CachedEmailAddress.DoesNotExist:
                pass

        if self.revoked is False:
            self.revocation_reason = None

        super(BadgeInstance, self).save(*args, **kwargs)

    def rebake(self, obi_version=UNVERSIONED_BAKED_VERSION, save=True):
        new_image = io.BytesIO()
        bake(
            image_file=self.cached_badgeclass.image.file,
            assertion_json_string=json_dumps(
                self.get_json(obi_version=obi_version), indent=2
            ),
            output_file=new_image,
        )

        new_filename = generate_rebaked_filename(
            self.image.name, self.cached_badgeclass.image.name
        )
        new_filename = self.image.field.generate_filename(
            self.image.instance, new_filename
        )
        new_name = default_storage.save(new_filename, ContentFile(new_image.read()))
        default_storage.delete(self.image.name)
        self.image.name = new_name
        if save:
            self.save()

    def publish(self):
        fields_cache = (
            self._state.fields_cache
        )  # stash the fields cache to avoid publishing related objects here
        self._state.fields_cache = dict()

        super(BadgeInstance, self).publish()
        self.badgeclass.publish()
        if self.recipient_user:
            self.recipient_user.publish()

        # publish all collections this instance was in
        for collection in self.backpackcollection_set.all():
            collection.publish()

        self.publish_by("entity_id", "revoked")
        self._state.fields_cache = fields_cache  # restore the stashed fields cache

    def delete(self, *args, **kwargs):
        badgeclass = self.badgeclass

        super(BadgeInstance, self).delete(*args, **kwargs)
        badgeclass.publish()
        if self.recipient_user:
            self.recipient_user.publish()
        self.publish_delete("entity_id", "revoked")

    def revoke(self, revocation_reason):
        if self.revoked:
            raise ValidationError("Assertion is already revoked")

        if not revocation_reason:
            raise ValidationError("revocation_reason is required")

        self.revoked = True
        self.revocation_reason = revocation_reason
        self.image.delete()
        self.save()

    # TODO: Use email related to the new domain, when one is created. Not urgent in this phase.
    def notify_earner(self, badgr_app=None, renotify=False, microdegree_id=None):
        """
        Sends an email notification to the badge recipient.
        """

        categoryExtension = None

        competencyExtensions = {}

        if len(self.badgeclass.cached_extensions()) > 0:
            for extension in self.badgeclass.cached_extensions():
                if extension.name == "extensions:CompetencyExtension":
                    competencyExtensions[extension.name] = json_loads(
                        extension.original_json
                    )
                if extension.name == "extensions:CategoryExtension":
                    categoryExtension = json_loads(extension.original_json)

        competencies = []

        for competency in competencyExtensions.get(
            "extensions:CompetencyExtension", []
        ):
            studyload = competency.get("studyLoad")
            studyloadFmt = "%s:%s h" % (
                math.floor(studyload / 60),
                str(studyload % 60).zfill(2),
            )

            competency_entry = {
                "name": competency.get("name"),
                "description": competency.get("description"),
                "framework": competency.get("framework"),
                "framework_identifier": competency.get("framework_identifier"),
                "source": competency.get("source"),
                "studyLoad": studyloadFmt,
                "skill": competency.get("category"),
            }
            competencies.append(competency_entry)

        if self.recipient_type != RECIPIENT_TYPE_EMAIL:
            return

        try:
            EmailBlacklist.objects.get(email=self.recipient_identifier)
        except EmailBlacklist.DoesNotExist:
            # Allow sending, as this email is not blacklisted.
            pass
        else:
            logger.warning(
                "The email for the badge with ID '%s' is blacklisted and was not sent",
                self.entity_id,
            )
            logger.debug(
                "Recipient: '%s'; badge instance: '%s'",
                self.recipient_identifier,
                self.json,
            )
            return

        if badgr_app is None:
            badgr_app = self.cached_issuer.cached_badgrapp
        if badgr_app is None:
            badgr_app = BadgrApp.objects.get_current(None)

        adapter = get_adapter()

        # get the base url for the badge instance
        httpPrefix = "https://" if settings.SECURE_SSL_REDIRECT else "http://"
        base_url = httpPrefix + badgr_app.cors

        pdf_document = adapter.generate_pdf_content(
            slug=self.entity_id, base_url=base_url
        )
        encoded_pdf_document = base64.b64encode(pdf_document).decode("utf-8")
        data_url = f"data:application/pdf;base64,{encoded_pdf_document}"

        try:
            if self.issuer.image:
                issuer_image_url = self.issuer.public_url + "/image"
            else:
                issuer_image_url = None

            if self.recipient_type == RECIPIENT_TYPE_EMAIL:
                name = get_name(self)

            url_name = "v1_api_user_collect_badges_in_backpack"

            save_url = OriginSetting.HTTP + reverse(url_name)

            url = "{url}?a={badgr_app}".format(url=save_url, badgr_app=badgr_app)

            email_context = {
                "name": name,
                "badge_name": self.badgeclass.name,
                "badge_category": categoryExtension["Category"],
                "badge_id": self.entity_id,
                "badge_description": self.badgeclass.description,
                "badge_competencies": competencies,
                "help_email": getattr(settings, "HELP_EMAIL", "info@opensenselab.org"),
                "issuer_name": self.issuer.name,
                "issuer_url": self.issuer.url,
                "issuer_email": self.issuer.email,
                "issuer_detail": self.issuer.public_url,
                "issuer_image_url": issuer_image_url,
                "badge_instance_url": self.public_url,
                "badge_instance_image": self.image.path,
                "pdf_download": data_url,
                "pdf_document": pdf_document,
                "image_url": self.public_url + "/image?type=png",
                "download_url": self.public_url + "?action=download",
                "site_name": "Open Educational Badges",
                "badgr_app": badgr_app,
                "activate_url": url,
                "call_to_action_label": "Badge im Rucksack sammeln",
            }
            if badgr_app.cors == "badgr.io":
                email_context["promote_mobile"] = True
            if renotify:
                email_context["renotify"] = "Reminder"
        except KeyError as e:
            # A property isn't stored right in json
            raise e

        template_name = "issuer/email/notify_earner"

        if (
            categoryExtension["Category"] == "learningpath"
            and microdegree_id is not None
        ):
            # if the recipient does not have an account no micro degree email is sent
            if self.user is not None:
                template_name = "issuer/email/notify_micro_degree_earner"

                url_name = "v1_api_user_save_microdegree"

                save_url = OriginSetting.HTTP + reverse(
                    url_name, kwargs={"entity_id": microdegree_id}
                )

                url = "{url}?a={badgr_app}".format(url=save_url, badgr_app=badgr_app)

                email_context["activate_url"] = url
                email_context["call_to_action_label"] = "Micro Degree auf OEB ansehen"

        adapter.send_mail(
            template_name, self.recipient_identifier, context=email_context
        )

    def get_extensions_manager(self):
        return self.badgeinstanceextension_set

    @property
    def recipient_user(self):
        from badgeuser.models import CachedEmailAddress, UserRecipientIdentifier

        try:
            email_address = CachedEmailAddress.cached.get(
                email=self.recipient_identifier
            )
            if email_address.verified:
                return email_address.user
        except CachedEmailAddress.DoesNotExist:
            try:
                identifier = UserRecipientIdentifier.cached.get(
                    identifier=self.recipient_identifier
                )
                if identifier.verified:
                    return identifier.user
            except UserRecipientIdentifier.DoesNotExist:
                pass
            pass
        return None

    def get_json(
        self,
        obi_version=None,
        expand_badgeclass=False,
        expand_issuer=False,
        include_extra=True,
        use_canonical_id=False,
        force_recreate=False,
    ):
        # choose obi version
        if not obi_version:
            obi_version = "3_0" if self.ob_json_3_0 else "2_0"

        # FIXME: special case
        # badgr-ui frontend uses this to display the public/assertions/ endpoint
        # also maybe social media sharing / widget.ts to display badge name
        def expand_json_ifneeded(json):
            if expand_badgeclass:
                json["badge"] = self.cached_badgeclass.get_json(obi_version=obi_version)
                json["badge"]["slug"] = self.cached_badgeclass.entity_id
                networkShare = self.cached_badgeclass.network_shares.filter(
                    is_active=True
                ).first()
                if networkShare:
                    network = networkShare.network
                    json["badge"]["sharedOnNetwork"] = {
                        "slug": network.entity_id,
                        "name": network.name,
                        "image": network.image.url,
                        "description": network.description,
                    }
                else:
                    json["badge"]["sharedOnNetwork"] = None

                json["badge"]["isNetworkBadge"] = (
                    self.cached_badgeclass.cached_issuer.is_network
                    and json["badge"]["sharedOnNetwork"] is None
                )

                if json["badge"]["isNetworkBadge"]:
                    json["badge"]["networkName"] = (
                        self.cached_badgeclass.cached_issuer.name
                    )
                    json["badge"]["networkImage"] = (
                        self.cached_badgeclass.cached_issuer.image.url
                    )
                else:
                    json["badge"]["networkImage"] = None
                    json["badge"]["networkName"] = None

                if expand_issuer:
                    json["badge"]["issuer"] = self.cached_issuer.get_json(
                        obi_version=obi_version
                    )
                json["image"] = self.image.url

        # FIXME: 'support' 1_1 for v1 serializer classes
        if obi_version == "1_1":
            obi_version = "2_0"

        if obi_version == "2_0":
            if not self.ob_json_2_0 or force_recreate:
                self.ob_json_2_0 = json_dumps(self.get_json_2_0())
                if self.pk:
                    self.save(update_fields=["ob_json_2_0"])

            json = json_loads(self.ob_json_2_0, object_pairs_hook=OrderedDict)

            expand_json_ifneeded(json)

            return json

        if obi_version == "3_0":
            if not self.ob_json_3_0 or force_recreate:
                self.ob_json_3_0 = json_dumps(self.get_json_3_0())
                if self.pk:
                    self.save(update_fields=["ob_json_3_0"])

            json = json_loads(self.ob_json_3_0, object_pairs_hook=OrderedDict)

            expand_json_ifneeded(json)

            return json

        raise NotImplementedError("Unsupported OB Version")

    def get_json_2_0(self):
        obi_version, context_iri = get_obi_context("2_0")

        json = OrderedDict(
            [
                ("@context", context_iri),
                ("type", "Assertion"),
                ("id", add_obi_version_ifneeded(self.jsonld_id, obi_version, True)),
                (
                    "badge",
                    add_obi_version_ifneeded(
                        self.cached_badgeclass.jsonld_id, obi_version, True
                    ),
                ),
                ("slug", self.entity_id),
            ]
        )

        image_url = self.image_url(public=True)
        json["image"] = image_url
        if self.original_json:
            image_info = self.get_original_json().get("image", None)
            if isinstance(image_info, dict):
                json["image"] = image_info
                json["image"]["id"] = image_url

        if self.revoked:
            return OrderedDict(
                [
                    ("@context", context_iri),
                    ("type", "Assertion"),
                    (
                        "id",
                        (add_obi_version_ifneeded(self.jsonld_id, obi_version, True)),
                    ),
                    ("revoked", self.revoked),
                    (
                        "revocationReason",
                        self.revocation_reason if self.revocation_reason else "",
                    ),
                ]
            )

        json["verification"] = {"type": "HostedBadge"}

        # source url
        if self.source_url:
            json["sourceUrl"] = self.source_url
            json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # evidence
        if self.evidence_url:
            # obi v2 multiple evidence
            json["evidence"] = [e.get_json(obi_version) for e in self.cached_evidence()]

        # narrative
        if self.narrative:
            json["narrative"] = self.narrative

        # issuedOn / expires
        json["issuedOn"] = self.issued_on.isoformat()
        if self.expires_at:
            json["expires"] = self.expires_at.isoformat()

        # recipient
        if self.hashed:
            json["recipient"] = {
                "hashed": True,
                "type": self.recipient_type,
                "identity": generate_sha256_hashstring(
                    self.recipient_identifier, self.salt
                ),
            }
            if self.salt:
                json["recipient"]["salt"] = self.salt
        else:
            json["recipient"] = {
                "hashed": False,
                "type": self.recipient_type,
                "identity": self.recipient_identifier,
            }

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                json[extension.name] = json_loads(extension.original_json)

        return json

    def get_json_3_0(self):
        obi_version, context_iri = get_obi_context("3_0")

        hashed_recipient = generate_sha256_hashstring(
            self.recipient_identifier, self.salt
        )

        credential_subject = {
            "type": ["AchievementSubject"],
            "identifier": [
                {
                    "type": "IdentityObject",
                    "identityHash": hashed_recipient,
                    "identityType": "emailAddress",
                    "hashed": True,
                    "salt": self.salt,
                }
            ],
            "achievement": {
                "id": add_obi_version_ifneeded(
                    self.cached_badgeclass.jsonld_id, obi_version
                ),
                "type": ["Achievement"],
                "name": self.cached_badgeclass.name,
                "description": self.cached_badgeclass.description,
                "achievementType": "Badge",
                "criteria": {
                    "narrative": self.narrative or "",
                },
                "image": {
                    "id": self.image_url(public=True),
                    "type": "Image",
                },
            },
        }

        if self.activity_start_date:
            credential_subject["activityStartDate"] = (
                self.activity_start_date.isoformat()
            )
        if self.activity_end_date:
            credential_subject["activityEndDate"] = self.activity_end_date.isoformat()

        if self.activity_city or self.activity_zip:
            activity_location = {"type": ["Address"]}

            if self.activity_city:
                activity_location["addressLocality"] = self.activity_city
            if self.activity_zip:
                activity_location["postalCode"] = self.activity_zip

            credential_subject["activityLocation"] = activity_location

        if self.activity_online:
            credential_subject["activityFormat"] = "Online"

        json = OrderedDict(
            [
                (
                    "@context",
                    [
                        "https://www.w3.org/ns/credentials/v2",
                        *context_iri,
                        "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json",
                    ],
                ),
                ("id", add_obi_version_ifneeded(self.jsonld_id, obi_version)),
                ("type", ["VerifiableCredential", "OpenBadgeCredential"]),
                ("name", self.cached_badgeclass.name),
                ("evidence", [e.get_json(obi_version) for e in self.cached_evidence()]),
                (
                    "issuer",
                    {
                        "id": add_obi_version_ifneeded(
                            self.cached_issuer.jsonld_id, obi_version
                        ),
                        "type": ["Profile"],
                        "name": self.cached_issuer.name,
                        "url": self.cached_issuer.url,
                        "email": self.cached_issuer.email,
                    },
                ),
                ("validFrom", self.issued_on.isoformat()),
                ("credentialSubject", credential_subject),
            ]
        )

        if self.expires_at:
            json["validUntil"] = self.expires_at.isoformat()

        json["credentialStatus"] = {
            "id": f"{self.jsonld_id}/revocations",
            "type": "1EdTechRevocationList",
        }

        if len(self.cached_extensions()) > 0:
            extension_contexts = []
            for extension in self.cached_extensions():
                extension_json = json_loads(extension.original_json)
                extension_name = extension.name

                try:
                    extension_context = extension_json["@context"]
                    if isinstance(extension_context, list):
                        extension_contexts += extension_context
                    else:
                        extension_contexts.append(extension_context)

                except KeyError:
                    pass

                json[extension_name] = extension_json

            # unique
            extension_contexts = list(set(extension_contexts))
            json["@context"] += extension_contexts

        badgeclass_extensions = self.cached_badgeclass.cached_extensions()
        if badgeclass_extensions:
            extension_contexts = []

            for extension in badgeclass_extensions:
                if extension.name == "extensions:OrgImageExtension":
                    continue
                extension_json = json_loads(extension.original_json)
                extension_name = extension.name

                # Extract contexts from extension data
                items = (
                    extension_json
                    if isinstance(extension_json, list)
                    else [extension_json]
                )
                for item in items:
                    if isinstance(item, dict) and "@context" in item:
                        ctx = item["@context"]
                        extension_contexts += ctx if isinstance(ctx, list) else [ctx]

                # Add cleaned extension data to credential
                if isinstance(extension_json, list):
                    json[extension_name] = [
                        {k: v for k, v in item.items() if k not in ["@context", "type"]}
                        for item in extension_json
                        if isinstance(item, dict)
                    ]
                else:
                    json[extension_name] = {
                        k: v
                        for k, v in extension_json.items()
                        if k not in ["@context", "type"]
                    }

            # Add unique contexts to top-level context
            json["@context"] += [
                ctx for ctx in set(extension_contexts) if ctx not in json["@context"]
            ]

        ##### proof / signing #####

        # load private key
        private_key = serialization.load_pem_private_key(
            self.cached_issuer.private_key.encode(), settings.SECRET_KEY.encode()
        )

        # basic proof dict with added @context
        proof = OrderedDict(
            [
                ("@context", "https://www.w3.org/ns/credentials/v2"),
                ("type", "DataIntegrityProof"),
                ("cryptosuite", "eddsa-rdfc-2022"),
                ("created", self.issued_on.isoformat()),
                (
                    "verificationMethod",
                    f"{add_obi_version_ifneeded(self.cached_issuer.jsonld_id, obi_version)}#key-0",
                ),
                ("proofPurpose", "assertionMethod"),
            ]
        )

        # transform https://www.w3.org/TR/vc-di-eddsa/#transformation-eddsa-rdfc-2022

        canonicalized_proof = jsonld.normalize(
            proof, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )
        canonicalized_json = jsonld.normalize(
            json, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )

        # hash transformed documents, 32bit each
        hashed_proof = sha256(canonicalized_proof.encode()).digest()
        hashed_json = sha256(canonicalized_json.encode()).digest()

        # concat for 64bit hash and sign
        signature = private_key.sign(hashed_proof + hashed_json)

        # base58 encode with multibase prefix z
        proof["proofValue"] = f"z{base58.b58encode(signature).decode()}"

        # remove proof @context
        del proof["@context"]

        # add proof to json
        json["proof"] = [proof]

        return json

    def get_revocation_json(self):
        revocation_list = {
            "id": f"{self.jsonld_id}/revocations",
            "issuer": add_obi_version_ifneeded(self.cached_issuer.jsonld_id, "3_0"),
            "revokedCredential": [],
        }
        if self.revoked:
            revocation_list["revokedCredential"].append(
                {
                    "id": add_obi_version_ifneeded(self.jsonld_id, "3_0"),
                    "revoked": True,
                    "revocationReason": self.revocation_reason
                    if self.revocation_reason
                    else "",
                }
            )

        return revocation_list

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(
        self,
        excluded_fields=(
            "@context",
            "id",
            "type",
            "uid",
            "recipient",
            "badge",
            "issuedOn",
            "image",
            "evidence",
            "narrative",
            "revoked",
            "revocationReason",
            "verify",
            "verification",
        ),
    ):
        filtered = super(BadgeInstance, self).get_filtered_json(
            excluded_fields=excluded_fields
        )
        # Ensure that the expires date string is in the expected ISO-85601 UTC format
        if (
            filtered is not None
            and filtered.get("expires", None)
            and not str(filtered.get("expires")).endswith("Z")
        ):
            filtered["expires"] = parse_original_datetime(filtered["expires"])
        return filtered

    @cachemodel.cached_method(auto_publish=True)
    def cached_evidence(self):
        if not self.pk:
            return []
        return self.badgeinstanceevidence_set.all()

    @property
    def evidence_url(self):
        """Exists for compliance with ob1.x badges"""
        evidence_list = self.cached_evidence()
        if len(evidence_list) > 1:
            return self.public_url
        if len(evidence_list) == 1 and evidence_list[0].evidence_url:
            return evidence_list[0].evidence_url
        elif len(evidence_list) == 1:
            return self.public_url

    @property
    def evidence_items(self):
        """exists to cajole EvidenceItemSerializer"""
        return self.cached_evidence()

    @evidence_items.setter
    def evidence_items(self, value):
        def _key(narrative, url):
            return "{}-{}".format(narrative or "", url or "")

        existing_evidence_idx = {
            _key(e.narrative, e.evidence_url): e for e in self.evidence_items
        }
        new_evidence_idx = {
            _key(v.get("narrative", None), v.get("evidence_url", None)): v
            for v in value
        }

        with transaction.atomic():
            if not self.pk:
                self.save()

            # add missing
            for evidence_data in value:
                key = _key(
                    evidence_data.get("narrative", None),
                    evidence_data.get("evidence_url", None),
                )
                if key not in existing_evidence_idx:
                    evidence_record, created = (
                        BadgeInstanceEvidence.cached.get_or_create(
                            badgeinstance=self,
                            narrative=evidence_data.get("narrative", None),
                            evidence_url=evidence_data.get("evidence_url", None),
                        )
                    )

            # remove old
            for evidence_record in self.evidence_items:
                key = _key(
                    evidence_record.narrative or None,
                    evidence_record.evidence_url or None,
                )
                if key not in new_evidence_idx:
                    evidence_record.delete()

    @property
    def cached_badgrapp(self):
        return self.cached_issuer.cached_badgrapp

    def get_baked_image_url(self, obi_version):
        if obi_version == UNVERSIONED_BAKED_VERSION:
            # requested version is the one referenced in assertion.image
            return self.image.url

        try:
            baked_image = BadgeInstanceBakedImage.cached.get(
                badgeinstance=self, obi_version=obi_version
            )
        except BadgeInstanceBakedImage.DoesNotExist:
            # rebake
            baked_image = BadgeInstanceBakedImage(
                badgeinstance=self, obi_version=obi_version
            )

            json_to_bake = self.get_json(
                obi_version=obi_version,
                expand_issuer=True,
                expand_badgeclass=True,
                include_extra=True,
                force_recreate=True,
            )
            badgeclass_name, ext = os.path.splitext(self.badgeclass.image.file.name)
            new_image = io.BytesIO()
            bake(
                image_file=self.cached_badgeclass.image.file,
                assertion_json_string=json_dumps(json_to_bake, indent=2),
                output_file=new_image,
            )
            baked_image.image.save(
                name="assertion-{id}-{version}{ext}".format(
                    id=self.entity_id, ext=ext, version=obi_version
                ),
                content=ContentFile(new_image.read()),
                save=False,
            )
            baked_image.save()

        return baked_image.image.url

    def generate_assertion_image(self, issuer_image=None, network_image=None):
        """Generate composed assertion image"""

        extensions = self.badgeclass.cached_extensions()
        categoryExtension = extensions.get(name="extensions:CategoryExtension")
        category = json_loads(categoryExtension.original_json)["Category"]
        org_img_ext = extensions.get(name="extensions:OrgImageExtension")
        original_image = json_loads(org_img_ext.original_json)["OrgImage"]

        composer = ImageComposer(category=category)

        image_b64 = composer.compose_badge_from_uploaded_image(
            original_image,
            issuer_image,
            network_image,
            draw_frame=self.badgeclass.imageFrame,
        )

        if not image_b64:
            raise ValueError("Assertion image generation failed")

        if image_b64.startswith("data:image/png;base64,"):
            image_b64 = image_b64.split(",", 1)[1]

        image_data = base64.b64decode(image_b64)

        filename = f"assertion_{uuid.uuid4()}.png"
        content_file = ContentFile(image_data, name=filename)

        self.image.save(filename, content_file, save=False)


def _baked_badge_instance_filename_generator(instance, filename):
    return "baked/{version}/{filename}".format(
        version=instance.obi_version, filename=filename
    )


class BadgeClassNetworkShare(models.Model):
    """
    Represents a badge that has been shared with a network.
    Partner issuers of this network can award this badge.
    A badge cannot be removed from the network after it has been shared.
    """

    badgeclass = models.ForeignKey(
        BadgeClass,
        on_delete=models.CASCADE,
        related_name="network_shares",
    )
    network = models.ForeignKey(
        Issuer,
        on_delete=models.CASCADE,
        related_name="shared_badges",
        limit_choices_to={"is_network": True},
    )
    shared_at = models.DateTimeField(auto_now_add=True)
    shared_by_user = models.ForeignKey(
        "badgeuser.BadgeUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="badge_shares",
    )
    shared_by_issuer = models.ForeignKey(
        Issuer,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="network_shares_created",
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ("badgeclass", "network")
        verbose_name = "Badge Class Network Share"
        verbose_name_plural = "Badge Class Network Shares"

    def __str__(self):
        return f"{self.badgeclass} shared with {self.network}"


class BadgeInstanceBakedImage(cachemodel.CacheModel):
    badgeinstance = models.ForeignKey("issuer.BadgeInstance", on_delete=models.CASCADE)
    obi_version = models.CharField(max_length=254)
    image = models.FileField(
        upload_to=_baked_badge_instance_filename_generator, blank=True
    )

    def publish(self):
        self.publish_by("badgeinstance", "obi_version")
        return super(BadgeInstanceBakedImage, self).publish()

    def delete(self, *args, **kwargs):
        self.publish_delete("badgeinstance", "obi_version")
        return super(BadgeInstanceBakedImage, self).delete(*args, **kwargs)


class BadgeInstanceEvidence(OriginalJsonMixin, cachemodel.CacheModel):
    badgeinstance = models.ForeignKey("issuer.BadgeInstance", on_delete=models.CASCADE)
    evidence_url = models.CharField(
        max_length=2083, blank=True, null=True, default=None
    )
    narrative = models.TextField(blank=True, null=True, default=None)

    objects = BadgeInstanceEvidenceManager()

    def publish(self):
        super(BadgeInstanceEvidence, self).publish()
        self.badgeinstance.publish()

    def delete(self, *args, **kwargs):
        badgeinstance = self.badgeinstance
        ret = super(BadgeInstanceEvidence, self).delete(*args, **kwargs)
        badgeinstance.publish()
        return ret

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_context=False):
        json = OrderedDict()
        if include_context:
            obi_version, context_iri = get_obi_context(obi_version)
            json["@context"] = context_iri

        if obi_version == "2_0":
            json["type"] = "Evidence"

        if obi_version == "3_0":
            json["type"] = ["Evidence"]

        if self.evidence_url:
            json["id"] = self.evidence_url
        if self.narrative:
            json["narrative"] = self.narrative

        return json


class BadgeClassAlignment(OriginalJsonMixin, cachemodel.CacheModel):
    badgeclass = models.ForeignKey("issuer.BadgeClass", on_delete=models.CASCADE)
    target_name = models.TextField()
    target_url = models.CharField(max_length=2083)
    target_description = models.TextField(blank=True, null=True, default=None)
    target_framework = models.TextField(blank=True, null=True, default=None)
    target_code = models.TextField(blank=True, null=True, default=None)

    def publish(self):
        super(BadgeClassAlignment, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassAlignment, self).delete(*args, **kwargs)
        self.badgeclass.publish()

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_context=False):
        json = OrderedDict()
        if include_context:
            obi_version, context_iri = get_obi_context(obi_version)
            json["@context"] = context_iri

        json["targetName"] = self.target_name
        json["targetUrl"] = self.target_url
        if self.target_description:
            json["targetDescription"] = self.target_description
        if self.target_framework:
            json["targetFramework"] = self.target_framework
        if self.target_code:
            json["targetCode"] = self.target_code

        return json


class BadgeClassTag(cachemodel.CacheModel):
    badgeclass = models.ForeignKey("issuer.BadgeClass", on_delete=models.CASCADE)
    name = models.CharField(max_length=254, db_index=True)

    def __str__(self):
        return self.name

    def publish(self):
        super(BadgeClassTag, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassTag, self).delete(*args, **kwargs)
        self.badgeclass.publish()


class LearningPathTag(cachemodel.CacheModel):
    learningPath = models.ForeignKey("issuer.LearningPath", on_delete=models.CASCADE)
    name = models.CharField(max_length=254, db_index=True)

    def __str__(self):
        return self.name

    def publish(self):
        super(LearningPathTag, self).publish()

    def delete(self, *args, **kwargs):
        super(LearningPathTag, self).delete(*args, **kwargs)


class IssuerExtension(BaseOpenBadgeExtension):
    issuer = models.ForeignKey("issuer.Issuer", on_delete=models.CASCADE)

    def publish(self):
        super(IssuerExtension, self).publish()
        self.issuer.publish(publish_staff=False)

    def delete(self, *args, **kwargs):
        super(IssuerExtension, self).delete(*args, **kwargs)
        self.issuer.publish(publish_staff=False)


class BadgeClassExtension(BaseOpenBadgeExtension):
    badgeclass = models.ForeignKey("issuer.BadgeClass", on_delete=models.CASCADE)

    def publish(self):
        super(BadgeClassExtension, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassExtension, self).delete(*args, **kwargs)
        self.badgeclass.publish()


class BadgeInstanceExtension(BaseOpenBadgeExtension):
    badgeinstance = models.ForeignKey("issuer.BadgeInstance", on_delete=models.CASCADE)

    def publish(self):
        super(BadgeInstanceExtension, self).publish()
        self.badgeinstance.publish()

    def delete(self, *args, **kwargs):
        super(BadgeInstanceExtension, self).delete(*args, **kwargs)
        self.badgeinstance.publish()


class ImportedBadgeAssertionExtension(BaseOpenBadgeExtension):
    importedBadge = models.ForeignKey(
        "issuer.ImportedBadgeAssertion", on_delete=models.CASCADE
    )

    def publish(self):
        super(ImportedBadgeAssertionExtension, self).publish()
        self.importedBadge.publish()

    def delete(self, *args, **kwargs):
        super(ImportedBadgeAssertionExtension, self).delete(*args, **kwargs)
        self.importedBadge.publish()


class QrCode(BaseVersionedEntity):
    badgeclass = models.ForeignKey(
        BadgeClass,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="qrcodes",
    )

    issuer = models.ForeignKey(Issuer, on_delete=models.CASCADE)

    title = models.CharField(max_length=254, blank=False, null=False)

    createdBy = models.CharField(max_length=254, blank=False, null=False)

    created_by_user = models.ForeignKey(
        "badgeuser.BadgeUser",
        null=True,
        related_name="+",
        on_delete=models.SET_NULL,
    )

    activity_start_date = models.DateTimeField(
        blank=True,
        null=True,
        default=None,
        help_text="The datetime the activity/course started",
    )
    activity_end_date = models.DateTimeField(
        blank=True,
        null=True,
        default=None,
        help_text="The datetime the activity/course ended",
    )

    activity_zip = models.CharField(max_length=255, null=True, blank=True)
    activity_city = models.CharField(max_length=255, null=True, blank=True)
    activity_online = models.BooleanField(blank=True, null=False, default=False)

    course_url = models.CharField(max_length=255, blank=True, null=True, default=None)

    valid_from = models.DateTimeField(blank=True, null=True, default=None)

    expires_at = models.DateTimeField(blank=True, null=True, default=None)

    evidence_items = JSONField(default=list, blank=True)

    notifications = models.BooleanField(null=False, default=False)


class RequestedBadge(BaseVersionedEntity):
    badgeclass = models.ForeignKey(
        BadgeClass,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="requestedbadges",
    )
    user = models.ForeignKey(
        "badgeuser.BadgeUser",
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
    )

    qrcode = models.ForeignKey(
        QrCode,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="requestedbadges",
    )

    firstName = models.CharField(max_length=254, blank=False, null=False)
    lastName = models.CharField(max_length=254, blank=False, null=False)
    email = models.CharField(max_length=254, blank=True, null=True)

    requestedOn = models.DateTimeField(blank=False, null=False, default=timezone.now)

    status = models.CharField(
        max_length=254, blank=False, null=False, default="Pending"
    )


class LearningPath(BaseVersionedEntity, BaseAuditedModel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_activated = self.activated

    name = models.CharField(max_length=254, blank=False, null=False)
    description = models.TextField(blank=True, null=True, default=None)
    issuer = models.ForeignKey(
        Issuer,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="learningpaths",
    )
    participationBadge = models.ForeignKey(
        BadgeClass, blank=False, null=False, on_delete=models.CASCADE
    )
    badgrapp = models.ForeignKey(
        "mainsite.BadgrApp",
        blank=True,
        null=True,
        default=None,
        on_delete=models.SET_NULL,
    )
    slug = models.CharField(
        max_length=255, db_index=True, blank=True, null=True, default=None
    )

    required_badges_count = models.PositiveIntegerField()
    activated = models.BooleanField(null=False, default=False)

    @property
    def public_url(self):
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def v1_api_participant_count(self):
        # count users with issued lp badges
        lp_badges = LearningPathBadge.objects.filter(learning_path=self)
        lp_badgeclasses = [lp_badge.badge for lp_badge in lp_badges]
        instances = BadgeInstance.objects.filter(
            badgeclass__in=lp_badgeclasses, revoked=False
        )
        users = set([i.user for i in instances])
        return len(users)

    @property
    def cached_badgrapp(self):
        id = self.badgrapp_id if self.badgrapp_id else None
        return BadgrApp.objects.get_by_id_or_default(badgrapp_id=id)

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)

    @cachemodel.cached_method(auto_publish=True)
    def cached_learningpathbadges(self):
        return self.learningpathbadge_set.all()

    @property
    def learningpath_badges(self):
        # TODO: return from cache
        # return self.cached_learningpathbadges()
        return self.learningpathbadge_set.all()

    @learningpath_badges.setter
    def learningpath_badges(self, badges_with_order):
        self.learningpathbadge_set.all().delete()

        for badge, order in badges_with_order:
            LearningPathBadge.objects.create(
                learning_path=self, badge=badge, order=order
            )

    @cachemodel.cached_method(auto_publish=True)
    def cached_tags(self):
        return self.learningpathtag_set.all()

    @property
    def tag_items(self):
        return self.cached_tags()

    @tag_items.setter
    def tag_items(self, value):
        if value is None:
            value = []
        existing_idx = [t.name for t in self.tag_items]
        new_idx = value

        with transaction.atomic():
            if not self.pk:
                self.save()

            # add missing
            for t in value:
                if t not in existing_idx:
                    tag = self.learningpathtag_set.create(name=t)

            # remove old
            for tag in self.tag_items:
                if tag.name not in new_idx:
                    tag.delete()

    def save(self, *args, **kwargs):
        activated = False

        if self.pk:
            if not self._original_activated and self.activated:
                activated = True
        else:
            if self.activated:
                activated = True

        super().save(*args, **kwargs)
        self._original_activated = self.activated

        if activated:
            from mainsite.tasks import process_learning_path_activation

            process_learning_path_activation.delay(self.pk)

    def get_json(
        self,
        obi_version=CURRENT_OBI_VERSION,
    ):
        json = OrderedDict({})
        json.update(
            OrderedDict(
                name=self.name,
                description=self.description,
                slug=self.entity_id,
                issuer_id=self.issuer.entity_id,
                created_at=self.created_at,
            )
        )

        tags = self.learningpathtag_set.all()
        badges = self.learningpathbadge_set.all()
        image = "{}{}?type=png".format(
            OriginSetting.HTTP,
            reverse(
                "badgeclass_image",
                kwargs={"entity_id": self.participationBadge.entity_id},
            ),
        )

        json["tags"] = list(t.name for t in tags)

        json["badges"] = [
            {
                "badge": badge.badge.get_json(obi_version=obi_version),
                "order": badge.order,
            }
            for badge in badges
        ]

        json["participationBadge_image"] = image

        json["activated"] = self.activated

        return json

    def get_absolute_url(self):
        return reverse("learningpath_json", kwargs={"entity_id": self.entity_id})

    def user_has_completed(self, recipient_identifier):
        badgeclasses = [lp_badge.badge for lp_badge in self.learningpath_badges]
        badgeinstances = BadgeInstance.objects.filter(
            recipient_identifier=recipient_identifier,
            badgeclass__in=badgeclasses,
            revoked=False,
        )
        completed_badges = list(
            {badgeinstance.badgeclass for badgeinstance in badgeinstances}
        )

        return len(completed_badges) >= self.required_badges_count

    def user_should_have_badge(self, recipient_identifier):
        if self.user_has_completed(recipient_identifier):
            # check to only award the participationBadge once
            badgeinstances = BadgeInstance.objects.filter(
                badgeclass=self.participationBadge,
                recipient_identifier=recipient_identifier,
                revoked=False,
            )
            return len(badgeinstances) == 0

        return False

    def calculate_progress(self, badgeclasses):
        return sum(
            json_loads(ext.original_json)["StudyLoad"]
            for badge in badgeclasses
            for ext in badge.cached_extensions()
            if ext.name == "extensions:StudyLoadExtension"
        )

    def get_lp_badgeinstance(self, recipient_identifier):
        return BadgeInstance.objects.filter(
            badgeclass=self.participationBadge,
            recipient_identifier=recipient_identifier,
            revoked=False,
        ).first()

    def get_studyload(self):
        studyLoadExt = self.participationBadge.cached_extensions().get(
            name="extensions:StudyLoadExtension"
        )
        studyLoadJson = json_loads(studyLoadExt.original_json)
        return studyLoadJson["StudyLoad"]


class LearningPathBadge(cachemodel.CacheModel):
    learning_path = models.ForeignKey(LearningPath, on_delete=models.CASCADE)
    badge = models.ForeignKey(BadgeClass, on_delete=models.CASCADE)
    order = models.PositiveIntegerField()

    def publish(self):
        super(LearningPathBadge, self).publish()

    def delete(self, *args, **kwargs):
        super(LearningPathBadge, self).delete(*args, **kwargs)


class RequestedLearningPath(BaseVersionedEntity):
    learningpath = models.ForeignKey(
        LearningPath,
        blank=False,
        null=False,
        on_delete=models.CASCADE,
        related_name="requested_learningpath",
    )
    user = models.ForeignKey(
        "badgeuser.BadgeUser",
        blank=False,
        null=False,
        on_delete=models.CASCADE,
    )

    requestedOn = models.DateTimeField(blank=False, null=False, default=timezone.now)

    status = models.CharField(
        max_length=254, blank=False, null=False, default="Pending"
    )
