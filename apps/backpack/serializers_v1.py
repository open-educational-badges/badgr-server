import datetime
from collections import OrderedDict

from django.core.exceptions import ValidationError as DjangoValidationError
from django.urls import reverse
from django.utils.dateparse import parse_datetime, parse_date
from rest_framework import serializers
from rest_framework.fields import JSONField
from rest_framework.exceptions import ValidationError as RestframeworkValidationError
from rest_framework.fields import SkipField

from backpack.models import BackpackCollection, BackpackCollectionBadgeInstance
from issuer.helpers import BadgeCheckHelper, ImportedBadgeHelper
from issuer.models import BadgeInstance, ImportedBadgeAssertion
from issuer.serializers_v1 import EvidenceItemSerializer
from mainsite.drf_fields import Base64FileField
from mainsite.serializers import StripTagsCharField, MarkdownCharField
from mainsite.utils import OriginSetting


class ImportedBadgeAssertionSerializer(serializers.Serializer):
    """
    Serializer for importing and retrieving imported badge assertions.
    """

    image = Base64FileField(required=False, write_only=True)
    url = serializers.URLField(required=False, write_only=True)
    assertion = serializers.CharField(required=False, write_only=True)
    id = serializers.CharField(source="entity_id", read_only=True)
    badge_name = serializers.CharField(read_only=True)
    badge_description = serializers.CharField(read_only=True)
    issuer_name = serializers.CharField(read_only=True)
    issuer_url = serializers.URLField(read_only=True)
    issued_on = serializers.DateTimeField(read_only=True)
    recipient_identifier = serializers.CharField(read_only=True)
    recipient_type = serializers.CharField(read_only=True)
    acceptance = serializers.CharField(default="Accepted")
    narrative = MarkdownCharField(read_only=True)

    original_json = serializers.JSONField(read_only=True)
    extensions = serializers.DictField(source="extension_items", read_only=True)

    def to_representation(self, obj):
        representation = super().to_representation(obj)

        if obj.image:
            representation["image"] = obj.image.url
        elif obj.badge_image_url:
            representation["image"] = obj.badge_image_url

        representation["imagePreview"] = {"type": "image", "id": obj.image_url()}

        if obj.issuer_image_url:
            representation["issuerImagePreview"] = {
                "type": "image",
                "id": obj.issuer_image_url,
            }

        representation["verification"] = {
            "type": "HostedBadge",
            "url": obj.verification_url,
        }

        representation["slug"] = obj.entity_id

        representation["json"] = {
            "id": obj.original_json.get("assertion", {}).get("id"),
            "type": "Assertion",
            "badge": {
                "name": obj.badge_name,
                "description": obj.badge_description,
                "image": obj.badge_image_url,
                "issuer": {
                    "name": obj.issuer_name,
                    "url": obj.issuer_url,
                    "email": obj.issuer_email,
                    "image": obj.issuer_image_url,
                },
            },
            "issuedOn": obj.issued_on if obj.issued_on else None,
            "recipient": {
                "type": obj.recipient_type,
                "identity": obj.recipient_identifier,
            },
            "verification": {"type": "HostedBadge", "url": obj.verification_url},
        }

        return representation

    def validate(self, data):
        """
        Ensure only one assertion input field given.
        """
        fields_present = [
            "image" in data,
            "url" in data,
            "assertion" in data and data.get("assertion"),
        ]
        if fields_present.count(True) > 1:
            raise serializers.ValidationError("Only one instance input field allowed.")

        return data

    def create(self, validated_data):
        owner = validated_data.get("user")

        try:
            instance, created = ImportedBadgeHelper.get_or_create_imported_badge(
                url=validated_data.get("url", None),
                imagefile=validated_data.get("image", None),
                assertion=validated_data.get("assertion", None),
                user=owner,
            )
            if not created:
                if instance.acceptance == ImportedBadgeAssertion.ACCEPTANCE_ACCEPTED:
                    raise RestframeworkValidationError(
                        [
                            {
                                "name": "DUPLICATE_BADGE",
                                "description": "You already have this badge in your backpack",
                            }
                        ]
                    )
                instance.acceptance = ImportedBadgeAssertion.ACCEPTANCE_ACCEPTED
                instance.save()
        except DjangoValidationError as e:
            raise RestframeworkValidationError(e.args[0])
        return instance


class LocalBadgeInstanceUploadSerializerV1(serializers.Serializer):
    image = Base64FileField(required=False, write_only=True)
    url = serializers.URLField(required=False, write_only=True)
    assertion = serializers.CharField(required=False, write_only=True)
    recipient_identifier = serializers.CharField(required=False, read_only=True)
    acceptance = serializers.CharField(default="Accepted")
    narrative = MarkdownCharField(required=False, read_only=True)
    evidence_items = EvidenceItemSerializer(many=True, required=False, read_only=True)
    pending = serializers.BooleanField(read_only=True)

    extensions = serializers.DictField(source="extension_items", read_only=True)

    # Reinstantiation using fields from badge instance when returned by .create
    # id = serializers.IntegerField(read_only=True)
    # json = V1InstanceSerializer(read_only=True)

    def to_representation(self, obj):
        """
        If the APIView initialized the serializer with the extra context
        variable 'format' from a query param in the GET request with the
        value "plain", make the `json` field for this instance read_only.
        """
        if self.context.get("format", "v1") == "plain":
            self.fields.json = serializers.DictField(read_only=True)
        representation = super(
            LocalBadgeInstanceUploadSerializerV1, self
        ).to_representation(obj)

        # supress errors for badges without extensions (i.e. imported)
        try:
            representation["extensions"]["extensions:CompetencyExtension"] = (
                obj.badgeclass.json["extensions:CompetencyExtension"]
            )
            representation["extensions"]["extensions:CategoryExtension"] = (
                obj.badgeclass.json["extensions:CategoryExtension"]
            )
            representation["extensions"]["extensions:StudyLoadExtension"] = (
                obj.badgeclass.json["extensions:StudyLoadExtension"]
            )
        except KeyError:
            pass

        representation["id"] = obj.entity_id
        representation["json"] = V1BadgeInstanceSerializer(
            obj, context=self.context
        ).data
        representation["imagePreview"] = {
            "type": "image",
            "id": "{}{}?type=png".format(
                OriginSetting.HTTP,
                reverse(
                    "badgeclass_image",
                    kwargs={"entity_id": obj.cached_badgeclass.entity_id},
                ),
            ),
        }
        if obj.cached_issuer.image:
            representation["issuerImagePreview"] = {
                "type": "image",
                "id": "{}{}?type=png".format(
                    OriginSetting.HTTP,
                    reverse(
                        "issuer_image",
                        kwargs={"entity_id": obj.cached_issuer.entity_id},
                    ),
                ),
            }

        if obj.image:
            representation["image"] = obj.image_url()

        representation["shareUrl"] = obj.share_url
        representation["courseUrl"] = obj.course_url

        networkShare = obj.cached_badgeclass.network_shares.filter(
            is_active=True
        ).first()
        if networkShare:
            network = networkShare.network
            representation["sharedOnNetwork"] = {
                "slug": network.entity_id,
                "name": network.name,
                "image": network.image.url,
                "description": network.description,
            }
        else:
            representation["sharedOnNetwork"] = None

        representation["isNetworkBadge"] = (
            obj.cached_badgeclass.cached_issuer.is_network
            and representation["sharedOnNetwork"] is None
        )

        if representation["isNetworkBadge"]:
            representation["networkName"] = obj.cached_badgeclass.cached_issuer.name
            representation["networkImage"] = (
                obj.cached_badgeclass.cached_issuer.image.url
            )
        else:
            representation["networkImage"] = None
            representation["networkName"] = None

        return representation

    def validate(self, data):
        """
        Ensure only one assertion input field given.
        """

        fields_present = [
            "image" in data,
            "url" in data,
            "assertion" in data and data.get("assertion"),
        ]
        if fields_present.count(True) > 1:
            raise serializers.ValidationError("Only one instance input field allowed.")

        return data

    def create(self, validated_data):
        owner = validated_data.get("created_by")

        try:
            instance, created = BadgeCheckHelper.get_or_create_imported_badge(
                url=validated_data.get("url", None),
                imagefile=validated_data.get("image", None),
                assertion=validated_data.get("assertion", None),
                created_by=owner,
            )
            if not created:
                if instance.acceptance == BadgeInstance.ACCEPTANCE_ACCEPTED:
                    raise RestframeworkValidationError(
                        [
                            {
                                "name": "DUPLICATE_BADGE",
                                "description": "You already have this badge in your backpack",
                            }
                        ]
                    )
                instance.acceptance = BadgeInstance.ACCEPTANCE_ACCEPTED
                instance.save()
            owner.publish()  # update BadgeUser.cached_badgeinstances()
        except DjangoValidationError as e:
            raise RestframeworkValidationError(e.args[0])
        return instance

    def update(self, instance, validated_data):
        """Only updating acceptance status (to 'Accepted') is permitted for now."""
        # Only locally issued badges will ever have an acceptance status other than 'Accepted'
        if (
            instance.acceptance == "Unaccepted"
            and validated_data.get("acceptance") == "Accepted"
        ):
            instance.acceptance = "Accepted"

            instance.save()
            owner = instance.user
            if owner:
                owner.publish()

        return instance


class CollectionBadgesSerializerV1(serializers.ListSerializer):
    def to_representation(self, data):
        filtered_data = [
            b
            for b in data
            if (
                b.cached_badgeinstance.acceptance
                is not BadgeInstance.ACCEPTANCE_REJECTED
                and b.cached_badgeinstance.revoked is False
            )
        ]
        filtered_data = [
            c
            for c in filtered_data
            if (
                c.cached_badgeinstance.recipient_identifier
                in c.cached_collection.owner.all_verified_recipient_identifiers
            )
        ]

        representation = super(CollectionBadgesSerializerV1, self).to_representation(
            filtered_data
        )
        return representation

    def save(self, **kwargs):
        collection = self.context.get("collection")
        updated_ids = set()

        # get all referenced badges in validated_data
        for entry in self.validated_data:
            if not entry.pk or getattr(entry, "_dirty", False):
                entry.save()
            updated_ids.add(entry.pk)

        if not self.context.get("add_only", False):
            for old_entry in collection.cached_collects():
                if old_entry.pk not in updated_ids:
                    old_entry.delete()

        self.instance = self.validated_data
        # return a list of the new entries added (which is all of the final list in case of update)
        return [e for e in self.validated_data if e.pk in updated_ids]


class CollectionBadgeSerializerV1(serializers.ModelSerializer):
    id = serializers.SlugRelatedField(
        slug_field="entity_id",
        queryset=BadgeInstance.objects.all(),
    )
    collection = serializers.SlugRelatedField(
        slug_field="entity_id",
        queryset=BackpackCollection.objects.all(),
        write_only=True,
        required=False,
    )

    class Meta:
        model = BackpackCollectionBadgeInstance
        list_serializer_class = CollectionBadgesSerializerV1
        fields = ("id", "collection", "badgeinstance")

    def get_validators(self):
        return []

    def to_internal_value(self, data):
        # populate collection from various methods
        collection = data.get("collection")
        if not collection:
            collection = self.context.get("collection")
        if not collection and self.parent.parent:
            collection = self.parent.parent.instance
        elif not collection and self.parent.instance:
            collection = self.parent.instance
        if not collection:
            return BackpackCollectionBadgeInstance(
                badgeinstance=BadgeInstance.cached.get(entity_id=data.get("id"))
            )

        try:
            badgeinstance = BadgeInstance.cached.get(entity_id=data.get("id"))
        except BadgeInstance.DoesNotExist:
            raise RestframeworkValidationError("Assertion not found")
        if (
            badgeinstance.recipient_identifier
            not in collection.owner.all_verified_recipient_identifiers
        ):
            raise serializers.ValidationError(
                "Cannot add badge to a collection created by a different recipient."
            )

        collect, created = BackpackCollectionBadgeInstance.objects.get_or_create(
            collection=collection, badgeinstance=badgeinstance
        )
        return collect

    def to_representation(self, instance):
        ret = OrderedDict()
        ret["id"] = instance.cached_badgeinstance.entity_id
        ret["description"] = ""
        return ret


class CollectionSerializerV1(serializers.Serializer):
    name = StripTagsCharField(required=True, max_length=128)
    slug = StripTagsCharField(required=False, max_length=128, source="entity_id")
    description = StripTagsCharField(
        required=False, allow_blank=True, allow_null=True, max_length=255
    )
    permanent_hash = serializers.CharField(read_only=True, source="permanent_url")
    share_hash = serializers.CharField(read_only=True)
    share_url = serializers.CharField(read_only=True, max_length=1024)
    badges = CollectionBadgeSerializerV1(
        read_only=False, many=True, required=False, source="cached_collects"
    )
    published = serializers.BooleanField(required=False)

    def to_representation(self, instance):
        representation = super(CollectionSerializerV1, self).to_representation(instance)
        if representation.get("share_url", None) is None:
            #  V1 api expects share_url to be an empty string and not null if unpublished
            representation["share_url"] = ""
        return representation

    def create(self, validated_data):
        owner = validated_data.get("created_by", self.context.get("user", None))
        new_collection = BackpackCollection.objects.create(
            name=validated_data.get("name"),
            description=validated_data.get("description", ""),
            created_by=owner,
        )
        published = validated_data.get("published", False)
        if published:
            new_collection.published = published
            new_collection.save()

        for collect in validated_data.get("cached_collects", []):
            collect.collection = new_collection
            collect.badgeuser = new_collection.created_by
            collect.save()

        return new_collection

    def update(self, instance, validated_data):
        instance.name = validated_data.get("name", instance.name)
        instance.description = validated_data.get("description", instance.description)
        instance.published = validated_data.get("published", instance.published)

        if (
            "cached_collects" in validated_data
            and validated_data["cached_collects"] is not None
        ):
            existing_entries = list(instance.cached_collects())
            updated_ids = set()

            for entry in validated_data["cached_collects"]:
                if not entry.pk:
                    entry.save()
                updated_ids.add(entry.pk)

            for old_entry in existing_entries:
                if old_entry.pk not in updated_ids:
                    old_entry.delete()

        instance.save()
        return instance


##
#
# the below exists to prop up V1BadgeInstanceSerializer for /v1/ backwards compatability
# in LocalBadgeInstanceUploadSerializer.
# It was taken from composition/format.py and verifier/serializers/fields.py
# before those apps were deprecated
#
# [Wiggins June 2017]
##


class BadgePotentiallyEmptyField(serializers.Field):
    def get_attribute(self, instance):
        value = serializers.Field.get_attribute(self, instance)

        if value == "" or value is None or value == {}:
            if not self.required or not self.allow_blank:
                raise SkipField()
        return value

    def validate_empty_values(self, data):
        """
        If an empty value (empty string, null) exists in an optional
        field, SkipField.
        """
        (is_empty_value, data) = serializers.Field.validate_empty_values(self, data)

        if is_empty_value or data == "":
            if self.required:
                self.fail("required")
            raise SkipField()

        return (False, data)


class VerifierBadgeDateTimeField(BadgePotentiallyEmptyField, serializers.Field):
    default_error_messages = {
        "not_int_or_str": "Invalid format. Expected an int or str.",
        "bad_str": "Invalid format. String is not ISO 8601 or unix timestamp.",
        "bad_int": "Invalid format. Unix timestamp is out of range.",
    }

    def to_internal_value(self, value):
        if isinstance(value, str):
            try:
                return datetime.datetime.utcfromtimestamp(float(value))
            except ValueError:
                pass

            result = parse_datetime(value)
            if not result:
                try:
                    result = datetime.datetime.combine(
                        parse_date(value), datetime.datetime.min.time()
                    )
                except (TypeError, ValueError):
                    self.fail("bad_str")
            return result
        elif isinstance(value, (int, float)):
            try:
                return datetime.datetime.utcfromtimestamp(value)
            except ValueError:
                self.fail("bad_int")
        else:
            self.fail("not_int_or_str")

    def to_representation(self, string_value):
        if isinstance(string_value, (str, int, float)):
            value = self.to_internal_value(string_value)
        else:
            value = string_value

        return value.isoformat()


class BadgeURLField(serializers.URLField):
    def to_representation(self, value):
        if self.context.get("format", "v1") == "v1":
            result = {"type": "@id", "id": value}
            if self.context.get("name") is not None:
                result["name"] = self.context.get("name")
            return result
        else:
            return value


class BadgeImageURLField(serializers.URLField):
    def to_representation(self, value):
        if self.context.get("format", "v1") == "v1":
            result = {"type": "image", "id": value}
            if self.context.get("name") is not None:
                result["name"] = self.context.get("name")
            return result
        else:
            return value


class BadgeStringField(serializers.CharField):
    def to_representation(self, value):
        if self.context.get("format", "v1") == "v1":
            return {"type": "xsd:string", "@value": value}
        else:
            return value


class BadgeEmailField(serializers.EmailField):
    def to_representation(self, value):
        if self.context.get("format", "v1") == "v1":
            return {"type": "email", "@value": value}
        else:
            return value


class BadgeDateTimeField(VerifierBadgeDateTimeField):
    def to_representation(self, string_value):
        value = super(BadgeDateTimeField, self).to_representation(string_value)
        if self.context.get("format", "v1") == "v1":
            return {"type": "xsd:dateTime", "@value": value}
        else:
            return value


class V1IssuerSerializer(serializers.Serializer):
    id = serializers.URLField(required=False)  # v0.5 Badge Classes have none
    type = serializers.CharField()
    name = BadgeStringField()
    url = BadgeURLField()
    description = BadgeStringField(required=False)
    image = BadgeImageURLField(required=False)
    email = BadgeEmailField(required=False)
    slug = serializers.CharField(required=False)


class V1BadgeClassSerializer(serializers.Serializer):
    id = serializers.URLField(required=False)  # v0.5 Badge Classes have none
    type = serializers.CharField()
    name = BadgeStringField()
    description = BadgeStringField()
    image = BadgeImageURLField()
    criteria = JSONField(required=False)
    criteria_text = BadgeStringField(required=False)
    criteria_url = BadgeURLField(required=False)
    issuer = V1IssuerSerializer()
    tags = serializers.ListField(child=BadgeStringField(), required=False)
    areas = serializers.ListField(child=BadgeStringField(), required=False)
    slug = BadgeStringField()

    def to_representation(self, instance):
        representation = super(V1BadgeClassSerializer, self).to_representation(instance)
        if "alignment" in instance:
            representation["alignment"] = instance["alignment"]
        return representation


class V1InstanceSerializer(serializers.Serializer):
    id = serializers.URLField(required=False)
    type = serializers.CharField()
    uid = BadgeStringField(required=False)
    recipient = BadgeEmailField()  # TODO: improve for richer types
    badge = V1BadgeClassSerializer()
    issuedOn = BadgeDateTimeField(required=False)  # missing in some translated v0.5.0
    validFrom = BadgeDateTimeField(required=False)  # for ob3.0
    expires = BadgeDateTimeField(required=False)
    image = BadgeImageURLField(required=False)
    evidence = BadgeURLField(required=False)
    credentialSubject = serializers.DictField(required=False)

    def to_representation(self, instance):
        data = super().to_representation(instance)

        # add context for checking of ob version
        data["@context"] = instance["@context"]

        return data


class V1BadgeInstanceSerializer(V1InstanceSerializer):
    """
    used to serialize a issuer.BadgeInstance like a composition.LocalBadgeInstance
    """

    pending = serializers.ReadOnlyField()

    def to_representation(self, instance):
        localbadgeinstance_json = instance.json
        if "evidence" in localbadgeinstance_json:
            localbadgeinstance_json["evidence"] = instance.evidence_url
        localbadgeinstance_json["uid"] = instance.entity_id
        if instance.expires_at:
            localbadgeinstance_json["expires"] = instance.expires_at.isoformat()
        # TODO: check if badge can be removed as now the badge metadata is also included under credentialSubject.achievement
        localbadgeinstance_json["badge"] = instance.cached_badgeclass.json
        localbadgeinstance_json["badge"]["slug"] = instance.cached_badgeclass.entity_id
        localbadgeinstance_json["badge"]["criteria"] = (
            instance.cached_badgeclass.get_criteria()
        )
        localbadgeinstance_json["badge"]["issuer"] = instance.cached_issuer.json

        # clean up recipient to match V1InstanceSerializer
        localbadgeinstance_json["recipient"] = {
            "type": "email",
            "recipient": instance.recipient_identifier,
        }

        credential_subject = localbadgeinstance_json.get("credentialSubject", {})

        if instance.activity_start_date:
            credential_subject["activityStartDate"] = (
                instance.activity_start_date.isoformat()
            )
        if instance.activity_end_date:
            credential_subject["activityEndDate"] = (
                instance.activity_end_date.isoformat()
            )

        if instance.activity_city:
            credential_subject["activityCity"] = instance.activity_city

        if instance.activity_online:
            credential_subject["activityOnline"] = instance.activity_online

        localbadgeinstance_json["credentialSubject"] = credential_subject
        return super(V1BadgeInstanceSerializer, self).to_representation(
            localbadgeinstance_json
        )
