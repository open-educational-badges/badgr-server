from rest_framework import serializers
from entity.serializers import DetailSerializerV2
from issuer.models import BadgeClass, Issuer
from django.contrib.gis.geos import Point
from rest_framework_gis.serializers import (
    GeoFeatureModelSerializer,
    GeometrySerializerMethodField,
)


class BadgeClassSerializerV3(DetailSerializerV2):
    class Meta(DetailSerializerV2.Meta):
        model = BadgeClass


class TagSerializerV3(serializers.Serializer):
    tags = serializers.ListField(child=serializers.CharField())


class BaseRequestIframeSerializer(serializers.Serializer):
    """Base serializer for all iFrame request endpoints"""

    LANGUAGES = [
        ("en", "English"),
        ("de", "German"),
    ]

    lang = serializers.ChoiceField(choices=LANGUAGES, default="en")


class RequestIframeSerializer(BaseRequestIframeSerializer):
    email = serializers.CharField()


class RequestIframeBadgeProcessSerializer(BaseRequestIframeSerializer):
    issuer = serializers.CharField(required=False, default=None)
    badge = serializers.CharField(required=False, default=None)


class IssuerGeoJSONSerializer(GeoFeatureModelSerializer):
    class Meta:
        model = Issuer
        geo_field = "location"  # Field containing the geometry (PointField)
        fields = ["id", "name", "image", "description", "category"]

    location = GeometrySerializerMethodField()

    def get_location(self, obj):
        if obj.lat and obj.lon:
            return Point(obj.lon, obj.lat)
        else:
            return None
