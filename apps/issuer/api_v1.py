# encoding: utf-8

import json
from django.conf import Settings, settings
from django.http import HttpResponse
from django.views import View
from drf_spectacular.utils import (
    extend_schema,
    extend_schema_view,
    OpenApiParameter,
    OpenApiExample,
    inline_serializer,
)
from django.contrib.auth import get_user_model
from rest_framework import status, authentication, serializers
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.mainsite.views import call_aiskills_api
from badgeuser.models import CachedEmailAddress, UserRecipientIdentifier
from entity.api import VersionedObjectMixin
from issuer.models import AiSkillRequest, Issuer, IssuerStaff
from issuer.permissions import IsOwnerOrStaff, BadgrOAuthTokenHasEntityScope
from issuer.serializers_v1 import (
    BadgeClassSerializerV1,
    IssuerRoleActionSerializerV1,
    IssuerStaffSerializerV1,
)
from issuer.utils import get_badgeclass_by_identifier, quota_check
from mainsite.permissions import AuthenticatedWithVerifiedIdentifier, IsServerAdmin
from mainsite.utils import throttleable


class AbstractIssuerAPIEndpoint(APIView):
    authentication_classes = (
        authentication.TokenAuthentication,
        authentication.SessionAuthentication,
        authentication.BasicAuthentication,
    )
    permission_classes = (AuthenticatedWithVerifiedIdentifier,)

    def get_object(self, slug, queryset=None):
        """Ensure user has permissions on Issuer"""

        queryset = queryset if queryset is not None else self.queryset
        try:
            obj = queryset.get(entity_id=slug)
        except self.model.DoesNotExist:
            return None

        try:
            self.check_object_permissions(self.request, obj)
        except PermissionDenied:
            return None
        else:
            return obj

    def get_list(self, slug=None, queryset=None, related=None):
        """Ensure user has permissions on Issuer, and return badgeclass queryset if so."""
        queryset = queryset if queryset is not None else self.queryset

        obj = queryset
        if slug is not None:
            obj = queryset.filter(slug=slug)
        if related is not None:
            obj = queryset.select_related(related)

        if not obj.exists():
            return self.model.objects.none()

        try:
            self.check_object_permissions(self.request, obj[0])
        except PermissionDenied:
            return self.model.objects.none()
        else:
            return obj


@extend_schema_view(
    get=extend_schema(
        summary="Get a list of users associated with a role on an Issuer",
        tags=["Issuers"],
        parameters=[
            OpenApiParameter(
                "slug",
                type=str,
                location=OpenApiParameter.PATH,
                description="The slug of the issuer",
                required=True,
            )
        ],
        responses={
            200: IssuerStaffSerializerV1(many=True),
            404: inline_serializer(
                name="IssuerStaffNotFound",
                fields={"error": serializers.CharField()},
            ),
        },
    ),
    post=extend_schema(
        summary="Add or remove a user from a role on an issuer. Limited to Owner users only",
        tags=["Issuers"],
        parameters=[
            OpenApiParameter(
                "slug",
                type=str,
                location=OpenApiParameter.PATH,
                description="The slug of the issuer whose roles to modify",
                required=True,
            )
        ],
        request=IssuerRoleActionSerializerV1,
        responses={
            200: inline_serializer(
                name="IssuerStaffRemoved",
                fields={"message": serializers.CharField()},
            ),
            201: IssuerStaffSerializerV1,
            400: inline_serializer(
                name="IssuerStaffBadRequest",
                fields={"error": serializers.CharField()},
            ),
            404: inline_serializer(
                name="IssuerStaffUserNotFound",
                fields={"error": serializers.CharField()},
            ),
        },
        examples=[
            OpenApiExample(
                "Add user by email",
                value={
                    "action": "add",
                    "email": "user@example.com",
                    "role": "staff",
                },
                request_only=True,
            ),
            OpenApiExample(
                "Add user by username",
                value={
                    "action": "add",
                    "username": "johndoe",
                    "role": "editor",
                },
                request_only=True,
            ),
            OpenApiExample(
                "Modify user role",
                value={
                    "action": "modify",
                    "email": "user@example.com",
                    "role": "owner",
                },
                request_only=True,
            ),
            OpenApiExample(
                "Remove user",
                value={
                    "action": "remove",
                    "email": "user@example.com",
                },
                request_only=True,
            ),
        ],
    ),
)
class IssuerStaffList(VersionedObjectMixin, APIView):
    """View or modify an issuer's staff members and privileges"""

    role = "staff"
    queryset = Issuer.objects.all()
    model = Issuer
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & IsOwnerOrStaff)
        | BadgrOAuthTokenHasEntityScope
    ]
    valid_scopes = {
        "get": ["rw:issuerOwner:*"],
        "post": ["rw:issuerOwner:*"],
        "@apispec_scopes": {},
    }

    def get(self, request, **kwargs):
        current_issuer = self.get_object(request, **kwargs)
        if not self.has_object_permissions(request, current_issuer):
            return Response(
                "Issuer {} not found. Authenticated user must have owner, editor or staff rights on the issuer.".format(
                    kwargs.get("slug")
                ),
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = IssuerStaffSerializerV1(
            IssuerStaff.objects.filter(issuer=current_issuer), many=True
        )

        if len(serializer.data) == 0:
            return Response([], status=status.HTTP_200_OK)
        return Response(serializer.data)

    @throttleable
    def post(self, request, **kwargs):
        # validate POST data
        serializer = IssuerRoleActionSerializerV1(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        current_issuer = self.get_object(request, **kwargs)

        user_id = None
        try:
            if serializer.validated_data.get("username"):
                user_id = serializer.validated_data.get("username")
                user_to_modify = get_user_model().objects.get(username=user_id)
            elif serializer.validated_data.get("url"):
                user_id = serializer.validated_data.get("url")
                user_to_modify = UserRecipientIdentifier.objects.get(
                    identifier=user_id, verified=True
                ).user
            elif serializer.validated_data.get("telephone"):
                user_id = serializer.validated_data.get("telephone")
                user_to_modify = UserRecipientIdentifier.objects.get(
                    identifier=user_id, verified=True
                ).user
            else:
                user_id = serializer.validated_data.get("email")
                user_to_modify = CachedEmailAddress.objects.get(
                    email=user_id, verified=True
                ).user
        except (
            get_user_model().DoesNotExist,
            CachedEmailAddress.DoesNotExist,
            UserRecipientIdentifier.DoesNotExist,
        ):
            error_text = "Wir haben die E-Mail-Adresse nicht im System gefunden. Es können nur Personen als Mitglied hinzugefügt werden, die sich bereits einen Account auf OEB angelegt haben."
            if user_id is None:
                error_text = (
                    "User not found. please provide a valid email address, "
                    "username, url or telephone identifier."
                )
            return Response(error_text, status=status.HTTP_404_NOT_FOUND)

        if user_to_modify == request.user:
            return Response(
                "Cannot modify your own permissions on an issuer profile",
                status=status.HTTP_400_BAD_REQUEST,
            )

        action = serializer.validated_data.get("action")
        if action == "add":
            role = serializer.validated_data.get("role")
            staff_instance, created = IssuerStaff.objects.get_or_create(
                user=user_to_modify, issuer=current_issuer, defaults={"role": role}
            )

            if created is False:
                raise ValidationError(
                    "Could not add user to staff list. User already in staff list."
                )

        elif action == "modify":
            role = serializer.validated_data.get("role")
            try:
                staff_instance = IssuerStaff.objects.get(
                    user=user_to_modify, issuer=current_issuer
                )
                staff_instance.role = role
                staff_instance.save(update_fields=("role",))
            except IssuerStaff.DoesNotExist:
                raise ValidationError(
                    "Cannot modify staff record. Matching staff record does not exist."
                )

        elif action == "remove":
            issuer_staffs = IssuerStaff.objects.filter(
                user=user_to_modify, issuer=current_issuer
            )
            # Do the deletion one by one so that the issuer_staffs custom delete method is called
            for issuer_staff in issuer_staffs:
                # Update the current issuer with a reference to the issuer of the issuer_staff,
                # since it's getting updated in the deletion process
                current_issuer = issuer_staff.issuer
                issuer_staff.delete()
            current_issuer.publish(publish_staff=False)
            user_to_modify.publish()

            # update cached issuers and badgeclasses for user
            current_issuer.save()
            user_to_modify.save()

            return Response(
                "User %s has been removed from %s staff."
                % (user_to_modify.username, current_issuer.name),
                status=status.HTTP_200_OK,
            )

        # update cached issuers and badgeclasses for user
        user_to_modify.save()

        return Response(IssuerStaffSerializerV1(staff_instance).data)


@extend_schema_view(
    get=extend_schema(
        summary="Get a specific BadgeClass by searching by identifier",
        tags=["BadgeClasses"],
        parameters=[
            OpenApiParameter(
                "identifier",
                type=str,
                location=OpenApiParameter.QUERY,
                description="The identifier of the badge. Possible values: JSONld identifier, BadgeClass.id, or BadgeClass.slug",
                required=True,
            )
        ],
        responses={
            200: BadgeClassSerializerV1,
            404: inline_serializer(
                name="BadgeClassNotFound",
                fields={"detail": serializers.CharField()},
            ),
        },
        examples=[
            OpenApiExample(
                "Find by slug",
                value={"identifier": "my-badge-class"},
                request_only=False,
            )
        ],
    ),
)
class FindBadgeClassDetail(APIView):
    """
    GET a specific BadgeClass by searching by identifier
    """

    permission_classes = (AuthenticatedWithVerifiedIdentifier,)

    def get(self, request, **kwargs):
        identifier = request.query_params.get("identifier")
        badge = get_badgeclass_by_identifier(identifier)
        if badge is None:
            raise NotFound("No BadgeClass found by identifier: {}".format(identifier))

        serializer = BadgeClassSerializerV1(badge)
        return Response(serializer.data)

class IssuerAiSkills(APIView):

    permission_classes = (AuthenticatedWithVerifiedIdentifier,)

    def get_object(self, request, **kwargs):
        issuerSlug = kwargs.get("issuerSlug")

        return Issuer.objects.get(entity_id=issuerSlug)

    def get(self, request, **kwargs):
        # for easier in-browser testing
        if settings.DEBUG:
            request.data.update(request.GET.dict())
            return self.post(request, **kwargs)
        else:
            return HttpResponse(b"", status=405)

    @quota_check('AISKILLS_REQUESTS')
    def post(self, request, **kwargs):

        issuer = self.get_object(request, **kwargs)

        if hasattr(settings, 'AISKILLS_DEMO_RESULT'):
            AiSkillRequest.objects.create(
                issuer = issuer,
                created_by=request.user,
                updated_by=request.user
            )
            return Response(json.loads(settings.AISKILLS_DEMO_RESULT))

        searchterm = request.data["text"]

        endpoint = getattr(
            settings,
            "AISKILLS_ENDPOINT_CHATS",
            getattr(settings, "AISKILLS_ENDPOINT", None),
        )
        payload = {"text_to_analyze": searchterm}

        response = call_aiskills_api(endpoint, "POST", payload)

        # log AiSkillRequest if api call was successful
        if response.status_code == 200:
            AiSkillRequest.objects.create(
                issuer = issuer,
                created_by=request.user,
                updated_by=request.user
            )

        return response
