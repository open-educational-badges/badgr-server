from backpack.models import BackpackCollection
from django.http import Http404, HttpResponse
from django.urls import reverse
from django.views.generic import RedirectView
from issuer.models import BadgeClass, BadgeInstance
from mainsite.badge_pdf import BadgePDFCreator
from mainsite.collection_pdf import CollectionPDFCreator
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
    TokenAuthentication,
)
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter,
    OpenApiResponse,
)
from drf_spectacular.types import OpenApiTypes


@extend_schema(
    summary="Download Badge PDF",
    description=(
        "Returns a PDF version of a badge instance. "
        "The user must be the badge recipient or issuer owner."
    ),
    parameters=[
        OpenApiParameter(
            name="slug",
            type=str,
            location=OpenApiParameter.PATH,
            description="Entity ID of the badge instance.",
        ),
    ],
    responses={
        200: OpenApiResponse(
            description="PDF file",
            response=OpenApiTypes.BINARY,
        ),
        404: OpenApiResponse(description="Badge not found"),
        403: OpenApiResponse(description="Permission denied"),
    },
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([])
def pdf(request, *args, **kwargs):
    slug = kwargs["slug"]
    try:
        badgeinstance = BadgeInstance.objects.get(entity_id=slug)

        # Get emails of all issuer owners
        """ issuer= Issuer.objects.get(entity_id=badgeinstance.issuer.entity_id)
        issuer_owners = issuer.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)
        issuer_owners_emails = list(map(attrgetter('primary_email'), issuer_owners)) """

        # User must be the recipient or an issuer staff with OWNER role
        # TODO: Check other recipient types
        # Temporary commented out
        """ if request.user.email != badgeinstance.recipient_identifier and
        request.user.email not in issuer_owners_emails:
            raise PermissionDenied """
    except BadgeInstance.DoesNotExist:
        raise Http404
    try:
        badgeclass = BadgeClass.objects.get(
            entity_id=badgeinstance.badgeclass.entity_id
        )
    except BadgeClass.DoesNotExist:
        raise Http404

    pdf_creator = BadgePDFCreator()
    pdf_content = pdf_creator.generate_pdf(
        badgeinstance, badgeclass, origin=request.META.get("HTTP_ORIGIN")
    )
    return HttpResponse(pdf_content, content_type="application/pdf")


@extend_schema(
    summary="Download Badge PDF",
    description=("Returns a PDF version of a collection. "),
    parameters=[
        OpenApiParameter(
            name="slug",
            type=str,
            location=OpenApiParameter.PATH,
            description="Entity ID of the badge collection.",
        ),
    ],
    responses={
        200: OpenApiResponse(
            description="PDF file",
            response=OpenApiTypes.BINARY,
        ),
        404: OpenApiResponse(description="Collection not found"),
        403: OpenApiResponse(description="Permission denied"),
    },
)
@api_view(["GET"])
@authentication_classes(
    [TokenAuthentication, SessionAuthentication, BasicAuthentication]
)
@permission_classes([IsAuthenticated])
def collectionPdf(request, *args, **kwargs):
    slug = kwargs["slug"]
    try:
        collection = BackpackCollection.objects.get(entity_id=slug)
    except BackpackCollection.DoesNotExist:
        raise Http404

    pdf_creator = CollectionPDFCreator()
    pdf_content = pdf_creator.generate_pdf(
        collection, origin=request.META.get("HTTP_ORIGIN")
    )
    return HttpResponse(pdf_content, content_type="application/pdf")


class RedirectSharedCollectionView(RedirectView):
    permanent = True

    def get_redirect_url(self, *args, **kwargs):
        share_hash = kwargs.get("share_hash", None)
        if not share_hash:
            raise Http404

        try:
            collection = BackpackCollection.cached.get_by_slug_or_entity_id_or_id(
                share_hash
            )
        except BackpackCollection.DoesNotExist:
            raise Http404
        return collection.public_url


class LegacyCollectionShareRedirectView(RedirectView):
    permanent = True

    def get_redirect_url(self, *args, **kwargs):
        new_pattern_name = self.request.resolver_match.url_name.replace("legacy_", "")
        kwargs.pop("pk")
        url = reverse(new_pattern_name, args=args, kwargs=kwargs)
        return url


class LegacyBadgeShareRedirectView(RedirectView):
    permanent = True

    def get_redirect_url(self, *args, **kwargs):
        badgeinstance = None
        share_hash = kwargs.get("share_hash", None)
        if not share_hash:
            raise Http404

        try:
            badgeinstance = BadgeInstance.cached.get_by_slug_or_entity_id_or_id(
                share_hash
            )
        except BadgeInstance.DoesNotExist:
            pass

        if not badgeinstance:
            # legacy badge share redirects need to support lookup by pk
            try:
                badgeinstance = BadgeInstance.cached.get(pk=share_hash)
            except (BadgeInstance.DoesNotExist, ValueError):
                pass

        if not badgeinstance:
            raise Http404

        return badgeinstance.public_url
