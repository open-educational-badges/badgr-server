import io
import os
import re
import urllib.parse

import cairosvg
from backpack.models import BackpackCollection
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.files.storage import DefaultStorage
from django.db.models import Q
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import NoReverseMatch, Resolver404, resolve, reverse
from django.views.generic import RedirectView
from entity.api import (
    BaseEntityDetailViewPublic,
    BaseEntityListView,
    UncachedPaginatedViewMixin,
    VersionedObjectMixin,
)
from entity.serializers import BaseSerializerV2
from mainsite.models import BadgrApp
from mainsite.utils import (
    OriginSetting,
    convert_svg_to_png,
    first_node_match,
    fit_image_to_height,
    set_url_query_params,
)
from PIL import Image
from rest_framework import permissions, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

import openbadges

from . import utils
from .models import (
    BadgeClass,
    BadgeInstance,
    Issuer,
    LearningPath,
    LearningPathBadge,
    QrCode,
)
from .serializers_v1 import (
    BadgeClassSerializerV1,
    IssuerSerializerV1,
    LearningPathSerializerV1,
    QrCodeSerializerV1,
)
import logging
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

logger = logging.getLogger("Badgr.Events")


class SlugToEntityIdRedirectMixin(object):
    slugToEntityIdRedirect = False

    def get_entity_id_by_slug(self, slug):
        try:
            object = self.model.cached.get(slug=slug)
            return getattr(object, "entity_id", None)
        except self.model.DoesNotExist:
            return None

    def get_slug_to_entity_id_redirect_url(self, slug):
        try:
            pattern_name = resolve(self.request.path_info).url_name
            entity_id = self.get_entity_id_by_slug(slug)
            if entity_id is None:
                raise Http404
            return reverse(pattern_name, kwargs={"entity_id": entity_id})
        except (Resolver404, NoReverseMatch):
            return None

    def get_slug_to_entity_id_redirect(self, slug):
        redirect_url = self.get_slug_to_entity_id_redirect_url(slug)
        if redirect_url is not None:
            query = self.request.META.get("QUERY_STRING", "")
            if query:
                redirect_url = "{}?{}".format(redirect_url, query)
            return redirect(redirect_url, permanent=True)
        else:
            raise Http404


class JSONListView(BaseEntityListView, UncachedPaginatedViewMixin):
    """
    Abstract List Class
    """

    permission_classes = (permissions.AllowAny,)
    allow_any_unauthenticated_access = True

    def log(self, obj):
        pass

    def get_queryset(self, request, **kwargs):
        return self.model.objects.all()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        exclude_orgImg = self.request.query_params.get("exclude_orgImg", None)
        if exclude_orgImg:
            context["exclude_fields"] = [
                *context.get("exclude_fields", []),
                "extensions:OrgImageExtension",
            ]

        return context

    def get(self, request, **kwargs):
        objects = UncachedPaginatedViewMixin.get_objects(self, request, **kwargs)
        context = self.get_context_data(**kwargs)
        serializer_class = self.serializer_class
        serializer = serializer_class(objects, many=True, context=context)
        headers = dict()
        paginator = getattr(self, "paginator", None)
        if paginator and callable(getattr(paginator, "get_link_header", None)):
            link_header = paginator.get_link_header()
            if link_header:
                headers["Link"] = link_header
        return Response(serializer.data, headers=headers)


class JSONComponentView(VersionedObjectMixin, APIView, SlugToEntityIdRedirectMixin):
    """
    Abstract Component Class
    """

    permission_classes = (permissions.AllowAny,)
    allow_any_unauthenticated_access = True
    authentication_classes = ()
    html_renderer_class = None
    template_name = "public/bot_openbadge.html"

    def log(self, obj):
        pass

    def get_json(self, request, **kwargs):
        try:
            json = self.current_object.get_json(
                obi_version=self._get_request_obi_version(request), **kwargs
            )
        except ObjectDoesNotExist:
            raise Http404

        return json

    def get(self, request, **kwargs):
        try:
            self.current_object = self.get_object(request, **kwargs)
        except Http404:
            if self.slugToEntityIdRedirect:
                return self.get_slug_to_entity_id_redirect(
                    kwargs.get("entity_id", None)
                )
            else:
                raise

        self.log(self.current_object)

        if self.is_bot():
            # if user agent matches a known bot, return a stub html with opengraph tags
            return render(request, self.template_name, context=self.get_context_data())

        if self.is_requesting_html():
            return HttpResponseRedirect(redirect_to=self.get_badgrapp_redirect())

        json = self.get_json(request=request)
        return Response(json)

    def is_bot(self):
        """
        bots get an stub that contains opengraph tags
        """
        bot_useragents = getattr(
            settings, "BADGR_PUBLIC_BOT_USERAGENTS", ["LinkedInBot"]
        )
        user_agent = self.request.META.get("HTTP_USER_AGENT", "")
        if any(a in user_agent for a in bot_useragents):
            return True
        return False

    def is_wide_bot(self):
        """
        some bots prefer a wide aspect ratio for the image
        """
        bot_useragents = getattr(
            settings, "BADGR_PUBLIC_BOT_USERAGENTS_WIDE", ["LinkedInBot"]
        )
        user_agent = self.request.META.get("HTTP_USER_AGENT", "")
        if any(a in user_agent for a in bot_useragents):
            return True
        return False

    def is_requesting_html(self):
        if self.format_kwarg == "json":
            return False

        html_accepts = ["text/html"]

        http_accept = self.request.META.get("HTTP_ACCEPT", "application/json")

        if self.is_bot() or any(a in http_accept for a in html_accepts):
            return True

        return False

    def get_badgrapp_redirect(self):
        badgrapp = self.current_object.cached_badgrapp
        badgrapp = BadgrApp.cached.get(
            pk=badgrapp.pk
        )  # ensure we have latest badgrapp information
        if not badgrapp.public_pages_redirect:
            badgrapp = BadgrApp.objects.get_current(
                request=None
            )  # use the default badgrapp

        redirect = badgrapp.public_pages_redirect
        if not redirect:
            redirect = "https://{}/public/".format(badgrapp.cors)
        else:
            if not redirect.endswith("/"):
                redirect += "/"

        path = self.request.path
        stripped_path = re.sub(r"^/public/", "", path)
        query_string = self.request.META.get("QUERY_STRING", None)
        ret = "{redirect}{path}{query}".format(
            redirect=redirect,
            path=stripped_path,
            query="?" + query_string if query_string else "",
        )
        return ret

    @staticmethod
    def _get_request_obi_version(request):
        return request.query_params.get("v")


class ImagePropertyDetailView(APIView, SlugToEntityIdRedirectMixin):
    permission_classes = (permissions.AllowAny,)

    def get_object(self, entity_id):
        try:
            current_object = self.model.cached.get(entity_id=entity_id)
        except self.model.DoesNotExist:
            return None
        else:
            self.log(current_object)
            return current_object

    def get(self, request, **kwargs):
        entity_id = kwargs.get("entity_id")
        current_object = self.get_object(entity_id)
        if (
            current_object is None
            and self.slugToEntityIdRedirect
            and getattr(request, "version", "v1") == "v2"
        ):
            return self.get_slug_to_entity_id_redirect(kwargs.get("entity_id", None))
        elif current_object is None:
            return Response(status=status.HTTP_404_NOT_FOUND)

        image_prop = getattr(current_object, self.prop)
        if not bool(image_prop):
            return Response(status=status.HTTP_404_NOT_FOUND)

        image_type = request.query_params.get("type", "original")
        if image_type not in ["original", "png"]:
            raise ValidationError("invalid image type: {}".format(image_type))

        supported_fmts = {"square": (1, 1), "wide": (1.91, 1)}
        image_fmt = request.query_params.get("fmt", "square").lower()
        if image_fmt not in list(supported_fmts.keys()):
            raise ValidationError("invalid image format: {}".format(image_fmt))

        image_url = image_prop.url
        filename, ext = os.path.splitext(image_prop.name)
        basename = os.path.basename(filename)
        dirname = os.path.dirname(filename)
        version_suffix = getattr(settings, "CAIROSVG_VERSION_SUFFIX", "1")
        new_name = "{dirname}/converted{version}/{basename}{fmt_suffix}.png".format(
            dirname=dirname,
            basename=basename,
            version=version_suffix,
            fmt_suffix="-{}".format(image_fmt) if image_fmt != "square" else "",
        )
        storage = DefaultStorage()

        if image_type == "original" and image_fmt == "square":
            image_url = image_prop.url
        elif ext == ".svg":
            if not storage.exists(new_name):
                png_buf = None
                with storage.open(image_prop.name, "rb") as input_svg:
                    if getattr(settings, "SVG_HTTP_CONVERSION_ENABLED", False):
                        max_square = getattr(settings, "IMAGE_FIELD_MAX_PX", 600)
                        png_buf = convert_svg_to_png(
                            input_svg.read(), max_square, max_square
                        )
                    # If conversion using the HTTP service fails, try falling back to python solution
                    if not png_buf:
                        png_buf = io.BytesIO()
                        input_svg.seek(0)
                        try:
                            cairosvg.svg2png(file_obj=input_svg, write_to=png_buf)
                        except IOError:
                            return redirect(
                                storage.url(image_prop.name)
                            )  # If conversion fails, return existing file.
                    img = Image.open(png_buf)

                    img = fit_image_to_height(img, supported_fmts[image_fmt])

                    out_buf = io.BytesIO()
                    img.save(out_buf, format="png")
                    storage.save(new_name, out_buf)
            image_url = storage.url(new_name)
        else:
            if not storage.exists(new_name):
                with storage.open(image_prop.name, "rb") as input_png:
                    out_buf = io.BytesIO()
                    # height and width set to the Height and Width of the original badge
                    img = Image.open(input_png)
                    img = fit_image_to_height(img, supported_fmts[image_fmt])

                    img.save(out_buf, format="png")
                    storage.save(new_name, out_buf)
            image_url = storage.url(new_name)

        return redirect(image_url)


@extend_schema(
    description="Returns public issuer details",
    parameters=[
        OpenApiParameter(
            name="entity_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="Issuer ID",
        )
    ],
    responses={
        200: OpenApiResponse(
            description="Issuer JSON",
            response=BadgeClassSerializerV1,
        )
    },
    tags=["Issuers"],
)
class IssuerJson(JSONComponentView):
    permission_classes = (permissions.AllowAny,)
    model = Issuer

    def log(self, obj):
        logger.info("Retrieved issuer '%s'", obj)

    def get_context_data(self, **kwargs):
        image_url = "{}{}?type=png".format(
            OriginSetting.HTTP,
            reverse(
                "issuer_image", kwargs={"entity_id": self.current_object.entity_id}
            ),
        )
        if self.is_wide_bot():
            image_url = "{}&fmt=wide".format(image_url)

        return dict(
            title=self.current_object.name,
            description=self.current_object.description,
            public_url=self.current_object.public_url,
            image_url=image_url,
        )


@extend_schema(
    description="Returns public details of badgeclasses for an issuer",
    parameters=[
        OpenApiParameter(
            name="entity_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="Issuer ID",
        )
    ],
    responses={
        200: OpenApiResponse(
            description="Issuer Badges JSON",
            response=BadgeClassSerializerV1,
        )
    },
    tags=["BadgeClasses"],
)
class IssuerBadgesJson(JSONComponentView):
    permission_classes = (permissions.AllowAny,)
    model = Issuer

    def log(self, obj):
        logger.info("Retrieved issuer badges '%s'", obj)

    def get_json(self, request):
        obi_version = self._get_request_obi_version(request)

        lps = self.current_object.learningpaths.all()
        ignore_classes = [i.participationBadge for i in lps if not i.activated]

        return [
            b.get_json(obi_version=obi_version)
            for b in self.current_object.cached_badgeclasses()
            if b not in ignore_classes
        ]


@extend_schema(
    description="Returns public details of learning paths for an issuer",
    parameters=[
        OpenApiParameter(
            name="entity_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="Issuer ID",
        )
    ],
    responses={
        200: OpenApiResponse(
            description="Issuer LearningPaths JSON",
            response=LearningPathSerializerV1,
        )
    },
    tags=["LearningPaths"],
)
class IssuerLearningPathsJson(JSONComponentView):
    permission_classes = (permissions.AllowAny,)
    model = Issuer

    def get_json(self, request):
        obi_version = self._get_request_obi_version(request)

        return [
            b.get_json(obi_version=obi_version)
            for b in self.current_object.cached_learningpaths()
        ]


@extend_schema(exclude=True)
class NetworkIssuersJson(JSONComponentView):
    permission_classes = (permissions.AllowAny,)
    model = Issuer

    def log(self, obj):
        logger.info("Retrieved network issuers '%s'", obj)

    def get(self, request, **kwargs):
        """
        Retrieves networks for a given issuer identified by its slug.
        """
        network_slug = kwargs.get("entity_id")
        try:
            network = Issuer.objects.get(entity_id=network_slug)
        except Issuer.DoesNotExist:
            return Response({"detail": "Issuer not found."}, status=404)

        self.log(network)

        json_data = self.get_json(request=request, network=network)

        return Response(json_data)

    def get_json(self, request, network):
        """
        Get the list of issuers for a given network.
        """
        issuers = Issuer.objects.filter(network_memberships__network=network)

        return [
            {
                "slug": issuer.entity_id,
                "name": issuer.name,
                "image": issuer.image.url,
            }
            for issuer in issuers
        ]


@extend_schema(exclude=True)
class IssuerNetworksJson(JSONComponentView):
    permission_classes = (permissions.AllowAny,)
    model = Issuer

    def log(self, obj):
        logger.info("Retrieved networks for issuer '%s'", obj)

    def get_json(self, request, issuer):
        """
        Get the list of networks for a given issuer.
        """
        networks = Issuer.objects.filter(memberships__issuer=issuer, is_network=True)

        return [
            {
                "slug": network.entity_id,
                "name": network.name,
                "image": network.image.url,
            }
            for network in networks
        ]

    def get(self, request, **kwargs):
        """
        Retrieves networks for a given issuer identified by its slug.
        """
        issuer_slug = kwargs.get("entity_id")
        try:
            issuer = Issuer.objects.get(entity_id=issuer_slug)
        except Issuer.DoesNotExist:
            return Response({"detail": "Issuer not found."}, status=404)

        self.log(issuer)

        json_data = self.get_json(request=request, issuer=issuer)

        return Response(json_data)


@extend_schema(exclude=True)
class IssuerImage(ImagePropertyDetailView):
    model = Issuer
    prop = "image"

    def log(self, obj):
        logger.info("Issuer image retrieved event '%s'", obj)


@extend_schema(
    description="Returns public issuers",
    responses={
        200: OpenApiResponse(
            description="Issuer list",
            response=IssuerSerializerV1,
        )
    },
    tags=["Issuers"],
)
class IssuerList(JSONListView):
    permission_classes = (permissions.AllowAny,)
    model = Issuer
    serializer_class = IssuerSerializerV1

    def log(self, obj):
        pass

    def get_context_data(self, **kwargs):
        context = super(IssuerList, self).get_context_data(**kwargs)

        # some fields have to be excluded due to data privacy concerns
        # in the get routes
        if self.request.method == "GET":
            context["exclude_fields"] = [
                *context.get("exclude_fields", []),
                "staff",
                "created_by",
                "email",
            ]
        return context

    def get_json(self, request):
        return super(IssuerList, self).get_json(request)


@extend_schema(
    description="Returns issuers that match the search term",
    responses={
        200: OpenApiResponse(
            description="Issuer Search",
            response=IssuerSerializerV1,
        )
    },
    tags=["Issuers"],
)
class IssuerSearch(JSONListView):
    permission_classes = (permissions.AllowAny,)
    model = Issuer
    serializer_class = IssuerSerializerV1

    def log(self, obj):
        pass

    def get(self, request, **kwargs):
        objects = self.model.objects

        issuers = []
        search_term = kwargs.get("searchterm", "")
        if search_term:
            issuers = objects.filter(
                Q(name__icontains=search_term) | Q(description__icontains=search_term),
                is_network=False,
            )
        serializer_class = self.serializer_class
        serializer = serializer_class(
            issuers, many=True, context={"exclude_fields": ["staff", "created_by"]}
        )
        return Response(serializer.data)


@extend_schema(
    description="Returns public badge class details",
    responses={
        200: OpenApiResponse(
            description="Badge class JSON",
            response=BadgeClassSerializerV1,
        )
    },
    parameters=[
        OpenApiParameter(
            name="entity_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="BadgeClass ID",
        ),
        OpenApiParameter(
            name="expand",
            location=OpenApiParameter.QUERY,
            type=OpenApiTypes.STR,
            style="form",
            explode=True,
            description='Fields to expand ("issuer")',
        ),
    ],
    tags=["BadgeClasses"],
)
class BadgeClassJson(JSONComponentView):
    permission_classes = (permissions.AllowAny,)
    model = BadgeClass

    def log(self, obj):
        logger.info("Badge class retrieved '%s'", obj)

    def get_json(self, request):
        expands = request.GET.getlist("expand", [])
        json = super(BadgeClassJson, self).get_json(request)
        obi_version = self._get_request_obi_version(request)

        if self.current_object.cached_issuer.is_network:
            json["isNetworkBadge"] = True
            json["networkName"] = self.current_object.cached_issuer.name
            json["networkImage"] = self.current_object.cached_issuer.image.url
        else:
            json["isNetworkBadge"] = False
            json["networkName"] = None
            json["networkImage"] = None

        if "issuer" in expands:
            json["issuer"] = self.current_object.cached_issuer.get_json(
                obi_version=obi_version
            )

        return json

    def get_context_data(self, **kwargs):
        image_url = "{}{}?type=png".format(
            OriginSetting.HTTP,
            reverse(
                "badgeclass_image", kwargs={"entity_id": self.current_object.entity_id}
            ),
        )
        if self.is_wide_bot():
            image_url = "{}&fmt=wide".format(image_url)
        return dict(
            title=self.current_object.name,
            description=self.current_object.description,
            public_url=self.current_object.public_url,
            image_url=image_url,
        )


@extend_schema(
    description="Returns list of badge classes",
    responses={
        200: OpenApiResponse(
            description="Badge class list",
            response=BadgeClassSerializerV1,
        )
    },
    tags=["BadgeClasses"],
)
class BadgeClassList(JSONListView):
    permission_classes = (permissions.AllowAny,)
    model = BadgeClass
    serializer_class = BadgeClassSerializerV1

    def log(self, obj):
        logger.info("Badge class list retrieved '%s'", obj)

    def get_context_data(self, **kwargs):
        context = super(BadgeClassList, self).get_context_data(**kwargs)

        # some fields have to be excluded due to data privacy concerns
        # in the get routes
        if self.request.method == "GET":
            context["exclude_fields"] = [
                *context.get("exclude_fields", []),
                "created_by",
            ]
        return context

    def get_json(self, request):
        return super(BadgeClassList, self).get_json(request)


@extend_schema(exclude=True)
class BadgeClassImage(ImagePropertyDetailView):
    model = BadgeClass
    prop = "image"

    def log(self, obj):
        logger.info("Badge class image retrieved '%s'", obj)


@extend_schema(exclude=True)
class BadgeClassCriteria(RedirectView, SlugToEntityIdRedirectMixin):
    permanent = False
    model = BadgeClass

    def get_redirect_url(self, *args, **kwargs):
        try:
            badge_class = self.model.cached.get(entity_id=kwargs.get("entity_id"))
        except self.model.DoesNotExist:
            if self.slugToEntityIdRedirect:
                return self.get_slug_to_entity_id_redirect_url(kwargs.get("entity_id"))
            else:
                return None
        return badge_class.get_absolute_url()


@extend_schema(exclude=True)
class BadgeInstanceJson(JSONComponentView):
    permission_classes = (permissions.AllowAny,)
    model = BadgeInstance

    def has_object_permissions(self, request, obj):
        if obj.pending:
            raise Http404
        return super(BadgeInstanceJson, self).has_object_permissions(request, obj)

    def get_json(self, request):
        expands = request.GET.getlist("expand", [])
        json = super(BadgeInstanceJson, self).get_json(
            request,
            expand_badgeclass=("badge" in expands),
            expand_issuer=("badge.issuer" in expands),
        )

        return json

    def get_context_data(self, **kwargs):
        image_url = "{}{}?type=png".format(
            OriginSetting.HTTP,
            reverse(
                "badgeclass_image",
                kwargs={"entity_id": self.current_object.cached_badgeclass.entity_id},
            ),
        )
        if self.is_wide_bot():
            image_url = "{}&fmt=wide".format(image_url)

        oembed_link_url = "{}{}?format=json&url={}".format(
            getattr(settings, "HTTP_ORIGIN"),
            reverse("oembed_api_endpoint"),
            urllib.parse.quote(self.current_object.public_url),
        )

        return dict(
            user_agent=self.request.META.get("HTTP_USER_AGENT", ""),
            title=self.current_object.cached_badgeclass.name,
            description=self.current_object.cached_badgeclass.description,
            public_url=self.current_object.public_url,
            image_url=image_url,
            oembed_link_url=oembed_link_url,
        )


@extend_schema(exclude=True)
class BadgeInstanceImage(ImagePropertyDetailView):
    model = BadgeInstance
    prop = "image"

    def log(self, badge_instance):
        logger.info("Badge instance '%s' downloaded", badge_instance.entity_id)

    def get_object(self, slug):
        obj = super(BadgeInstanceImage, self).get_object(slug)
        if obj and obj.revoked:
            return None
        return obj


@extend_schema(exclude=True)
class BadgeInstanceRevocations(JSONComponentView):
    model = BadgeInstance

    def get_json(self, request):
        return self.current_object.get_revocation_json()


@extend_schema(exclude=True)
class BackpackCollectionJson(JSONComponentView):
    permission_classes = (permissions.AllowAny,)
    model = BackpackCollection

    def get_context_data(self, **kwargs):
        image_url = ""
        if self.current_object.cached_badgeinstances().exists():
            chosen_assertion = sorted(
                self.current_object.cached_badgeinstances(), key=lambda b: b.issued_on
            )[0]
            image_url = "{}{}?type=png".format(
                OriginSetting.HTTP,
                reverse(
                    "badgeinstance_image",
                    kwargs={"entity_id": chosen_assertion.entity_id},
                ),
            )
            if self.is_wide_bot():
                image_url = "{}&fmt=wide".format(image_url)

        return dict(
            title=self.current_object.name,
            description=self.current_object.description,
            public_url=self.current_object.share_url,
            image_url=image_url,
        )

    def get(self, request, **kwargs):
        try:
            return super().get(request, **kwargs)
        except Http404:
            if self.is_requesting_html():
                return HttpResponseRedirect(
                    redirect_to=self.get_default_badgrapp_redirect()
                )
            else:
                return HttpResponse(status=204)

    def get_default_badgrapp_redirect(self):
        badgrapp = BadgrApp.objects.get_current(
            request=None
        )  # use the default badgrapp

        redirect = badgrapp.public_pages_redirect
        if not redirect:
            redirect = "https://{}/public/".format(badgrapp.cors)
        else:
            if not redirect.endswith("/"):
                redirect += "/"

        path = self.request.path
        stripped_path = re.sub(r"^/public/", "", path)

        if self.kwargs.get("entity_id", None):
            stripped_path = re.sub(
                self.kwargs.get("entity_id", ""), "not-found", stripped_path
            )
        ret = "{redirect}{path}".format(
            redirect=redirect,
            path=stripped_path,
        )
        return ret

    def get_json(self, request):
        # bypass cached version with old share_hash
        self.current_object.refresh_from_db()

        expands = request.GET.getlist("expand", [])
        if not self.current_object.published:
            raise Http404

        json = self.current_object.get_json(
            obi_version=self._get_request_obi_version(request),
            expand_badgeclass=("badges.badge" in expands),
            expand_issuer=("badges.badge.issuer" in expands),
        )
        return json


@extend_schema(exclude=True)
class BakedBadgeInstanceImage(
    VersionedObjectMixin, APIView, SlugToEntityIdRedirectMixin
):
    permission_classes = (permissions.AllowAny,)
    allow_any_unauthenticated_access = True
    model = BadgeInstance

    def get(self, request, **kwargs):
        try:
            assertion = self.get_object(request, **kwargs)
        except Http404:
            if self.slugToEntityIdRedirect:
                return self.get_slug_to_entity_id_redirect(
                    kwargs.get("entity_id", None)
                )
            else:
                raise

        requested_version = request.query_params.get("v")

        if not requested_version:
            requested_version = "3_0" if assertion.ob_json_3_0 else "2_0"

        if requested_version not in list(utils.OBI_VERSION_CONTEXT_IRIS.keys()):
            raise ValidationError("Invalid OpenBadges version")

        redirect_url = assertion.get_baked_image_url(obi_version=requested_version)

        return redirect(redirect_url, permanent=True)


@extend_schema(exclude=True)
class OEmbedAPIEndpoint(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def get_object(url):
        request_url = urllib.parse.urlparse(url)

        try:
            resolved = resolve(request_url.path)
        except Http404:
            raise Http404("Cannot find resource.")

        if resolved.url_name == "badgeinstance_json":
            return BadgeInstance.cached.get(entity_id=resolved.kwargs.get("entity_id"))
        raise Http404("Cannot find resource.")

    def get_badgrapp_redirect(self, entity):
        badgrapp = entity.cached_badgrapp
        if not badgrapp or not badgrapp.public_pages_redirect:
            badgrapp = BadgrApp.objects.get_current(
                request=None
            )  # use the default badgrapp

        redirect_url = badgrapp.public_pages_redirect
        if not redirect_url:
            redirect_url = "https://{}/public/".format(badgrapp.cors)
        else:
            if not redirect_url.endswith("/"):
                redirect_url += "/"

        path = entity.get_absolute_url()
        stripped_path = re.sub(r"^/public/", "", path)
        ret = "{redirect}{path}".format(redirect=redirect_url, path=stripped_path)
        ret = set_url_query_params(ret, embedVersion=2)
        return ret

    def get_max_constrained_height(self, request):
        min_height = 420
        height = int(request.query_params.get("maxwidth", min_height))
        return max(min_height, height)

    def get_max_constrained_width(self, request):
        max_width = 800
        min_width = 320
        width = int(request.query_params.get("maxwidth", max_width))
        return max(min_width, min(width, max_width))

    def get(self, request, **kwargs):
        try:
            url = request.query_params.get("url")
            constrained_height = self.get_max_constrained_height(request)
            constrained_width = self.get_max_constrained_width(request)
            response_format = request.query_params.get("format", "json")
        except (TypeError, ValueError):
            raise ValidationError("Cannot parse OEmbed request parameters.")

        if response_format != "json":
            return Response(
                "Only json format is supported at this time.",
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )

        try:
            badgeinstance = self.get_object(url)
        except BadgeInstance.DoesNotExist:
            raise Http404("Object to embed not found.")

        badgeclass = badgeinstance.cached_badgeclass
        issuer = badgeinstance.cached_issuer
        badgrapp = BadgrApp.objects.get_current(request)

        data = {
            "type": "rich",
            "version": "1.0",
            "title": badgeclass.name,
            "author_name": issuer.name,
            "author_url": issuer.url,
            "provider_name": badgrapp.name,
            "provider_url": badgrapp.ui_login_redirect,
            "thumbnail_url": badgeinstance.image_url(),
            "thumnail_width": 200,  # TODO: get real data; respect maxwidth
            "thumbnail_height": 200,  # TODO: get real data; respect maxheight
            "width": constrained_width,
            "height": constrained_height,
        }

        data["html"] = (
            """<iframe src="{src}" frameborder="0" width="{width}px" height="{height}px"></iframe>""".format(
                src=self.get_badgrapp_redirect(badgeinstance),
                width=constrained_width,
                height=constrained_height,
            )
        )

        return Response(data, status=status.HTTP_200_OK)


@extend_schema(
    summary="Verify a Badge",
    description="Verify a badge by entity ID. Returns the badge instance JSON including expanded badge class and issuer.",
    request={"application/json": None},
    responses={
        200: {"type": "object"},
        404: {"type": "object"},
        400: {"type": "object"},
    },
    tags=["Assertions"],
)
class VerifyBadgeAPIEndpoint(JSONComponentView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def get_object(entity_id):
        try:
            return BadgeInstance.cached.get(entity_id=entity_id)

        except BadgeInstance.DoesNotExist:
            raise Http404

    def post(self, request, **kwargs):
        entity_id = request.data.get("entity_id")
        badge_instance = self.get_object(entity_id)

        # only do badgecheck verify if not a local badge
        if badge_instance.source_url:
            recipient_profile = {
                badge_instance.recipient_type: badge_instance.recipient_identifier
            }

            badge_check_options = {
                "include_original_json": True,
                "use_cache": True,
            }

            try:
                response = openbadges.verify(
                    badge_instance.jsonld_id,
                    recipient_profile=recipient_profile,
                    **badge_check_options,
                )
            except ValueError as e:
                raise ValidationError(
                    [{"name": "INVALID_BADGE", "description": str(e)}]
                )

            graph = response.get("graph", [])

            revoked_obo = first_node_match(graph, dict(revoked=True))

            if bool(revoked_obo):
                instance = BadgeInstance.objects.get(source_url=revoked_obo["id"])
                if not instance.revoked:
                    instance.revoke(
                        revoked_obo.get("revocationReason", "Badge is revoked")
                    )

            else:
                report = response.get("report", {})
                is_valid = report.get("valid")

                if not is_valid:
                    if report.get("errorCount", 0) > 0:
                        errors = [
                            {
                                "name": "UNABLE_TO_VERIFY",
                                "description": "Unable to verify the assertion",
                            }
                        ]
                    raise ValidationError(errors)

                validation_subject = report.get("validationSubject")

                badge_instance_obo = first_node_match(
                    graph, dict(id=validation_subject)
                )
                if not badge_instance_obo:
                    raise ValidationError(
                        [
                            {
                                "name": "ASSERTION_NOT_FOUND",
                                "description": "Unable to find an badge instance",
                            }
                        ]
                    )

                badgeclass_obo = first_node_match(
                    graph, dict(id=badge_instance_obo.get("badge", None))
                )
                if not badgeclass_obo:
                    raise ValidationError(
                        [
                            {
                                "name": "ASSERTION_NOT_FOUND",
                                "description": "Unable to find a badgeclass",
                            }
                        ]
                    )

                issuer_obo = first_node_match(
                    graph, dict(id=badgeclass_obo.get("issuer", None))
                )
                if not issuer_obo:
                    raise ValidationError(
                        [
                            {
                                "name": "ASSERTION_NOT_FOUND",
                                "description": "Unable to find an issuer",
                            }
                        ]
                    )

                original_json = response.get("input").get("original_json", {})

                BadgeInstance.objects.update_from_ob2(
                    badge_instance.badgeclass,
                    badge_instance_obo,
                    badge_instance.recipient_identifier,
                    badge_instance.recipient_type,
                    original_json.get(badge_instance_obo.get("id", ""), None),
                )

                badge_instance.rebake(save=True)

                BadgeClass.objects.update_from_ob2(
                    badge_instance.issuer,
                    badgeclass_obo,
                    original_json.get(badgeclass_obo.get("id", ""), None),
                )

                Issuer.objects.update_from_ob2(
                    issuer_obo, original_json.get(issuer_obo.get("id", ""), None)
                )
        result = self.get_object(entity_id).get_json(
            expand_badgeclass=True, expand_issuer=True
        )

        return Response(
            BaseSerializerV2.response_envelope([result], True, "OK"),
            status=status.HTTP_200_OK,
        )


@extend_schema(
    summary="Retrieve a Learning Path",
    description="Get detailed JSON data for a Learning Path by its slug or ID.",
    parameters=[
        OpenApiParameter(
            name="entity_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="Slug or ID of the Learning Path",
        )
    ],
    responses=LearningPathSerializerV1,
    tags=["LearningPaths"],
)
class LearningPathJson(BaseEntityDetailViewPublic, SlugToEntityIdRedirectMixin):
    permission_classes = (permissions.AllowAny,)
    model = LearningPath
    serializer_class = LearningPathSerializerV1

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context["exclude_fields"] = [
            *context.get("exclude_fields", []),
            "created_by",
        ]

        return context


@extend_schema(
    summary="Get list of public learning paths",
    responses=LearningPathSerializerV1,
    tags=["LearningPaths"],
)
class LearningPathList(JSONListView):
    permission_classes = (permissions.AllowAny,)
    model = LearningPath
    serializer_class = LearningPathSerializerV1

    def get_queryset(self, request, **kwargs):
        queryset = LearningPath.objects.filter(activated=True)
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context["exclude_fields"] = [
            *context.get("exclude_fields", []),
            "created_by",
        ]

        return context

    def get_json(self, request):
        return super(LearningPathList, self).get_json(request)


@extend_schema(exclude=True)
class BadgeLearningPathList(JSONListView):
    permission_classes = (permissions.AllowAny,)
    model = LearningPath
    serializer_class = LearningPathSerializerV1

    def get(self, request, entity_id=None, *args, **kwargs):
        try:
            badge = BadgeClass.objects.get(entity_id=entity_id)
        except BadgeClass.DoesNotExist:
            raise Http404

        learningpath_badges = LearningPathBadge.objects.filter(
            badge=badge
        ).select_related("learning_path")

        learning_paths = {
            lpb.learning_path for lpb in learningpath_badges
        }  # Use set comprehension for uniqueness

        serialized_learning_paths = self.serializer_class(
            learning_paths,
            many=True,
            context={"request": request, "exclude_fields": ["created_by"]},
        )

        return Response(serialized_learning_paths.data)


@extend_schema(
    summary="Get details of qr code",
    parameters=[
        OpenApiParameter(
            name="entity_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="QR Code ID",
        )
    ],
    responses=QrCodeSerializerV1,
    tags=["QrCodes"],
)
class QRCodeJson(BaseEntityDetailViewPublic, SlugToEntityIdRedirectMixin):
    """
    Public QRCode endpoint for badge requests
    Allows unauthenticated users to fetch QR code details
    """

    permission_classes = (permissions.AllowAny,)
    model = QrCode
    serializer_class = QrCodeSerializerV1

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        return context
