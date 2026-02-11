import base64
from io import BytesIO
import json
import time
import re
import os
from hashlib import md5
import html

from django import forms
from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import reverse_lazy
from django.db import IntegrityError
from django.core.cache import cache
from django.http import (
    HttpResponseServerError,
    HttpResponseNotFound,
    HttpResponseRedirect,
    HttpResponse,
)
from django.shortcuts import redirect
from django.template import loader
from django.template.exceptions import TemplateDoesNotExist
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.generic import FormView, RedirectView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.decorators import (
    permission_classes,
    authentication_classes,
    api_view,
)
from rest_framework.authentication import (
    SessionAuthentication,
    BasicAuthentication,
    TokenAuthentication,
)

from apps.mainsite.permissions import IsServerAdmin
from badgeuser.models import BadgeUser
from badgeuser.serializers_v1 import BadgeUserProfileSerializerV1
from entity.api_v3 import EntityViewSet
from mainsite.authentication import BadgrOAuth2Authentication, ValidAltcha
from issuer.tasks import rebake_all_assertions, update_issuedon_all_assertions
from issuer.models import BadgeClass, Issuer, QrCode, RequestedBadge
from issuer.serializers_v1 import IssuerSerializerV1, RequestedBadgeSerializer
from mainsite.admin_actions import clear_cache
from mainsite.models import EmailBlacklist, BadgrApp, AltchaChallenge
from mainsite.serializers import LegacyVerifiedAuthTokenSerializer
from mainsite.utils import createHash, createHmac, validate_qr_code_validity
from random import randrange

import mainsite

from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import DefaultStorage


import uuid
from django.http import JsonResponse
import requests
from requests_oauthlib import OAuth1
from issuer.permissions import is_badgeclass_staff
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table
from reportlab.lib.utils import ImageReader
import logging
from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter,
    OpenApiTypes,
    inline_serializer,
)
from rest_framework import serializers


logger = logging.getLogger("Badgr.Events")


##
#
#  Error Handler Views
#
##
@xframe_options_exempt
def error404(request, *args, **kwargs):
    try:
        template = loader.get_template("error/404.html")
    except TemplateDoesNotExist:
        return HttpResponseServerError(
            "<h1>Page not found (404)</h1>", content_type="text/html"
        )
    return HttpResponseNotFound(
        template.render(
            {
                "STATIC_URL": getattr(settings, "STATIC_URL", "/static/"),
            }
        )
    )


@xframe_options_exempt
def error500(request, *args, **kwargs):
    try:
        template = loader.get_template("error/500.html")
    except TemplateDoesNotExist:
        return HttpResponseServerError(
            "<h1>Server Error (500)</h1>", content_type="text/html"
        )
    return HttpResponseServerError(
        template.render(
            {
                "STATIC_URL": getattr(settings, "STATIC_URL", "/static/"),
            }
        )
    )


def info_view(request, *args, **kwargs):
    return redirect(getattr(settings, "LOGIN_BASE_URL"))


# TODO: It is possible to call this method without authentication, thus storing files on the server
@csrf_exempt
def upload(req):
    if req.method == "POST":
        uploaded_file = req.FILES["files"]
        file_extension = uploaded_file.name.split(".")[-1]
        random_filename = str(uuid.uuid4())
        final_filename = random_filename + "." + file_extension
        store = DefaultStorage()
        store.save(final_filename, uploaded_file)
    return JsonResponse({"filename": final_filename})


def call_aiskills_api(endpoint, method, payload: dict):
    apiKey = getattr(settings, "AISKILLS_API_KEY")
    params = {"api_key": apiKey}
    headers = {"accept": "application/json"}

    # FIXME: is retrying server-side the best option? especially with the 5 second delay
    #        there might be no feedback to the user for more than 20 seconds if the API
    #        throws an unexpected error
    attempt_num = 0  # keep track of how many times we've retried
    while attempt_num < 4:
        # if POST, transfer payload in body
        if method == "POST":
            headers = {
                **headers,
                "Content-Type": "application/json",
            }
            response = requests.post(
                endpoint, params=params, data=json.dumps(payload), headers=headers
            )
        # for GET, add payload to query params
        elif method == "GET":
            params = {**params, **payload}
            response = requests.get(endpoint, params=params, headers=headers)
        else:
            return JsonResponse(
                {"error": "Internal function called using invalid request method"},
                status=400,
            )

        if response.status_code == 200:
            data = response.json()
            return JsonResponse(data, status=status.HTTP_200_OK)
        elif response.status_code == 403 or response.status_code == 401:
            # Probably the API KEY was wrong
            return JsonResponse(
                {"error": "Couldn't authenticate against AI skills service!"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        elif response.status_code == 400:
            # Invalid input
            return JsonResponse(
                {"error": "Invalid searchterm!"}, status=status.HTTP_400_BAD_REQUEST
            )
        elif response.status_code == 500:
            # This is, weirdly enough, typically also an indication of an invalid searchterm
            # st: According to the developer of the API this should never happen as the API only returns 400,
            # maybe this was a bug during development?
            return JsonResponse(
                {"error": extractErrorMessage500(response)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            attempt_num += 1
            logger.warning(
                "Request to AI skills endpoint failed with response code %d (try %d): '%s'",
                response.status_code,
                attempt_num,
                response.text,
            )
            # No need to sleep if there's no more try
            if attempt_num < 4:
                time.sleep(5)  # Wait for 5 seconds before re-trying

    return JsonResponse(
        {"error": f"Request failed with status code {response.status_code}"},
        status=response.status_code,
    )


@extend_schema(
    summary="Analyze text with AI skills",
    description="Analyze text using AI skills service",
    tags=["AI Skills"],
    request=inline_serializer(
        name="AISkillsRequest",
        fields={"text": serializers.CharField()},
    ),
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@authentication_classes(
    [TokenAuthentication, SessionAuthentication, BasicAuthentication]
)

# require valid altcha challenge for demo on start page
@permission_classes([ValidAltcha])
def aiskills(req):
    searchterm = req.data["text"]

    # fallback to previous setting name
    endpoint = getattr(
        settings,
        "AISKILLS_ENDPOINT_CHATS",
        getattr(settings, "AISKILLS_ENDPOINT", None),
    )
    payload = {"text_to_analyze": searchterm}

    return call_aiskills_api(endpoint, "POST", payload)


@extend_schema(
    summary="Get AI skills keywords",
    description="Retrieve keywords from AI skills service",
    tags=["AI Skills"],
    request=inline_serializer(
        name="AISkillsKeywordsRequest",
        fields={
            "keyword": serializers.CharField(),
            "lang": serializers.CharField(),
        },
    ),
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@authentication_classes(
    [TokenAuthentication, SessionAuthentication, BasicAuthentication]
)
@permission_classes([IsAuthenticated])
def aiskills_keywords(req):
    searchterm = req.data["keyword"]
    lang = req.data["lang"]

    endpoint = getattr(settings, "AISKILLS_ENDPOINT_KEYWORDS")
    payload = {"query": searchterm, "lang": lang}

    return call_aiskills_api(endpoint, "GET", payload)


@extend_schema(exclude=True)
@api_view(["GET"])
@permission_classes([AllowAny])
def createCaptchaChallenge(req):
    if req.method != "GET":
        return JsonResponse(
            {"error": "Method not allowed"}, status=status.HTTP_400_BAD_REQUEST
        )

    hmac_secret = getattr(settings, "ALTCHA_SECRET")
    minnumber = getattr(settings, "ALTCHA_MINNUMBER", 10000)
    maxnumber = getattr(settings, "ALTCHA_MAXNUMBER", 100000)

    salt = os.urandom(12).hex()
    number = randrange(minnumber, maxnumber, 1)
    challenge = createHash(salt, number)
    signature = createHmac(hmac_secret, challenge)

    AltchaChallenge.objects.create(salt=salt, challenge=challenge, signature=signature)

    ch = {
        "algorithm": "SHA-256",
        "challenge": challenge,
        "salt": salt,
        "signature": signature,
        "maxnumber": maxnumber,
    }

    return JsonResponse(ch)


@extend_schema(
    request=inline_serializer(
        name="BadgeRequestSerializer",
        fields={
            "firstname": serializers.CharField(),
            "lastname": serializers.CharField(),
            "email": serializers.EmailField(),
            "ageConfirmation": serializers.BooleanField(),
        },
    ),
    responses={
        200: inline_serializer(
            name="BadgeRequestResponseSerializer",
            fields={
                "message": serializers.CharField(),
                "requested_badges": serializers.ListField(
                    child=serializers.DictField()
                ),
            },
        ),
        400: inline_serializer(
            name="BadgeRequestErrorSerializer",
            fields={
                "error": serializers.CharField(),
            },
        ),
    },
    parameters=[
        OpenApiParameter(
            name="qrCodeId",
            type=str,
            location=OpenApiParameter.PATH,
            description="QR Code Entity ID",
        )
    ],
    tags=["Requested Badges"],
)
@api_view(["POST", "GET"])
@permission_classes([AllowAny])
def requestBadge(req, qrCodeId):
    if req.method != "POST" and req.method != "GET":
        return JsonResponse(
            {"error": "Method not allowed"}, status=status.HTTP_400_BAD_REQUEST
        )
    try:
        qrCode = QrCode.objects.get(entity_id=qrCodeId)
    except QrCode.DoesNotExist:
        return JsonResponse({"error": "Invalid qrCodeId"}, status=400)

    if req.method == "GET":
        requestedBadges = RequestedBadge.objects.filter(qrcode=qrCode)
        serializer = RequestedBadgeSerializer(requestedBadges, many=True)
        return JsonResponse(
            {"requested_badges": serializer.data}, status=status.HTTP_200_OK
        )

    elif req.method == "POST":
        validity_error = validate_qr_code_validity(qrCode)
        if validity_error:
            return JsonResponse(
                {"error": validity_error}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            data = json.loads(req.data)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        firstName = data.get("firstname")
        lastName = data.get("lastname")
        email = data.get("email")
        ageConfirmation = data.get("ageConfirmation")

        if not all([firstName, lastName, email]):
            return JsonResponse(
                {"error": "Missing required fields: firstname, lastname, email"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not ageConfirmation or ageConfirmation is not True:
            return JsonResponse(
                {"error": "Age confirmation is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            qrCode = QrCode.objects.get(entity_id=qrCodeId)

        except QrCode.DoesNotExist:
            return JsonResponse({"error": "Invalid qrCodeId"}, status=400)

        badge = RequestedBadge(
            firstName=firstName,
            lastName=lastName,
            email=email,
        )

        badge.badgeclass = qrCode.badgeclass
        badge.qrcode = qrCode

        badge.save()

        return JsonResponse(
            {"message": "Badge request received"}, status=status.HTTP_200_OK
        )


@extend_schema(
    summary="Get server timestamp",
    description="Retrieve the current server timestamp",
    tags=["System"],
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["GET"])
@permission_classes([AllowAny])
def getTimestamp(req):
    if req.method != "GET":
        return JsonResponse(
            {"error": "Method not allowed"}, status=status.HTTP_400_BAD_REQUEST
        )
    timestamp = mainsite.__timestamp__

    return JsonResponse({"message": timestamp}, status=status.HTTP_200_OK)


def PageSetup(canvas, doc, badgeImage, issuerImage):
    canvas.saveState()

    # Header
    try:
        if issuerImage is not None:
            institutionImage = ImageReader(issuerImage)
            canvas.drawImage(
                institutionImage,
                20,
                705,
                width=80,
                height=80,
                mask="auto",
                preserveAspectRatio=True,
            )
    except Exception:
        oebLogo = ImageReader("{}images/Logo-Oeb.png".format(settings.STATIC_URL))
        canvas.drawImage(
            oebLogo, 20, 710, width=80, height=80, mask="auto", preserveAspectRatio=True
        )

    page_width = canvas._pagesize[0]
    page_height = canvas._pagesize[1]
    canvas.setStrokeColor("#492E98")
    canvas.line(page_width / 2 - 185, 750, page_width / 2 + 250, 750)

    badge = ImageReader(badgeImage)
    canvas.drawImage(
        badge, 250, 200, width=100, height=100, mask="auto", preserveAspectRatio=True
    )

    arrow = ImageReader(
        "{}images/arrow-qrcode-download.png".format(settings.STATIC_URL)
    )
    canvas.drawImage(
        arrow, 100, 300, width=80, height=80, mask="auto", preserveAspectRatio=True
    )
    # TODO: change Font-family to rubik
    canvas.setFont("Rubik-Bold", 16)
    canvas.drawString(100, 275, "Hol' dir jetzt")
    canvas.drawString(100, 250, "deinen Badge!")

    bottom_10_percent_height = page_height * 0.10
    canvas.setFillColor("#F1F0FF")
    canvas.rect(0, 0, page_width, bottom_10_percent_height, stroke=0, fill=1)

    canvas.restoreState()

    canvas.saveState()
    footer_text = "ERSTELLT ÜBER"

    canvas.setFont("Rubik-Bold", 12)
    canvas.setFillColor("#323232")

    text_x = page_width / 2
    text_y = bottom_10_percent_height / 2
    canvas.drawCentredString(text_x, text_y, footer_text)

    text = '<a href="https://openbadges.education"><u><strong>OPENBADGES.EDUCATION</strong></u></a>'
    p = Paragraph(
        text,
        ParagraphStyle(
            name="oeb", fontSize=12, textColor="#1400ff", alignment=TA_CENTER
        ),
    )
    p.wrap(page_width, bottom_10_percent_height)
    p.drawOn(canvas, 0, text_y - 15)


@extend_schema(
    summary="Delete badge request",
    description="Delete a badge request by ID",
    tags=["Requested Badges"],
    parameters=[
        OpenApiParameter(
            name="requestId",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="Request entity ID",
        ),
    ],
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def deleteBadgeRequest(req, requestId):
    if req.method != "DELETE":
        return JsonResponse(
            {"error": "Method not allowed"}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        badge = RequestedBadge.objects.get(entity_id=requestId)

        if not is_badgeclass_staff(req.user, badge.badgeclass):
            return Response(
                {"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN
            )

    except RequestedBadge.DoesNotExist:
        return JsonResponse({"error": "Invalid requestId"}, status=400)

    badge.delete()

    return JsonResponse({"message": "Badge request deleted"}, status=status.HTTP_200_OK)


@extend_schema(
    summary="Get badge requests by badge class",
    description="Retrieve count of badge requests for a specific badge class",
    tags=["Requested Badges"],
    parameters=[
        OpenApiParameter(
            name="badgeSlug",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="Badge class entity ID",
        ),
    ],
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def badgeRequestsByBadgeClass(req, badgeSlug):
    if req.method != "GET":
        return JsonResponse(
            {"error": "Method not allowed"}, status=status.HTTP_400_BAD_REQUEST
        )

    requestedBadgesCount = 0
    try:
        badgeClass = BadgeClass.objects.get(entity_id=badgeSlug)
    except BadgeClass.DoesNotExist:
        return JsonResponse({"error": "Invalid badgeSlug"}, status=400)

    if not is_badgeclass_staff(req.user, badgeClass):
        return Response(
            {"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN
        )

    requestedBadgesCount = RequestedBadge.objects.filter(badgeclass=badgeClass).count()
    return JsonResponse(
        {"request_count": requestedBadgesCount}, status=status.HTTP_200_OK
    )


def create_page(response, page_content, badgeImage, issuerImage):
    doc = SimpleDocTemplate(response, pagesize=A4)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Justify", alignment=TA_JUSTIFY))

    Story = []
    Story.extend(page_content)

    doc.build(
        Story,
        onFirstPage=lambda canvas, doc: PageSetup(canvas, doc, badgeImage, issuerImage),
    )


@extend_schema(
    summary="Download QR code as PDF",
    description="Generate and download a QR code PDF for a badge instance",
    tags=["Assertions"],
    parameters=[
        OpenApiParameter(
            name="badgeSlug",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="Badge class entity ID",
        ),
    ],
    request=inline_serializer(
        name="QRCodeDownloadRequest",
        fields={"image": serializers.CharField()},
    ),
    responses={200: OpenApiTypes.BINARY},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def downloadQrCode(request, *args, **kwargs):
    if request.method != "POST":
        return JsonResponse(
            {"error": "Method not allowed"}, status=status.HTTP_400_BAD_REQUEST
        )
    badgeSlug = kwargs.get("badgeSlug")

    try:
        badge = BadgeClass.objects.get(entity_id=badgeSlug)
    except BadgeClass.DoesNotExist:
        return JsonResponse({"error": "Invalid badgeSlug"}, status=400)

    if not is_badgeclass_staff(request.user, badge):
        return Response(
            {"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN
        )

    image_data = request.data.get("image")

    image_data = image_data.split(",")[1]  # Remove the data URL prefix
    image_bytes = base64.b64decode(image_data)

    image_stream = BytesIO(image_bytes)

    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = 'inline; filename="qrcode.pdf"'
    Story = []

    Story.append(Spacer(1, 100))

    badgeTitle_style = ParagraphStyle(
        name="BadgeTitle",
        fontSize=24,
        leading=30,
        textColor="#492E98",
        alignment=TA_CENTER,
    )

    badgeTitle = f"<strong>{badge.name}</strong>"
    Story.append(Paragraph(badgeTitle, badgeTitle_style))
    Story.append(Spacer(1, 35))

    image = Image(image_stream, width=250, height=250)
    table_data = [[image]]
    table = Table(
        table_data, colWidths=250, rowHeights=250, cornerRadii=[15, 15, 15, 15]
    )

    table.setStyle(
        [
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 3, "#492E98"),
            ("TOPPADDING", (0, 0), (-1, -1), 0),  # Remove paddings
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]
    )
    Story.append(table)
    Story.append(Spacer(1, 125))

    badgeImage = badge.image

    issuerImage = badge.issuer.image

    # issued_by_style = ParagraphStyle(name='Issued_By', fontSize=18, textColor='#492E98', alignment=TA_CENTER)
    # text = f"<strong>- Vergeben von: {badge.issuer.name}</strong> -"
    # Story.append(Paragraph(text, issued_by_style))

    create_page(response, Story, badgeImage, issuerImage)

    return response


def extractErrorMessage500(response: Response):
    expression = re.compile("<pre>Error: ([^<]+)<br>")
    match = expression.search(response.text)
    return match.group(1) if match else "Invalid searchterm! (Unknown error)"


@extend_schema(exclude=True)
@api_view(["GET"])
@authentication_classes(
    [
        BadgrOAuth2Authentication,
        TokenAuthentication,
        SessionAuthentication,
        BasicAuthentication,
    ]
)
@permission_classes([IsAuthenticated])
def nounproject(req, searchterm, page):
    if req.method == "GET":
        attempt_num = 0  # keep track of how many times we've retried
        while attempt_num < 4:
            auth = OAuth1(
                getattr(settings, "NOUNPROJECT_API_KEY"),
                getattr(settings, "NOUNPROJECT_SECRET"),
            )
            endpoint = (
                "http://api.thenounproject.com/v2/icon?query="
                + searchterm
                + "&limit=10&page="
                + page
            )
            response = requests.get(endpoint, auth=auth)
            if response.status_code == 200:
                data = response.json()
                return JsonResponse(data, status=status.HTTP_200_OK)
            elif response.status_code == 403:
                # Probably the API KEY / SECRET was wrong
                return JsonResponse(
                    {"error": "Couldn't authenticate against thenounproject!"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            else:
                attempt_num += 1
                logger.warning(
                    "Request to nounproject endpoint failed with response code %d (try %d): '%s'",
                    response.status_code,
                    attempt_num,
                    response.text,
                )
                # No need to sleep if there's no more try
                if attempt_num < 4:
                    time.sleep(5)  # Wait for 5 seconds before re-trying

        return JsonResponse(
            {"error": f"Request failed with status code {response.status_code}"},
            status=response.status_code,
        )
    else:
        return JsonResponse(
            {"error": "Method not allowed"}, status=status.HTTP_400_BAD_REQUEST
        )


def email_unsubscribe_response(request, message, error=False):
    badgr_app_pk = request.GET.get("a", None)

    badgr_app = BadgrApp.objects.get_by_id_or_default(badgr_app_pk)

    query_param = "infoMessage" if error else "authError"
    redirect_url = "{url}?{query_param}={message}".format(
        url=badgr_app.ui_login_redirect, query_param=query_param, message=message
    )
    return HttpResponseRedirect(redirect_to=redirect_url)


def email_unsubscribe(request, *args, **kwargs):
    if time.time() > int(kwargs["expiration"]):
        return email_unsubscribe_response(
            request, "Your unsubscription link has expired.", error=True
        )

    try:
        email = base64.b64decode(kwargs["email_encoded"]).decode("utf-8")
    except TypeError as e:
        logger.error(
            "The unsubscribe link was invalid and caused a type error: '%s'", e
        )
        logger.info("Encoded e-Mail: '%s'", kwargs["email_encoded"])
        return email_unsubscribe_response(
            request, "Invalid unsubscribe link.", error=True
        )

    if not EmailBlacklist.verify_email_signature(**kwargs):
        logger.error("The unsubscribe link signature was invalid")
        logger.info("E-Mail: '%s'", email)
        return email_unsubscribe_response(
            request, "Invalid unsubscribe link.", error=True
        )

    blacklist_instance = EmailBlacklist(email=email)
    try:
        blacklist_instance.save()
        logger.info("Successfully unsubscribed E-Mail '%s'", email)
    except IntegrityError:
        pass
    except Exception as e:
        logger.error("Unsubscribing E-Mail failed with an exception: '%s'", e)
        logger.info("E-Mail: '%s'", email)
        return email_unsubscribe_response(
            request, "Failed to unsubscribe email.", error=True
        )

    return email_unsubscribe_response(
        request,
        "You will no longer receive email notifications for earned"
        " badges from this domain.",
    )


# CMS contents


def call_cms_api(request, path, params={}):
    params = {"api_key": settings.CMS_API_KEY, **params}
    try:
        params["lang"] = request.GET.get("lang")
    except Exception:
        pass

    headers = {"accept": "application/json"}
    url = settings.CMS_API_BASE_URL + settings.CMS_API_BASE_PATH + path

    cache_key = md5(url.encode() + json.dumps(params).encode()).hexdigest()

    data = cache.get(cache_key)
    if not data:
        try:
            response = requests.get(url, params=params, headers=headers)
            data = response.json()
            cache.set(cache_key, data, 60)
        except Exception:
            data = ""
    return JsonResponse(data, safe=False)


def cms_transform_urls(text):
    # replace with asset:// to be able to easily restore later
    text = text.replace(f"{settings.CMS_API_BASE_URL}/wp-content", "asset://")

    # temporarily replace iframe src originating from cms with a placeholder restore later
    pattern = re.compile(r'(<iframe\b[^>]*\bsrc=)(["\'])(.*?)(\2)', flags=re.IGNORECASE)
    for match in pattern.finditer(text):
        matched_url = match.group(3)
        if matched_url.find(settings.CMS_API_BASE_URL) >= 0:
            suffix = matched_url.split(settings.CMS_API_BASE_URL)[1]
            text = text.replace(matched_url, f"external://{suffix}")

    text = text.replace(settings.CMS_API_BASE_URL, "/page")
    text = text.replace("/page/post", "/post")
    text = text.replace("/page/en/post", "/post")
    text = text.replace("external://", settings.CMS_API_BASE_URL)
    text = text.replace("asset://", f"{settings.CMS_API_BASE_URL}/wp-content")
    return text


def cms_api_menu_list(request):
    api_response = call_cms_api(request, "menu/list")
    api_data = json.loads(api_response.content.decode())

    # transform menu response
    menus = {"header": {"de": [], "en": []}, "footer": {"de": [], "en": []}}
    for i, menu in api_data.items():
        all_items = [
            {
                "id": x["ID"],
                "page_id": int(x["object_id"]),
                "title": x["title"],
                "url": cms_transform_urls(x["url"]),
                "parent": int(x["menu_item_parent"]),
                "children": [],
            }
            for x in menu["items"]
        ]

        # turn into tree
        items = []
        for x in all_items:
            if x["parent"] == 0:
                items.append(x)
            else:
                parent = next(filter(lambda y: y["id"] == x["parent"], items), None)
                if parent:
                    parent["children"].append(x)

        if menu["menu"]["slug"] == "footer":
            menus["footer"]["de"] = items
        elif menu["menu"]["slug"] == "footer-eng":
            menus["footer"]["en"] = items
        elif menu["menu"]["slug"] == "header":
            menus["header"]["de"] = items
        elif menu["menu"]["slug"] == "header-eng":
            menus["header"]["en"] = items

    return JsonResponse(menus)


def cms_api_page_details(request):
    slug = request.GET.get("slug")
    api_response = call_cms_api(request, "page/slug", {"slug": slug})
    api_data = json.loads(api_response.content.decode())

    try:
        api_data["post_content"] = cms_transform_urls(api_data["post_content"])
    except KeyError:
        api_data["post_content"] = "Page not found"

    return JsonResponse(api_data)


def cms_api_post_details(request):
    slug = request.GET.get("slug")
    api_response = call_cms_api(request, "post/slug", {"slug": "post/" + slug})
    api_data = json.loads(api_response.content.decode())

    try:
        api_data["post_content"] = cms_transform_urls(api_data["post_content"])
    except KeyError:
        api_data["post_content"] = "Page not found"

    return JsonResponse(api_data)


def cms_api_post_list(request):
    api_response = call_cms_api(request, "post/list", {})
    api_data = json.loads(api_response.content.decode())
    for post in api_data:
        post["post_content"] = cms_transform_urls(post["post_content"])
        post["slug"] = cms_transform_urls(post["slug"])

    return JsonResponse(api_data, safe=False)


def cms_api_style(request):
    api_response = call_cms_api(request, "style", {})
    api_response_content = api_response.content.decode()
    api_response_content = api_response_content.replace("body.", ".body.")
    api_response_content = api_response_content.replace("body ", ":host ")
    api_response_content = api_response_content.replace("body{", ":host{")
    api_response_content = api_response_content.replace(":root", ":host")
    api_response_content = html.unescape(api_response_content)
    api_data = json.loads(api_response_content)

    return HttpResponse(api_data, content_type="text/css")


def cms_api_script(request):
    api_response = call_cms_api(request, "script", {})
    api_response_content = api_response.content.decode()
    api_response_content = api_response_content.replace(
        "document.querySelector",
        "document.querySelector('cms-content shadow-dom').shadowRoot.querySelector",
    )
    api_data = json.loads(api_response_content)

    return HttpResponse(api_data, content_type="text/javascript")


class AppleAppSiteAssociation(APIView):
    schema = None
    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)

    def get(self, request):
        data = {"applinks": {"apps": [], "details": []}}

        for app_id in getattr(settings, "APPLE_APP_IDS", []):
            data["applinks"]["details"].append(app_id)

        return Response(data=data)


@extend_schema(exclude=True)
class LegacyLoginAndObtainAuthToken(ObtainAuthToken):
    serializer_class = LegacyVerifiedAuthTokenSerializer

    def post(self, request, *args, **kwargs):
        response = super(LegacyLoginAndObtainAuthToken, self).post(
            request, *args, **kwargs
        )
        response.data["warning"] = (
            "This method of obtaining a token is deprecated and will be removed. "
            "This request has been logged."
        )
        return response


class SitewideActionForm(forms.Form):
    ACTION_CLEAR_CACHE = "CLEAR_CACHE"
    ACTION_REBAKE_ALL_ASSERTIONS = "REBAKE_ALL_ASSERTIONS"
    ACTION_FIX_ISSUEDON = "FIX_ISSUEDON"

    ACTIONS = {
        ACTION_CLEAR_CACHE: clear_cache,
        ACTION_REBAKE_ALL_ASSERTIONS: rebake_all_assertions,
        ACTION_FIX_ISSUEDON: update_issuedon_all_assertions,
    }
    CHOICES = (
        (
            ACTION_CLEAR_CACHE,
            "Clear Cache",
        ),
        (
            ACTION_REBAKE_ALL_ASSERTIONS,
            "Rebake all assertions",
        ),
        (
            ACTION_FIX_ISSUEDON,
            "Re-process issuedOn for backpack assertions",
        ),
    )

    action = forms.ChoiceField(choices=CHOICES, required=True, label="Pick an action")
    confirmed = forms.BooleanField(
        required=True, label="Are you sure you want to perform this action?"
    )


class SitewideActionFormView(FormView):
    form_class = SitewideActionForm
    template_name = "admin/sitewide_actions.html"
    success_url = reverse_lazy("admin:index")

    @method_decorator(staff_member_required)
    def dispatch(self, request, *args, **kwargs):
        return super(SitewideActionFormView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        action = form.ACTIONS[form.cleaned_data["action"]]

        if hasattr(action, "delay"):
            action.delay()
        else:
            action()

        return super(SitewideActionFormView, self).form_valid(form)


class RedirectToUiLogin(RedirectView):
    schema = None

    def get_redirect_url(self, *args, **kwargs):
        badgrapp = BadgrApp.objects.get_current()
        return (
            badgrapp.ui_login_redirect
            if badgrapp.ui_login_redirect is not None
            else badgrapp.email_confirmation_redirect
        )


class DocsAuthorizeRedirect(RedirectView):
    schema = None

    def get_redirect_url(self, *args, **kwargs):
        badgrapp = BadgrApp.objects.get_current(request=self.request)
        url = badgrapp.oauth_authorization_redirect
        if not url:
            url = "https://{cors}/auth/oauth2/authorize".format(cors=badgrapp.cors)

        query = self.request.META.get("QUERY_STRING", "")
        if query:
            url = "{}?{}".format(url, query)
        return url


class AdminUser(EntityViewSet):
    permission_classes = [IsServerAdmin]
    queryset = BadgeUser.objects.all()
    serializer_class = BadgeUserProfileSerializerV1


class AdminIssuer(EntityViewSet):
    permission_classes = [IsServerAdmin]
    queryset = Issuer.objects.all()
    serializer_class = IssuerSerializerV1
