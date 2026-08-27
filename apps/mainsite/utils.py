"""
Utility functions and constants that might be used across the project.
"""

import hmac
import io
import base64
import datetime
import hashlib
import json
import puremagic
import math
import re
import requests
import urllib.request
import urllib.parse
import urllib.error
import urllib.parse
import uuid

from django.apps import apps
from django.conf import settings
from django.core.cache import cache
from django.core.files.storage import DefaultStorage
from rest_framework.exceptions import UnsupportedMediaType
from django.urls import get_callable
from django.http import HttpResponse
from django.utils import timezone

from PIL import Image

from rest_framework.status import HTTP_429_TOO_MANY_REQUESTS

from xml.etree import cElementTree as ET


class ObjectView(object):
    """
    A simple utility that allows Rest Framework Serializers to serialize dict-based input
    when there is no appropriate model Class to instantiate.

    Instantiate an ObjectView(source_dict) in the serializer's to_internal_value() method.
    """

    def __init__(self, d):
        self.__dict__ = d

    def __unicode__(self):
        return str(self.__dict__)


slugify_function_path = getattr(
    settings, "AUTOSLUG_SLUGIFY_FUNCTION", "autoslug.utils.slugify"
)

slugify = get_callable(slugify_function_path)


def installed_apps_list():
    installed_apps = []
    for app in ("issuer", "composition", "badgebook"):
        if apps.is_installed(app):
            installed_apps.append(app)
    return installed_apps


def client_ip_from_request(request):
    """Returns the IP of the request, accounting for the possibility of being behind a proxy."""
    ip = request.META.get("HTTP_X_FORWARDED_FOR", None)
    if ip:
        # X_FORWARDED_FOR returns client1, proxy1, proxy2,...
        ip = ip.split(", ")[0]
    else:
        ip = request.META.get("REMOTE_ADDR", "")
    return ip


def backoff_cache_key(client_descriptor=""):
    return "failed_auth_backoff_{}".format(client_descriptor)


class OriginSettingsObject(object):
    DefaultOrigin = "http://localhost:8000"

    @property
    def DEFAULT_HTTP_PROTOCOL(self):
        parsed = urllib.parse.urlparse(self.HTTP)
        return parsed.scheme

    @property
    def HTTP(self):
        return getattr(settings, "HTTP_ORIGIN", OriginSettingsObject.DefaultOrigin)


OriginSetting = OriginSettingsObject()


"""
Cache Utilities
"""


def filter_cache_key(key, key_prefix, version):
    generated_key = ":".join([key_prefix, str(version), key])
    if len(generated_key) > 250:
        return hashlib.md5(generated_key.encode("utf-8")).hexdigest()
    return generated_key


def verify_svg(fileobj):
    """
    Check if provided file is svg
    from: https://gist.github.com/ambivalentno/9bc42b9a417677d96a21
    """
    fileobj.seek(0)
    tag = None
    try:
        for event, el in ET.iterparse(fileobj, events=(b"start",)):
            tag = el.tag
            break
    except ET.ParseError:
        pass
    finally:
        fileobj.seek(0)
    return tag == "{http://www.w3.org/2000/svg}svg"


def scrubSvgElementTree(svg_elem):
    """
    Takes an element (https://docs.python.org/2/library/xml.etree.elementtree.html#element-objects)
    from an element tree then scrubs malicious tags and attributes.
    :return: (svg_elem)
    """
    MALICIOUS_SVG_TAGS = ["script"]
    MALICIOUS_SVG_ATTRIBUTES = ["onload"]
    SVG_NAMESPACE = "http://www.w3.org/2000/svg"

    ET.register_namespace("", SVG_NAMESPACE)

    # find malicious tags and attributes
    elements_to_strip = []
    for tag_name in MALICIOUS_SVG_TAGS:
        elements_to_strip.extend(
            svg_elem.findall(".//{{{ns}}}{tag}".format(ns=SVG_NAMESPACE, tag=tag_name))
        )

    # strip malicious tags
    for e in elements_to_strip:
        parent = svg_elem.find(".//{tag}/..".format(tag=e.tag))
        parent.remove(e)

    # strip malicious attributes
    for el in svg_elem.iter():
        for attrib_name in MALICIOUS_SVG_ATTRIBUTES:
            if attrib_name in el.attrib:
                del el.attrib[attrib_name]

    return svg_elem


def fit_image_to_height(img, aspect_ratio, height=600):
    """
    Resize an image with the option to change the image ratio.
    :param img: An :py:class:`~PIL.Image.Image` object.
    :param aspect_ratio: A tuple that describes an aspect ratio. E.G: (1.91, 1)
    :param height: Maximum image height, defaults to 600.
    :return: An :py:class:`~PIL.Image.Image` object.
    """

    def _fit_dimension(size, desired_height):
        return int(math.floor((size - desired_height) / 2))

    img.thumbnail((height, height))
    new_size = (int(aspect_ratio[0] * height), int(aspect_ratio[1] * height))
    resized_dimension = new_size[1]
    resized_img = img.resize((resized_dimension, resized_dimension), Image.BICUBIC)
    new_img = Image.new("RGBA", new_size, 0)
    new_img.paste(
        resized_img,
        (_fit_dimension(new_size[0], height), _fit_dimension(new_size[1], height)),
    )

    return new_img


def fetch_remote_file_to_storage(
    remote_url,
    upload_to="",
    allowed_mime_types=(),
    resize_to_height=None,
    aspect_ratio=(1, 1),
):
    """
    Fetches a remote url, and stores it in DefaultStorage. Can optionally resize and change the
    aspect ratio of an image when saving to DefaultStorage. Currently only PNG are supported for resizing and reframing
    :return: (status_code, new_storage_name)
    """
    SVG_MIME_TYPE = "image/svg+xml"
    RESIZABLE_MIME_TYPES = ["image/png"]

    if not allowed_mime_types:
        raise UnsupportedMediaType("Allowed mime types must be passed in.")

    magic_strings = None
    content = None
    status_code = None

    if _is_data_uri(remote_url):
        # data:[<MIME-type>][;charset=<encoding>][;base64],<data>
        # finds the end of the substring 'base64' adds one more to get the comma as well.
        base64_image_from_data_uri = remote_url[
            (re.search("base64", remote_url).end()) + 1 :
        ]
        content = decoded_test = base64.b64decode(base64_image_from_data_uri)
        magic_strings = puremagic.magic_string(decoded_test)
        status_code = 200

    store = DefaultStorage()

    if magic_strings is None:
        r = requests.get(remote_url, stream=True)
        if r.status_code == 200:
            magic_strings = puremagic.magic_string(r.content)
            content = r.content
            status_code = r.status_code

    if magic_strings and content:
        derived_mime_type = None
        derived_ext = None
        stripped_svg_string = None

        for magic_string in magic_strings:
            if getattr(magic_string, "mime_type", None) in allowed_mime_types:
                derived_mime_type = getattr(magic_string, "mime_type", None)
                derived_ext = getattr(magic_string, "extension", None)
                break

        if (
            not derived_mime_type
            and re.search(b"<svg", content[:1024])
            and content.strip()[-6:] == b"</svg>"
        ):
            derived_mime_type = SVG_MIME_TYPE
            derived_ext = ".svg"

        if derived_mime_type == SVG_MIME_TYPE:
            stripped_svg_element = ET.fromstring(content)
            scrubSvgElementTree(stripped_svg_element)
            stripped_svg_string = ET.tostring(stripped_svg_element)

        if derived_mime_type not in allowed_mime_types:
            magic_string_info = max(
                magic_strings,
                key=lambda ms: ms.confidence and ms.extension and ms.mime_type,
            )
            raise UnsupportedMediaType(
                media_type="{} {}".format(
                    getattr(magic_string_info, "mime_type", "Unknown"),
                    getattr(magic_string_info, "extension", "Unknown"),
                )
            )

        if not derived_ext:
            raise UnsupportedMediaType(media_type="Unknown file extension.")

        string_to_write_to_file = stripped_svg_string or content

        storage_name = "{upload_to}/cached/{filename}{ext}".format(
            upload_to=upload_to,
            filename=hashlib.sha256(string_to_write_to_file).hexdigest(),
            ext=derived_ext,
        )

        if not store.exists(storage_name):
            out_buf = io.BytesIO()
            if resize_to_height and derived_mime_type in RESIZABLE_MIME_TYPES:
                img = Image.open(io.BytesIO(string_to_write_to_file))
                img = fit_image_to_height(img, aspect_ratio, resize_to_height)
                img.save(out_buf, format=derived_ext.split(".")[1])
            else:
                out_buf = io.BytesIO(string_to_write_to_file)

            store.save(storage_name, out_buf)
        return status_code, storage_name
    return status_code, None


def _is_data_uri(value):
    return re.search("data:", value[:8])


def clamped_backoff_in_seconds(backoff_count):
    max_backoff = getattr(
        settings, "TOKEN_BACKOFF_MAXIMUM_SECONDS", 3600
    )  # max is 1 hour
    backoff_period = getattr(settings, "TOKEN_BACKOFF_PERIOD_SECONDS", 2)
    max_number_of_backoffs = 12

    return min(
        max_backoff, backoff_period ** min(max_number_of_backoffs, backoff_count)
    )


def _expunge_stale_backoffs(backoff):
    backoff_keys = list(backoff.keys())
    for key in backoff_keys:
        try:
            an_hour_ago = timezone.now() - timezone.timedelta(hours=1)
            if backoff[key]["until"] < an_hour_ago:
                raise ValueError("This client_ip backoff is expired and can be removed")
        except (
            ValueError,
            TypeError,
            KeyError,
        ):
            del backoff[key]

    if not len(backoff):
        return
    return backoff


def iterate_backoff_count(backoff, client_ip):
    if backoff is None:
        backoff = dict()
    if backoff.get(client_ip) is None:
        backoff[client_ip] = {"count": 0}
    backoff[client_ip]["count"] += 1
    backoff[client_ip]["until"] = timezone.now() + datetime.timedelta(
        seconds=clamped_backoff_in_seconds(backoff[client_ip]["count"])
    )

    return _expunge_stale_backoffs(backoff)


def clear_backoff_count_for_ip(backoff, client_ip):
    if backoff is None:
        return

    if backoff.get(client_ip) is not None:
        del backoff[client_ip]
    return _expunge_stale_backoffs(backoff)


def throttleable(f):
    def wrapper(*args, **kw):
        max_backoff = getattr(
            settings, "TOKEN_BACKOFF_MAXIMUM_SECONDS", 3600
        )  # max is 1 hour. Set to 0 to disable.
        request = args[0].request
        username = request.POST.get("username", request.POST.get("client_id", None))
        client_ip = client_ip_from_request(request)
        backoff = cache.get(backoff_cache_key(username))

        if backoff is not None and len(backoff):
            backoff_for_ip = backoff.get(client_ip, dict())

            if max_backoff != 0 and not _request_authenticated_with_admin_scope(
                request
            ):
                backoff_until = backoff_for_ip.get("until", None)
                if backoff_until and backoff_until > timezone.now():
                    # Don't increase the backoff count, just return 429.
                    return HttpResponse(
                        json.dumps(
                            {
                                "error_description": "Too many login attempts. Please wait and try again.",
                                "error": "login attempts throttled",
                                "expires": clamped_backoff_in_seconds(
                                    backoff_for_ip.get("count")
                                ),
                            }
                        ),
                        status=HTTP_429_TOO_MANY_REQUESTS,
                    )

        try:
            result = f(*args, **kw)  # execute the decorated function

            if 200 <= result.status_code < 300:
                cache.set(
                    backoff_cache_key(username),
                    clear_backoff_count_for_ip(backoff, client_ip),
                )  # clear any existing backoff
            else:
                cache.set(
                    backoff_cache_key(username),
                    iterate_backoff_count(backoff, client_ip),
                    timeout=max_backoff,
                )
        except Exception as e:
            cache.set(
                backoff_cache_key(username),
                iterate_backoff_count(backoff, client_ip),
                timeout=max_backoff,
            )
            raise e

        return result

    return wrapper


def generate_entity_uri():
    """
    Generate a unique url-safe identifier
    """
    entity_uuid = uuid.uuid4()
    b64_string = base64.urlsafe_b64encode(entity_uuid.bytes)
    b64_trimmed = re.sub(r"=+$", "", b64_string.decode())
    return b64_trimmed


def first_node_match(graph, condition):
    """return the first dict in a list of dicts that matches condition dict"""
    for node in graph:
        if all(item in list(node.items()) for item in list(condition.items())):
            return node


def list_of(value):
    if value is None:
        return []
    elif isinstance(value, list):
        return value
    return [value]


def set_url_query_params(url, **kwargs):
    """
    Given a url, possibly including query parameters, return a url with the given query parameters set, replaced on a
    per-key basis.
    """
    url_parts = list(urllib.parse.urlparse(url))
    query = dict(urllib.parse.parse_qsl(url_parts[4]))
    query.update(kwargs)
    url_parts[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(url_parts)


def _request_authenticated_with_admin_scope(request):
    """
    Given a request object that may or may not have an associated auth token, return true if rw:issuerAdmin in scope
    :param request:
    :return: bool
    """
    token = getattr(request, "auth", None)
    if token is None:
        return False
    return "rw:serverAdmin" in getattr(token, "scope", "")


def netloc_to_domain(netloc):
    # Authorization specified in URL
    domain = netloc.split("@")[-1]
    # Port specified in URL
    domain = domain.split(":")[0]
    return domain


def hash_for_image(imageFileField):
    # image should be django.db.models.fields.files.FileField
    # from https://nitratine.net/blog/post/how-to-hash-files-in-python/
    try:
        block_size = 65536
        file_hash = hashlib.sha256()
        image_data = imageFileField
        file_buffer = image_data.read(block_size)
        while len(file_buffer) > 0:
            file_hash.update(file_buffer)
            file_buffer = image_data.read(block_size)
        image_data.seek(0)
        return file_hash.hexdigest()
    except Exception:
        return ""


def convert_svg_to_png(svg_string, height, width):
    """
    Converts an SVG string into a PNG image via a conversion API
    :param svg_string: An SVG
    :param height: PNG height
    :param width: PNG width
    :return: BytesIO of PNG bytes or False
    """
    if getattr(settings, "SVG_HTTP_CONVERSION_ENABLED", False) is False:
        return False

    endpoint = getattr(settings, "SVG_HTTP_CONVERSION_ENDPOINT")
    if not endpoint:
        return False

    response = requests.post(
        endpoint, json=dict(svgString=svg_string, height=height, width=width)
    )
    if response.status_code != 200:
        return False
    try:
        result = response.json()
        if "body" not in result or result["statusCode"] != 200:
            return False
        b64png = result["body"].replace("data:image/png;base64,", "")
        return io.BytesIO(base64.b64decode(b64png))
    except ValueError:
        # Issuing decoding response JSON
        return False


"""
Captcha Utilities (Inspired by: https://github.com/wearetechnative/terraform-aws-html-form-action/blob/main/lambda_src/html_form_action.py)
"""


def createHash(salt, number):
    hasher = hashlib.sha256()
    hasher.update((salt + str(number)).encode("utf-8"))
    hash_value = hasher.digest()
    return hash_value.hex()


def createHmac(secret_key, challenge):
    hash_algorithm = "sha256"
    hmac_object = hmac.new(
        secret_key.encode(),
        challenge.encode(),
        getattr(hashlib, hash_algorithm),
    )
    return hmac_object.hexdigest()


def validate_altcha(captcha, request=None):
    from mainsite.models import AltchaChallenge

    hmac_secret = getattr(settings, "ALTCHA_SECRET")
    data = json.loads(base64.b64decode(captcha))

    alg_ok = data["algorithm"] == "SHA-256"
    challenge_ok = data["challenge"] == createHash(data["salt"], data["number"])
    signature_ok = data["signature"] == createHmac(hmac_secret, data["challenge"])

    if not (alg_ok and challenge_ok and signature_ok):
        return False

    try:
        challenge = AltchaChallenge.objects.get(challenge=data["challenge"])

        if challenge.used:
            # prevent replay attacks
            return False

        challenge.used = True
        challenge.used_at = timezone.now()

        if request and hasattr(request, "META"):
            challenge.solved_by_ip = client_ip_from_request(request)

        challenge.save()
        return True

    except AltchaChallenge.DoesNotExist:
        return False


def verifyIssuerAutomatically(url, email):
    emailDomain = email.split("@")[1].lower()
    urlDomain = extract_domain(url)
    return urlDomain == emailDomain


def extract_domain(url):
    # Define a regular expression pattern for extracting the domain
    pattern = r"(https?://)?(www\d?\.)?(?P<domain>[\w\.-]+\.\w+)(/\S*)?"
    # Use re.match to search for the pattern at the beginning of the URL
    match = re.match(pattern, url)
    # Check if a match is found
    if match:
        # Extract the domain from the named group "domain" and convert it to lowercase
        domain = match.group("domain")
        return domain.lower()
    else:
        return None


def get_name(badgeinstance):
    """Evaluates the name to be displayed for the recipient of the badge.

    This is either the name that was specified in the award process of the badge
    (which is by now mandatory) or, if none was specified, the full profile of the
    recipient. If no name was specified and the profile can't be found, we return `None`.
    """

    from badgeuser.models import BadgeUser

    recipientProfile = badgeinstance.extension_items.get(
        "extensions:recipientProfile", {}
    )
    name = recipientProfile.get("name", None)
    if name:
        return name

    try:
        badgeuser = BadgeUser.objects.get(email=badgeinstance.recipient_identifier)
        first_name = badgeuser.first_name.capitalize()
        last_name = badgeuser.last_name.capitalize()
        return f"{first_name} {last_name}"
    except BadgeUser.DoesNotExist:
        return None


def validate_qr_code_validity(qrCode):
    """
    Validates if a QR code is still valid based on its validity dates.
    Returns None if valid, or an error message if invalid.
    """
    # If no validity dates set, consider it always valid
    if not qrCode.valid_from or not qrCode.expires_at:
        return None

    now = timezone.now()

    if now < qrCode.valid_from:
        return "QR code is not yet valid"

    if now > qrCode.expires_at:
        return "QR code has expired"

    return None
