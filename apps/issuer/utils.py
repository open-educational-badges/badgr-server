import aniso8601
import hashlib
import pytz
import re
from urllib.parse import urlparse, urlunparse
from functools import reduce

from django.urls import resolve, Resolver404
from django.utils import timezone
from django.conf import settings

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from geopy.geocoders import Nominatim
from ratelimit import limits, sleep_and_retry
from rest_framework.response import Response

from apps.mainsite.exceptions import BadgrQuotaExceededException
from mainsite.utils import OriginSetting


OBI_VERSION_CONTEXT_IRIS = {
    "1_1": "https://w3id.org/openbadges/v1",
    "2_0": "https://w3id.org/openbadges/v2",
    "3_0": ["https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],
}

CURRENT_OBI_VERSION = "2_0"
CURRENT_OBI_CONTEXT_IRI = OBI_VERSION_CONTEXT_IRIS.get(CURRENT_OBI_VERSION)

# assertions that were baked and saved to BadgeInstance.image used this version
UNVERSIONED_BAKED_VERSION = "3_0"


def get_obi_context(obi_version):
    context_iri = OBI_VERSION_CONTEXT_IRIS.get(obi_version, None)
    if context_iri is None:
        obi_version = CURRENT_OBI_VERSION
        context_iri = CURRENT_OBI_CONTEXT_IRI
    return (obi_version, context_iri)


def add_obi_version_ifneeded(url, obi_version, force_add=False):
    if obi_version == CURRENT_OBI_VERSION and not force_add:
        return url
    if not url.startswith(OriginSetting.HTTP):
        return url
    return "{url}{sep}v={obi_version}".format(
        url=url, sep="&" if "?" in url else "?", obi_version=obi_version
    )


def generate_sha256_hashstring(identifier, salt=None):
    key = "{}{}".format(identifier, salt if salt is not None else "")
    return "sha256$" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_md5_hashstring(identifier, salt=None):
    key = "{}{}".format(identifier, salt if salt is not None else "")
    return "md5$" + hashlib.md5(key.encode("utf-8")).hexdigest()


def generate_rebaked_filename(oldname, badgeclass_filename):
    parts = oldname.split(".")
    badgeclass_filename_parts = badgeclass_filename.split(".")
    ext = badgeclass_filename_parts.pop()
    parts.append("rebaked")
    return "assertion-{}.{}".format(
        hashlib.md5("".join(parts).encode("utf-8")).hexdigest(), ext
    )


def is_probable_url(string):
    earl = re.compile(r"^https?")
    if string is None:
        return False
    return earl.match(string)


def obscure_email_address(email):
    charlist = list(email)

    return "".join(
        letter
        if letter
        in (
            "@",
            ".",
        )
        else "*"
        for letter in charlist
    )


def get_badgeclass_by_identifier(identifier):
    """
    Finds a Issuer.BadgeClass by an identifier that can be either:
        - JSON-ld id
        - BadgeClass.id
        - BadgeClass.slug
    """

    from issuer.models import BadgeClass

    # attempt to resolve identifier as JSON-ld id
    if identifier.startswith(OriginSetting.HTTP):
        try:
            resolver_match = resolve(identifier.replace(OriginSetting.HTTP, ""))
            if resolver_match:
                entity_id = resolver_match.kwargs.get("entity_id", None)
                if entity_id:
                    try:
                        return BadgeClass.cached.get(entity_id=entity_id)
                    except BadgeClass.DoesNotExist:
                        pass
        except Resolver404:
            pass

    # attempt to resolve as BadgeClass.slug
    try:
        return BadgeClass.cached.get(slug=identifier)
    except BadgeClass.DoesNotExist:
        pass

    # attempt to resolve as BadgeClass.entity_id
    try:
        return BadgeClass.cached.get(entity_id=identifier)
    except (BadgeClass.DoesNotExist, ValueError):
        pass

    # attempt to resolve as JSON-ld of external badge
    try:
        return BadgeClass.cached.get(source_url=identifier)
    except BadgeClass.DoesNotExist:
        pass

    # nothing found
    return None


def parse_original_datetime(t, tzinfo=pytz.utc):
    try:
        result = timezone.datetime.fromtimestamp(float(t), pytz.utc).isoformat()
    except (ValueError, TypeError):
        try:
            dt = aniso8601.parse_datetime(t)
            if not timezone.is_aware(dt):
                dt = pytz.utc.localize(dt)
            elif timezone.is_aware(dt) and dt.tzinfo != tzinfo:
                dt = dt.astimezone(tzinfo)
            result = dt.isoformat()
        except (ValueError, TypeError):
            dt = timezone.datetime.strptime(t, "%Y-%m-%d")
            if not timezone.is_aware(dt):
                dt = pytz.utc.localize(dt)
            elif timezone.is_aware(dt) and dt.tzinfo != tzinfo:
                dt = dt.astimezone(tzinfo).isoformat()
            result = dt.isoformat()

    if result and result.endswith("00:00"):
        return result[:-6] + "Z"
    return result


def request_authenticated_with_server_admin_token(request):
    try:
        return "rw:serverAdmin" in set(request.auth.scope.split())
    except AttributeError:
        return False


def sanitize_id(recipient_identifier, identifier_type, allow_uppercase=False):
    if identifier_type == "email":
        return recipient_identifier if allow_uppercase else recipient_identifier.lower()
    elif identifier_type == "url":
        p = urlparse(recipient_identifier)
        return urlunparse(
            (
                p.scheme,
                p.netloc.lower(),
                p.path,
                p.params,
                p.query,
                p.fragment,
            )
        )
    return recipient_identifier


def generate_private_key_pem():
    private_key = ed25519.Ed25519PrivateKey.generate()
    encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            settings.SECRET_KEY.encode()
        ),
    ).decode()
    return encrypted_key


def assertion_is_v3(assertion_json):
    context = assertion_json["@context"]
    # if @context is string it's probably v2
    if isinstance(context, str):
        return False
    # search for vc context IRIs
    return reduce(lambda x, y: x or "/credentials/" in y, context, False)

@sleep_and_retry
@limits(calls=1, period=1)
def geocode(addr_string: str):
    """
    Geocodes the given addr_string.
    Rate limitted to 1 request/s; will sleep if exceeded.
    """
    nom = Nominatim(user_agent="OpenEducationalBadges")
    geoloc = nom.geocode(addr_string)
    return geoloc


def quota_check(quota_name: str):
    def decorator(function):
        def wrapper(*args, **kwargs):
            issuer = args[0].get_object(args[1], **kwargs)
            quota = issuer.get_quota_usage(quota_name)
            if not quota:
                raise BadgrQuotaExceededException
            return function(*args, **kwargs)
        return wrapper
    return decorator
