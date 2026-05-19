# encoding: utf-8


import uuid
from collections.abc import MutableMapping

import openbadges
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction, IntegrityError

import requests_cache
from requests_cache.backends import BaseCache

import logging
from issuer.models import (
    ImportedBadgeAssertion,
    ImportedBadgeAssertionExtension,
    Issuer,
    BadgeClass,
    BadgeInstance,
)
from issuer.utils import (
    OBI_VERSION_CONTEXT_IRIS,
    assertion_is_v3,
    generate_sha256_hashstring,
)
import json

import requests


logger = logging.getLogger("Badgr.Events")


class DjangoCacheDict(MutableMapping):
    """TODO: Fix this class, its broken!"""

    _keymap_cache_key = "DjangoCacheDict_keys"

    def __init__(self, namespace, id=None, timeout=None):
        self.namespace = namespace
        self._timeout = timeout

        if id is None:
            id = uuid.uuid4().hexdigest()
        self._id = id
        self.keymap_cache_key = self._keymap_cache_key + "_" + self._id

    def build_key(self, *args):
        return "{keymap_cache_key}{namespace}{key}".format(
            keymap_cache_key=self.keymap_cache_key,
            namespace=self.namespace,
            key="".join(args),
        ).encode("utf-8")

    def timeout(self):
        return self._timeout

    def _keymap(self):
        keymap = cache.get(self.keymap_cache_key)
        if keymap is None:
            return []
        return keymap

    def __getitem__(self, key):
        result = cache.get(self.build_key(key))
        if result is None:
            raise KeyError
        return result

    def __setitem__(self, key, value):
        built_key = self.build_key(key)
        cache.set(built_key, value, timeout=self.timeout())

        # this probably needs locking...
        keymap = self._keymap()
        keymap.append(built_key)
        cache.set(self.keymap_cache_key, keymap, timeout=None)

    def __delitem__(self, key):
        built_key = self.build_key(key)
        cache.delete(built_key)

        # this probably needs locking...
        keymap = self._keymap()
        keymap.remove(built_key)
        cache.set(self.keymap_cache_key, keymap, timeout=None)

    def __len__(self):
        keymap = self._keymap()
        return len(keymap)

    def __iter__(self):
        keymap = self._keymap()
        for key in keymap:
            yield cache.get(key)

    def __str__(self):
        return "<{}>".format(self.keymap_cache_key)

    def clear(self):
        self._id = uuid.uuid4().hexdigest()
        self.keymap_cache_key = self._keymap_cache_key + "_" + self._id


class OpenBadgesContextCache(BaseCache):
    OPEN_BADGES_CONTEXT_V2_URI = OBI_VERSION_CONTEXT_IRIS.get("2_0")
    OPEN_BADGE_CONTEXT_CACHE_KEY = "OPEN_BADGE_CONTEXT_CACHE_KEY"
    FORTY_EIGHT_HOURS_IN_SECONDS = 60 * 60 * 24 * 2

    def __init__(self, *args, **kwargs):
        super(OpenBadgesContextCache, self).__init__(*args, **kwargs)

        cached_context = self._get_cached_content()

        if cached_context:
            self._intialize_instance_attributes(cached_context)
        else:
            self._set_cached_content()
            self._intialize_instance_attributes(self._get_cached_content())

    def _get_cached_content(self):
        return cache.get(self.OPEN_BADGE_CONTEXT_CACHE_KEY, None)

    def _set_cached_content(self):
        self.session = requests_cache.CachedSession(backend="memory", expire_after=300)
        response = self.session.get(
            self.OPEN_BADGES_CONTEXT_V2_URI,
            headers={"Accept": "application/ld+json, application/json"},
        )
        if response.status_code == 200:
            cache.set(
                self.OPEN_BADGE_CONTEXT_CACHE_KEY,
                {"response": self.session.cache.responses},
                timeout=self.FORTY_EIGHT_HOURS_IN_SECONDS,
            )

    def _intialize_instance_attributes(self, cached):
        self.responses = cached.get("response", None)


class DjangoCacheRequestsCacheBackend(BaseCache):
    def __init__(self, namespace="requests-cache", **options):
        super(DjangoCacheRequestsCacheBackend, self).__init__(**options)
        self.responses = DjangoCacheDict(namespace, "responses")
        self.keys_map = DjangoCacheDict(namespace, "urls")


def first_node_match(graph, criteria):
    """Find the first node in a graph that matches all criteria."""
    for node in graph:
        match = True
        for k, v in criteria.items():
            if node.get(k) != v:
                match = False
                break
        if match:
            return node
    return None


class ImportedBadgeHelper:
    error_map = [
        (
            ["FETCH_HTTP_NODE"],
            {
                "name": "FETCH_HTTP_NODE",
                "description": "Unable to reach URL",
            },
        ),
        (
            ["VERIFY_RECIPIENT_IDENTIFIER"],
            {
                "name": "VERIFY_RECIPIENT_IDENTIFIER",
                "description": "The recipient does not match any of your verified emails",
            },
        ),
        (
            ["VERIFY_JWS", "VERIFY_KEY_OWNERSHIP"],
            {
                "name": "VERIFY_SIGNATURE",
                "description": "Could not verify signature",
            },
        ),
        (
            ["VERIFY_SIGNED_ASSERTION_NOT_REVOKED"],
            {
                "name": "ASSERTION_REVOKED",
                "description": "This assertion has been revoked",
            },
        ),
        (
            ["VERIFY_EMAIL_VERIFIED"],
            {
                "name": "EMAIL_NOT_VERIFIED",
                "description": "The email of this assertion is not yet verified.",
            },
        ),
    ]

    @classmethod
    def translate_errors(cls, badgecheck_messages):
        for m in badgecheck_messages:
            if m.get("messageLevel") == "ERROR":
                for errors, backpack_error in cls.error_map:
                    if m.get("name") in errors:
                        yield backpack_error
                yield m

    @classmethod
    def badgecheck_options(cls):
        from django.conf import settings

        return getattr(
            settings,
            "BADGECHECK_OPTIONS",
            {
                "include_original_json": True,
                "use_cache": True,
            },
        )

    @classmethod
    def get_or_create_imported_badge(
        cls, url=None, imagefile=None, assertion=None, user=None
    ):
        """
        Import a badge directly to the ImportedBadgeAssertion model
        without creating Issuer and BadgeClass objects.
        """
        # Validate that only one input method is provided
        query = (url, imagefile, assertion)
        query = [v for v in query if v is not None]
        if len(query) != 1:
            raise ValidationError("Must provide only 1 of: url, imagefile or assertion")
        query = query[0]

        # Prepare recipient profile for verification
        if user:
            emails = [d.email for d in user.email_items.all()]
            badgecheck_recipient_profile = {
                "email": emails + [v.email for v in user.cached_email_variants()],
                "telephone": user.cached_verified_phone_numbers(),
                "url": user.cached_verified_urls(),
            }
        else:
            badgecheck_recipient_profile = None

        try:
            if type(query) is dict:
                try:
                    query = json.dumps(query)
                except (TypeError, ValueError):
                    raise ValidationError("Could not parse dict to json")

            if hasattr(query, "seek"):
                query.seek(0)

            # use openbadges library to parse json from images
            verifier_store = openbadges.load_store(
                query,
                recipient_profile=badgecheck_recipient_profile,
                **cls.badgecheck_options(),
            )
            store_state = verifier_store.get_state()

            # Surface errors from store init (e.g. PNG with no embedded OB metadata)
            failed_tasks = [
                t for t in store_state.get("tasks", []) if t.get("success") is False
            ]
            if failed_tasks:
                raise ValidationError(
                    [
                        {
                            "name": "INVALID_BADGE",
                            "description": failed_tasks[0].get(
                                "result", "Unable to read badge metadata from file"
                            ),
                        }
                    ]
                )

            query_json = store_state["input"]["value"]

            if isinstance(query_json, bytes):
                query_json = query_json.decode("utf-8")

            # If unbaked data is a URL, fetch content manually to bypass
            if isinstance(query_json, str) and query_json.startswith("http"):
                try:
                    r = requests.get(
                        query_json,
                        headers={"Accept": "application/ld+json, application/json"},
                        timeout=10,
                    )
                    if r.status_code == 200:
                        query_json = r.text
                except Exception:
                    pass

            # Normalize once: downstream code always receives a dict
            if isinstance(query_json, dict):
                verifier_input = query_json
            elif isinstance(query_json, (str, bytes, bytearray)):
                try:
                    verifier_input = json.loads(query_json)
                except (ValueError, TypeError):
                    verifier_input = None
            else:
                verifier_input = None

            if verifier_input is None:
                raise ValueError(f"Invalid badge input type: {type(query_json)}")

            is_v3 = assertion_is_v3(verifier_input)

            if is_v3:
                # skip openbadges library validator
                response = cls.validate_v3(verifier_input, badgecheck_recipient_profile)

            else:
                # Check if the user is mistakenly uploading a BadgeClass definition
                badge_type = verifier_input.get("type")
                if badge_type == "BadgeClass" or (
                    isinstance(badge_type, list) and "BadgeClass" in badge_type
                ):
                    raise ValidationError(
                        [
                            {
                                "name": "INVALID_INPUT_TYPE",
                                "description": "This file contains a Badge Class definition. Please upload an awarded Badge Assertion instead.",
                            }
                        ]
                    )

                # ob2 validation through openbadges library
                # openbadges.verify() expects a URL, JSON string, or file — not a dict.
                # Pass the original URL when available (avoids double-fetch); otherwise
                # serialise the dict back to a JSON string.
                if isinstance(query, str) and query.startswith("http"):
                    verify_input = query
                else:
                    verify_input = json.dumps(verifier_input)

                response = openbadges.verify(
                    verify_input,
                    recipient_profile=badgecheck_recipient_profile,
                    **cls.badgecheck_options(),
                )

        except ValueError as e:
            raise ValidationError([{"name": "INVALID_BADGE", "description": str(e)}])

        report = response.get("report", {})
        is_valid = report.get("valid")

        if not is_valid:
            if report.get("errorCount", 0) > 0:
                errors = list(cls.translate_errors(report.get("messages", [])))
            else:
                errors = [
                    {
                        "name": "UNABLE_TO_VERIFY",
                        "description": "Unable to verify the assertion",
                    }
                ]
            raise ValidationError(errors)

        if not is_v3:
            graph = response.get("graph", [])

            assertion_data = first_node_match(graph, dict(type="Assertion"))
            if not assertion_data:
                raise ValidationError(
                    [
                        {
                            "name": "ASSERTION_NOT_FOUND",
                            "description": "Unable to find an assertion",
                        }
                    ]
                )

            badgeclass_data = first_node_match(
                graph, dict(id=assertion_data.get("badge", None))
            )
            if not badgeclass_data:
                raise ValidationError(
                    [
                        {
                            "name": "ASSERTION_NOT_FOUND",
                            "description": "Unable to find a badgeclass",
                        }
                    ]
                )

            issuer_data = first_node_match(
                graph, dict(id=badgeclass_data.get("issuer", None))
            )
            if not issuer_data:
                raise ValidationError(
                    [
                        {
                            "name": "ASSERTION_NOT_FOUND",
                            "description": "Unable to find an issuer",
                        }
                    ]
                )

            original_json = response.get("input").get("original_json", {})

        else:
            assertion_data = response["assertion_obo"]
            badgeclass_data = response["badgeclass_obo"]
            issuer_data = response["issuer_obo"]

            original_json = response.get("input")

        recipient_profile = report.get("recipientProfile", {})
        if not recipient_profile and user:
            recipient_type = "email"
            recipient_identifier = user.primary_email
        else:
            recipient_type, recipient_identifier = list(recipient_profile.items())[0]

        existing_badge = ImportedBadgeAssertion.objects.filter(
            user=user,
            recipient_identifier=recipient_identifier,
            issuer_url=issuer_data.get("url", ""),
            badge_name=badgeclass_data.get("name", ""),
            original_json__contains=assertion_data.get("id", ""),
        ).first()

        existing_instance = BadgeInstance.objects.filter(
            user=user,
            recipient_identifier=recipient_identifier,
            recipient_type=recipient_type,
            revoked=False,
            badgeclass__name=badgeclass_data.get("name", ""),
            issuer__url=issuer_data.get("url", ""),
        ).first()

        if existing_badge:
            return existing_badge, False

        if existing_instance:
            raise ValidationError(
                [
                    {
                        "name": "DUPLICATE_BADGE",
                        "description": "You already have this badge in your backpack.",
                    }
                ]
            )

        badge_image_url = badgeclass_data.get("image", "")

        with transaction.atomic():
            imported_badge = ImportedBadgeAssertion(
                user=user,
                badge_name=badgeclass_data.get("name", ""),
                badge_description=badgeclass_data.get("description", ""),
                image=badgeclass_data.get("image", ""),
                badge_image_url=badge_image_url,
                issuer_name=issuer_data.get("name", ""),
                issuer_url=issuer_data.get("url", ""),
                issuer_email=issuer_data.get("email", ""),
                issuer_image_url=issuer_data.get("image", ""),
                issued_on=assertion_data.get(
                    "issuedOn", assertion_data.get("validFrom", None)
                ),
                expires_at=assertion_data.get(
                    "expires", assertion_data.get("validUntil", None)
                ),
                recipient_identifier=recipient_identifier,
                recipient_type=recipient_type,
                original_json=original_json
                or {
                    "assertion": assertion_data,
                    "badgeclass": badgeclass_data,
                    "issuer": issuer_data,
                },
                narrative=assertion_data.get("narrative", ""),
                verification_url=assertion_data.get("verification", {}).get("url", ""),
            )

            imported_badge.save()

            for extension_key, extension_data in badgeclass_data.items():
                if extension_key.startswith("extensions:"):
                    extension = ImportedBadgeAssertionExtension(
                        importedBadge=imported_badge,
                        name=extension_key,
                        original_json=json.dumps(extension_data),
                    )
                    extension.save()

        return imported_badge, True

    @classmethod
    def validate_v3(cls, input, recipient_profile_in):
        session = requests.Session()

        recipient_profile_out = {}

        # validate hashed email
        try:
            credential_subject = input.get("credentialSubject")
            credential_identifiers = credential_subject.get("identifier")
            for credential_identifier in credential_identifiers:
                if credential_identifier.get("identityType") == "emailAddress":
                    identity_hash = credential_identifier.get("identityHash")
                    identity_salt = credential_identifier.get("salt")
                    for email in recipient_profile_in["email"]:
                        hashed_mail = generate_sha256_hashstring(email, identity_salt)
                        if hashed_mail == identity_hash:
                            recipient_profile_out["email"] = email

        except KeyError:
            pass

        if not recipient_profile_out:
            raise ValidationError(
                [
                    {
                        "name": "VERIFY_RECIPIENT_IDENTIFIER",
                        "description": "Recipients do not match",
                    }
                ]
            )

        assertion_obo = input
        issuer_id = input.get("issuer").get("id")
        issuer_obo = {}
        badgeclass_id = input.get("credentialSubject").get("achievement").get("id")
        badgeclass_obo = {}

        # load json if ids are urls
        try:
            result = session.get(
                issuer_id, headers={"Accept": "application/ld+json, application/json"}
            )
            result_text = result.content.decode()
            issuer_obo = json.loads(result_text)
        except Exception:
            pass

        try:
            result = session.get(
                badgeclass_id,
                headers={"Accept": "application/ld+json, application/json"},
            )
            result_text = result.content.decode()
            badgeclass_obo = json.loads(result_text)
        except Exception:
            pass

        return {
            "report": {
                "validationSubject": "",
                "errorCount": 0,
                "warningCount": 0,
                "messages": [],
                "recipientProfile": recipient_profile_out,
                "valid": True,
            },
            "graph": [],
            "input": input,
            "assertion_obo": assertion_obo,
            "issuer_obo": issuer_obo,
            "badgeclass_obo": badgeclass_obo,
        }


class BadgeCheckHelper(object):
    _cache_instance = None
    error_map = [
        (
            ["FETCH_HTTP_NODE"],
            {
                "name": "FETCH_HTTP_NODE",
                "description": "Unable to reach URL",
            },
        ),
        (
            ["VERIFY_RECIPIENT_IDENTIFIER"],
            {
                "name": "VERIFY_RECIPIENT_IDENTIFIER",
                "description": "The recipient does not match any of your verified emails",
            },
        ),
        (
            ["VERIFY_JWS", "VERIFY_KEY_OWNERSHIP"],
            {
                "name": "VERIFY_SIGNATURE",
                "description": "Could not verify signature",
            },
        ),
        (
            ["VERIFY_SIGNED_ASSERTION_NOT_REVOKED"],
            {
                "name": "ASSERTION_REVOKED",
                "description": "This assertion has been revoked",
            },
        ),
    ]

    @classmethod
    def translate_errors(cls, badgecheck_messages):
        for m in badgecheck_messages:
            if m.get("messageLevel") == "ERROR":
                for errors, backpack_error in cls.error_map:
                    if m.get("name") in errors:
                        yield backpack_error
                yield m

    @classmethod
    def cache_instance(cls):
        if cls._cache_instance is None:
            # TODO: note this class is broken and does not work correctly!
            cls._cache_instance = DjangoCacheRequestsCacheBackend(
                namespace="badgr_requests_cache"
            )
        return cls._cache_instance

    @classmethod
    def badgecheck_options(cls):
        return getattr(
            settings,
            "BADGECHECK_OPTIONS",
            {
                "include_original_json": True,
                "use_cache": True,
                # 'cache_backend': cls.cache_instance()  #  just use locmem cache for now
            },
        )

    @classmethod
    def get_or_create_assertion(
        cls, url=None, imagefile=None, assertion=None, created_by=None
    ):
        # distill 3 optional arguments into one query argument
        query = (url, imagefile, assertion)
        query = [v for v in query if v is not None]
        if len(query) != 1:
            raise ValueError("Must provide only 1 of: url, imagefile or assertion_obo")
        query = query[0]

        if created_by:
            emails = [d.email for d in created_by.email_items.all()]
            badgecheck_recipient_profile = {
                "email": emails + [v.email for v in created_by.cached_email_variants()],
                "telephone": created_by.cached_verified_phone_numbers(),
                "url": created_by.cached_verified_urls(),
            }
        else:
            badgecheck_recipient_profile = None

        try:
            if type(query) is dict:
                try:
                    query = json.dumps(query)
                except (TypeError, ValueError):
                    raise ValidationError("Could not parse dict to json")
            response = openbadges.verify(
                query,
                recipient_profile=badgecheck_recipient_profile,
                **cls.badgecheck_options(),
            )
        except ValueError as e:
            raise ValidationError([{"name": "INVALID_BADGE", "description": str(e)}])

        report = response.get("report", {})
        is_valid = report.get("valid")

        if not is_valid:
            if report.get("errorCount", 0) > 0:
                errors = list(cls.translate_errors(report.get("messages", [])))
            else:
                errors = [
                    {
                        "name": "UNABLE_TO_VERIFY",
                        "description": "Unable to verify the assertion",
                    }
                ]
            raise ValidationError(errors)

        graph = response.get("graph", [])

        assertion_obo = first_node_match(graph, dict(type="Assertion"))
        if not assertion_obo:
            raise ValidationError(
                [
                    {
                        "name": "ASSERTION_NOT_FOUND",
                        "description": "Unable to find an assertion",
                    }
                ]
            )

        badgeclass_obo = first_node_match(
            graph, dict(id=assertion_obo.get("badge", None))
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

        recipient_profile = report.get("recipientProfile", {})
        recipient_type, recipient_identifier = list(recipient_profile.items())[0]

        issuer_image = Issuer.objects.image_from_ob2(issuer_obo)
        badgeclass_image = BadgeClass.objects.image_from_ob2(badgeclass_obo)
        badgeinstance_image = BadgeInstance.objects.image_from_ob2(
            badgeclass_image, assertion_obo
        )

        def commit_new_badge():
            with transaction.atomic():
                issuer, issuer_created = Issuer.objects.get_or_create_from_ob2(
                    issuer_obo,
                    original_json=original_json.get(issuer_obo.get("id")),
                    image=issuer_image,
                )
                # set issuer as verified temporarily so the badge can be created
                issuer.verified = True
                badgeclass, badgeclass_created = (
                    BadgeClass.objects.get_or_create_from_ob2(
                        issuer,
                        badgeclass_obo,
                        original_json=original_json.get(badgeclass_obo.get("id")),
                        image=badgeclass_image,
                    )
                )
                return BadgeInstance.objects.get_or_create_from_ob2(
                    badgeclass,
                    assertion_obo,
                    recipient_identifier=recipient_identifier,
                    recipient_type=recipient_type,
                    original_json=original_json.get(assertion_obo.get("id")),
                    image=badgeinstance_image,
                )

        try:
            return commit_new_badge()
        except IntegrityError:
            logger.error(
                "Race condition caught when saving new assertion: {}".format(query)
            )
            return commit_new_badge()

    @classmethod
    def get_assertion_obo(cls, badge_instance):
        try:
            response = openbadges.verify(
                badge_instance.source_url,
                recipient_profile=None,
                **cls.badgecheck_options(),
            )
        except ValueError:
            return None

        report = response.get("report", {})
        is_valid = report.get("valid")

        if is_valid:
            graph = response.get("graph", [])

            assertion_obo = first_node_match(graph, dict(type="Assertion"))
            if assertion_obo:
                return assertion_obo
