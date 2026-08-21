from hashlib import sha256

import requests
from requests.exceptions import RequestException

from django.conf import settings

# Bounds how long a badge-issuance request will wait on this external
# service. Held for the duration of a DB row lock (see requestBadge()),
# so this must never be allowed to hang indefinitely.
BLACKLIST_REQUEST_TIMEOUT_SECONDS = 10


def api_submit_recipient_id(id_type, recipient_id):
    blacklist_api_key = getattr(settings, "BADGR_BLACKLIST_API_KEY", None)
    blacklist_query_endpoint = getattr(settings, "BADGR_BLACKLIST_QUERY_ENDPOINT", None)
    if blacklist_api_key and blacklist_query_endpoint:
        recipient_id_hash = generate_hash(id_type, recipient_id)

        try:
            response = requests.post(
                blacklist_query_endpoint,
                json={"id": recipient_id_hash},
                headers={
                    "Authorization": "BEARER {api_key}".format(
                        api_key=blacklist_api_key
                    ),
                },
                timeout=BLACKLIST_REQUEST_TIMEOUT_SECONDS,
            )
        except RequestException:
            return None

        return response
    else:
        return None


def api_query_recipient_id(
    id_type, recipient_id, blacklist_query_endpoint, blacklist_api_key
):
    recipient_id_hash = generate_hash(id_type, recipient_id)
    request_query = "{endpoint}?id={recipient_id_hash}".format(
        endpoint=blacklist_query_endpoint, recipient_id_hash=recipient_id_hash
    )

    try:
        response = requests.get(
            request_query,
            headers={
                "Authorization": "BEARER {api_key}".format(api_key=blacklist_api_key),
            },
            timeout=BLACKLIST_REQUEST_TIMEOUT_SECONDS,
        )
    except RequestException:
        return None

    return response


def api_query_is_in_blacklist(id_type, recipient_id):
    blacklist_api_key = getattr(settings, "BADGR_BLACKLIST_API_KEY", None)
    blacklist_query_endpoint = getattr(settings, "BADGR_BLACKLIST_QUERY_ENDPOINT", None)
    if blacklist_query_endpoint and blacklist_api_key:
        response = api_query_recipient_id(
            id_type, recipient_id, blacklist_query_endpoint, blacklist_api_key
        )

        if response and response.status_code == 200:
            query = response.json()
            if len(query) > 0:
                return True
            else:
                return False

        if response is None:
            raise Exception("Blacklist failed to respond")

        return False
    return False


def generate_hash(id_type, id_value):
    return "{id_type}$sha256${hash}".format(
        id_type=id_type, hash=sha256(id_value.encode("utf-8")).hexdigest()
    )
