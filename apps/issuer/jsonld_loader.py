from pyld.jsonld import set_document_loader, ContextResolver
from cachetools import LRUCache
import requests
import logging
import json
import os

logger = logging.getLogger(__name__)

_doc_cache = LRUCache(maxsize=100)
_resolved_context_cache = LRUCache(maxsize=1000)

CONTEXT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "mainsite",
    "static",
    "ims-contexts",
)


def _get_local_context(url):
    """Map remote URLs to local files"""
    mappings = {
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json": os.path.join(
            CONTEXT_DIR, "ob-context-3.0.3.json"
        ),
        "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json": os.path.join(
            CONTEXT_DIR, "ob-extensions.json"
        ),
    }
    path = mappings.get(url)
    if path and os.path.exists(path):
        return path
    return None


def cached_document_loader(url, options=None):
    if url in _doc_cache:
        return _doc_cache[url]

    local_path = _get_local_context(url)
    if local_path:
        with open(local_path, "r") as f:
            doc = {
                "contextUrl": None,
                "documentUrl": url,
                "document": json.load(f),
            }
            _doc_cache[url] = doc
            logger.info(f"Loaded JSON-LD context from local file: {url}")
            return doc

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        doc = {
            "contextUrl": None,
            "documentUrl": url,
            "document": response.json(),
        }
        _doc_cache[url] = doc
        return doc
    except Exception as e:
        logger.error(f"JSON-LD loader failed for {url}: {e}")
        raise


_context_resolver = ContextResolver(_resolved_context_cache, cached_document_loader)


def setup_jsonld_loader():
    set_document_loader(cached_document_loader)
    _precache_common_contexts()


def get_context_resolver():
    return _context_resolver


def _precache_common_contexts():
    urls = [
        "https://www.w3.org/ns/credentials/v2",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json",
    ]
    for url in urls:
        try:
            cached_document_loader(url)
        except Exception:
            logger.warning(f"Could not pre-cache: {url}")
