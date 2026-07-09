import hashlib
import json
from urllib.parse import urlparse

from django.conf import settings
from django.core.cache import cache

from apps.mainsite.views import call_aiskills_api

# ESCO taxonomy releases roughly every 6-12 months; cache for 6 months.
# To force-refresh after an ESCO update, clear keys matching skills_tree_*
_6_MONTHS = 60 * 60 * 24 * 180


# pulls esco competencies from badge assertions and enhances them with
# tree structure breadcrumbs using the AI Tool APIs
def get_skills_tree(badge_instances, language):
    skill_studyloads = {}
    for instance in badge_instances:
        if len(instance.badgeclass.cached_extensions()) > 0:
            for extension in instance.badgeclass.cached_extensions():
                if extension.name == "extensions:CompetencyExtension":
                    extension_json = json.loads(extension.original_json)
                    for competency in extension_json:
                        if competency["framework_identifier"]:
                            esco_uri = competency["framework_identifier"]
                            parsed_uri = urlparse(esco_uri)
                            uri_path = parsed_uri.path
                            studyload = competency["studyLoad"]
                            try:
                                skill_studyloads[uri_path] += studyload
                            except KeyError:
                                skill_studyloads[uri_path] = studyload

    if not skill_studyloads:
        return {"skills": []}

    # stable cache key: sorted URIs + language
    uri_hash = hashlib.md5(
        (language + "," + ",".join(sorted(skill_studyloads.keys()))).encode()
    ).hexdigest()
    cache_key = f"skills_tree_{uri_hash}"

    tree = cache.get(cache_key)
    if tree is None:
        endpoint = getattr(settings, "AISKILLS_ENDPOINT_TREE")
        payload = {"concept_uris": list(skill_studyloads.keys()), "lang": language}
        tree = json.loads(call_aiskills_api(endpoint, "POST", payload).content.decode())
        cache.set(cache_key, tree, timeout=_6_MONTHS)

    # studyload is per-issuer so applied after cache lookup
    for skill in tree["skills"]:
        skill["studyLoad"] = skill_studyloads.get(skill["concept_uri"], 0)

    return tree
