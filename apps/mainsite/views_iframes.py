import json

from django.conf import settings
from django.http import HttpResponseNotFound
from django.shortcuts import render
from django.views.decorators.clickjacking import xframe_options_exempt
from lti_tool.views import csrf_exempt

from issuer.models import BadgeClass, Issuer
from mainsite.models import IframeUrl


@xframe_options_exempt
@csrf_exempt
def iframe(request, *args, **kwargs):
    iframe_uuid = kwargs.get("iframe_uuid")
    try:
        iframe = IframeUrl.objects.get(id=iframe_uuid)
        # get from db and delete to create "single-use" urls
        # TODO: might be better to change to a time based solution
        iframe.delete()
    except IframeUrl.DoesNotExist:
        return HttpResponseNotFound()

    try:
        if iframe.name == "profile":
            return iframe_profile(
                request, iframe.params["skills"], iframe.params["language"]
            )
        if iframe.name == "badge-create-or-edit":
            try:
                badge = iframe.params["badge"]
            except KeyError:
                badge = None

            try:
                issuer = iframe.params["issuer"]
            except KeyError:
                issuer = None

            try:
                show_badge_selection = bool(iframe.params["badgeSelection"])
            except KeyError:
                show_badge_selection = False

            return iframe_badge_create_or_edit(
                request,
                iframe.params["token"],
                badge,
                issuer,
                iframe.params["language"],
                show_badge_selection,
            )
        if iframe.name == "competencies":
            return iframe_competencies(
                request, iframe.params["badges"], iframe.params["language"]
            )
        if iframe.name == "badges":
            return iframe_badges(
                request, iframe.params["badges"], iframe.params["language"]
            )
        if iframe.name == "learningpaths":
            return iframe_learningpaths(
                request, iframe.params["learningpaths"], iframe.params["language"]
            )
        if iframe.name == "backpack":
            return iframe_backpack(
                request,
                iframe.params["skills"],
                iframe.params["badges"],
                iframe.params["learningpaths"],
                iframe.params["language"],
            )
        if iframe.name == "dashboard":
            return iframe_dashboard(
                request,
                iframe.params["issuerSlug"],
                iframe.params["token"],
                iframe.params["language"],
            )
    except Exception as e:
        # show errors while debug
        if settings.DEBUG:
            raise e
        # else continue to 404
        pass

    return HttpResponseNotFound()


def iframe_profile(request, skills, language):
    skill_json = json.dumps(skills, ensure_ascii=False)
    return render(
        request,
        "iframes/profile/index.html",
        context={
            "asset_path": settings.WEBCOMPONENTS_ASSETS_PATH,
            "skill_json": skill_json,
            "language": language,
        },
    )


def iframe_competencies(request, badges, language):
    badges_json = json.dumps(badges, ensure_ascii=False)
    return render(
        request,
        "iframes/competencies/index.html",
        context={
            "asset_path": settings.WEBCOMPONENTS_ASSETS_PATH,
            "badges_json": badges_json,
            "language": language,
        },
    )


def iframe_badges(request, badges, language):
    badges_json = json.dumps(badges, ensure_ascii=False)
    return render(
        request,
        "iframes/badges/index.html",
        context={
            "asset_path": settings.WEBCOMPONENTS_ASSETS_PATH,
            "badges_json": badges_json,
            "language": language,
        },
    )


def iframe_learningpaths(request, learningpaths, language):
    learningpaths_json = json.dumps(learningpaths, ensure_ascii=False)
    return render(
        request,
        "iframes/learningpaths/index.html",
        context={
            "asset_path": settings.WEBCOMPONENTS_ASSETS_PATH,
            "learningpaths_json": learningpaths_json,
            "language": language,
        },
    )


def iframe_backpack(request, skills, badges, learningpaths, language):
    skill_json = json.dumps(skills, ensure_ascii=False)
    badges_json = json.dumps(badges, ensure_ascii=False)
    learningpaths_json = json.dumps(learningpaths, ensure_ascii=False)
    return render(
        request,
        "iframes/backpack/index.html",
        context={
            "asset_path": settings.WEBCOMPONENTS_ASSETS_PATH,
            "skill_json": skill_json,
            "badges_json": badges_json,
            "learningpaths_json": learningpaths_json,
            "language": language,
        },
    )


def iframe_dashboard(request, issuer_slug: str, token: str, language: str):
    return render(
        request,
        "iframes/dashboard/index.html",
        context={
            "asset_path": settings.WEBCOMPONENTS_ASSETS_PATH,
            "issuer_slug": issuer_slug,
            "token": token,
            "language": language,
        },
    )


def iframe_badge_create_or_edit(
    request,
    token: str,
    badge: BadgeClass | None,
    issuer: Issuer | None,
    language: str,
    badgeSelection: bool = False,
):
    badge_json = json.dumps(badge, ensure_ascii=False)
    issuer_json = json.dumps(issuer, ensure_ascii=False)
    return render(
        request,
        "iframes/badge-edit/index.html",
        context={
            "asset_path": settings.WEBCOMPONENTS_ASSETS_PATH,
            "language": language,
            "badge": badge_json,
            "token": token,
            "issuer": issuer_json,
            "showBadgeSelection": json.dumps(badgeSelection, ensure_ascii=False),
        },
    )
