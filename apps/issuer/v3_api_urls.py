from django.urls import include, path
from rest_framework import routers

from . import api_v3

router = routers.DefaultRouter()
router.register(r"badges", api_v3.Badges, basename="badges")
router.register(r"badgeinstances", api_v3.BadgeInstances, basename="badgeinstances")
router.register(r"issuers", api_v3.Issuers)
router.register(r"learningpaths", api_v3.LearningPaths)
router.register(r"networks", api_v3.Networks, basename="networks")

urlpatterns = [
    path("learnersprofile", api_v3.LearnersProfile.as_view()),
    path("learners-competencies", api_v3.LearnersCompetencies.as_view()),
    path("learners-badges", api_v3.LearnersBadges.as_view()),
    path("learners-learningpaths", api_v3.LearnersLearningPaths.as_view()),
    path("learners-backpack", api_v3.LearnersBackpack.as_view()),
    path("badge-create-embed", api_v3.BadgeCreateEmbed.as_view()),
    path("badge-edit-embed", api_v3.BadgeEditEmbed.as_view()),
    path("", include(router.urls)),
]
