from django.urls import re_path

from badgeuser.api_2fa import (
    TwoFactorSetupView,
    TwoFactorConfirmView,
    TwoFactorVerifyView,
    TwoFactorDisableView,
)
from badgeuser.api import (
    BadgeUserConfirmStaffRequest,
    BadgeUserSaveMicroDegree,
    BadgeUserStaffRequestDetail,
    BadgeUserStaffRequestList,
    BadgeUserToken,
    BadgeUserForgotPassword,
    BadgeUserEmailConfirm,
    BadgeUserDetail,
    BadgeUserResendEmailConfirmation,
    ConfirmNetworkInvitation,
    GetRedirectPath,
    LearningPathList,
    BadgeUserCollectBadgesInBackpack,
)
from badgeuser.api_v1 import BadgeUserEmailList, BadgeUserEmailDetail

urlpatterns = [
    re_path(r"^auth-token$", BadgeUserToken.as_view(), name="v1_api_user_auth_token"),
    re_path(r"^profile$", BadgeUserDetail.as_view(), name="v1_api_user_profile"),
    re_path(
        r"^forgot-password$",
        BadgeUserForgotPassword.as_view(),
        name="v1_api_auth_forgot_password",
    ),
    re_path(r"^emails$", BadgeUserEmailList.as_view(), name="v1_api_user_emails"),
    re_path(
        r"^emails/(?P<id>[^/]+)$",
        BadgeUserEmailDetail.as_view(),
        name="v1_api_user_email_detail",
    ),
    re_path(
        r"^legacyconfirmemail/(?P<confirm_id>[^/]+)$",
        BadgeUserEmailConfirm.as_view(),
        name="legacy_user_email_confirm",
    ),
    re_path(
        r"^confirmemail/(?P<confirm_id>[^/]+)$",
        BadgeUserEmailConfirm.as_view(),
        name="v1_api_user_email_confirm",
    ),
    re_path(
        r"^resendemail$",
        BadgeUserResendEmailConfirmation.as_view(),
        name="v1_api_resend_user_verification_email",
    ),
    re_path(
        r"^learningpaths$", LearningPathList.as_view(), name="v1_api_user_learningpaths"
    ),
    re_path(
        r"^save-microdegree/(?P<entity_id>[^/]+)$",
        BadgeUserSaveMicroDegree.as_view(),
        name="v1_api_user_save_microdegree",
    ),
    re_path(
        r"^collect-badges-in-backpack$",
        BadgeUserCollectBadgesInBackpack.as_view(),
        name="v1_api_user_collect_badges_in_backpack",
    ),
    re_path(
        r"^get-redirect-path$",
        GetRedirectPath.as_view(),
        name="v1_api_user_get_redirect_path",
    ),
    re_path(
        r"^issuerStaffRequests$",
        BadgeUserStaffRequestList.as_view(),
        name="v1_api_user_issuer_staff_requests_list",
    ),
    re_path(
        r"^issuerStaffRequest/issuer/(?P<issuer_id>[^/]+)$",
        BadgeUserStaffRequestList.as_view(),
        name="v1_api_user_issuer_staff_requests",
    ),
    re_path(
        r"^issuerStaffRequest/(?P<request_id>[^/]+)$",
        BadgeUserStaffRequestDetail.as_view(),
        name="v1_api_user_issuer_staff_request_detail",
    ),
    re_path(
        r"^confirm-staff-request/(?P<entity_id>[^/]+)$",
        BadgeUserConfirmStaffRequest.as_view(),
        name="v1_api_user_confirm_staffrequest",
    ),
    re_path(
        r"^confirm-network-invitation/(?P<inviteSlug>[^/]+)$",
        ConfirmNetworkInvitation.as_view(),
        name="v1_api_user_confirm_network_invite",
    ),
    re_path(r"^2fa/setup$", TwoFactorSetupView.as_view(), name="v1_api_user_2fa_setup"),
    re_path(
        r"^2fa/confirm$", TwoFactorConfirmView.as_view(), name="v1_api_user_2fa_confirm"
    ),
    re_path(
        r"^2fa/verify$", TwoFactorVerifyView.as_view(), name="v1_api_user_2fa_verify"
    ),
    re_path(
        r"^2fa/disable$", TwoFactorDisableView.as_view(), name="v1_api_user_2fa_disable"
    ),
]
