import oauth2_provider
from django.conf import settings
from rest_framework import permissions
import rules

from issuer.models import Issuer, IssuerStaff, NetworkMembership

SAFE_METHODS = ["GET", "HEAD", "OPTIONS"]


@rules.predicate
def is_owner(user, issuer):
    if not hasattr(issuer, "cached_issuerstaff"):
        return False

    for staff_record in issuer.cached_issuerstaff():
        if (
            staff_record.user_id == user.id
            and staff_record.role == IssuerStaff.ROLE_OWNER
        ):
            return True

    if hasattr(issuer, "is_network") and issuer.is_network:
        for membership in issuer.memberships.all():
            partner_issuer = membership.issuer
            for staff_record in partner_issuer.cached_issuerstaff():
                if (
                    staff_record.user_id == user.id
                    and staff_record.role == IssuerStaff.ROLE_OWNER
                ):
                    return True

    return False


@rules.predicate
def is_editor(user, issuer):
    if not hasattr(issuer, "cached_issuerstaff"):
        return False

    for staff_record in issuer.cached_issuerstaff():
        if staff_record.user_id == user.id and staff_record.role in (
            IssuerStaff.ROLE_OWNER,
            IssuerStaff.ROLE_EDITOR,
        ):
            return True

    if hasattr(issuer, "is_network") and issuer.is_network:
        for membership in issuer.memberships.all():
            partner_issuer = membership.issuer
            for staff_record in partner_issuer.cached_issuerstaff():
                if staff_record.user_id == user.id and staff_record.role in (
                    IssuerStaff.ROLE_OWNER,
                    IssuerStaff.ROLE_EDITOR,
                ):
                    return True

    return False


@rules.predicate
def is_staff(user, issuer):
    if not hasattr(issuer, "cached_issuerstaff"):
        return False

    for staff_record in issuer.cached_issuerstaff():
        if staff_record.user_id == user.id:
            return True

    if hasattr(issuer, "is_network") and issuer.is_network:
        for membership in issuer.memberships.all():
            partner_issuer = membership.issuer
            for staff_record in partner_issuer.cached_issuerstaff():
                if staff_record.user_id == user.id:
                    return True

    return False


is_on_staff = is_owner | is_staff
is_staff_editor = is_owner | is_editor

# FIXME: should those be set here?
try:
    rules.add_perm("issuer.is_owner", is_owner)
    rules.add_perm("issuer.is_editor", is_staff_editor)
    rules.add_perm("issuer.is_staff", is_on_staff)
except KeyError:
    pass


@rules.predicate
def is_badgeclass_owner(user, badgeclass):
    return any(
        staff.role == IssuerStaff.ROLE_OWNER
        for staff in badgeclass.cached_issuer.cached_issuerstaff()
        if staff.user_id == user.id
    )


@rules.predicate
def is_badgeclass_editor(user, badgeclass):
    return any(
        staff.role in [IssuerStaff.ROLE_EDITOR, IssuerStaff.ROLE_OWNER]
        for staff in badgeclass.cached_issuer.cached_issuerstaff()
        if staff.user_id == user.id
    )


@rules.predicate
def is_badgeclass_staff(user, badgeclass):
    return any(
        staff.user_id == user.id
        for staff in badgeclass.cached_issuer.cached_issuerstaff()
    )


@rules.predicate
def is_partner_issuer_staff(user, badgeclass):
    """
    Check if user is staff of a partner issuer in a network where this badge has been shared.
    Returns True if:
    1. The badge has been shared with a network (via BadgeClassNetworkShare) or is a network badge
    2. The user is staff of an issuer that is a member of that network
    3. The share is active
    """
    issuer = badgeclass.issuer
    if issuer.is_network:
        for membership in issuer.memberships.all():
            partner_staff = (
                membership.issuer.cached_issuerstaff().filter(user=user).first()
            )
            if partner_staff:
                return True

    network_shares = badgeclass.network_shares.filter(is_active=True).select_related(
        "network"
    )

    for share in network_shares:
        network = share.network
        partner_memberships = network.memberships.select_related("issuer")

        for membership in partner_memberships:
            partner_issuer = membership.issuer
            if any(
                staff.user_id == user.id
                for staff in partner_issuer.cached_issuerstaff()
            ):
                return True

    return False


@rules.predicate
def is_learningpath_staff(user, learningpath):
    issuer = learningpath.cached_issuer
    if any(staff.user_id == user.id for staff in issuer.cached_issuerstaff()):
        return True
    if issuer.is_network:
        return is_network_member(user, issuer)
    return False


@rules.predicate
def is_learningpath_editor(user, learningpath):
    return any(
        staff.role in [IssuerStaff.ROLE_EDITOR, IssuerStaff.ROLE_OWNER]
        for staff in learningpath.cached_issuer.cached_issuerstaff()
        if staff.user_id == user.id
    )


@rules.predicate
def is_learningpath_owner(user, learningpath):
    return any(
        staff.role == IssuerStaff.ROLE_OWNER
        for staff in learningpath.cached_issuer.cached_issuerstaff()
        if staff.user_id == user.id
    )


@rules.predicate
def is_network_member(user, network):
    """
    Check if user is staff of any issuer that is a member of the given network
    """
    if not network or not network.is_network:
        return False

    user_staff_issuer_ids = IssuerStaff.objects.filter(user=user).values_list(
        "issuer_id", flat=True
    )

    return NetworkMembership.objects.filter(
        network=network, issuer_id__in=user_staff_issuer_ids
    ).exists()


can_issue_badgeclass = (
    is_badgeclass_owner | is_badgeclass_staff | is_partner_issuer_staff
)
can_edit_badgeclass = is_badgeclass_owner | is_badgeclass_editor

can_issue_learningpath = is_learningpath_staff
can_edit_learningpath = is_learningpath_owner | is_learningpath_editor

# FIXME: should those be set here?
try:
    rules.add_perm("issuer.can_issue_badge", can_issue_badgeclass)
    rules.add_perm("issuer.can_edit_badgeclass", can_edit_badgeclass)
    rules.add_perm("issuer.can_issue_learningpath", can_issue_learningpath)
    rules.add_perm("issuer.can_edit_learningpath", can_edit_learningpath)
    rules.add_perm("network.is_member", is_network_member)
except KeyError:
    pass


class MayIssueLearningPath(permissions.BasePermission):
    """
    ---
    model: LearningPath
    """

    def has_object_permission(self, request, view, learningpath):
        return _is_server_admin(request) or request.user.has_perm(
            "issuer.can_issue_learningpath", learningpath
        )


class MayIssueBadgeClass(permissions.BasePermission):
    """
    Allows those who have been given permission to issue badges on an Issuer to create
    IssuerAssertions from its IssuerBadgeClasses
    ---
    model: BadgeClass
    """

    def has_object_permission(self, request, view, badgeclass):
        return _is_server_admin(request) or request.user.has_perm(
            "issuer.can_issue_badge", badgeclass
        )


class MayEditBadgeClass(permissions.BasePermission):
    """
    Request.user is authorized to perform safe operations on a BadgeClass
    if they are on its issuer's staff. They may perform unsafe operations
    on a BadgeClass if they are among its issuers' editors.
    ---
    model: BadgeClass
    """

    def has_object_permission(self, request, view, badgeclass):
        if _is_server_admin(request):
            return True
        if request.method in SAFE_METHODS:
            return request.user.has_perm("issuer.can_issue_badge", badgeclass)
        else:
            return request.user.has_perm("issuer.can_edit_badgeclass", badgeclass)


class IsOwnerOrStaff(permissions.BasePermission):
    """
    Ensures request user is owner for unsafe operations, or at least
    staff for safe operations.
    """

    def has_object_permission(self, request, view, issuer):
        if _is_server_admin(request):
            return True
        if request.method in SAFE_METHODS:
            return request.user.has_perm("issuer.is_staff", issuer)
        else:
            return request.user.has_perm("issuer.is_owner", issuer)


class IsEditor(permissions.BasePermission):
    """
    Request.user is authorized to perform safe operations if they are staff or
    perform unsafe operations if they are owner or editor of an issuer.
    ---
    model: Issuer
    """

    def has_object_permission(self, request, view, issuer):
        if _is_server_admin(request):
            return True
        if request.method in SAFE_METHODS:
            return request.user.has_perm("issuer.is_staff", issuer)
        else:
            return request.user.has_perm("issuer.is_editor", issuer)


class IsEditorButOwnerForDelete(permissions.BasePermission):
    """
    Request.user is authorized to perform safe operations if they are staff or
    perform unsafe operations if they are owner or editor of an issuer.
    ---
    model: Issuer
    """

    def has_object_permission(self, request, view, issuer):
        if request.method in SAFE_METHODS:
            return request.user.has_perm("issuer.is_staff", issuer)
        elif request.method == "DELETE":
            return request.user.has_perm("issuer.is_owner", issuer)
        else:
            return request.user.has_perm("issuer.is_editor", issuer)


class IsStaff(permissions.BasePermission):
    """
    Request user is authorized to perform operations if they are owner or on staff
    of an Issuer.
    ---
    model: Issuer
    """

    def has_object_permission(self, request, view, issuer):
        return _is_server_admin(request) or request.user.has_perm(
            "issuer.is_staff", issuer
        )


class IsNetworkMember(permissions.BasePermission):
    """
    Request.user is authorized to access network resources if they are staff
    of an issuer that is a member of the network.
    ---
    model: Issuer (Network)
    """

    def has_object_permission(self, request, view, network):
        if not network.is_network:
            return False

        return request.user.has_perm("network.is_member", network)

    def has_permission(self, request, view):
        """
        For list views where we need to check network membership
        based on URL parameters or query parameters
        """

        network_id = view.kwargs.get("network_id") or request.GET.get("network_id")

        if not network_id:
            return False

        try:
            network = Issuer.objects.get(id=network_id, is_network=True)
            return request.user.has_perm("network.is_member", network)
        except Issuer.DoesNotExist:
            return False


class ApprovedIssuersOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if _is_server_admin(request):
            return True
        if request.method == "POST" and getattr(
            settings, "BADGR_APPROVED_ISSUERS_ONLY", False
        ):
            return request.user.has_perm("issuer.add_issuer")
        return True

    def has_permission(self, request, view):
        return _is_server_admin(request) or self.has_object_permission(
            request, view, None
        )


class AuditedModelOwner(permissions.BasePermission):
    """
    Request user matches .created_by
    ---
    model: BaseAuditedModel
    """

    def has_object_permission(self, request, view, obj):
        created_by_id = getattr(obj, "created_by_id", None)
        return created_by_id and request.user.id == created_by_id


class VerifiedEmailMatchesRecipientIdentifier(permissions.BasePermission):
    """
    One of request user's verified emails matches obj.recipient_identifier.
    For badges imported by this user, they can delete the badge.
    ---
    model: BadgeInstance
    """

    def has_object_permission(self, request, view, obj):
        if _is_server_admin(request):
            return True
        recipient_identifier = getattr(obj, "recipient_identifier", None)
        if getattr(obj, "pending", False):
            return (
                recipient_identifier
                and recipient_identifier in request.user.all_recipient_identifiers
            )
        return (
            recipient_identifier
            and recipient_identifier in request.user.all_verified_recipient_identifiers
        )


class AuthorizationIsBadgrOAuthToken(permissions.BasePermission):
    message = "Invalid token"

    def has_permission(self, request, view):
        return _is_server_admin(request) or isinstance(
            request.auth, oauth2_provider.models.AccessToken
        )


class BadgrOAuthTokenHasScope(permissions.BasePermission):
    def has_permission(self, request, view):
        valid_scopes = self.valid_scopes_for_view(view, method=request.method)
        token = request.auth

        if not token:
            if "*" in valid_scopes:
                return True

            # fallback scopes for authenticated users
            if request.user and request.user.is_authenticated:
                default_auth_scopes = set(["rw:profile", "rw:issuer", "rw:backpack"])
                if len(set(valid_scopes) & default_auth_scopes) > 0:
                    return True

            return False

        # Do not apply scope if using a non-oauth tokens
        if not isinstance(token, oauth2_provider.models.AccessToken):
            return True

        # default behavior of token.is_valid(valid_scopes) requires ALL of valid_scopes on the token
        # we want to check if ANY of valid_scopes are present in the token
        matching_scopes = set(valid_scopes) & set(token.scope.split())
        return not token.is_expired() and len(matching_scopes) > 0

    @classmethod
    def valid_scopes_for_view(cls, view, method=None):
        valid_scopes = getattr(view, "valid_scopes", [])
        if isinstance(valid_scopes, dict) and method is not None:
            for m in (method, method.lower(), method.upper()):
                if m in valid_scopes:
                    return valid_scopes[m]
            return []

        return valid_scopes


class BadgrOAuthTokenHasEntityScope(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        token = request.auth

        # This fails for authentication methods other than oauth2 token auth. Compose view permissions correctly.
        if not isinstance(token, oauth2_provider.models.AccessToken):
            return False

        # badgeclass/assertion objects defer to the issuer for permissions
        if hasattr(obj, "cached_issuer"):
            entity_id = obj.cached_issuer.entity_id
        else:
            entity_id = obj.entity_id

        valid_scopes = self._get_valid_scopes(request, view)
        valid_scopes = [s for s in valid_scopes if "*" in s]
        valid_scopes = set(
            [self._resolve_wildcard(scope, entity_id) for scope in valid_scopes]
        )
        token_scopes = set(token.scope.split())

        return (
            not token.is_expired() and len(valid_scopes.intersection(token_scopes)) > 0
        )

    def _resolve_wildcard(self, scope, entity_id):
        if scope.endswith(":*"):
            base_scope, _ = scope.rsplit(":*", 1)
            return ":".join([base_scope, entity_id])
        else:
            return scope

    def _get_valid_scopes(self, request, view):
        view_scopes = getattr(view, "valid_scopes")
        if isinstance(view_scopes, dict):
            return view_scopes.get(request.method.lower(), [])
        return view_scopes


def _is_server_admin(request):
    try:
        return "rw:serverAdmin" in request.auth.scopes
    except AttributeError:
        return False
