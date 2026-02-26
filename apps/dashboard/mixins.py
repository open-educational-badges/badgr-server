import logging
from issuer.models import BadgeInstance, Issuer
from .services.regional_service import RegionalService

logger = logging.getLogger(__name__)


class RegionalFilterMixin:
    """
    Reusable mixin for regional filtering based on issuer's zip code.

    Logic:
    1. Get zip_code from current user (request.user.zip_code)
    2. Extract PLZ3 (first 3 digits)
    3. Determine Landkreis from CSV via PLZ3
    4. Get all PLZ for this Landkreis
    5. Filter issuer IDs whose zip is in this PLZ list
    6. Filter badge instances by issuer region instead of user region
    """

    def get_regional_issuer_ids(self, request):
        """
        Get issuer IDs based on the Landkreis (district) of the current user.
        Returns None if no filter should be applied (user has no zip_code).

        Implements defensive error handling:
        - Checks for None user (unauthenticated requests)
        - Checks for missing zip_code attribute
        - Logs authentication and data issues

        Args:
            request: HTTP request with authenticated user

        Returns:
            list: List of issuer IDs in the same region, or None to return all
        """
        # Defensive check: ensure request has a user
        if not hasattr(request, 'user') or request.user is None:
            logger.warning(
                "get_regional_issuer_ids called with no authenticated user. "
                "Returning None to show all issuers."
            )
            return None

        user = request.user

        # Defensive check: ensure user is authenticated
        if not user.is_authenticated:
            logger.warning(
                "get_regional_issuer_ids called with unauthenticated user. "
                "Returning None to show all issuers."
            )
            return None

        # Check if user has zip_code attribute
        if not hasattr(user, 'zip_code') or not user.zip_code:
            logger.debug(
                f"User {user.id if hasattr(user, 'id') else 'unknown'} "
                "has no zip_code. Regional filtering disabled."
            )
            return None

        # Validate zip code format
        try:
            zip_code = str(user.zip_code).strip()
        except Exception as e:
            logger.warning(
                f"Error converting zip_code to string for user "
                f"{user.id if hasattr(user, 'id') else 'unknown'}: {e}"
            )
            return None

        if len(zip_code) < 3:
            logger.debug(
                f"User {user.id if hasattr(user, 'id') else 'unknown'} "
                f"has invalid zip_code '{zip_code}' (less than 3 digits). "
                "Regional filtering disabled."
            )
            return None

        # Extract first 3 digits
        plz3 = zip_code[:3]

        # Get regional service instance
        try:
            service = RegionalService.get_instance()
        except Exception as e:
            logger.error(f"Error getting RegionalService instance: {e}")
            return None

        if service is None:
            logger.error("RegionalService.get_instance() returned None")
            return None

        landkreis = service.get_landkreis_by_plz3(plz3)

        if not landkreis:
            logger.debug(
                f"No Landkreis found for PLZ3 '{plz3}'. "
                "Regional filtering disabled."
            )
            return None

        # Get all PLZ for this Landkreis
        regional_plz_list = service.get_all_plz_for_landkreis(landkreis)

        if not regional_plz_list:
            logger.debug(
                f"No PLZ list found for Landkreis '{landkreis}'. "
                "Regional filtering disabled."
            )
            return None

        # Filter issuers whose zip is in the regional PLZ list
        # Changed from filtering users to filtering issuers
        try:
            issuer_ids = Issuer.objects.filter(
                zip__in=regional_plz_list
            ).values_list('id', flat=True)

            return list(issuer_ids)
        except Exception as e:
            logger.error(
                f"Error filtering issuers by regional PLZ list: {e}. "
                "Returning None to show all issuers."
            )
            return None

    def get_regional_badge_instances(self, request):
        """
        Get BadgeInstances filtered by regional issuers.

        Changed from user-based to issuer-based filtering:
        - Now filters by issuer.zip instead of user.zip_code
        - Badges are filtered by the region of the issuing institution

        Implements defensive error handling:
        - Handles database query errors gracefully
        - Logs errors for debugging
        - Returns empty queryset on failure instead of raising exception

        Args:
            request: HTTP request with authenticated user

        Returns:
            QuerySet: Filtered BadgeInstance queryset
        """
        try:
            queryset = BadgeInstance.objects.filter(
                revoked=False
            ).select_related('badgeclass', 'badgeclass__issuer')

            # Changed: now using issuer-based filtering instead of user-based
            regional_issuer_ids = self.get_regional_issuer_ids(request)
            if regional_issuer_ids is not None:
                # Filter by issuer ID through the badgeclass relationship
                queryset = queryset.filter(badgeclass__issuer_id__in=regional_issuer_ids)

            return queryset

        except Exception as e:
            logger.error(
                f"Error getting regional badge instances: {e}. "
                "Returning empty queryset."
            )
            # Return empty queryset instead of raising exception
            return BadgeInstance.objects.none()
