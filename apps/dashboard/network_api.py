# encoding: utf-8
"""
Network Dashboard API endpoints

These endpoints provide dashboard KPIs, competency areas, and top badges
filtered by a specific network (networkSlug).

URL Pattern: /v1/issuer/networks/{networkSlug}/dashboard/*
"""
from django.http import Http404
from django.db.models import Count, Q
from django.utils import timezone
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiResponse

from issuer.models import (
    BadgeInstance,
    BadgeClass,
    BadgeClassExtension,
    BadgeClassNetworkShare,
    Issuer,
    NetworkMembership,
    LearningPath,
)
from badgeuser.models import BadgeUser
from .network_serializers import (
    NetworkKPIsResponseSerializer,
    NetworkCompetencyAreasResponseSerializer,
    NetworkTopBadgesResponseSerializer,
    NetworkRecentActivityResponseSerializer,
    NetworkStrengthenedCompetenciesResponseSerializer,
    NetworkBadgeAwardsTimelineResponseSerializer,
    NetworkBadgeTypeDistributionResponseSerializer,
    NetworkDeliveryMethodDistributionResponseSerializer,
    NetworkBadgeLocationsResponseSerializer,
    NetworkLearnersOverviewResponseSerializer,
    NetworkLearnersResidenceResponseSerializer,
    NetworkLearnersResidenceDetailResponseSerializer,
    NetworkLearnersGenderResponseSerializer,
    NetworkLearnersGenderDetailResponseSerializer,
    NetworkSkillsTreeResponseSerializer,
)
from backpack.utils import get_skills_tree
from .services.regional_service import RegionalService
from mainsite.permissions import AuthenticatedWithVerifiedIdentifier
from issuer.permissions import BadgrOAuthTokenHasScope

import json
import logging

logger = logging.getLogger("Badgr.Events")


class NetworkDashboardBaseView(APIView):
    """Base view for network dashboard endpoints with common functionality"""

    permission_classes = [AuthenticatedWithVerifiedIdentifier & BadgrOAuthTokenHasScope]
    valid_scopes = ["rw:issuer"]

    def get_network(self, network_slug):
        """
        Get the network (Issuer with is_network=True) by slug/entity_id.

        Args:
            network_slug: The entity_id of the network

        Returns:
            Issuer instance

        Raises:
            Http404 if network not found
        """
        try:
            return Issuer.objects.get(entity_id=network_slug, is_network=True)
        except Issuer.DoesNotExist:
            raise Http404(f"Network with slug '{network_slug}' not found")

    def get_network_issuer_ids(self, network):
        """
        Get all issuer IDs that are members of this network.

        Args:
            network: The network Issuer instance

        Returns:
            QuerySet of issuer IDs
        """
        return NetworkMembership.objects.filter(
            network=network
        ).values_list('issuer_id', flat=True)

    def get_network_relevant_badge_class_ids(self, network):
        """
        Get IDs of badge classes that are relevant for network dashboard analytics.

        Returns IDs for:
        - Netzwerk-Badges: Badges created by the network itself (issuer=network)
        - Partner-Badges: Badges shared with the network via BadgeClassNetworkShare

        This is a utility method that can be used for filtering badge instances
        in various dashboard views.

        Args:
            network: The network Issuer instance

        Returns:
            set of BadgeClass IDs
        """
        # Get IDs of badges created by the network itself (Netzwerk-Badges)
        network_badge_ids = set(
            BadgeClass.objects.filter(issuer=network).values_list('id', flat=True)
        )

        # Get IDs of badges shared with this network (Partner-Badges)
        partner_badge_ids = set(
            BadgeClassNetworkShare.objects.filter(
                network=network,
                is_active=True
            ).values_list('badgeclass_id', flat=True)
        )

        # Return combined set of all network-relevant badge class IDs
        return network_badge_ids | partner_badge_ids

    def get_network_badge_instances(self, network):
        """
        Get all non-revoked BadgeInstances for network-relevant badges.

        Only includes badge instances where the BadgeClass is either:
        - Netzwerk-Badges: Created by the network itself (badgeclass.issuer=network)
        - Partner-Badges: Shared with the network via BadgeClassNetworkShare

        NOTE: This excludes badge instances from partner institutions for badges
        that have NOT been explicitly shared with the network.

        Args:
            network: The network Issuer instance

        Returns:
            QuerySet of BadgeInstance
        """
        # Get IDs of badges shared with this network (Partner-Badges)
        partner_badge_ids = BadgeClassNetworkShare.objects.filter(
            network=network,
            is_active=True
        ).values_list('badgeclass_id', flat=True)

        # Return badge instances where the badge class is either:
        # 1. Created by the network itself (Netzwerk-Badges)
        # 2. Shared with the network via BadgeClassNetworkShare (Partner-Badges)
        return BadgeInstance.objects.filter(
            revoked=False
        ).filter(
            Q(badgeclass__issuer=network) | Q(badgeclass_id__in=partner_badge_ids)
        ).select_related('badgeclass', 'badgeclass__issuer', 'user')

    def get_network_badge_classes(self, network):
        """
        Get BadgeClasses that are relevant for network dashboard analytics.

        Only includes:
        - Netzwerk-Badges: Badges created by the network itself (issuer=network)
        - Partner-Badges: Badges shared with the network via BadgeClassNetworkShare

        NOTE: This excludes badges created by partner institutions that have NOT
        been explicitly shared with the network.

        Args:
            network: The network Issuer instance

        Returns:
            QuerySet of BadgeClass
        """
        # Get IDs of badges shared with this network (Partner-Badges)
        partner_badge_ids = BadgeClassNetworkShare.objects.filter(
            network=network,
            is_active=True
        ).values_list('badgeclass_id', flat=True)

        # Return badges that are either:
        # 1. Created by the network itself (Netzwerk-Badges)
        # 2. Shared with the network via BadgeClassNetworkShare (Partner-Badges)
        return BadgeClass.objects.filter(
            Q(issuer=network) | Q(id__in=partner_badge_ids)
        ).select_related('issuer')

    def calculate_trend(self, current_count, previous_count):
        """Calculate trend direction and absolute value difference"""
        if previous_count == 0:
            if current_count > 0:
                return 'up', current_count
            return 'stable', 0

        change = current_count - previous_count
        if change > 0:
            return 'up', change
        elif change < 0:
            return 'down', abs(change)
        else:
            return 'stable', 0

    def calculate_trend_percent(self, current_count, previous_count):
        """Calculate trend direction and percentage change"""
        if previous_count == 0:
            if current_count > 0:
                return 'up', 100  # 100% increase from zero
            return 'stable', 0

        percent_change = round(((current_count - previous_count) / previous_count) * 100)
        if percent_change > 0:
            return 'up', percent_change
        elif percent_change < 0:
            return 'down', abs(percent_change)
        else:
            return 'stable', 0


class NetworkDashboardKPIsView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/kpis

    Returns aggregated key performance indicators for a specific network.
    """

    @extend_schema(
        summary="Get Network Dashboard KPIs",
        description="""
Returns aggregated key performance indicators for a specific network.

**KPIs Returned:**
- institutions_count: Number of institutions in the network
- badges_created: Number of different badges created
- badges_awarded: Total badges awarded
- participation_badges: Number of TEILNAHME-Badges
- competency_badges: Number of KOMPETENZ-Badges
- competency_hours: Total hours of competencies strengthened
- competency_hours_last_month: New competency hours in the last 30 days
- learners_count: Number of learners with badges
- badges_per_month: Average badges per month
- learners_with_paths: Learners with network learning paths

**Filtering:**
- `deliveryMethod` - Filter by badge delivery method (online, in-person)
        """,
        tags=["Network Dashboard", "KPIs"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="deliveryMethod",
                location=OpenApiParameter.QUERY,
                description="Filter by badge delivery method",
                required=False,
                type=str,
                enum=["online", "in-person"],
            ),
        ],
        responses={
            200: NetworkKPIsResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get network dashboard KPIs"""
        try:
            # Get deliveryMethod filter parameter
            delivery_method = request.query_params.get('deliveryMethod')

            # Validate deliveryMethod if provided
            if delivery_method and delivery_method not in ['online', 'in-person']:
                return Response(
                    {"error": f"Invalid deliveryMethod: '{delivery_method}'. Must be 'online' or 'in-person'."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get network
            network = self.get_network(networkSlug)

            # Get all issuers in this network
            issuer_ids = list(self.get_network_issuer_ids(network))
            institutions_count = len(issuer_ids)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply deliveryMethod filter if specified
            if delivery_method:
                if delivery_method == 'online':
                    badge_instances = badge_instances.filter(activity_online=True)
                elif delivery_method == 'in-person':
                    badge_instances = badge_instances.filter(activity_online=False)

            # Get badge classes for this network
            badge_classes = self.get_network_badge_classes(network)

            # Calculate date ranges for trends
            now = timezone.now()
            last_month_start = now - timedelta(days=30)
            two_months_ago = now - timedelta(days=60)

            # ===== KPI Calculations =====

            # 1. institutions_count - Number of issuers in network
            # (already calculated above)

            # 2. badges_created - Different badge classes created
            badges_created = badge_classes.count()
            badges_created_current = badge_classes.filter(
                created_at__gte=last_month_start
            ).count()
            badges_created_previous = badge_classes.filter(
                created_at__gte=two_months_ago,
                created_at__lt=last_month_start
            ).count()
            badges_created_trend, badges_created_trend_value = self.calculate_trend(
                badges_created_current, badges_created_previous
            )

            # 3. badges_awarded - Total badge instances (all awarded badges)
            # Includes badges awarded to non-registered users via email (user=null but recipient_identifier set)
            badges_awarded = badge_instances.count()
            badges_awarded_current = badge_instances.filter(
                created_at__gte=last_month_start
            ).count()
            badges_awarded_previous = badge_instances.filter(
                created_at__gte=two_months_ago,
                created_at__lt=last_month_start
            ).count()
            badges_awarded_trend, badges_awarded_trend_value = self.calculate_trend(
                badges_awarded_current, badges_awarded_previous
            )

            # 4 & 5. participation_badges and competency_badges
            # Count based on CategoryExtension
            participation_count, competency_count = self._count_badge_categories(
                badge_classes
            )

            # 6. competency_hours - Sum of studyLoad from CompetencyExtension
            competency_hours = self._calculate_competency_hours(badge_instances)
            competency_hours_current = self._calculate_competency_hours(
                badge_instances.filter(created_at__gte=last_month_start)
            )
            competency_hours_previous = self._calculate_competency_hours(
                badge_instances.filter(
                    created_at__gte=two_months_ago,
                    created_at__lt=last_month_start
                )
            )
            # Percentage trend for competency_hours (total)
            hours_trend_percent, hours_trend_percent_value = self.calculate_trend_percent(
                competency_hours_current, competency_hours_previous
            )
            # Absolute trend in hours for competency_hours_last_month
            hours_trend_abs, hours_trend_abs_value = self.calculate_trend(
                competency_hours_current, competency_hours_previous
            )

            # 7. learners_count - Unique recipients (by email/recipient_identifier)
            # Includes both registered users and non-registered email recipients
            learners_count = badge_instances.values('recipient_identifier').distinct().count()
            learners_current = badge_instances.filter(
                created_at__gte=last_month_start
            ).values('recipient_identifier').distinct().count()
            learners_previous = badge_instances.filter(
                created_at__gte=two_months_ago,
                created_at__lt=last_month_start
            ).values('recipient_identifier').distinct().count()
            learners_trend, learners_trend_value = self.calculate_trend(
                learners_current, learners_previous
            )

            # 8. badges_per_month - Average badges per month
            badges_per_month = self._calculate_badges_per_month(badge_instances)

            # 9. learners_with_paths - Users with learning paths in network
            learners_with_paths = self._count_learners_with_paths(issuer_ids)

            # Build KPIs response
            kpis = [
                {
                    'id': 'institutions_count',
                    'value': institutions_count,
                    'trend': 'stable',
                    'trendValue': 0,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
                {
                    'id': 'badges_created',
                    'value': badges_created,
                    'trend': badges_created_trend,
                    'trendValue': badges_created_trend_value,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
                {
                    'id': 'badges_awarded',
                    'value': badges_awarded,
                    'trend': badges_awarded_trend,
                    'trendValue': badges_awarded_trend_value,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': True,
                },
                {
                    'id': 'participation_badges',
                    'value': participation_count,
                    'trend': 'stable',
                    'trendValue': 0,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
                {
                    'id': 'competency_badges',
                    'value': competency_count,
                    'trend': 'stable',
                    'trendValue': 0,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
                {
                    'id': 'competency_hours',
                    'value': competency_hours,
                    'trend': hours_trend_percent,
                    'trendValue': hours_trend_percent_value,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
                {
                    'id': 'competency_hours_last_month',
                    'value': competency_hours_current,
                    'trend': hours_trend_abs,
                    'trendValue': hours_trend_abs_value,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
                {
                    'id': 'learners_count',
                    'value': learners_count,
                    'trend': learners_trend,
                    'trendValue': learners_trend_value,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
                {
                    'id': 'badges_per_month',
                    'value': badges_per_month,
                    'trend': 'stable',
                    'trendValue': 0,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
                {
                    'id': 'learners_with_paths',
                    'value': learners_with_paths,
                    'trend': 'stable',
                    'trendValue': 0,
                    'trendPeriod': 'lastMonth',
                    'hasMonthlyDetails': False,
                },
            ]

            response_data = {
                'metadata': {
                    'filters': {
                        'deliveryMethod': delivery_method,
                    },
                    'lastUpdated': timezone.now().isoformat(),
                },
                'kpis': kpis
            }
            serializer = NetworkKPIsResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardKPIsView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _count_badge_categories(self, badge_classes):
        """
        Count participation and competency badges based on CategoryExtension.

        Returns:
            tuple: (participation_count, competency_count)
        """
        badge_class_ids = badge_classes.values_list('id', flat=True)

        category_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CategoryExtension'
        )

        participation_count = 0
        competency_count = 0

        for ext in category_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                category = ext_data.get('Category', '').lower()
                if category == 'participation':
                    participation_count += 1
                elif category == 'competency':
                    competency_count += 1
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        return participation_count, competency_count

    def _calculate_competency_hours(self, badge_instances):
        """
        Calculate total competency hours from studyLoad in CompetencyExtension.

        StudyLoad is stored in minutes, converted to hours.

        Args:
            badge_instances: QuerySet of BadgeInstance

        Returns:
            int: Total hours
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        # Build mapping of badgeclass_id -> total study_load
        badgeclass_study_load = {}
        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                total_load = 0
                for comp in ext_data:
                    if isinstance(comp, dict):
                        total_load += comp.get('studyLoad', 0) or 0

                badgeclass_study_load[ext.badgeclass_id] = total_load
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Sum hours for all badge instances
        total_minutes = 0
        for badge in badge_instances:
            total_minutes += badgeclass_study_load.get(badge.badgeclass_id, 0)

        # Convert minutes to hours
        return round(total_minutes / 60) if total_minutes > 0 else 0

    def _calculate_badges_per_month(self, badge_instances):
        """
        Calculate average badges awarded per month.

        Uses the date range from first to last badge.
        """
        if not badge_instances.exists():
            return 0

        first_badge = badge_instances.order_by('created_at').first()
        last_badge = badge_instances.order_by('-created_at').first()

        if not first_badge or not last_badge:
            return 0

        # Calculate months between first and last
        delta = relativedelta(last_badge.created_at, first_badge.created_at)
        months = delta.years * 12 + delta.months
        if months == 0:
            months = 1  # At least 1 month

        total_badges = badge_instances.count()
        return round(total_badges / months)

    def _count_learners_with_paths(self, issuer_ids):
        """
        Count unique users who have participated in learning paths from network issuers.

        Participation is determined by users who have earned badges that are part of
        learning paths in this network.
        """
        try:
            from issuer.models import LearningPathBadge

            # Get learning paths from network issuers
            learning_paths = LearningPath.objects.filter(issuer_id__in=issuer_ids)

            if not learning_paths.exists():
                return 0

            # Get all badge classes that are part of these learning paths
            lp_badge_class_ids = LearningPathBadge.objects.filter(
                learning_path__in=learning_paths
            ).values_list('badge_id', flat=True)

            # Count unique users who have earned these badges
            unique_users = BadgeInstance.objects.filter(
                badgeclass_id__in=lp_badge_class_ids,
                revoked=False
            ).exclude(
                user__isnull=True
            ).values('user').distinct().count()

            return unique_users
        except Exception as e:
            logger.warning(f"Error counting learners with paths: {e}")
            return 0


class NetworkDashboardCompetencyAreasView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/competency-areas

    Returns the top competency areas for a specific network.
    """

    @extend_schema(
        summary="Get Network Top Competency Areas",
        description="""
Returns the top competency areas for a specific network.
Data is optimized for bubble chart visualization.

**Delivery Method Filter:**
Use `deliveryMethod` parameter to filter competency areas by badge delivery method:
- `online` - Only include badges delivered online (activity_online=True)
- `in-person` - Only include badges delivered in-person (activity_online=False)
- If not specified, includes all badges regardless of delivery method
        """,
        tags=["Network Dashboard", "Competencies"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="limit",
                location=OpenApiParameter.QUERY,
                description="Maximum number of competency areas to return (1-50)",
                required=False,
                type=int,
                default=6
            ),
            OpenApiParameter(
                name="deliveryMethod",
                location=OpenApiParameter.QUERY,
                description="Filter by delivery method: 'online' or 'in-person'",
                required=False,
                type=str,
                enum=['online', 'in-person']
            ),
        ],
        responses={
            200: NetworkCompetencyAreasResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get network top competency areas"""
        try:
            # Get limit from query params
            limit = int(request.query_params.get('limit', 6))
            limit = min(max(limit, 1), 50)

            # Get deliveryMethod filter
            delivery_method = request.query_params.get('deliveryMethod')

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply delivery method filter
            if delivery_method == 'online':
                badge_instances = badge_instances.filter(activity_online=True)
            elif delivery_method == 'in-person':
                badge_instances = badge_instances.filter(activity_online=False)

            if not badge_instances.exists():
                return Response({
                    'metadata': {
                        'totalAreas': 0,
                        'lastUpdated': timezone.now().date().isoformat(),
                    },
                    'data': [],
                })

            # Categorize badges by competency area
            area_stats = self._categorize_by_competency(badge_instances)

            # Sort by weight (instance count) and limit
            sorted_areas = sorted(
                area_stats.items(),
                key=lambda x: x[1]['weight'],
                reverse=True
            )[:limit]

            # Calculate total weight for percentage
            total_weight = sum(stats['weight'] for _, stats in sorted_areas)

            # Build response data
            data_list = []
            for area_id, stats in sorted_areas:
                percentage = (stats['weight'] / total_weight * 100) if total_weight > 0 else 0

                data_list.append({
                    'id': area_id,
                    'name': stats['name'],
                    'value': round(percentage, 1),
                    'weight': stats['weight'],
                })

            response_data = {
                'metadata': {
                    'totalAreas': len(data_list),
                    'lastUpdated': timezone.now().date().isoformat(),
                },
                'data': data_list,
            }

            serializer = NetworkCompetencyAreasResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardCompetencyAreasView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _categorize_by_competency(self, badge_instances):
        """
        Categorize badge instances by competency area based on CompetencyExtension.

        Returns:
            dict: {area_id: {'weight': count, 'name': display_name}}
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        # Get all competency extensions for these badge classes
        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        # Build mapping of badgeclass_id -> competencies
        badgeclass_competencies = {}
        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                competencies = []
                for comp in ext_data:
                    if isinstance(comp, dict) and 'name' in comp:
                        competencies.append(comp.get('name', ''))

                badgeclass_competencies[ext.badgeclass_id] = competencies
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Count instances per competency area
        area_stats = {}
        for badge in badge_instances:
            competencies = badgeclass_competencies.get(badge.badgeclass_id, [])

            for comp_name in competencies:
                # Normalize area_id
                area_id = comp_name.lower().replace(' ', '_').replace('-', '_')

                if area_id not in area_stats:
                    area_stats[area_id] = {
                        'weight': 0,
                        'name': comp_name,
                    }

                area_stats[area_id]['weight'] += 1

        return area_stats


class NetworkDashboardTopBadgesView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/top-badges

    Returns the top most awarded badges within a specific network.
    """

    @extend_schema(
        summary="Get Network Top Badges",
        description="""
Returns the top most awarded badges within a specific network.
Badges are ranked by total number of awards.
        """,
        tags=["Network Dashboard", "Badges"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="limit",
                location=OpenApiParameter.QUERY,
                description="Number of top badges to return (1-10)",
                required=False,
                type=int,
                default=3
            ),
        ],
        responses={
            200: NetworkTopBadgesResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get network top badges"""
        try:
            # Get limit from query params
            limit = int(request.query_params.get('limit', 3))
            limit = min(max(limit, 1), 10)

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)
            total_badges = badge_instances.count()

            if total_badges == 0:
                return Response({
                    'metadata': {
                        'totalBadges': 0,
                        'lastUpdated': timezone.now().date().isoformat(),
                    },
                    'badges': [],
                })

            # Get top badges by award count
            top_badge_counts = badge_instances.values(
                'badgeclass__entity_id',
                'badgeclass__name',
            ).annotate(
                count=Count('id')
            ).order_by('-count')[:limit]

            # Build response
            badges_data = []
            for rank, item in enumerate(top_badge_counts, start=1):
                badge_class = BadgeClass.objects.filter(
                    entity_id=item['badgeclass__entity_id']
                ).first()

                image_url = ''
                if badge_class and badge_class.image:
                    image_url = badge_class.image_url(public=True)

                badges_data.append({
                    'rank': rank,
                    'badgeId': item['badgeclass__entity_id'],
                    'badgeTitle': item['badgeclass__name'],
                    'image': image_url,
                    'count': item['count'],
                })

            response_data = {
                'metadata': {
                    'totalBadges': total_badges,
                    'lastUpdated': timezone.now().date().isoformat(),
                },
                'badges': badges_data,
            }

            serializer = NetworkTopBadgesResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardTopBadgesView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardRecentActivityView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/recent-activity

    Returns the most recent badge award activities within a specific network.
    """

    @extend_schema(
        summary="Get Network Recent Activity",
        description="""
Returns the most recent badge award activities within a specific network.

**Activity Information Includes:**
- Award date
- Badge information (title, image)
- Issuer who awarded the badge
- Number of recipients

**Ordering:**
Activities are ordered by date, most recent first.
        """,
        tags=["Network Dashboard", "Badges"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="limit",
                location=OpenApiParameter.QUERY,
                description="Number of recent activities to return (1-20)",
                required=False,
                type=int,
                default=4
            ),
        ],
        responses={
            200: NetworkRecentActivityResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get network recent activity"""
        try:
            # Get limit from query params
            limit = int(request.query_params.get('limit', 4))
            limit = min(max(limit, 1), 20)

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            if not badge_instances.exists():
                return Response({
                    'metadata': {
                        'totalActivities': 0,
                        'lastUpdated': timezone.now().date().isoformat(),
                    },
                    'activities': [],
                })

            # Group badge instances by date, badge class, and issuer
            # This creates "activity events" where multiple recipients got the same badge
            # on the same day from the same issuer
            # Note: We use 'issuer' (the actual awarding institution) not
            # 'badgeclass__issuer' (which could be the network for shared badges)
            from django.db.models.functions import TruncDate

            activities = badge_instances.annotate(
                award_date=TruncDate('created_at')
            ).values(
                'award_date',
                'badgeclass__entity_id',
                'badgeclass__name',
                'issuer__entity_id',  # The institution ID that awarded the badge
                'issuer__name',  # The institution name that awarded the badge
            ).annotate(
                recipient_count=Count('id')
            ).order_by('-award_date')[:limit]

            # Build response
            activities_data = []
            for item in activities:
                badge_class = BadgeClass.objects.filter(
                    entity_id=item['badgeclass__entity_id']
                ).first()

                image_url = ''
                if badge_class and badge_class.image:
                    image_url = badge_class.image_url(public=True)

                activities_data.append({
                    'date': item['award_date'].isoformat() if item['award_date'] else '',
                    'badgeId': item['badgeclass__entity_id'],
                    'badgeTitle': item['badgeclass__name'],
                    'badgeImage': image_url,
                    'issuerId': item['issuer__entity_id'] or '',
                    'issuerName': item['issuer__name'] or '',
                    'recipientCount': item['recipient_count'],
                })

            response_data = {
                'metadata': {
                    'totalActivities': len(activities_data),
                    'lastUpdated': timezone.now().date().isoformat(),
                },
                'activities': activities_data,
            }

            serializer = NetworkRecentActivityResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardRecentActivityView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardStrengthenedCompetenciesView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/strengthened-competencies

    Returns the individual competencies that have been strengthened the most
    within a network, ordered by competency hours.
    """

    @extend_schema(
        summary="Get Most Strengthened Individual Competencies",
        description="""
Returns the individual competencies (Einzelkompetenzen) that have been
strengthened the most within a network, ordered by competency hours.

**Use Case:** Display "Am meisten gestärkte Einzelkompetenzen" section

**Data Includes:**
- Competency ID (unique identifier)
- Competency title (localized via titleKey)
- Total competency hours invested
- ESCO URI for standardized European competency framework reference

**Delivery Method Filter:**
Use `deliveryMethod` parameter to filter competencies by badge delivery method:
- `online` - Only include badges delivered online (activity_online=True)
- `in-person` - Only include badges delivered in-person (activity_online=False)
- If not specified, includes all badges regardless of delivery method
        """,
        tags=["Network Dashboard", "Competencies"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="limit",
                location=OpenApiParameter.QUERY,
                description="Maximum number of competencies to return (1-50)",
                required=False,
                type=int,
                default=8
            ),
            OpenApiParameter(
                name="sortBy",
                location=OpenApiParameter.QUERY,
                description="Field to sort by (hours, count, title)",
                required=False,
                type=str,
                default='hours'
            ),
            OpenApiParameter(
                name="sortOrder",
                location=OpenApiParameter.QUERY,
                description="Sort direction (asc, desc)",
                required=False,
                type=str,
                default='desc'
            ),
            OpenApiParameter(
                name="deliveryMethod",
                location=OpenApiParameter.QUERY,
                description="Filter by delivery method: 'online' or 'in-person'",
                required=False,
                type=str,
                enum=['online', 'in-person']
            ),
        ],
        responses={
            200: NetworkStrengthenedCompetenciesResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get most strengthened individual competencies"""
        try:
            # Get parameters
            limit = int(request.query_params.get('limit', 8))
            limit = min(max(limit, 1), 50)
            sort_by = request.query_params.get('sortBy', 'hours')
            sort_order = request.query_params.get('sortOrder', 'desc')
            delivery_method = request.query_params.get('deliveryMethod')

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply delivery method filter
            if delivery_method == 'online':
                badge_instances = badge_instances.filter(activity_online=True)
            elif delivery_method == 'in-person':
                badge_instances = badge_instances.filter(activity_online=False)

            if not badge_instances.exists():
                return Response({
                    'metadata': {
                        'totalCompetencies': 0,
                        'totalHours': 0,
                        'lastUpdated': timezone.now().date().isoformat(),
                    },
                    'competencies': [],
                })

            # Get all competency data from badge instances
            competency_stats = self._aggregate_competencies(badge_instances)

            # Sort competencies
            reverse = sort_order == 'desc'
            if sort_by == 'hours':
                sorted_comps = sorted(
                    competency_stats.values(),
                    key=lambda x: x['hours'],
                    reverse=reverse
                )
            elif sort_by == 'count':
                sorted_comps = sorted(
                    competency_stats.values(),
                    key=lambda x: x['count'],
                    reverse=reverse
                )
            else:  # title
                sorted_comps = sorted(
                    competency_stats.values(),
                    key=lambda x: x['title'].lower(),
                    reverse=reverse
                )

            # Limit results
            sorted_comps = sorted_comps[:limit]

            # Calculate totals
            total_hours = sum(c['hours'] for c in competency_stats.values())

            # Build response
            competencies_data = []
            for comp in sorted_comps:
                competencies_data.append({
                    'competencyId': comp['id'],
                    'title': comp['title'],
                    'titleKey': f"competency.{comp['id']}",
                    'hours': comp['hours'],
                    'escoUri': comp.get('escoUri', ''),
                })

            response_data = {
                'metadata': {
                    'totalCompetencies': len(competency_stats),
                    'totalHours': total_hours,
                    'lastUpdated': timezone.now().date().isoformat(),
                },
                'competencies': competencies_data,
            }

            serializer = NetworkStrengthenedCompetenciesResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardStrengthenedCompetenciesView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _aggregate_competencies(self, badge_instances):
        """
        Aggregate competencies from badge instances with their total hours.

        Returns:
            dict: {competency_id: {'id': str, 'title': str, 'hours': int, 'count': int, 'escoUri': str}}
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        # Get all competency extensions for these badge classes
        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        # Build mapping of badgeclass_id -> competencies with study load
        badgeclass_competencies = {}
        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                competencies = []
                for comp in ext_data:
                    if isinstance(comp, dict) and 'name' in comp:
                        competencies.append({
                            'name': comp.get('name', ''),
                            'studyLoad': comp.get('studyLoad', 0) or 0,
                            'escoUri': comp.get('framework_identifier', ''),
                        })

                badgeclass_competencies[ext.badgeclass_id] = competencies
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Aggregate competencies across all badge instances
        competency_stats = {}
        for badge in badge_instances:
            competencies = badgeclass_competencies.get(badge.badgeclass_id, [])

            for comp in competencies:
                comp_name = comp['name']
                # Create normalized ID from name
                comp_id = comp_name.lower().replace(' ', '_').replace('-', '_')

                if comp_id not in competency_stats:
                    competency_stats[comp_id] = {
                        'id': comp_id,
                        'title': comp_name,
                        'hours': 0,
                        'count': 0,
                        'escoUri': comp.get('escoUri', ''),
                    }

                # Add study load (convert minutes to hours)
                competency_stats[comp_id]['hours'] += round(comp['studyLoad'] / 60)
                competency_stats[comp_id]['count'] += 1

        return competency_stats


class NetworkDashboardCompetencyDetailView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/strengthened-competencies/{competencyId}

    Returns detailed information about a specific competency including
    badge count, learner count, institution count, and institutions list.
    """

    @extend_schema(
        summary="Get Competency Detail Information",
        description="""
Returns detailed information about a specific competency within a network,
including statistics about badges, learners, and institutions.

**Use Case:** Display detailed competency information when clicking on a
competency in the "Am meisten gestärkte Einzelkompetenzen" section.

**Data Includes:**
- Competency basic data (ID, title, hours, ESCO URI)
- Badge count: Number of badges covering this competency
- User count: Number of learners who strengthened this competency
- Institution count: Number of institutions offering badges with this competency
- Institutions list: Detailed list of institutions with their badge/user statistics
        """,
        tags=["Network Dashboard", "Competencies"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="competencyId",
                location=OpenApiParameter.PATH,
                description="Unique identifier of the competency",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="institutionLimit",
                location=OpenApiParameter.QUERY,
                description="Maximum number of institutions to return (1-50)",
                required=False,
                type=int,
                default=10
            ),
            OpenApiParameter(
                name="deliveryMethod",
                location=OpenApiParameter.QUERY,
                description="Filter by delivery method: 'online' or 'in-person'",
                required=False,
                type=str,
                enum=['online', 'in-person']
            ),
        ],
        responses={
            200: OpenApiResponse(description="Successful response with competency details"),
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network or competency not found"),
        }
    )
    def get(self, request, networkSlug, competencyId, **kwargs):
        """Get detailed information for a specific competency"""
        try:
            # Get parameters
            institution_limit = int(request.query_params.get('institutionLimit', 10))
            institution_limit = min(max(institution_limit, 1), 50)
            delivery_method = request.query_params.get('deliveryMethod')

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply delivery method filter
            if delivery_method == 'online':
                badge_instances = badge_instances.filter(activity_online=True)
            elif delivery_method == 'in-person':
                badge_instances = badge_instances.filter(activity_online=False)

            if not badge_instances.exists():
                raise Http404(f"Competency '{competencyId}' not found")

            # Get all badge class IDs
            badge_class_ids = list(badge_instances.values_list('badgeclass_id', flat=True).distinct())

            # Get competency extensions for these badge classes
            competency_extensions = BadgeClassExtension.objects.filter(
                badgeclass_id__in=badge_class_ids,
                name='extensions:CompetencyExtension'
            )

            # Find badge classes that have the requested competency
            matching_badge_class_ids = set()
            competency_data = None  # Will store title, escoUri

            for ext in competency_extensions:
                try:
                    ext_data = ext.original_json
                    if isinstance(ext_data, str):
                        ext_data = json.loads(ext_data)

                    if not isinstance(ext_data, list):
                        ext_data = [ext_data]

                    for comp in ext_data:
                        if isinstance(comp, dict) and 'name' in comp:
                            comp_name = comp.get('name', '')
                            # Create normalized ID from name (same logic as _aggregate_competencies)
                            comp_id = comp_name.lower().replace(' ', '_').replace('-', '_')

                            if comp_id == competencyId:
                                matching_badge_class_ids.add(ext.badgeclass_id)
                                if competency_data is None:
                                    competency_data = {
                                        'title': comp_name,
                                        'escoUri': comp.get('framework_identifier', ''),
                                        'studyLoad': comp.get('studyLoad', 0) or 0,
                                    }

                except (json.JSONDecodeError, AttributeError, TypeError):
                    continue

            if not matching_badge_class_ids:
                raise Http404(f"Competency '{competencyId}' not found")

            # Filter badge instances to only those with the matching competency
            matching_badge_instances = badge_instances.filter(badgeclass_id__in=matching_badge_class_ids)

            # Calculate totals
            total_badges = matching_badge_instances.count()
            total_users = matching_badge_instances.values('recipient_identifier').distinct().count()

            # Get study load per badge class for hours calculation
            badgeclass_study_load = {}
            for ext in competency_extensions:
                if ext.badgeclass_id not in matching_badge_class_ids:
                    continue
                try:
                    ext_data = ext.original_json
                    if isinstance(ext_data, str):
                        ext_data = json.loads(ext_data)
                    if not isinstance(ext_data, list):
                        ext_data = [ext_data]

                    for comp in ext_data:
                        if isinstance(comp, dict) and 'name' in comp:
                            comp_id = comp.get('name', '').lower().replace(' ', '_').replace('-', '_')
                            if comp_id == competencyId:
                                badgeclass_study_load[ext.badgeclass_id] = comp.get('studyLoad', 0) or 0
                except (json.JSONDecodeError, AttributeError, TypeError):
                    continue

            # Calculate total hours
            total_hours = 0
            for bi in matching_badge_instances:
                study_load = badgeclass_study_load.get(bi.badgeclass_id, 0)
                total_hours += round(study_load / 60)  # Convert minutes to hours

            # Aggregate by institution (issuer)
            institution_stats = {}
            for bi in matching_badge_instances:
                issuer_id = bi.issuer_id
                if issuer_id not in institution_stats:
                    institution_stats[issuer_id] = {
                        'badge_ids': set(),
                        'recipients': set(),
                        'hours': 0,
                        'last_activity': None,
                    }

                institution_stats[issuer_id]['badge_ids'].add(bi.id)
                if bi.recipient_identifier:
                    institution_stats[issuer_id]['recipients'].add(bi.recipient_identifier)

                study_load = badgeclass_study_load.get(bi.badgeclass_id, 0)
                institution_stats[issuer_id]['hours'] += round(study_load / 60)

                if bi.issued_on:
                    if institution_stats[issuer_id]['last_activity'] is None:
                        institution_stats[issuer_id]['last_activity'] = bi.issued_on
                    elif bi.issued_on > institution_stats[issuer_id]['last_activity']:
                        institution_stats[issuer_id]['last_activity'] = bi.issued_on

            # Get issuer details
            issuer_ids = list(institution_stats.keys())
            issuers = {i.id: i for i in Issuer.objects.filter(id__in=issuer_ids)}

            # Build institutions list
            institutions = []
            for issuer_id, stats in institution_stats.items():
                issuer = issuers.get(issuer_id)
                if issuer:
                    institutions.append({
                        'institutionId': issuer.entity_id,
                        'name': issuer.name,
                        'slug': issuer.entity_id,  # Using entity_id as slug
                        'badgeCount': len(stats['badge_ids']),
                        'userCount': len(stats['recipients']),
                        'competencyHours': stats['hours'],
                        'lastActivity': stats['last_activity'].isoformat() if stats['last_activity'] else None,
                        'logoUrl': issuer.image.url if issuer.image else None,
                    })

            # Sort by badge count descending
            institutions.sort(key=lambda x: x['badgeCount'], reverse=True)

            # Limit institutions
            institutions = institutions[:institution_limit]

            # Build response
            response_data = {
                'competencyId': competencyId,
                'title': competency_data['title'] if competency_data else competencyId,
                'titleKey': f"competency.{competencyId}",
                'hours': total_hours,
                'escoUri': competency_data['escoUri'] if competency_data else '',
                'badgeCount': total_badges,
                'userCount': total_users,
                'institutionCount': len(institution_stats),
                'institutions': institutions,
            }

            return Response(response_data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardCompetencyDetailView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardCompetencyAreaDetailView(NetworkDashboardBaseView):
    """
    POST /v1/issuer/networks/{networkSlug}/dashboard/competency-area-detail

    Returns aggregated statistics for a competency area (Kompetenzbereich) based on
    the provided ESCO URIs of individual competencies belonging to that area.
    """

    @extend_schema(
        summary="Get Competency Area Detail Information",
        description="""
Returns aggregated statistics for a competency area based on the provided ESCO URIs.

**Use Case:** Display detailed competency area information when clicking on a
bubble in the "Top Kompetenz-Bereiche" skill visualization.

**Why POST instead of GET:**
Since the database only stores individual competencies (not competency areas/categories),
the frontend must send the list of ESCO URIs that belong to the clicked competency area.

**Data Aggregation:**
- Total hours: Sum of all competency hours within the area
- Badge count: Count of distinct badges covering any competency in the area
- User count: Count of distinct learners who strengthened any competency in the area
- Institution count: Count of distinct institutions offering badges in this area
- Top competencies: List of individual competencies with highest hours in this area
        """,
        tags=["Network Dashboard", "Competencies"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
        ],
        request={
            'application/json': {
                'type': 'object',
                'required': ['areaName', 'competencyUris'],
                'properties': {
                    'areaName': {'type': 'string', 'description': 'Display name of the competency area'},
                    'areaConceptUri': {'type': 'string', 'description': 'ESCO concept URI of the competency area'},
                    'competencyUris': {'type': 'array', 'items': {'type': 'string'}, 'description': 'List of ESCO URIs'},
                    'topCompetenciesLimit': {'type': 'integer', 'default': 10},
                    'institutionLimit': {'type': 'integer', 'default': 10},
                }
            }
        },
        responses={
            200: OpenApiResponse(description="Successful response with aggregated competency area statistics"),
            400: OpenApiResponse(description="Bad request - invalid or empty competency URIs"),
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def post(self, request, networkSlug, **kwargs):
        """Get aggregated statistics for a competency area"""
        try:
            # Parse request body
            area_name = request.data.get('areaName')
            area_concept_uri = request.data.get('areaConceptUri', '')
            competency_uris = request.data.get('competencyUris', [])
            top_competencies_limit = min(int(request.data.get('topCompetenciesLimit', 10)), 50)
            institution_limit = min(int(request.data.get('institutionLimit', 10)), 50)

            # Validate required fields
            if not area_name:
                return Response(
                    {"error": "Missing required 'areaName' field"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not competency_uris or not isinstance(competency_uris, list):
                return Response(
                    {"error": "Missing or invalid 'competencyUris' field - must be a non-empty array"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            if not badge_instances.exists():
                return Response({
                    'areaName': area_name,
                    'areaConceptUri': area_concept_uri,
                    'totalHours': 0,
                    'totalCompetencies': len(competency_uris),
                    'matchedCompetencies': 0,
                    'badgeCount': 0,
                    'userCount': 0,
                    'institutionCount': 0,
                    'topCompetencies': [],
                    'institutions': [],
                })

            # Get all badge class IDs
            badge_class_ids = list(badge_instances.values_list('badgeclass_id', flat=True).distinct())

            # Get competency extensions for these badge classes
            competency_extensions = BadgeClassExtension.objects.filter(
                badgeclass_id__in=badge_class_ids,
                name='extensions:CompetencyExtension'
            )

            # Normalize URIs for comparison (some may have trailing slashes, etc.)
            competency_uris_set = set(uri.rstrip('/') for uri in competency_uris)

            # Find badge classes and competencies that match any of the provided URIs
            matching_badge_class_ids = set()
            matched_competencies = {}  # uri -> competency data
            badgeclass_competency_data = {}  # badgeclass_id -> list of matched competency data

            for ext in competency_extensions:
                try:
                    ext_data = ext.original_json
                    if isinstance(ext_data, str):
                        ext_data = json.loads(ext_data)

                    if not isinstance(ext_data, list):
                        ext_data = [ext_data]

                    matched_in_badge = []
                    for comp in ext_data:
                        if isinstance(comp, dict):
                            # Check if this competency's ESCO URI matches any in our list
                            comp_uri = comp.get('framework_identifier', '').rstrip('/')
                            comp_name = comp.get('name', '')

                            if comp_uri and comp_uri in competency_uris_set:
                                matching_badge_class_ids.add(ext.badgeclass_id)

                                # Create normalized ID from name
                                comp_id = comp_name.lower().replace(' ', '_').replace('-', '_') if comp_name else comp_uri

                                if comp_uri not in matched_competencies:
                                    matched_competencies[comp_uri] = {
                                        'id': comp_id,
                                        'title': comp_name,
                                        'escoUri': comp_uri,
                                        'studyLoad': comp.get('studyLoad', 0) or 0,
                                    }

                                matched_in_badge.append({
                                    'uri': comp_uri,
                                    'studyLoad': comp.get('studyLoad', 0) or 0,
                                })

                    if matched_in_badge:
                        badgeclass_competency_data[ext.badgeclass_id] = matched_in_badge

                except (json.JSONDecodeError, AttributeError, TypeError):
                    continue

            if not matching_badge_class_ids:
                return Response({
                    'areaName': area_name,
                    'areaConceptUri': area_concept_uri,
                    'totalHours': 0,
                    'totalCompetencies': len(competency_uris),
                    'matchedCompetencies': 0,
                    'badgeCount': 0,
                    'userCount': 0,
                    'institutionCount': 0,
                    'topCompetencies': [],
                    'institutions': [],
                })

            # Filter badge instances to only those with matching competencies
            matching_badge_instances = badge_instances.filter(badgeclass_id__in=matching_badge_class_ids)

            # Calculate totals
            total_badges = matching_badge_instances.count()
            total_users = matching_badge_instances.values('recipient_identifier').distinct().count()

            # Calculate total hours and aggregate by competency
            competency_stats = {}  # uri -> {hours, badge_count, recipients}
            institution_stats = {}  # issuer_id -> {badge_ids, recipients}

            for bi in matching_badge_instances:
                # Get competencies for this badge class
                comp_data_list = badgeclass_competency_data.get(bi.badgeclass_id, [])

                for comp_data in comp_data_list:
                    uri = comp_data['uri']
                    study_load = comp_data['studyLoad']

                    if uri not in competency_stats:
                        competency_stats[uri] = {
                            'hours': 0,
                            'badge_ids': set(),
                            'recipients': set(),
                        }

                    competency_stats[uri]['hours'] += round(study_load / 60)  # Convert minutes to hours
                    competency_stats[uri]['badge_ids'].add(bi.id)
                    if bi.recipient_identifier:
                        competency_stats[uri]['recipients'].add(bi.recipient_identifier)

                # Aggregate by institution
                issuer_id = bi.issuer_id
                if issuer_id not in institution_stats:
                    institution_stats[issuer_id] = {
                        'badge_ids': set(),
                        'recipients': set(),
                    }

                institution_stats[issuer_id]['badge_ids'].add(bi.id)
                if bi.recipient_identifier:
                    institution_stats[issuer_id]['recipients'].add(bi.recipient_identifier)

            # Calculate total hours
            total_hours = sum(stats['hours'] for stats in competency_stats.values())

            # Build top competencies list
            top_competencies = []
            for uri, stats in competency_stats.items():
                comp_info = matched_competencies.get(uri, {})
                top_competencies.append({
                    'competencyId': comp_info.get('id', uri),
                    'title': comp_info.get('title', uri),
                    'titleKey': f"competency.{comp_info.get('id', uri)}",
                    'escoUri': uri,
                    'hours': stats['hours'],
                    'badgeCount': len(stats['badge_ids']),
                    'userCount': len(stats['recipients']),
                })

            # Sort by hours descending and limit
            top_competencies.sort(key=lambda x: x['hours'], reverse=True)
            top_competencies = top_competencies[:top_competencies_limit]

            # Get issuer details and build institutions list
            issuer_ids = list(institution_stats.keys())
            issuers = {i.id: i for i in Issuer.objects.filter(id__in=issuer_ids)}

            institutions = []
            for issuer_id, stats in institution_stats.items():
                issuer = issuers.get(issuer_id)
                if issuer:
                    institutions.append({
                        'institutionId': issuer.entity_id,
                        'name': issuer.name,
                        'slug': issuer.entity_id,
                        'badgeCount': len(stats['badge_ids']),
                        'userCount': len(stats['recipients']),
                        'logoUrl': issuer.image.url if issuer.image else None,
                    })

            # Sort by badge count descending and limit
            institutions.sort(key=lambda x: x['badgeCount'], reverse=True)
            institutions = institutions[:institution_limit]

            # Build response
            response_data = {
                'areaName': area_name,
                'areaConceptUri': area_concept_uri,
                'totalHours': total_hours,
                'totalCompetencies': len(competency_uris),
                'matchedCompetencies': len(matched_competencies),
                'badgeCount': total_badges,
                'userCount': total_users,
                'institutionCount': len(institution_stats),
                'topCompetencies': top_competencies,
                'institutions': institutions,
            }

            return Response(response_data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardCompetencyAreaDetailView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardBadgeAwardsTimelineView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/badge-awards-timeline

    Returns badge awards grouped by date for timeline/chart visualization.
    """

    @extend_schema(
        summary="Get Badge Awards Timeline",
        description="""
Returns badge awards grouped by date for timeline/chart visualization.
Shows "Vergebene Badges im Jahr" with configurable time grouping.

**Use Case:** Display badge awards line chart in Network Dashboard

**Data Includes:**
- Date of award(s)
- Total number of badges awarded
- Badge type breakdown (participation, competency, learningpath)
        """,
        tags=["Network Dashboard", "Badges", "Time Series"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="year",
                location=OpenApiParameter.QUERY,
                description="Filter by specific year",
                required=False,
                type=int
            ),
            OpenApiParameter(
                name="startDate",
                location=OpenApiParameter.QUERY,
                description="Start date for the timeline (ISO 8601)",
                required=False,
                type=str
            ),
            OpenApiParameter(
                name="endDate",
                location=OpenApiParameter.QUERY,
                description="End date for the timeline (ISO 8601)",
                required=False,
                type=str
            ),
            OpenApiParameter(
                name="groupBy",
                location=OpenApiParameter.QUERY,
                description="Time grouping granularity (day, week, month)",
                required=False,
                type=str,
                default='month'
            ),
            OpenApiParameter(
                name="badgeType",
                location=OpenApiParameter.QUERY,
                description="Filter by badge type (all, participation, competency, learningpath)",
                required=False,
                type=str,
                default='all'
            ),
        ],
        responses={
            200: NetworkBadgeAwardsTimelineResponseSerializer,
            400: OpenApiResponse(description="Invalid date format or parameters"),
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get badge awards timeline"""
        try:
            # Get parameters
            year = request.query_params.get('year')
            start_date_str = request.query_params.get('startDate')
            end_date_str = request.query_params.get('endDate')
            group_by = request.query_params.get('groupBy', 'month')
            badge_type_filter = request.query_params.get('badgeType', 'all')

            # Validate group_by
            if group_by not in ['day', 'week', 'month']:
                group_by = 'month'

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply date filters
            if year:
                try:
                    year = int(year)
                    badge_instances = badge_instances.filter(
                        created_at__year=year
                    )
                except ValueError:
                    pass

            if start_date_str:
                try:
                    start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                    badge_instances = badge_instances.filter(
                        created_at__date__gte=start_date
                    )
                except ValueError:
                    return Response(
                        {'error': 'BAD_REQUEST', 'message': 'Invalid startDate format. Use YYYY-MM-DD'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if end_date_str:
                try:
                    end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
                    badge_instances = badge_instances.filter(
                        created_at__date__lte=end_date
                    )
                except ValueError:
                    return Response(
                        {'error': 'BAD_REQUEST', 'message': 'Invalid endDate format. Use YYYY-MM-DD'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if not badge_instances.exists():
                return Response({
                    'metadata': {
                        'totalAwards': 0,
                        'year': year if year else None,
                        'groupBy': group_by,
                        'lastUpdated': timezone.now().isoformat(),
                    },
                    'timeline': [],
                })

            # Get badge type mapping
            badge_type_mapping = self._get_badge_type_mapping(badge_instances)

            # Group by time period
            timeline_data = self._aggregate_timeline(
                badge_instances, group_by, badge_type_filter, badge_type_mapping
            )

            # Calculate total
            total_awards = sum(entry['count'] for entry in timeline_data)

            response_data = {
                'metadata': {
                    'totalAwards': total_awards,
                    'year': year if year else None,
                    'groupBy': group_by,
                    'lastUpdated': timezone.now().isoformat(),
                },
                'timeline': timeline_data,
            }

            serializer = NetworkBadgeAwardsTimelineResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardBadgeAwardsTimelineView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_badge_type_mapping(self, badge_instances):
        """
        Get mapping of badge class ID to badge type (participation, competency, learningpath).

        Returns:
            dict: {badgeclass_id: badge_type}
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        category_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CategoryExtension'
        )

        badge_type_mapping = {}
        for ext in category_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                category = ext_data.get('Category', '').lower()
                # Map 'skill' to 'competency' for consistency
                if category in ['skill', 'competency']:
                    badge_type_mapping[ext.badgeclass_id] = 'competency'
                elif category == 'participation':
                    badge_type_mapping[ext.badgeclass_id] = 'participation'
                elif category in ['learningpath', 'micro_degree']:
                    badge_type_mapping[ext.badgeclass_id] = 'learningpath'
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        return badge_type_mapping

    def _aggregate_timeline(self, badge_instances, group_by, badge_type_filter, badge_type_mapping):
        """
        Aggregate badge instances by time period.

        Returns:
            list: [{'date': str, 'count': int, 'byType': {...}}]
        """
        from django.db.models.functions import TruncDate, TruncWeek, TruncMonth

        # Choose truncation function
        if group_by == 'day':
            trunc_func = TruncDate('created_at')
        elif group_by == 'week':
            trunc_func = TruncWeek('created_at')
        else:  # month
            trunc_func = TruncMonth('created_at')

        # Also get badge class info for type breakdown
        badge_instances_with_period = badge_instances.annotate(
            period=trunc_func
        ).values('period', 'badgeclass_id')

        # Build timeline with type breakdown
        timeline_dict = {}
        for item in badge_instances_with_period:
            period = item['period']
            if period not in timeline_dict:
                timeline_dict[period] = {
                    'count': 0,
                    'participation': 0,
                    'competency': 0,
                    'learningpath': 0,
                }

            badge_type = badge_type_mapping.get(item['badgeclass_id'], 'competency')

            # Apply badge type filter
            if badge_type_filter != 'all' and badge_type != badge_type_filter:
                continue

            timeline_dict[period]['count'] += 1
            timeline_dict[period][badge_type] += 1

        # Convert to list format
        timeline_data = []
        for period in sorted(timeline_dict.keys()):
            data = timeline_dict[period]
            if data['count'] > 0:
                timeline_data.append({
                    'date': period.strftime('%Y-%m-%d') if period else '',
                    'count': data['count'],
                    'byType': {
                        'participation': data['participation'],
                        'competency': data['competency'],
                        'learningpath': data['learningpath'],
                    }
                })

        return timeline_data


class NetworkDashboardBadgeTypeDistributionView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/badge-type-distribution

    Returns the distribution of badges by type for pie/donut chart visualization.
    """

    @extend_schema(
        summary="Get Badge Distribution by Type",
        description="""
Returns the distribution of badges by type for pie/donut chart visualization.
Shows "Badge-Verteilung nach Typ" with counts and percentages.

**Badge Types:**
- participation - Teilnahmezertifikate
- competency - Kompetenzbadges
- learningpath - Micro Degrees / Lernpfade
        """,
        tags=["Network Dashboard", "Badges"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="year",
                location=OpenApiParameter.QUERY,
                description="Optional year filter for distribution",
                required=False,
                type=int
            ),
        ],
        responses={
            200: NetworkBadgeTypeDistributionResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get badge type distribution"""
        try:
            # Get parameters
            year = request.query_params.get('year')

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply year filter
            if year:
                try:
                    year = int(year)
                    badge_instances = badge_instances.filter(
                        created_at__year=year
                    )
                except ValueError:
                    year = None

            total_badges = badge_instances.count()

            if total_badges == 0:
                return Response({
                    'metadata': {
                        'totalBadges': 0,
                        'year': year if year else None,
                        'lastUpdated': timezone.now().isoformat(),
                    },
                    'distribution': [],
                })

            # Get badge type counts
            badge_type_counts = self._count_badge_types(badge_instances)

            # Build distribution response
            distribution_data = []
            type_keys = {
                'participation': 'Badge.categories.participation',
                'competency': 'Badge.categories.competency',
                'learningpath': 'Badge.categories.learningpath',
            }

            for badge_type in ['participation', 'competency', 'learningpath']:
                count = badge_type_counts.get(badge_type, 0)
                percentage = round((count / total_badges * 100), 1) if total_badges > 0 else 0

                distribution_data.append({
                    'type': badge_type,
                    'typeKey': type_keys[badge_type],
                    'count': count,
                    'percentage': percentage,
                })

            response_data = {
                'metadata': {
                    'totalBadges': total_badges,
                    'year': year if year else None,
                    'lastUpdated': timezone.now().isoformat(),
                },
                'distribution': distribution_data,
            }

            serializer = NetworkBadgeTypeDistributionResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardBadgeTypeDistributionView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _count_badge_types(self, badge_instances):
        """
        Count badge instances by type.

        Returns:
            dict: {badge_type: count}
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        # Get category extensions
        category_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CategoryExtension'
        )

        # Build mapping
        badge_type_mapping = {}
        for ext in category_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                category = ext_data.get('Category', '').lower()
                # Map 'skill' to 'competency' for consistency
                if category in ['skill', 'competency']:
                    badge_type_mapping[ext.badgeclass_id] = 'competency'
                elif category == 'participation':
                    badge_type_mapping[ext.badgeclass_id] = 'participation'
                elif category in ['learningpath', 'micro_degree']:
                    badge_type_mapping[ext.badgeclass_id] = 'learningpath'
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Count by type
        type_counts = {
            'participation': 0,
            'competency': 0,
            'learningpath': 0,
        }

        for badge in badge_instances:
            badge_type = badge_type_mapping.get(badge.badgeclass_id, 'competency')
            type_counts[badge_type] += 1

        return type_counts


class NetworkDashboardDeliveryMethodDistributionView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/delivery-method-distribution

    Returns the distribution of badges by delivery method (Online vs Präsenz).
    Based on the activity_online field of BadgeInstance.
    """

    @extend_schema(
        summary="Get Badge Distribution by Delivery Method",
        description="""
Returns the distribution of badges by delivery method (Durchführungsart).
Shows how badges are split between online and in-person (Präsenz) delivery.

**Use Case:** Display "Durchführungsart Badges" donut chart in Badge Analysis

**Delivery Methods:**
- online - Online/Remote delivery (activity_online = True)
- in-person - In-person/Präsenz delivery (activity_online = False)

**Data Includes:**
- Total badge count
- Count and percentage for each delivery method
        """,
        tags=["Network Dashboard", "Badges", "Badge Analysis"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="year",
                location=OpenApiParameter.QUERY,
                description="Optional year filter for distribution",
                required=False,
                type=int
            ),
        ],
        responses={
            200: NetworkDeliveryMethodDistributionResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get badge delivery method distribution"""
        try:
            # Get parameters
            year = request.query_params.get('year')

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply year filter
            if year:
                try:
                    year = int(year)
                    badge_instances = badge_instances.filter(
                        created_at__year=year
                    )
                except ValueError:
                    year = None

            total_badges = badge_instances.count()

            if total_badges == 0:
                return Response({
                    'metadata': {
                        'totalBadges': 0,
                        'year': year if year else None,
                        'lastUpdated': timezone.now().isoformat(),
                    },
                    'total': 0,
                    'online': {
                        'value': 0,
                        'percentage': 0.0,
                    },
                    'inPerson': {
                        'value': 0,
                        'percentage': 0.0,
                    },
                })

            # Count by delivery method using activity_online field
            online_count = badge_instances.filter(activity_online=True).count()
            in_person_count = badge_instances.filter(activity_online=False).count()

            # Calculate percentages
            online_percentage = round((online_count / total_badges * 100), 1) if total_badges > 0 else 0.0
            in_person_percentage = round((in_person_count / total_badges * 100), 1) if total_badges > 0 else 0.0

            response_data = {
                'metadata': {
                    'totalBadges': total_badges,
                    'year': year if year else None,
                    'lastUpdated': timezone.now().isoformat(),
                },
                'total': total_badges,
                'online': {
                    'value': online_count,
                    'percentage': online_percentage,
                },
                'inPerson': {
                    'value': in_person_count,
                    'percentage': in_person_percentage,
                },
            }

            serializer = NetworkDeliveryMethodDistributionResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardDeliveryMethodDistributionView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardRecentBadgeAwardsView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/recent-badge-awards

    Returns badges awarded in the last month within the network,
    grouped by badge with competency details.
    """

    @extend_schema(
        summary="Get Recent Badge Awards (Last Month)",
        description="""
Returns badges awarded in the last month within the network,
grouped by badge with competency details.

**Use Case:** Display "Vergebene Badges im letzten Monat" table in Badge Analysis

**Data Includes:**
- Award date
- Badge name and identifier
- Award count (how many times awarded)
- Associated competencies with ESCO URIs

**Ordering:**
By default ordered by date descending (most recent first).
        """,
        tags=["Network Dashboard", "Badges", "Badge Analysis"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="limit",
                location=OpenApiParameter.QUERY,
                description="Maximum number of badge awards to return (1-100)",
                required=False,
                type=int,
                default=20
            ),
            OpenApiParameter(
                name="days",
                location=OpenApiParameter.QUERY,
                description="Number of days to look back (default 30 for last month)",
                required=False,
                type=int,
                default=30
            ),
            OpenApiParameter(
                name="sortBy",
                location=OpenApiParameter.QUERY,
                description="Field to sort by (date, count, badgeName)",
                required=False,
                type=str,
                default='date'
            ),
            OpenApiParameter(
                name="sortOrder",
                location=OpenApiParameter.QUERY,
                description="Sort direction (asc, desc)",
                required=False,
                type=str,
                default='desc'
            ),
        ],
        responses={
            200: OpenApiResponse(description="Successful response with recent badge awards"),
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get recent badge awards with competency details"""
        try:
            # Get parameters
            limit = int(request.query_params.get('limit', 20))
            limit = min(max(limit, 1), 100)
            days = int(request.query_params.get('days', 30))
            days = min(max(days, 1), 365)
            sort_by = request.query_params.get('sortBy', 'date')
            sort_order = request.query_params.get('sortOrder', 'desc')

            # Validate sort_by
            if sort_by not in ['date', 'count', 'badgeName']:
                sort_by = 'date'

            # Get network
            network = self.get_network(networkSlug)

            # Calculate date range
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)

            # Get badge instances for this network within the date range
            badge_instances = self.get_network_badge_instances(network).filter(
                created_at__date__gte=start_date,
                created_at__date__lte=end_date
            )

            if not badge_instances.exists():
                return Response({
                    'metadata': {
                        'totalAwards': 0,
                        'periodStart': start_date.isoformat(),
                        'periodEnd': end_date.isoformat(),
                        'lastUpdated': timezone.now().isoformat(),
                    },
                    'awards': [],
                })

            # Get badge class info (competencies, type, image)
            badge_class_info = self._get_badge_class_info(badge_instances)

            # Aggregate awards by badge and date
            awards_data = self._aggregate_awards(badge_instances, badge_class_info)

            # Sort awards
            reverse = sort_order == 'desc'
            if sort_by == 'date':
                awards_data.sort(key=lambda x: x['date'], reverse=reverse)
            elif sort_by == 'count':
                awards_data.sort(key=lambda x: x['count'], reverse=reverse)
            else:  # badgeName
                awards_data.sort(key=lambda x: x['badgeName'].lower(), reverse=reverse)

            # Limit results
            awards_data = awards_data[:limit]

            # Calculate total awards
            total_awards = badge_instances.count()

            response_data = {
                'metadata': {
                    'totalAwards': total_awards,
                    'periodStart': start_date.isoformat(),
                    'periodEnd': end_date.isoformat(),
                    'lastUpdated': timezone.now().isoformat(),
                },
                'awards': awards_data,
            }

            from .network_serializers import NetworkRecentBadgeAwardsResponseSerializer
            serializer = NetworkRecentBadgeAwardsResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardRecentBadgeAwardsView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_badge_class_info(self, badge_instances):
        """
        Get badge class info including competencies, type, and image.

        Returns:
            dict: {badgeclass_id: {'name': str, 'entity_id': str, 'image': str, 'type': str, 'competencies': list}}
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        # Get badge classes
        badge_classes = BadgeClass.objects.filter(id__in=badge_class_ids)

        badge_info = {}
        for bc in badge_classes:
            badge_info[bc.id] = {
                'name': bc.name,
                'entity_id': bc.entity_id,
                'image': bc.image.url if bc.image else '',
                'type': 'competency',  # default
                'competencies': [],
            }

        # Get category extensions for badge type
        category_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CategoryExtension'
        )

        for ext in category_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                category = ext_data.get('Category', '').lower()
                if category in ['skill', 'competency']:
                    badge_info[ext.badgeclass_id]['type'] = 'competency'
                elif category == 'participation':
                    badge_info[ext.badgeclass_id]['type'] = 'participation'
                elif category in ['learningpath', 'micro_degree']:
                    badge_info[ext.badgeclass_id]['type'] = 'learningpath'
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Get competency extensions
        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                competencies = []
                for comp in ext_data:
                    if isinstance(comp, dict) and 'name' in comp:
                        competencies.append({
                            'name': comp.get('name', ''),
                            'escoUri': comp.get('framework_identifier', '') or None,
                        })

                badge_info[ext.badgeclass_id]['competencies'] = competencies
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        return badge_info

    def _aggregate_awards(self, badge_instances, badge_class_info):
        """
        Aggregate badge awards by badge and date.

        Returns:
            list: [{'date': str, 'badgeId': str, 'badgeName': str, ...}]
        """
        from collections import defaultdict

        # Group by (date, badge_class_id)
        awards_by_date_badge = defaultdict(int)
        for instance in badge_instances:
            key = (instance.created_at.date(), instance.badgeclass_id)
            awards_by_date_badge[key] += 1

        # Build response data
        awards_data = []
        for (date, badgeclass_id), count in awards_by_date_badge.items():
            info = badge_class_info.get(badgeclass_id, {})

            awards_data.append({
                'date': date.isoformat(),
                'badgeId': info.get('entity_id', ''),
                'badgeName': info.get('name', ''),
                'badgeImage': info.get('image', ''),
                'badgeType': info.get('type', 'competency'),
                'count': count,
                'competencies': info.get('competencies', []),
            })

        return awards_data


class NetworkDashboardBadgeLocationsView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/badge-locations

    Returns the geographic distribution of badges by city and ZIP code area.
    """

    @extend_schema(
        summary="Get Badge Geographic Distribution",
        description="""
Returns the geographic distribution of badges by city and ZIP code area.

**Use Case:** Display badge location distribution on maps or in tables,
particularly useful for analyzing in-person badge delivery patterns.

**Data Includes:**
- City name
- ZIP code area (e.g., "80xxx" for German 5-digit codes)
- Badge count per location
- Percentage of total badges

**Delivery Method Filter:**
Use `deliveryMethod` parameter to filter locations by badge delivery method:
- `in-person` - Most relevant for geographic analysis
- `online` - Usually less meaningful for geographic distribution
- If not specified, includes all badges regardless of delivery method
        """,
        tags=["Network Dashboard", "Badge Analysis"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="deliveryMethod",
                location=OpenApiParameter.QUERY,
                description="Filter by delivery method: 'online' or 'in-person'",
                required=False,
                type=str,
                enum=['online', 'in-person']
            ),
            OpenApiParameter(
                name="limit",
                location=OpenApiParameter.QUERY,
                description="Maximum number of locations to return (sorted by badgeCount descending)",
                required=False,
                type=int,
                default=20
            ),
        ],
        responses={
            200: NetworkBadgeLocationsResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get badge geographic distribution"""
        try:
            # Get parameters
            delivery_method = request.query_params.get('deliveryMethod')
            limit = int(request.query_params.get('limit', 20))
            limit = min(max(limit, 1), 100)

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply delivery method filter
            if delivery_method == 'online':
                badge_instances = badge_instances.filter(activity_online=True)
            elif delivery_method == 'in-person':
                badge_instances = badge_instances.filter(activity_online=False)

            if not badge_instances.exists():
                return Response({
                    'metadata': {
                        'totalLocations': 0,
                        'totalBadges': 0,
                        'deliveryMethod': delivery_method,
                        'lastUpdated': timezone.now().isoformat(),
                    },
                    'locations': [],
                })

            # Aggregate badges by city (regional grouping)
            location_stats, total_badges = self._aggregate_by_city(badge_instances, network)

            # Sort by badge count and limit
            sorted_locations = sorted(
                location_stats.values(),
                key=lambda x: x['badgeCount'],
                reverse=True
            )[:limit]

            # Calculate percentages
            for loc in sorted_locations:
                loc['badgePercentage'] = round(
                    (loc['badgeCount'] / total_badges * 100) if total_badges > 0 else 0,
                    1
                )

            response_data = {
                'metadata': {
                    'totalLocations': len(sorted_locations),
                    'totalBadges': total_badges,
                    'deliveryMethod': delivery_method,
                    'lastUpdated': timezone.now().isoformat(),
                },
                'locations': sorted_locations,
            }

            serializer = NetworkBadgeLocationsResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardBadgeLocationsView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _aggregate_by_city(self, badge_instances, network):
        """
        Aggregate badge instances by city, grouped by network region.

        Logic:
        1. Get the network's ZIP code
        2. Determine the Landkreis (district) from the network's PLZ
        3. Get all ZIP codes belonging to that Landkreis
        4. Group badges by city name (aggregating multiple PLZs for the same city):
           - Badges from issuers in the same region: grouped by city name
           - Badges from issuers outside the region: grouped as "other"

        Args:
            badge_instances: QuerySet of BadgeInstance objects
            network: The network (Issuer with is_network=True)

        Returns:
            tuple: (dict of location_stats, total_badge_count)
        """
        from collections import defaultdict
        from dashboard.services.regional_service import RegionalService

        location_stats = defaultdict(lambda: {
            'city': '',
            'badgeCount': 0,
        })

        total_badges = 0

        # Get regional PLZ set for the network
        regional_plz_set = set()
        network_zip = network.zip or ''
        regional_service = RegionalService.get_instance()

        if network_zip:
            # Extract PLZ3 (first 3 digits)
            plz3 = regional_service.get_plz3_from_plz(network_zip)

            if plz3:
                landkreis = regional_service.get_landkreis_by_plz3(plz3)

                if landkreis:
                    regional_plz_list = regional_service.get_all_plz_for_landkreis(landkreis)
                    regional_plz_set = set(regional_plz_list)
                    logger.debug(
                        f"Network {network.entity_id} in Landkreis '{landkreis}' "
                        f"with {len(regional_plz_set)} regional PLZ codes"
                    )

        # Get badge instances with location info
        instances_with_location = badge_instances.select_related('issuer').values(
            'id', 'activity_city', 'activity_zip',
            'issuer__city', 'issuer__zip'
        )

        for instance in instances_with_location:
            # Prefer activity location, fall back to issuer location
            zip_code = instance.get('activity_zip') or instance.get('issuer__zip') or ''

            total_badges += 1

            # Check if this badge is from the network's region
            is_in_region = zip_code in regional_plz_set if zip_code and regional_plz_set else False

            if is_in_region:
                # Get city name from PLZ (CSV data) - aggregate by city
                city = regional_service.get_ort_by_plz(zip_code) or instance.get('activity_city') or instance.get('issuer__city') or 'Unbekannt'
                location_key = city.lower()
                location_stats[location_key]['city'] = city
                location_stats[location_key]['badgeCount'] += 1
            else:
                # Group all other badges as "other"
                location_stats['other']['city'] = 'other'
                location_stats['other']['badgeCount'] += 1

        return dict(location_stats), total_badges


# ==========================================
# LERNENDE (LEARNERS) ENDPOINTS
# ==========================================

class NetworkDashboardLearnersOverviewView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/learners

    Returns comprehensive learner statistics for the Lernende tab in the network dashboard.
    """

    # Gender label mappings
    GENDER_LABELS = {
        'male': 'Männlich',
        'female': 'Weiblich',
        'diverse': 'Divers',
        'noAnswer': 'Keine Angabe',
    }

    @extend_schema(
        summary="Get Learners Overview Data",
        description="""
Returns comprehensive learner statistics for the Lernende tab.

**Data Includes:**
- Total learner count (Lernende insgesamt)
- Total competency hours (Kompetenzstunden insgesamt)
- Learner residence distribution (Wohnort der Lernenden)
- Gender distribution (Verteilung Geschlecht)
        """,
        tags=["Network Dashboard", "Learners"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
        ],
        responses={
            200: NetworkLearnersOverviewResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get learners overview data"""
        try:
            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Get total unique learners by recipient_identifier (includes non-registered users)
            total_learners = badge_instances.values('recipient_identifier').distinct().count()

            # Get registered user IDs for residence and gender distribution (need profile data)
            learner_user_ids = badge_instances.exclude(
                user__isnull=True
            ).values_list('user_id', flat=True).distinct()

            # Calculate total competency hours
            total_competency_hours = self._calculate_total_competency_hours(badge_instances)

            # Calculate trends (compare with previous month)
            learner_trend_data = self._calculate_learner_trend(network, total_learners)
            hours_trend_data = self._calculate_competency_hours_trend(network, total_competency_hours)

            # Get residence distribution (top 5 + other)
            residence_distribution = self._get_residence_distribution(
                badge_instances, learner_user_ids, network, limit=5
            )

            # Get gender distribution
            gender_distribution = self._get_gender_distribution(
                badge_instances, learner_user_ids
            )

            response_data = {
                'metadata': {
                    'lastUpdated': timezone.now().isoformat(),
                },
                'kpis': {
                    'totalLearners': {
                        'value': total_learners,
                        'trend': learner_trend_data.get('trend'),
                        'trendValue': learner_trend_data.get('trendValue'),
                        'trendPeriod': learner_trend_data.get('trendPeriod'),
                    },
                    'totalCompetencyHours': {
                        'value': total_competency_hours,
                        'trend': hours_trend_data.get('trend'),
                        'trendValue': hours_trend_data.get('trendValue'),
                        'trendPeriod': hours_trend_data.get('trendPeriod'),
                    },
                },
                'residenceDistribution': residence_distribution,
                'genderDistribution': gender_distribution,
            }

            serializer = NetworkLearnersOverviewResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardLearnersOverviewView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _calculate_total_competency_hours(self, badge_instances):
        """Calculate total competency hours from badge instances."""
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        # Build mapping of badgeclass_id -> total study_load
        badgeclass_study_load = {}
        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                total_load = 0
                for comp in ext_data:
                    if isinstance(comp, dict):
                        total_load += comp.get('studyLoad', 0) or 0

                badgeclass_study_load[ext.badgeclass_id] = total_load
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Sum hours for all badge instances
        total_minutes = 0
        for badge in badge_instances:
            total_minutes += badgeclass_study_load.get(badge.badgeclass_id, 0)

        # Convert minutes to hours
        return round(total_minutes / 60) if total_minutes > 0 else 0

    def _calculate_learner_trend(self, network, current_total):
        """
        Calculate the trend for total learners by comparing activity in the last 30 days
        with activity in the previous 30 days (matching KPIs endpoint logic).

        Args:
            network: The network Issuer instance
            current_total: Current total number of learners (not used in trend calc)

        Returns:
            dict with trend, trendValue, trendPeriod
        """
        now = timezone.now()
        last_month_start = now - timedelta(days=30)
        two_months_ago = now - timedelta(days=60)

        badge_instances = self.get_network_badge_instances(network)

        # Count unique recipients who received badges in the last 30 days
        learners_current = badge_instances.filter(
            created_at__gte=last_month_start
        ).values('recipient_identifier').distinct().count()

        # Count unique recipients who received badges in the previous 30 days (30-60 days ago)
        learners_previous = badge_instances.filter(
            created_at__gte=two_months_ago,
            created_at__lt=last_month_start
        ).values('recipient_identifier').distinct().count()

        # Use the same calculate_trend method as KPIs endpoint
        trend, trend_value = self.calculate_trend(learners_current, learners_previous)
        return {
            'trend': trend,
            'trendValue': trend_value,
            'trendPeriod': 'lastMonth'
        }

    def _calculate_competency_hours_trend(self, network, current_total):
        """
        Calculate the trend for competency hours by comparing activity in the last 30 days
        with activity in the previous 30 days (matching KPIs endpoint logic).

        Args:
            network: The network Issuer instance
            current_total: Current total competency hours (not used in trend calc)

        Returns:
            dict with trend, trendValue, trendPeriod
        """
        now = timezone.now()
        last_month_start = now - timedelta(days=30)
        two_months_ago = now - timedelta(days=60)

        badge_instances = self.get_network_badge_instances(network)

        # Calculate competency hours from badges awarded in the last 30 days
        hours_current = self._calculate_total_competency_hours(
            badge_instances.filter(created_at__gte=last_month_start)
        )

        # Calculate competency hours from badges awarded in the previous 30 days (30-60 days ago)
        hours_previous = self._calculate_total_competency_hours(
            badge_instances.filter(
                created_at__gte=two_months_ago,
                created_at__lt=last_month_start
            )
        )

        # Use calculate_trend_percent for consistency with KPIs endpoint
        trend, trend_value = self.calculate_trend_percent(hours_current, hours_previous)
        return {
            'trend': trend,
            'trendValue': trend_value,
            'trendPeriod': 'lastMonth'
        }

    def _compute_trend(self, current_value, previous_value):
        """
        Compute trend direction and percentage change.

        Args:
            current_value: Current value
            previous_value: Previous value to compare against

        Returns:
            dict with trend (up/down/stable), trendValue (percentage), trendPeriod
        """
        if previous_value == 0:
            if current_value > 0:
                return {
                    'trend': 'up',
                    'trendValue': 100.0,
                    'trendPeriod': 'lastMonth'
                }
            else:
                return {
                    'trend': 'stable',
                    'trendValue': 0.0,
                    'trendPeriod': 'lastMonth'
                }

        # Calculate percentage change
        change = ((current_value - previous_value) / previous_value) * 100
        rounded_change = round(change, 1)

        # Determine trend direction (stable if change is less than 1%)
        if abs(rounded_change) < 1.0:
            trend = 'stable'
        elif rounded_change > 0:
            trend = 'up'
        else:
            trend = 'down'

        return {
            'trend': trend,
            'trendValue': abs(rounded_change),  # Always positive, direction is in 'trend'
            'trendPeriod': 'lastMonth'
        }

    def _get_residence_distribution(self, badge_instances, learner_user_ids, network, limit=5):
        """
        Get residence distribution for learners based on the network's region.

        Groups learners by city (Ort) based on whether the USER's zip_code is from
        the same region (Landkreis) as the network. Uses the user's PLZ from BadgeUser.zip_code.

        Args:
            badge_instances: QuerySet of BadgeInstance objects
            learner_user_ids: List of user IDs who have badges
            network: The network Issuer object (has zip field for reference)
            limit: Maximum number of cities to show before grouping into "other"

        Returns:
            List of residence distribution entries (without zipCode)
        """
        from collections import defaultdict
        from .services.regional_service import RegionalService

        regional_service = RegionalService.get_instance()

        # Get network's PLZ and determine its Landkreis (for reference only)
        network_plz = network.zip or ''
        network_plz3 = regional_service.get_plz3_from_plz(network_plz)
        network_landkreis = regional_service.get_landkreis_by_plz3(network_plz3) if network_plz3 else None

        # Get all PLZs for the network's Landkreis
        regional_plz_set = set()
        if network_landkreis:
            regional_plz_set = set(regional_service.get_all_plz_for_landkreis(network_landkreis))

        # Get unique learner user IDs and their zip_code from BadgeUser
        unique_user_ids = set(learner_user_ids)
        learner_users = BadgeUser.objects.filter(
            id__in=unique_user_ids
        ).values('id', 'zip_code')
        user_plz_map = {u['id']: u['zip_code'] or '' for u in learner_users}

        # Count learners per city (Ort) within the region
        # Structure: {ort_name: count}
        city_learner_counts = defaultdict(int)
        other_count = 0

        # For each unique learner, check if their PLZ is in the network's region
        for user_id in unique_user_ids:
            user_plz = user_plz_map.get(user_id, '')

            if user_plz and user_plz in regional_plz_set:
                # User is in the network's region - get city from CSV based on user's PLZ
                ort = regional_service.get_ort_by_plz(user_plz) or 'Unbekannt'
                city_learner_counts[ort] += 1
            else:
                # User is outside the region or has no PLZ
                other_count += 1

        # Sort cities by count (descending)
        sorted_cities = sorted(
            city_learner_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        # Calculate total for percentages
        total_learners = sum(count for _, count in sorted_cities) + other_count

        # Build distribution (top N cities)
        distribution = []
        additional_other_count = 0

        for i, (city_name, count) in enumerate(sorted_cities):
            if i < limit:
                percentage = round((count / total_learners * 100), 1) if total_learners > 0 else 0
                distribution.append({
                    'city': city_name,
                    'learnerCount': count,
                    'percentage': percentage,
                })
            else:
                additional_other_count += count

        # Add "Other" category (users outside region + overflow cities)
        total_other = other_count + additional_other_count
        if total_other > 0:
            percentage = round((total_other / total_learners * 100), 1) if total_learners > 0 else 0
            distribution.append({
                'city': 'other',
                'learnerCount': total_other,
                'percentage': percentage,
            })

        return distribution

    def _get_gender_distribution(self, badge_instances, learner_user_ids):
        """
        Get gender distribution for learners.

        Uses gender-guesser library to infer gender from first_name.
        """
        from collections import defaultdict
        import gender_guesser.detector as gender_detector

        detector = gender_detector.Detector()

        # Get users with their first name
        learner_users = BadgeUser.objects.filter(
            id__in=learner_user_ids
        ).values('id', 'first_name')

        # Map gender-guesser results to API values
        # gender-guesser returns: 'male', 'female', 'mostly_male', 'mostly_female', 'andy', 'unknown'
        gender_mapping = {
            'male': 'male',
            'mostly_male': 'male',
            'female': 'female',
            'mostly_female': 'female',
            'andy': 'noAnswer',  # androgynous/unisex name
            'unknown': 'noAnswer',
        }

        # Count learners by gender
        gender_counts = defaultdict(int)
        for user in learner_users:
            first_name = (user.get('first_name') or '').strip()
            if first_name:
                # Detect gender from first name
                detected = detector.get_gender(first_name)
                normalized_gender = gender_mapping.get(detected, 'noAnswer')
            else:
                normalized_gender = 'noAnswer'
            gender_counts[normalized_gender] += 1

        total_learners = sum(gender_counts.values())

        # Build distribution
        distribution = []
        for gender in ['male', 'female', 'diverse', 'noAnswer']:
            count = gender_counts.get(gender, 0)
            if count > 0:  # Only include genders with at least 1 learner
                percentage = round((count / total_learners * 100), 1) if total_learners > 0 else 0
                distribution.append({
                    'gender': gender,
                    'count': count,
                    'percentage': percentage,
                })

        return distribution


class NetworkDashboardLearnersResidenceView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/learners/residence

    Returns the distribution of learners by their residence (Wohnort der Lernenden).
    """

    @extend_schema(
        summary="Get Learners Residence Distribution",
        description="""
Returns the distribution of learners by their residence (Wohnort der Lernenden).
Shows where learners live, grouped by city/region.

**Default Behavior:**
Returns top 5 regions by learner count plus an "Andere Wohnorte" (Other) category.
        """,
        tags=["Network Dashboard", "Learners"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="limit",
                location=OpenApiParameter.QUERY,
                description="Maximum number of individual regions to return before grouping into 'Other' (1-20)",
                required=False,
                type=int,
                default=5
            ),
            OpenApiParameter(
                name="includeOther",
                location=OpenApiParameter.QUERY,
                description="Whether to include the 'Andere Wohnorte' (Other) aggregation category",
                required=False,
                type=bool,
                default=True
            ),
        ],
        responses={
            200: NetworkLearnersResidenceResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get learners residence distribution"""
        try:
            # Get parameters
            limit = int(request.query_params.get('limit', 5))
            limit = min(max(limit, 1), 20)
            include_other = request.query_params.get('includeOther', 'true').lower() == 'true'

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Get unique learners
            learner_user_ids = badge_instances.exclude(
                user__isnull=True
            ).values_list('user_id', flat=True).distinct()

            if not learner_user_ids:
                return Response({
                    'metadata': {
                        'totalLearners': 0,
                        'totalCities': 0,
                        'lastUpdated': timezone.now().isoformat(),
                    },
                    'statistics': [],
                })

            # Get residence distribution
            distribution, total_cities = self._get_detailed_residence_distribution(
                badge_instances, network, limit, include_other
            )

            total_learners = sum(item['learnerCount'] for item in distribution)

            response_data = {
                'metadata': {
                    'totalLearners': total_learners,
                    'totalCities': total_cities,
                    'lastUpdated': timezone.now().isoformat(),
                },
                'statistics': distribution,
            }

            serializer = NetworkLearnersResidenceResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardLearnersResidenceView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_detailed_residence_distribution(self, badge_instances, network, limit, include_other):
        """
        Get detailed residence distribution for learners.

        Uses the USER's zip_code from BadgeUser to determine their city.
        The network's Landkreis is used only to determine if the user is in the same region.

        Returns:
            tuple: (distribution_list, total_cities_count)
        """
        from collections import defaultdict
        from .services.regional_service import RegionalService

        regional_service = RegionalService.get_instance()

        # Get network's PLZ and determine its Landkreis (for reference only)
        network_plz = network.zip or ''
        network_plz3 = regional_service.get_plz3_from_plz(network_plz)
        network_landkreis = regional_service.get_landkreis_by_plz3(network_plz3) if network_plz3 else None

        # Get all PLZs for the network's Landkreis
        regional_plz_set = set()
        if network_landkreis:
            regional_plz_set = set(regional_service.get_all_plz_for_landkreis(network_landkreis))

        # Get unique learner user IDs from badge instances
        unique_user_ids = set(
            badge_instances.exclude(user__isnull=True)
            .values_list('user_id', flat=True).distinct()
        )

        # Get users with their zip_code from BadgeUser
        learner_users = BadgeUser.objects.filter(
            id__in=unique_user_ids
        ).values('id', 'zip_code')
        user_plz_map = {u['id']: u['zip_code'] or '' for u in learner_users}

        # Count learners per city (Ort) within the region
        city_learner_counts = defaultdict(int)
        other_count = 0

        # For each unique learner, check if their PLZ is in the network's region
        for user_id in unique_user_ids:
            user_plz = user_plz_map.get(user_id, '')

            if user_plz and user_plz in regional_plz_set:
                # User is in the network's region - get city from CSV based on user's PLZ
                ort = regional_service.get_ort_by_plz(user_plz) or 'Unbekannt'
                city_learner_counts[ort] += 1
            else:
                # User is outside the region or has no PLZ
                other_count += 1

        total_cities = len(city_learner_counts)

        # Sort by count and get top N
        sorted_cities = sorted(
            city_learner_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        total_learners = sum(count for _, count in sorted_cities) + other_count

        # Build distribution
        distribution = []
        additional_other_count = 0

        for i, (city_name, count) in enumerate(sorted_cities):
            if i < limit:
                percentage = round((count / total_learners * 100), 1) if total_learners > 0 else 0
                distribution.append({
                    'city': city_name,
                    'learnerCount': count,
                    'percentage': percentage,
                })
            else:
                additional_other_count += count

        # Add "Other" category if requested
        total_other = other_count + additional_other_count
        if include_other and total_other > 0:
            percentage = round((total_other / total_learners * 100), 1) if total_learners > 0 else 0
            distribution.append({
                'city': 'other',
                'learnerCount': total_other,
                'percentage': percentage,
            })

        return distribution, total_cities


class NetworkDashboardLearnersResidenceDetailView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/learners/residence/{city}

    Returns detailed competency analysis for learners from a specific city.
    """

    @extend_schema(
        summary="Get Learner Residence Detail (Regionsdetail)",
        description="""
Returns detailed competency analysis for learners from a specific city.
This is the drill-down view when clicking on a residence bar in the overview.

**Data Includes:**
- City metadata (city name, associated ZIP codes, total learners)
- Top competency areas with percentages (for bubble chart)
- Top individual competencies with hours, badges, and trends

**Note:** The endpoint uses city name because a city can have multiple ZIP codes.
This allows aggregating all learners from a city regardless of their specific ZIP code.
        """,
        tags=["Network Dashboard", "Learners"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="city",
                location=OpenApiParameter.PATH,
                description="City name (e.g., 'München') or 'other' for aggregated other cities",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="competencyLimit",
                location=OpenApiParameter.QUERY,
                description="Maximum number of strengthened competencies to return (1-20)",
                required=False,
                type=int,
                default=8
            ),
        ],
        responses={
            200: NetworkLearnersResidenceDetailResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network or city not found"),
        }
    )
    def get(self, request, networkSlug, city, **kwargs):
        """Get learner residence detail by city"""
        try:
            # Get parameters
            competency_limit = int(request.query_params.get('competencyLimit', 8))
            competency_limit = min(max(competency_limit, 1), 20)

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Get learners for this city
            learner_user_ids, city_name, zip_codes = self._get_learners_for_city(
                badge_instances, city, network
            )

            if not learner_user_ids:
                raise Http404(f"No learners found for city '{city}'")

            total_learners = len(set(learner_user_ids))

            # Get badge instances for these learners
            city_badge_instances = badge_instances.filter(user_id__in=learner_user_ids)

            # Get top competency areas
            top_competency_areas = self._get_top_competency_areas(city_badge_instances)

            # Get top strengthened competencies
            top_strengthened_competencies = self._get_top_strengthened_competencies(
                city_badge_instances, competency_limit
            )

            response_data = {
                'metadata': {
                    'city': city_name,
                    'zipCodes': zip_codes,
                    'totalLearners': total_learners,
                    'lastUpdated': timezone.now().isoformat(),
                },
                'topCompetencyAreas': top_competency_areas,
                'topStrengthenedCompetencies': top_strengthened_competencies,
            }

            serializer = NetworkLearnersResidenceDetailResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardLearnersResidenceDetailView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_learners_for_city(self, badge_instances, city_param, network):
        """
        Get learner user IDs for a specific city.

        Uses the USER's zip_code from BadgeUser to determine their city.
        The network's Landkreis is used only to determine if the user is in the same region.

        Args:
            badge_instances: QuerySet of BadgeInstance
            city_param: City name (e.g., 'München') or 'other'
            network: The network Issuer object

        Returns:
            tuple: (list of user_ids, city_name, list of zip_codes)
        """
        from collections import defaultdict
        from .services.regional_service import RegionalService

        regional_service = RegionalService.get_instance()

        # Get network's PLZ and determine its Landkreis (for reference only)
        network_plz = network.zip or ''
        network_plz3 = regional_service.get_plz3_from_plz(network_plz)
        network_landkreis = regional_service.get_landkreis_by_plz3(network_plz3) if network_plz3 else None

        # Get all PLZs for the network's Landkreis
        regional_plz_set = set()
        if network_landkreis:
            regional_plz_set = set(regional_service.get_all_plz_for_landkreis(network_landkreis))

        # Get unique learner user IDs from badge instances
        unique_user_ids = set(
            badge_instances.exclude(user__isnull=True)
            .values_list('user_id', flat=True).distinct()
        )

        # Get users with their zip_code from BadgeUser
        learner_users = BadgeUser.objects.filter(
            id__in=unique_user_ids
        ).values('id', 'zip_code')
        user_plz_map = {u['id']: u['zip_code'] or '' for u in learner_users}

        # Build mapping: city -> PLZs and user_ids
        city_data = defaultdict(lambda: {'plzs': set(), 'user_ids': set()})
        other_user_ids = set()

        for user_id in unique_user_ids:
            user_plz = user_plz_map.get(user_id, '')

            if user_plz and user_plz in regional_plz_set:
                # User is in the network's region - get city name from CSV based on user's PLZ
                ort = regional_service.get_ort_by_plz(user_plz) or 'Unbekannt'
                city_data[ort]['plzs'].add(user_plz)
                city_data[ort]['user_ids'].add(user_id)
            else:
                # User is outside the region or has no PLZ
                other_user_ids.add(user_id)

        # Handle the requested city
        if city_param.lower() == 'other':
            return list(other_user_ids), 'other', []

        # Find matching city (case-insensitive)
        for city_name, data in city_data.items():
            if city_name.lower() == city_param.lower():
                return list(data['user_ids']), city_name, sorted(list(data['plzs']))

        # No match found
        return [], city_param, []

    def _get_top_competency_areas(self, badge_instances, limit=6):
        """
        Get top competency areas for the given badge instances.

        Returns a list of competency area data for bubble chart visualization.
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        # Get competency extensions
        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        # Build mapping of badgeclass_id -> competency areas
        badgeclass_areas = {}
        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                areas = []
                for comp in ext_data:
                    if isinstance(comp, dict) and 'category' in comp:
                        areas.append(comp.get('category', ''))
                    elif isinstance(comp, dict) and 'name' in comp:
                        # Use competency name as fallback
                        areas.append(comp.get('name', ''))

                badgeclass_areas[ext.badgeclass_id] = areas
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Count instances per area
        from collections import defaultdict
        area_counts = defaultdict(int)

        for badge in badge_instances:
            areas = badgeclass_areas.get(badge.badgeclass_id, [])
            for area in areas:
                if area:
                    area_counts[area] += 1

        # Sort and limit
        sorted_areas = sorted(area_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        total_weight = sum(count for _, count in sorted_areas)

        # Build response
        result = []
        for area_name, count in sorted_areas:
            area_id = area_name.lower().replace(' ', '_').replace('-', '_')
            percentage = round((count / total_weight * 100), 1) if total_weight > 0 else 0

            result.append({
                'id': area_id,
                'name': area_name,
                'value': percentage,
                'weight': count,
            })

        return result

    def _get_top_strengthened_competencies(self, badge_instances, limit=8):
        """
        Get top strengthened individual competencies for the given badge instances.

        Returns a list of competencies with hours, badges, and trends.
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        # Get competency extensions
        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        # Build mapping of badgeclass_id -> competencies with study load
        badgeclass_competencies = {}
        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                competencies = []
                for comp in ext_data:
                    # Only include competencies with ESCO URI (framework_identifier)
                    # to be consistent with get_skills_tree which requires ESCO URI
                    if isinstance(comp, dict) and 'name' in comp and comp.get('framework_identifier'):
                        competencies.append({
                            'name': comp.get('name', ''),
                            'studyLoad': comp.get('studyLoad', 0) or 0,
                            'escoUri': comp.get('framework_identifier', ''),
                            'category': comp.get('category', ''),
                        })

                badgeclass_competencies[ext.badgeclass_id] = competencies
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Aggregate competencies - count unique recipients (learners) per competency
        from collections import defaultdict
        competency_stats = defaultdict(lambda: {
            'recipients': set(),  # Track unique recipients per competency (by email)
            'hours': 0,
            'badges': 0,
            'escoUri': '',
            'category': '',
        })

        for badge in badge_instances:
            competencies = badgeclass_competencies.get(badge.badgeclass_id, [])
            counted_badge_for_comp = set()
            recipient = badge.recipient_identifier  # Get the recipient email from the badge instance

            for comp in competencies:
                comp_name = comp['name']
                if not comp_name:
                    continue

                comp_id = comp_name.lower().replace(' ', '_').replace('-', '_')

                competency_stats[comp_id]['name'] = comp_name
                # Track unique recipients (by email) instead of incrementing count
                if recipient:
                    competency_stats[comp_id]['recipients'].add(recipient)
                competency_stats[comp_id]['hours'] += round(comp['studyLoad'] / 60)

                if comp_id not in counted_badge_for_comp:
                    competency_stats[comp_id]['badges'] += 1
                    counted_badge_for_comp.add(comp_id)

                if comp['escoUri'] and not competency_stats[comp_id]['escoUri']:
                    competency_stats[comp_id]['escoUri'] = comp['escoUri']
                if comp['category'] and not competency_stats[comp_id]['category']:
                    competency_stats[comp_id]['category'] = comp['category']

        # Sort by unique learner count and limit
        sorted_competencies = sorted(
            competency_stats.items(),
            key=lambda x: len(x[1]['recipients']),
            reverse=True
        )[:limit]

        # Build response
        result = []
        for comp_id, stats in sorted_competencies:
            result.append({
                'competencyId': comp_id,
                'competencyKey': f"competency.{comp_id}",
                'title': stats.get('name', comp_id),
                'areaKey': stats.get('category', ''),
                'count': len(stats['recipients']),  # Count unique recipients (by email), not badge instances
                'hours': stats['hours'],
                'badges': stats['badges'],
                'trend': 'stable',  # Simplified - could calculate actual trend
                'trendValue': 0,
                'escoUri': stats.get('escoUri', ''),
            })

        return result


class NetworkDashboardLearnersGenderView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/learners/gender

    Returns the distribution of learners by gender.
    """

    # Gender label mappings
    GENDER_LABELS = {
        'male': 'Männlich',
        'female': 'Weiblich',
        'diverse': 'Divers',
        'noAnswer': 'Keine Angabe',
    }

    @extend_schema(
        summary="Get Learners Gender Distribution",
        description="""
Returns the distribution of learners by gender (Verteilung Geschlecht unter Lernende).

**Data Includes:**
- Gender category (male, female, diverse, noAnswer)
- Localized gender label
- Learner count per gender
- Percentage of total learners
        """,
        tags=["Network Dashboard", "Learners"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
        ],
        responses={
            200: NetworkLearnersGenderResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network not found"),
        }
    )
    def get(self, request, networkSlug, **kwargs):
        """Get learners gender distribution"""
        try:
            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Get unique learners
            learner_user_ids = badge_instances.exclude(
                user__isnull=True
            ).values_list('user_id', flat=True).distinct()

            if not learner_user_ids:
                return Response({
                    'metadata': {
                        'totalLearners': 0,
                        'lastUpdated': timezone.now().isoformat(),
                    },
                    'distribution': [],
                })

            # Get gender distribution
            distribution = self._get_gender_distribution(learner_user_ids)
            total_learners = sum(item['count'] for item in distribution)

            response_data = {
                'metadata': {
                    'totalLearners': total_learners,
                    'lastUpdated': timezone.now().isoformat(),
                },
                'distribution': distribution,
            }

            serializer = NetworkLearnersGenderResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardLearnersGenderView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_gender_distribution(self, learner_user_ids):
        """
        Get gender distribution for learners.

        Uses gender-guesser library to infer gender from first_name.
        """
        from collections import defaultdict
        import gender_guesser.detector as gender_detector

        detector = gender_detector.Detector()

        # Get users with their first name
        learner_users = BadgeUser.objects.filter(
            id__in=learner_user_ids
        ).values('id', 'first_name')

        # Map gender-guesser results to API values
        gender_mapping = {
            'male': 'male',
            'mostly_male': 'male',
            'female': 'female',
            'mostly_female': 'female',
            'andy': 'noAnswer',
            'unknown': 'noAnswer',
        }

        # Count learners by gender
        gender_counts = defaultdict(int)
        for user in learner_users:
            first_name = (user.get('first_name') or '').strip()
            if first_name:
                detected = detector.get_gender(first_name)
                normalized_gender = gender_mapping.get(detected, 'noAnswer')
            else:
                normalized_gender = 'noAnswer'
            gender_counts[normalized_gender] += 1

        total_learners = sum(gender_counts.values())

        # Build distribution
        distribution = []
        for gender in ['male', 'female', 'diverse', 'noAnswer']:
            count = gender_counts.get(gender, 0)
            if count > 0:
                percentage = round((count / total_learners * 100), 1) if total_learners > 0 else 0
                distribution.append({
                    'gender': gender,
                    'count': count,
                    'percentage': percentage,
                })

        return distribution


class NetworkDashboardLearnersGenderDetailView(NetworkDashboardBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/learners/gender/{gender}

    Returns detailed competency analysis for learners of a specific gender.
    """

    # Gender label mappings
    GENDER_LABELS = {
        'male': 'Männlich',
        'female': 'Weiblich',
        'diverse': 'Divers',
        'noAnswer': 'Keine Angabe',
    }

    # Gender value mappings (from localized labels to internal values)
    GENDER_VALUE_MAPPING = {
        'male': 'male',
        'female': 'female',
        'diverse': 'diverse',
        'noanswer': 'noAnswer',
        'männlich': 'male',
        'weiblich': 'female',
        'divers': 'diverse',
        'keine angabe': 'noAnswer',
    }

    @extend_schema(
        summary="Get Learner Gender Detail (Geschlechtverteilungsdetails)",
        description="""
Returns detailed competency analysis for learners of a specific gender.
This is the drill-down view when clicking on a gender bar in the overview.

**Data Includes:**
- Total badges for this gender (metadata.totalBadges = sum of all badge counts)
- Top competency areas (Kompetenzbereiche) as bubble chart
- Most strengthened individual competencies (Gestärkte Einzelkompetenzen)
- ALL badges awarded to this gender (sorted by count, no 'other' category)
        """,
        tags=["Network Dashboard", "Learners"],
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID (slug)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="gender",
                location=OpenApiParameter.PATH,
                description="Gender category (male, female, diverse, noAnswer) or localized label",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="competencyLimit",
                location=OpenApiParameter.QUERY,
                description="Maximum number of individual competencies to return (1-20)",
                required=False,
                type=int,
                default=5
            ),
        ],
        responses={
            200: NetworkLearnersGenderDetailResponseSerializer,
            401: OpenApiResponse(description="Unauthorized"),
            403: OpenApiResponse(description="Forbidden"),
            404: OpenApiResponse(description="Network or gender not found"),
        }
    )
    def get(self, request, networkSlug, gender, **kwargs):
        """Get learner gender detail"""
        try:
            # Get parameters
            competency_limit = int(request.query_params.get('competencyLimit', 5))
            competency_limit = min(max(competency_limit, 1), 20)

            # Normalize gender parameter
            normalized_gender = self.GENDER_VALUE_MAPPING.get(gender.lower(), None)
            if not normalized_gender:
                raise Http404(f"Invalid gender category: '{gender}'")

            # Get network
            network = self.get_network(networkSlug)

            # Get badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Get learners for this gender
            learner_user_ids = self._get_learners_for_gender(badge_instances, normalized_gender)

            if not learner_user_ids:
                raise Http404(f"No learners found for gender '{gender}'")

            total_learners = len(set(learner_user_ids))

            # Get badge instances for these learners
            gender_badge_instances = badge_instances.filter(user_id__in=learner_user_ids)

            # Get ALL badges for this gender (no limit, no 'other' category)
            # totalBadges in metadata = sum of all badge counts
            top_badges = self._get_top_badges(gender_badge_instances)
            total_badges = sum(badge['count'] for badge in top_badges)

            # Get top competency areas (Kompetenzbereiche)
            top_kompetenzbereiche = self._get_top_competency_areas(gender_badge_instances)

            # Get top individual competencies (Einzelkompetenzen)
            top_einzelkompetenzen = self._get_top_individual_competencies(
                gender_badge_instances, competency_limit
            )

            response_data = {
                'metadata': {
                    'gender': normalized_gender,
                    'totalLearners': total_learners,
                    'totalBadges': total_badges,
                    'lastUpdated': timezone.now().isoformat(),
                },
                'topCompetencyAreas': top_kompetenzbereiche,
                'topStrengthenedCompetencies': top_einzelkompetenzen,
                'topBadges': top_badges,
            }

            serializer = NetworkLearnersGenderDetailResponseSerializer(response_data)
            return Response(serializer.data)

        except Http404:
            raise
        except Exception as e:
            logger.error(f"Error in NetworkDashboardLearnersGenderDetailView: {str(e)}")
            return Response(
                {'error': 'Internal Server Error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_learners_for_gender(self, badge_instances, gender):
        """
        Get learner user IDs for a specific gender.

        Uses gender-guesser library to infer gender from first_name.
        """
        import gender_guesser.detector as gender_detector

        detector = gender_detector.Detector()

        # Get unique learner user IDs
        all_learner_ids = badge_instances.exclude(
            user__isnull=True
        ).values_list('user_id', flat=True).distinct()

        # Get users with their first name
        learner_users = BadgeUser.objects.filter(
            id__in=all_learner_ids
        ).values('id', 'first_name')

        # Map gender-guesser results to API values
        gender_mapping = {
            'male': 'male',
            'mostly_male': 'male',
            'female': 'female',
            'mostly_female': 'female',
            'andy': 'noAnswer',
            'unknown': 'noAnswer',
        }

        matching_user_ids = []
        for user in learner_users:
            first_name = (user.get('first_name') or '').strip()
            if first_name:
                detected = detector.get_gender(first_name)
                normalized_gender = gender_mapping.get(detected, 'noAnswer')
            else:
                normalized_gender = 'noAnswer'

            if normalized_gender == gender:
                matching_user_ids.append(user['id'])

        return matching_user_ids

    def _get_top_competency_areas(self, badge_instances, limit=6):
        """
        Get top competency areas for the given badge instances.
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        # Get competency extensions
        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        # Build mapping of badgeclass_id -> competency areas
        badgeclass_areas = {}
        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                areas = []
                for comp in ext_data:
                    if isinstance(comp, dict):
                        area = comp.get('category', '') or comp.get('name', '')
                        if area:
                            areas.append(area)

                badgeclass_areas[ext.badgeclass_id] = areas
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Count instances per area
        from collections import defaultdict
        area_counts = defaultdict(int)

        for badge in badge_instances:
            areas = badgeclass_areas.get(badge.badgeclass_id, [])
            for area in areas:
                area_counts[area] += 1

        # Sort and limit
        sorted_areas = sorted(area_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        total_weight = sum(count for _, count in sorted_areas)

        # Build response
        result = []
        for area_name, count in sorted_areas:
            area_id = area_name.lower().replace(' ', '_').replace('-', '_')
            percentage = round((count / total_weight * 100), 1) if total_weight > 0 else 0

            result.append({
                'id': area_id,
                'name': area_name,
                'value': percentage,
                'weight': count,
            })

        return result

    def _get_top_individual_competencies(self, badge_instances, limit=5):
        """
        Get top individual competencies for the given badge instances.
        """
        badge_class_ids = badge_instances.values_list('badgeclass_id', flat=True).distinct()

        # Get competency extensions
        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        # Build mapping of badgeclass_id -> competencies
        badgeclass_competencies = {}
        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                competencies = []
                for comp in ext_data:
                    if isinstance(comp, dict) and 'name' in comp:
                        competencies.append({
                            'name': comp.get('name', ''),
                            'studyLoad': comp.get('studyLoad', 0) or 0,
                            'escoUri': comp.get('framework_identifier', ''),
                        })

                badgeclass_competencies[ext.badgeclass_id] = competencies
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Aggregate competencies
        from collections import defaultdict
        competency_stats = defaultdict(lambda: {
            'count': 0,
            'hours': 0,
            'escoUri': '',
        })

        for badge in badge_instances:
            competencies = badgeclass_competencies.get(badge.badgeclass_id, [])

            for comp in competencies:
                comp_name = comp['name']
                if not comp_name:
                    continue

                comp_id = comp_name.lower().replace(' ', '_').replace('-', '_')

                competency_stats[comp_id]['name'] = comp_name
                competency_stats[comp_id]['count'] += 1
                competency_stats[comp_id]['hours'] += round(comp['studyLoad'] / 60)

                if comp['escoUri'] and not competency_stats[comp_id]['escoUri']:
                    competency_stats[comp_id]['escoUri'] = comp['escoUri']

        # Sort by count and limit
        sorted_competencies = sorted(
            competency_stats.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:limit]

        # Build response
        result = []
        for comp_id, stats in sorted_competencies:
            result.append({
                'competencyId': comp_id,
                'name': stats.get('name', comp_id),
                'count': stats['count'],
                'hours': stats['hours'],
                'escoUri': stats.get('escoUri', ''),
            })

        return result

    def _get_top_badges(self, badge_instances, limit=None):
        """
        Get all badges for the given badge instances, sorted by count.
        Returns ALL badges without any 'other' aggregation.
        The sum of all badge counts equals totalBadges in metadata.
        """
        # Get ALL badge counts
        badge_counts = list(badge_instances.values(
            'badgeclass__entity_id',
            'badgeclass__name',
        ).annotate(
            count=Count('id')
        ).order_by('-count'))

        # Get badge class info for study load
        badge_class_ids = [item['badgeclass__entity_id'] for item in badge_counts]
        badge_classes = BadgeClass.objects.filter(entity_id__in=badge_class_ids)

        # Get study load mapping
        study_load_mapping = {}
        competency_extensions = BadgeClassExtension.objects.filter(
            badgeclass__entity_id__in=badge_class_ids,
            name='extensions:CompetencyExtension'
        )

        for ext in competency_extensions:
            try:
                ext_data = ext.original_json
                if isinstance(ext_data, str):
                    ext_data = json.loads(ext_data)

                if not isinstance(ext_data, list):
                    ext_data = [ext_data]

                total_load = 0
                for comp in ext_data:
                    if isinstance(comp, dict):
                        total_load += comp.get('studyLoad', 0) or 0

                # Store by entity_id
                bc = BadgeClass.objects.filter(id=ext.badgeclass_id).first()
                if bc:
                    study_load_mapping[bc.entity_id] = round(total_load / 60)
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

        # Build response
        result = []
        for item in badge_counts:
            badge_class = badge_classes.filter(entity_id=item['badgeclass__entity_id']).first()
            image_url = ''
            if badge_class and badge_class.image:
                image_url = badge_class.image_url(public=True)

            hours = study_load_mapping.get(item['badgeclass__entity_id'], 0) * item['count']

            result.append({
                'badgeId': item['badgeclass__entity_id'],
                'name': item['badgeclass__name'],
                'count': item['count'],
                'hours': hours,
                'image': image_url,
            })

        return result


# ==========================================
# COMPETENCY AREAS SKILLS TREE ENDPOINT
# ==========================================

@extend_schema(
    summary="Get Skills Tree for Network",
    description="""
Returns a hierarchical skills tree from badge assertions within the network.
Uses ESCO framework for skill classification with tree structure breadcrumbs.

**Filtering:**
- `region` - Filter by Landkreis (district) based on learner PLZ
- `gender` - Filter by learner gender (male, female, diverse, noAnswer)
- `deliveryMethod` - Filter by badge delivery method (online, in-person)
- All filters can be combined

**Tree Structure:**
Each skill includes:
- `concept_uri`: ESCO skill URI path
- `pref_label`: Preferred skill name in requested language
- `broader`: Array of parent categories (breadcrumbs) from root to skill
- `studyLoad`: Total competency minutes from badges
    """,
    tags=["Network Dashboard", "Competencies"],
    parameters=[
        OpenApiParameter(
            name="networkSlug",
            location=OpenApiParameter.PATH,
            description="Network entity ID",
            required=True,
            type=str,
        ),
        OpenApiParameter(
            name="lang",
            location=OpenApiParameter.QUERY,
            description="Language for skill labels (de or en)",
            required=False,
            type=str,
            enum=["de", "en"],
            default="de"
        ),
        OpenApiParameter(
            name="region",
            location=OpenApiParameter.QUERY,
            description="Filter by Landkreis (district) name",
            required=False,
            type=str,
        ),
        OpenApiParameter(
            name="gender",
            location=OpenApiParameter.QUERY,
            description="Filter by learner gender",
            required=False,
            type=str,
            enum=["male", "female", "diverse", "noAnswer"],
        ),
        OpenApiParameter(
            name="deliveryMethod",
            location=OpenApiParameter.QUERY,
            description="Filter by badge delivery method",
            required=False,
            type=str,
            enum=["online", "in-person"],
        ),
    ],
    responses={
        200: OpenApiResponse(
            response=NetworkSkillsTreeResponseSerializer,
            description="Successful response with skills tree"
        ),
        404: OpenApiResponse(description="Network not found"),
    },
)
class NetworkDashboardCompetencyAreasSkillsView(NetworkDashboardBaseView):
    """
    Returns a hierarchical skills tree from badge assertions within the network.
    Uses the get_skills_tree function to fetch ESCO skill hierarchy with studyLoads.

    Supports filtering by:
    - region: Landkreis (district) based on learner PLZ
    - city: Ort (city name) based on learner PLZ - matches user's zip_code with CSV data
            Special value 'other' returns skills from users NOT in the network's Landkreis
    - gender: Learner gender (male, female, diverse, noAnswer)
    - deliveryMethod: Badge delivery method (online, in-person)
    """

    # Gender value mapping (same as NetworkDashboardLearnersGenderDetailView)
    GENDER_VALUE_MAPPING = {
        'male': 'male',
        'female': 'female',
        'diverse': 'diverse',
        'noanswer': 'noAnswer',
        'männlich': 'male',
        'weiblich': 'female',
        'divers': 'diverse',
        'keine angabe': 'noAnswer',
    }

    def get(self, request, networkSlug, **kwargs):
        """Get skills tree for network with optional region/city/gender/deliveryMethod filters"""
        try:
            # Get parameters
            lang = request.query_params.get('lang', 'de')
            if lang not in ['de', 'en']:
                lang = 'de'

            region_filter = request.query_params.get('region')
            city_filter = request.query_params.get('city')
            gender_filter = request.query_params.get('gender')
            delivery_method = request.query_params.get('deliveryMethod')

            # Validate deliveryMethod if provided
            if delivery_method and delivery_method not in ['online', 'in-person']:
                return Response(
                    {"error": f"Invalid deliveryMethod: '{delivery_method}'. Must be 'online' or 'in-person'."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Normalize gender if provided
            normalized_gender = None
            if gender_filter:
                normalized_gender = self.GENDER_VALUE_MAPPING.get(
                    gender_filter.lower()
                )
                if not normalized_gender:
                    return Response(
                        {"error": f"Invalid gender: '{gender_filter}'"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Get network
            network = self.get_network(networkSlug)

            # Get base badge instances for this network
            badge_instances = self.get_network_badge_instances(network)

            # Apply deliveryMethod filter if specified
            if delivery_method:
                if delivery_method == 'online':
                    badge_instances = badge_instances.filter(activity_online=True)
                elif delivery_method == 'in-person':
                    badge_instances = badge_instances.filter(activity_online=False)

            # Apply region filter if specified
            if region_filter:
                regional_service = RegionalService.get_instance()
                plz_list = regional_service.get_all_plz_for_landkreis(region_filter)

                if not plz_list:
                    # If no PLZ found, return empty result
                    return Response({
                        'metadata': {
                            'totalSkills': 0,
                            'totalStudyLoad': 0,
                            'filters': {
                                'region': region_filter,
                                'city': city_filter,
                                'gender': gender_filter,
                                'deliveryMethod': delivery_method,
                            },
                            'lastUpdated': timezone.now().isoformat(),
                        },
                        'skills': []
                    })

                # Get user IDs for learners in this region
                user_ids_in_region = list(
                    BadgeUser.objects.filter(
                        zip_code__in=plz_list
                    ).values_list('id', flat=True)
                )

                badge_instances = badge_instances.filter(user_id__in=user_ids_in_region)

            # Apply city filter if specified (filters by user's PLZ matching the city)
            if city_filter:
                regional_service = RegionalService.get_instance()

                if city_filter.lower() == 'other':
                    # "other" means users NOT in the network's Landkreis
                    # Get network's PLZ and determine its Landkreis
                    network_plz = network.zip or ''
                    network_plz3 = regional_service.get_plz3_from_plz(network_plz)
                    network_landkreis = regional_service.get_landkreis_by_plz3(network_plz3) if network_plz3 else None

                    # Get all PLZs in the network's Landkreis (empty set if no Landkreis)
                    regional_plz_set = set()
                    if network_landkreis:
                        regional_plz_set = set(regional_service.get_all_plz_for_landkreis(network_landkreis))

                    # Get all unique user IDs from badge instances
                    unique_user_ids = set(
                        badge_instances.exclude(user__isnull=True)
                        .values_list('user_id', flat=True).distinct()
                    )

                    # Get users with their zip_code
                    learner_users = BadgeUser.objects.filter(
                        id__in=unique_user_ids
                    ).values('id', 'zip_code')

                    # Find users whose PLZ is NOT in the network's Landkreis
                    # If network has no Landkreis (regional_plz_set is empty), ALL users are "other"
                    other_user_ids = []
                    for user in learner_users:
                        user_plz = user['zip_code'] or ''
                        if not user_plz or user_plz not in regional_plz_set:
                            other_user_ids.append(user['id'])

                    badge_instances = badge_instances.filter(user_id__in=other_user_ids)
                else:
                    # Normal city filter - get PLZ for the specified city
                    plz_list = regional_service.get_all_plz_for_ort(city_filter)

                    if not plz_list:
                        # If no PLZ found for this city, return empty result
                        return Response({
                            'metadata': {
                                'totalSkills': 0,
                                'totalStudyLoad': 0,
                                'filters': {
                                    'region': region_filter,
                                    'city': city_filter,
                                    'gender': gender_filter,
                                    'deliveryMethod': delivery_method,
                                },
                                'lastUpdated': timezone.now().isoformat(),
                            },
                            'skills': []
                        })

                    # Get user IDs for learners in this city
                    user_ids_in_city = list(
                        BadgeUser.objects.filter(
                            zip_code__in=plz_list
                        ).values_list('id', flat=True)
                    )

                    badge_instances = badge_instances.filter(user_id__in=user_ids_in_city)

            # Apply gender filter if specified
            if normalized_gender:
                learner_user_ids = self._get_learners_for_gender(
                    badge_instances, normalized_gender
                )
                badge_instances = badge_instances.filter(user_id__in=learner_user_ids)

            # Check if we have any badge instances
            if not badge_instances.exists():
                return Response({
                    'metadata': {
                        'totalSkills': 0,
                        'totalStudyLoad': 0,
                        'filters': {
                            'region': region_filter,
                            'city': city_filter,
                            'gender': gender_filter,
                            'deliveryMethod': delivery_method,
                        },
                        'lastUpdated': timezone.now().isoformat(),
                    },
                    'skills': []
                })

            # Call get_skills_tree with the filtered badge instances
            skills_tree = get_skills_tree(badge_instances, lang)

            # Calculate totals
            skills = skills_tree.get('skills', [])
            total_skills = len(skills)
            total_study_load = sum(skill.get('studyLoad', 0) for skill in skills)

            # Build response
            response_data = {
                'metadata': {
                    'totalSkills': total_skills,
                    'totalStudyLoad': total_study_load,
                    'filters': {
                        'region': region_filter,
                        'city': city_filter,
                        'gender': gender_filter,
                        'deliveryMethod': delivery_method,
                    },
                    'lastUpdated': timezone.now().isoformat(),
                },
                'skills': skills
            }

            return Response(response_data)

        except Http404:
            raise
        except Exception as e:
            logger.exception(f"Error fetching skills tree: {e}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_learners_for_gender(self, badge_instances, gender):
        """
        Get learner user IDs for a specific gender.
        Uses gender-guesser library to infer gender from first_name.
        """
        import gender_guesser.detector as gender_detector

        detector = gender_detector.Detector()

        # Get unique user IDs from badge instances
        user_ids = badge_instances.values_list('user_id', flat=True).distinct()
        users = BadgeUser.objects.filter(id__in=user_ids)

        matching_user_ids = []
        for user in users:
            first_name = user.first_name or ''
            guessed = detector.get_gender(first_name)

            # Map gender-guesser values to our gender values
            if gender == 'male':
                if guessed in ['male', 'mostly_male']:
                    matching_user_ids.append(user.id)
            elif gender == 'female':
                if guessed in ['female', 'mostly_female']:
                    matching_user_ids.append(user.id)
            elif gender == 'diverse':
                if guessed == 'andy':  # androgynous
                    matching_user_ids.append(user.id)
            elif gender == 'noAnswer':
                if guessed == 'unknown':
                    matching_user_ids.append(user.id)

        return matching_user_ids


# =============================================================================
# Sozialraum/Socialspace Dashboard Endpoints
# =============================================================================

class NetworkDashboardSocialspaceBaseView(NetworkDashboardBaseView):
    """
    Base view for Socialspace dashboard endpoints.
    Cities are determined from institution (Issuer) zip codes.
    """

    def get_network_issuers(self, network):
        """
        Get all issuers (institutions) that are members of this network.

        Args:
            network: The network Issuer instance

        Returns:
            QuerySet of Issuer objects
        """
        issuer_ids = self.get_network_issuer_ids(network)
        return Issuer.objects.filter(id__in=issuer_ids)

    def get_cities_from_issuers(self, issuers):
        """
        Get unique cities from issuer zip codes using RegionalService.

        Args:
            issuers: QuerySet of Issuer objects

        Returns:
            dict mapping city names to set of PLZs
        """
        regional_service = RegionalService.get_instance()
        cities = {}

        for issuer in issuers:
            if issuer.zip:
                ort = regional_service.get_ort_by_plz(issuer.zip)
                if ort:
                    if ort not in cities:
                        cities[ort] = set()
                    cities[ort].add(issuer.zip)

        return cities

    def get_issuers_for_city(self, issuers, city):
        """
        Get issuers whose zip code maps to the specified city.

        Args:
            issuers: QuerySet of Issuer objects
            city: City name

        Returns:
            QuerySet of Issuer objects
        """
        regional_service = RegionalService.get_instance()

        # Get all PLZs for this city
        plz_list = regional_service.get_all_plz_for_ort(city)
        if not plz_list:
            return issuers.none()

        return issuers.filter(zip__in=plz_list)

    def get_learners_for_city(self, badge_instances, city):
        """
        Get learners (unique users) whose PLZ maps to the specified city.

        Args:
            badge_instances: QuerySet of BadgeInstance objects
            city: City name

        Returns:
            List of user IDs
        """
        regional_service = RegionalService.get_instance()

        # Get all PLZs for this city
        plz_list = regional_service.get_all_plz_for_ort(city)
        if not plz_list:
            return []

        # Get unique user IDs from badge instances
        unique_user_ids = set(
            badge_instances.exclude(user__isnull=True)
            .values_list('user_id', flat=True).distinct()
        )

        # Filter users by PLZ
        return list(
            BadgeUser.objects.filter(
                id__in=unique_user_ids,
                zip_code__in=plz_list
            ).values_list('id', flat=True)
        )


class NetworkDashboardSocialspaceInstitutionsView(NetworkDashboardSocialspaceBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/socialspace/institutions

    Returns institutions list for a specific network.
    Optionally filter by city.
    """

    @extend_schema(
        summary="Get Institutions List for Network",
        description="Returns institutions list for a specific network. Optionally filter by city.",
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="city",
                location=OpenApiParameter.QUERY,
                description="Optional filter by city name",
                required=False,
                type=str
            ),
            OpenApiParameter(
                name="type",
                location=OpenApiParameter.QUERY,
                description="Filter by institution type",
                required=False,
                type=str
            ),
        ],
        responses={
            200: OpenApiResponse(description="Successful response"),
            404: OpenApiResponse(description="Network not found"),
        },
        tags=["Sozialraum", "Institutions"]
    )
    def get(self, request, networkSlug, **kwargs):
        try:
            network = self.get_network(networkSlug)
            city_filter = request.query_params.get('city', None)
            type_filter = request.query_params.get('type', None)

            # Get all issuers in this network
            issuers = self.get_network_issuers(network)

            # Apply city filter if specified
            if city_filter:
                issuers = self.get_issuers_for_city(issuers, city_filter)

            # Apply type filter if specified
            if type_filter:
                issuers = issuers.filter(category=type_filter)

            # Count badges issued and active users per issuer
            # NOTE: Only count network-relevant badges (network badges + partner badges)
            issuer_ids = list(issuers.values_list('id', flat=True))
            network_badge_class_ids = self.get_network_relevant_badge_class_ids(network)

            # Get badge counts per issuer (only network-relevant badges)
            badge_counts = BadgeInstance.objects.filter(
                revoked=False,
                issuer_id__in=issuer_ids,
                badgeclass_id__in=network_badge_class_ids
            ).values('issuer_id').annotate(count=Count('id'))
            badge_count_map = {item['issuer_id']: item['count'] for item in badge_counts}

            # Get active learner counts per issuer (unique recipients with network-relevant badges)
            active_learner_counts = BadgeInstance.objects.filter(
                revoked=False,
                issuer_id__in=issuer_ids,
                badgeclass_id__in=network_badge_class_ids
            ).values('issuer_id').annotate(
                learner_count=Count('recipient_identifier', distinct=True)
            )
            active_user_map = {item['issuer_id']: item['learner_count'] for item in active_learner_counts}

            # Build institutions list
            regional_service = RegionalService.get_instance()
            institutions = []
            for issuer in issuers:
                ort = regional_service.get_ort_by_plz(issuer.zip) if issuer.zip else None
                institutions.append({
                    'issuerId': issuer.entity_id,
                    'name': issuer.name,
                    'type': issuer.category if issuer.category != 'n/a' else None,
                    'image': issuer.image.url if issuer.image else None,
                    'city': ort or issuer.city,
                    'badgesIssued': badge_count_map.get(issuer.id, 0),
                    'activeUsers': active_user_map.get(issuer.id, 0),
                    'joinedDate': issuer.created_at.date().isoformat() if hasattr(issuer, 'created_at') else None,
                })

            # Calculate summary
            now = timezone.now()
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            new_this_month = issuers.filter(created_at__gte=month_start).count()

            # Count by type
            type_counts = {}
            for issuer in issuers:
                t = issuer.category if issuer.category != 'n/a' else 'other'
                type_counts[t] = type_counts.get(t, 0) + 1

            response_data = {
                'institutions': institutions,
                'summary': {
                    'total': len(institutions),
                    'newThisMonth': new_this_month,
                    'byType': type_counts,
                }
            }

            return Response(response_data)

        except Http404:
            raise
        except Exception as e:
            logger.exception(f"Error fetching socialspace institutions: {e}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardSocialspaceCitiesView(NetworkDashboardSocialspaceBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/socialspace/cities

    Returns list of available cities for the socialspace dashboard.
    Cities are derived from institution zip codes.
    """

    @extend_schema(
        summary="Get Available Cities",
        description="Returns list of available cities for the socialspace dashboard.",
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID",
                required=True,
                type=str
            ),
        ],
        responses={
            200: OpenApiResponse(description="Successful response"),
            404: OpenApiResponse(description="Network not found"),
        },
        tags=["Sozialraum"]
    )
    def get(self, request, networkSlug, **kwargs):
        try:
            network = self.get_network(networkSlug)
            regional_service = RegionalService.get_instance()

            # Get all issuers in this network
            issuers = self.get_network_issuers(network)

            # Build mapping: city -> list of issuer IDs
            city_issuer_ids = {}
            for issuer in issuers:
                if issuer.zip:
                    ort = regional_service.get_ort_by_plz(issuer.zip)
                    if ort:
                        if ort not in city_issuer_ids:
                            city_issuer_ids[ort] = []
                        city_issuer_ids[ort].append(issuer.id)

            # Count badges per city (only network-relevant badges issued by issuers in that city)
            network_badge_class_ids = self.get_network_relevant_badge_class_ids(network)
            cities = []
            for city, issuer_ids in city_issuer_ids.items():
                # Count network-relevant badges issued by issuers in this city
                badge_count = BadgeInstance.objects.filter(
                    revoked=False,
                    issuer_id__in=issuer_ids,
                    badgeclass_id__in=network_badge_class_ids
                ).count()

                cities.append({
                    'city': city,
                    'badges': badge_count,
                })

            # Sort by badge count descending
            cities.sort(key=lambda x: x['badges'], reverse=True)

            return Response({'cities': cities})

        except Http404:
            raise
        except Exception as e:
            logger.exception(f"Error fetching socialspace cities: {e}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardSocialspaceCityDetailView(NetworkDashboardSocialspaceBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/socialspace/city-detail

    Returns detailed metrics for a specific city.
    """

    @extend_schema(
        summary="Get City Detail Metrics",
        description="Returns detailed metrics for a specific city including KPIs, badge distribution, and top institutions.",
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="city",
                location=OpenApiParameter.QUERY,
                description="City name (required)",
                required=True,
                type=str
            ),
        ],
        responses={
            200: OpenApiResponse(description="Successful response"),
            400: OpenApiResponse(description="Missing city parameter"),
            404: OpenApiResponse(description="Network not found"),
        },
        tags=["Sozialraum"]
    )
    def get(self, request, networkSlug, **kwargs):
        try:
            network = self.get_network(networkSlug)
            city = request.query_params.get('city', None)

            if not city:
                return Response(
                    {"error": "Missing required 'city' parameter"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            regional_service = RegionalService.get_instance()

            # Get all issuers in this network
            all_issuers = self.get_network_issuers(network)

            # Find issuers whose zip maps to this city (same approach as /cities endpoint)
            issuer_ids = []
            city_lower = city.lower()
            for issuer in all_issuers:
                if issuer.zip:
                    ort = regional_service.get_ort_by_plz(issuer.zip)
                    if ort and ort.lower() == city_lower:
                        issuer_ids.append(issuer.id)

            # Get badge instances for these issuers (only network-relevant badges)
            network_badge_class_ids = self.get_network_relevant_badge_class_ids(network)
            badge_instances = BadgeInstance.objects.filter(
                revoked=False,
                issuer_id__in=issuer_ids,
                badgeclass_id__in=network_badge_class_ids
            )

            # Count unique recipients (by email) with network-relevant badges from city institutions
            learner_count = badge_instances.values('recipient_identifier').distinct().count()

            # Total badges (only network-relevant)
            total_badges = badge_instances.count()

            # Institution count
            institutions_count = len(issuer_ids)

            # Badge distribution by type - using CategoryExtension
            badge_type_counts = {'participation': 0, 'competency': 0, 'learningpath': 0}

            # Get badge type mapping from CategoryExtension
            badge_class_ids = list(badge_instances.values_list('badgeclass_id', flat=True).distinct())
            badge_type_mapping = {}

            category_extensions = BadgeClassExtension.objects.filter(
                badgeclass_id__in=badge_class_ids,
                name='extensions:CategoryExtension'
            )

            for ext in category_extensions:
                ext_json = ext.original_json if hasattr(ext, 'original_json') else {}
                if isinstance(ext_json, str):
                    ext_json = json.loads(ext_json)
                category = ext_json.get('Category', '').lower()

                if category in ['skill', 'competency']:
                    badge_type_mapping[ext.badgeclass_id] = 'competency'
                elif category == 'participation':
                    badge_type_mapping[ext.badgeclass_id] = 'participation'
                elif category in ['learningpath', 'micro_degree']:
                    badge_type_mapping[ext.badgeclass_id] = 'learningpath'

            # Count badge types
            for bi in badge_instances:
                badge_type = badge_type_mapping.get(bi.badgeclass_id, 'participation')
                badge_type_counts[badge_type] += 1

            # Top institutions by badge count (only network-relevant badges)
            top_institutions_data = BadgeInstance.objects.filter(
                revoked=False,
                issuer_id__in=issuer_ids,
                badgeclass_id__in=network_badge_class_ids
            ).values('issuer_id').annotate(badge_count=Count('id')).order_by('-badge_count')[:5]

            top_institutions = []
            for item in top_institutions_data:
                issuer = Issuer.objects.get(id=item['issuer_id'])
                top_institutions.append({
                    'issuerId': issuer.entity_id,
                    'name': issuer.name,
                    'badgeCount': item['badge_count'],
                    'image': issuer.image.url if issuer.image else None,
                })

            response_data = {
                'city': city,
                'learnerCount': learner_count,
                'totalBadges': total_badges,
                'institutions': institutions_count,
                'badgesByType': badge_type_counts,
                'topInstitutions': top_institutions,
            }

            return Response(response_data)

        except Http404:
            raise
        except Exception as e:
            logger.exception(f"Error fetching socialspace city detail: {e}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardSocialspaceLearnersView(NetworkDashboardSocialspaceBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/socialspace/learners

    Returns learner demographics for a specific city.
    """

    @extend_schema(
        summary="Get Learner Demographics for City",
        description="Returns learner demographics including gender and residence distribution for a city.",
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="city",
                location=OpenApiParameter.QUERY,
                description="City name (required)",
                required=True,
                type=str
            ),
        ],
        responses={
            200: OpenApiResponse(description="Successful response"),
            400: OpenApiResponse(description="Missing city parameter"),
            404: OpenApiResponse(description="Network not found"),
        },
        tags=["Sozialraum", "Learners"]
    )
    def get(self, request, networkSlug, **kwargs):
        try:
            import gender_guesser.detector as gender_detector

            network = self.get_network(networkSlug)
            city = request.query_params.get('city', None)

            if not city:
                return Response(
                    {"error": "Missing required 'city' parameter"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            regional_service = RegionalService.get_instance()

            # Get all issuers in this network
            all_issuers = self.get_network_issuers(network)

            # Find issuers whose zip maps to this city (same approach as /cities endpoint)
            issuer_ids = []
            city_lower = city.lower()
            for issuer in all_issuers:
                if issuer.zip:
                    ort = regional_service.get_ort_by_plz(issuer.zip)
                    if ort and ort.lower() == city_lower:
                        issuer_ids.append(issuer.id)

            if not issuer_ids:
                return Response({
                    'city': city,
                    'learnerCount': 0,
                    'genderDistribution': [],
                    'residenceDistribution': [],
                })

            # Get badge instances from these city issuers (only network-relevant badges)
            network_badge_class_ids = self.get_network_relevant_badge_class_ids(network)
            badge_instances = BadgeInstance.objects.filter(
                revoked=False,
                issuer_id__in=issuer_ids,
                badgeclass_id__in=network_badge_class_ids
            )

            # Get unique learners who received network-relevant badges from city institutions
            user_ids = list(badge_instances.exclude(user__isnull=True).values_list('user_id', flat=True).distinct())
            learners = BadgeUser.objects.filter(id__in=user_ids)
            learner_count = learners.count()

            if learner_count == 0:
                return Response({
                    'city': city,
                    'learnerCount': 0,
                    'genderDistribution': [],
                    'residenceDistribution': [],
                })

            # Gender distribution using gender-guesser
            detector = gender_detector.Detector()
            gender_counts = {'male': 0, 'female': 0, 'diverse': 0}

            for user in learners:
                first_name = user.first_name or ''
                guessed = detector.get_gender(first_name)

                if guessed in ['male', 'mostly_male']:
                    gender_counts['male'] += 1
                elif guessed in ['female', 'mostly_female']:
                    gender_counts['female'] += 1
                else:
                    gender_counts['diverse'] += 1

            gender_distribution = []
            for gender, count in gender_counts.items():
                if count > 0:
                    percentage = round((count / learner_count) * 100, 1)
                    gender_distribution.append({
                        'gender': gender,
                        'count': count,
                        'percentage': percentage,
                    })

            # Residence distribution by city (PLZ -> Ort)
            # Shows where the learners LIVE, not where they got badges
            residence_counts = {}
            unknown_count = 0

            for user in learners:
                user_plz = user.zip_code
                if user_plz:
                    user_ort = regional_service.get_ort_by_plz(user_plz)
                    if user_ort:
                        residence_counts[user_ort] = residence_counts.get(user_ort, 0) + 1
                    else:
                        # PLZ exists but doesn't map to a known city
                        unknown_count += 1
                else:
                    # No PLZ data
                    unknown_count += 1

            # Sort by count (descending) and build distribution
            sorted_residences = sorted(residence_counts.items(), key=lambda x: x[1], reverse=True)

            residence_distribution = []
            for residence_city, count in sorted_residences:
                percentage = round((count / learner_count) * 100, 1)
                residence_distribution.append({
                    'district': residence_city,
                    'learnerCount': count,
                    'percentage': percentage,
                    'isOtherCategory': False,
                })

            # Add unknown/no PLZ as separate category at the end
            if unknown_count > 0:
                percentage = round((unknown_count / learner_count) * 100, 1)
                residence_distribution.append({
                    'district': 'Unbekannt',
                    'learnerCount': unknown_count,
                    'percentage': percentage,
                    'isOtherCategory': True,
                })

            response_data = {
                'city': city,
                'learnerCount': learner_count,
                'genderDistribution': gender_distribution,
                'residenceDistribution': residence_distribution,
            }

            return Response(response_data)

        except Http404:
            raise
        except Exception as e:
            logger.exception(f"Error fetching socialspace learners: {e}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkDashboardSocialspaceCompetenciesView(NetworkDashboardSocialspaceBaseView):
    """
    GET /v1/issuer/networks/{networkSlug}/dashboard/socialspace/competencies

    Returns strengthened individual competencies for a specific city.
    """

    @extend_schema(
        summary="Get Strengthened Competencies for City",
        description="Returns strengthened individual competencies with hours and ESCO links for a city.",
        parameters=[
            OpenApiParameter(
                name="networkSlug",
                location=OpenApiParameter.PATH,
                description="Network entity ID",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="city",
                location=OpenApiParameter.QUERY,
                description="City name (required)",
                required=True,
                type=str
            ),
            OpenApiParameter(
                name="limit",
                location=OpenApiParameter.QUERY,
                description="Maximum competencies to return (default: 10, max: 50)",
                required=False,
                type=int
            ),
        ],
        responses={
            200: OpenApiResponse(description="Successful response"),
            400: OpenApiResponse(description="Missing city parameter"),
            404: OpenApiResponse(description="Network not found"),
        },
        tags=["Sozialraum", "Competencies"]
    )
    def get(self, request, networkSlug, **kwargs):
        try:
            network = self.get_network(networkSlug)
            city = request.query_params.get('city', None)
            limit = min(int(request.query_params.get('limit', 10)), 50)

            if not city:
                return Response(
                    {"error": "Missing required 'city' parameter"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            regional_service = RegionalService.get_instance()

            # Get all issuers in this network
            all_issuers = self.get_network_issuers(network)

            # Find issuers whose zip maps to this city (same approach as /cities endpoint)
            issuer_ids = []
            city_lower = city.lower()
            for issuer in all_issuers:
                if issuer.zip:
                    ort = regional_service.get_ort_by_plz(issuer.zip)
                    if ort and ort.lower() == city_lower:
                        issuer_ids.append(issuer.id)

            if not issuer_ids:
                return Response({
                    'city': city,
                    'totalCompetencyHours': 0,
                    'competencies': [],
                })

            # Get badge instances from these city issuers (only network-relevant badges)
            network_badge_class_ids = self.get_network_relevant_badge_class_ids(network)
            badge_instances = BadgeInstance.objects.filter(
                revoked=False,
                issuer_id__in=issuer_ids,
                badgeclass_id__in=network_badge_class_ids
            )

            # Get badge class IDs (already filtered to network-relevant)
            badge_class_ids = list(badge_instances.values_list('badgeclass_id', flat=True).distinct())

            # Get competency extensions for these badge classes
            competency_extensions = BadgeClassExtension.objects.filter(
                badgeclass_id__in=badge_class_ids,
                name='extensions:CompetencyExtension'
            )

            # Build mapping of badgeclass_id -> competencies with study load
            badgeclass_competencies = {}
            for ext in competency_extensions:
                try:
                    ext_data = ext.original_json
                    if isinstance(ext_data, str):
                        ext_data = json.loads(ext_data)

                    # Normalize to list (can be list or single dict)
                    if not isinstance(ext_data, list):
                        ext_data = [ext_data]

                    competencies_list = []
                    for comp in ext_data:
                        if isinstance(comp, dict) and 'name' in comp:
                            competencies_list.append({
                                'name': comp.get('name', ''),
                                'studyLoad': comp.get('studyLoad', 0) or 0,
                                'escoUri': comp.get('framework_identifier', ''),
                                'category': comp.get('category', ''),
                            })

                    badgeclass_competencies[ext.badgeclass_id] = competencies_list
                except (json.JSONDecodeError, AttributeError, TypeError) as e:
                    logger.warning(f"Error parsing competency extension: {e}")
                    continue

            # Aggregate competencies from badge instances
            from collections import defaultdict
            competency_stats = defaultdict(lambda: {
                'name': '',
                'hours': 0,
                'escoUri': '',
                'category': '',
                'badge_count': 0,
            })

            total_hours = 0
            for bi in badge_instances:
                competencies_list = badgeclass_competencies.get(bi.badgeclass_id, [])
                counted_for_badge = set()

                for comp in competencies_list:
                    comp_name = comp['name']
                    if not comp_name:
                        continue

                    # Use name as key (case-insensitive)
                    comp_key = comp_name.lower()

                    # Convert studyLoad from minutes to hours
                    study_hours = round(comp['studyLoad'] / 60) if comp['studyLoad'] else 0

                    competency_stats[comp_key]['name'] = comp_name
                    competency_stats[comp_key]['hours'] += study_hours
                    total_hours += study_hours

                    if comp['escoUri'] and not competency_stats[comp_key]['escoUri']:
                        competency_stats[comp_key]['escoUri'] = comp['escoUri']
                    if comp['category'] and not competency_stats[comp_key]['category']:
                        competency_stats[comp_key]['category'] = comp['category']

                    # Count each badge only once per competency
                    if comp_key not in counted_for_badge:
                        competency_stats[comp_key]['badge_count'] += 1
                        counted_for_badge.add(comp_key)

            # Sort by hours and limit
            sorted_competencies = sorted(
                competency_stats.items(),
                key=lambda x: x[1]['hours'],
                reverse=True
            )[:limit]

            competencies = []
            for comp_key, stats in sorted_competencies:
                competencies.append({
                    'name': stats['name'],
                    'hours': stats['hours'],
                    'escoUri': stats['escoUri'],
                    'category': stats['category'],
                    'badgeCount': stats['badge_count'],
                })

            response_data = {
                'city': city,
                'totalCompetencyHours': total_hours,
                'competencies': competencies,
            }

            return Response(response_data)

        except Http404:
            raise
        except Exception as e:
            logger.exception(f"Error fetching socialspace competencies: {e}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
