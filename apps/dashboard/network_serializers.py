# encoding: utf-8
"""
Network Dashboard serializers following the OpenAPI specification.

These serializers match the schema defined in dashboard-overview-openapi.yaml
"""
from rest_framework import serializers


class NetworkKPIDataSerializer(serializers.Serializer):
    """
    Serializer for individual KPI data.

    KPI IDs:
    - institutions_count: Institutionen im Netzwerk
    - badges_created: verschiedene Badges erstellt
    - badges_awarded: Badges insgesamt vergeben
    - participation_badges: TEILNAHME-Badges
    - competency_badges: KOMPETENZ-Badges
    - competency_hours: Stunden Kompetenzen gestärkt
    - learners_count: Lernende Personen mit Badges
    - badges_per_month: Badges durchschnittlich pro Monat
    - learners_with_paths: Lernende mit Netzwerkpfaden
    """
    id = serializers.ChoiceField(
        choices=[
            'institutions_count',
            'badges_created',
            'badges_awarded',
            'participation_badges',
            'competency_badges',
            'competency_hours',
            'competency_hours_last_month',
            'learners_count',
            'badges_per_month',
            'learners_with_paths',
        ],
        help_text="Unique KPI identifier for frontend translation mapping"
    )
    value = serializers.IntegerField(
        help_text="The numeric value of the KPI"
    )
    trend = serializers.ChoiceField(
        choices=['up', 'down', 'stable'],
        required=False,
        help_text="Trend direction indicator"
    )
    trendValue = serializers.IntegerField(
        required=False,
        help_text="Numeric value of the trend change"
    )
    trendPeriod = serializers.ChoiceField(
        choices=['lastMonth', 'lastWeek', 'lastYear'],
        required=False,
        help_text="Period for trend calculation"
    )
    hasMonthlyDetails = serializers.BooleanField(
        default=False,
        help_text="Whether monthly details are available for drill-down"
    )


class NetworkKPIsFiltersSerializer(serializers.Serializer):
    """Serializer for KPIs filter metadata"""
    deliveryMethod = serializers.CharField(
        required=False,
        allow_null=True,
        help_text="Delivery method filter applied (online, in-person, or null)"
    )


class NetworkKPIsMetadataSerializer(serializers.Serializer):
    """Serializer for KPIs metadata"""
    filters = NetworkKPIsFiltersSerializer(required=False)
    lastUpdated = serializers.CharField(
        help_text="ISO timestamp when data was last updated"
    )


class NetworkKPIsResponseSerializer(serializers.Serializer):
    """Serializer for Network KPIs response"""
    metadata = NetworkKPIsMetadataSerializer(required=False)
    kpis = NetworkKPIDataSerializer(many=True)


class NetworkCompetencyAreaDataSerializer(serializers.Serializer):
    """
    Serializer for competency area data.

    Frontend assigns colors and icons based on area ID.
    """
    id = serializers.CharField(
        help_text="Unique identifier for the competency area"
    )
    name = serializers.CharField(
        help_text="Display name of the competency area"
    )
    value = serializers.FloatField(
        help_text="Percentage value for bubble size visualization"
    )
    weight = serializers.IntegerField(
        help_text="Absolute count for bubble weight calculation"
    )


class NetworkCompetencyAreasMetadataSerializer(serializers.Serializer):
    """Serializer for competency areas metadata"""
    totalAreas = serializers.IntegerField(
        help_text="Total number of competency areas returned"
    )
    lastUpdated = serializers.CharField(
        help_text="Date when data was last updated (YYYY-MM-DD)"
    )


class NetworkCompetencyAreasResponseSerializer(serializers.Serializer):
    """Serializer for Network Competency Areas response"""
    metadata = NetworkCompetencyAreasMetadataSerializer()
    data = NetworkCompetencyAreaDataSerializer(many=True)


class NetworkTopBadgeDataSerializer(serializers.Serializer):
    """
    Serializer for top badge data.

    Frontend assigns icons and colors based on rank position.
    """
    rank = serializers.IntegerField(
        min_value=1,
        help_text="Ranking position (1, 2, 3, etc.)"
    )
    badgeId = serializers.CharField(
        help_text="Unique identifier for the badge"
    )
    badgeTitle = serializers.CharField(
        help_text="Human-readable badge title"
    )
    image = serializers.URLField(
        allow_blank=True,
        help_text="URL to the badge image"
    )
    count = serializers.IntegerField(
        min_value=0,
        help_text="Number of times this badge was awarded"
    )


class NetworkTopBadgesMetadataSerializer(serializers.Serializer):
    """Serializer for top badges metadata"""
    totalBadges = serializers.IntegerField(
        help_text="Total number of badges in the network"
    )
    lastUpdated = serializers.CharField(
        help_text="Date when data was last updated (YYYY-MM-DD)"
    )


class NetworkTopBadgesResponseSerializer(serializers.Serializer):
    """Serializer for Network Top Badges response"""
    metadata = NetworkTopBadgesMetadataSerializer()
    badges = NetworkTopBadgeDataSerializer(many=True)


class NetworkRecentActivityDataSerializer(serializers.Serializer):
    """
    Serializer for recent badge award activity data.
    Contains badge and issuer information for linking to detail pages.
    """
    date = serializers.CharField(
        help_text="Date when the badge was awarded (YYYY-MM-DD)"
    )
    badgeId = serializers.CharField(
        help_text="Unique identifier (slug) for the badge. Use for linking to badge detail page: /public/badges/{badgeId}"
    )
    badgeTitle = serializers.CharField(
        help_text="Human-readable badge title"
    )
    badgeImage = serializers.URLField(
        allow_blank=True,
        help_text="URL to the badge image"
    )
    issuerId = serializers.CharField(
        help_text="Unique identifier (slug) for the issuer/institution. Use for linking to issuer page: /issuer/issuers/{issuerId}"
    )
    issuerName = serializers.CharField(
        help_text="Human-readable name of the institution that awarded the badge"
    )
    recipientCount = serializers.IntegerField(
        min_value=1,
        help_text="Number of recipients who received this badge in this award event"
    )


class NetworkRecentActivityMetadataSerializer(serializers.Serializer):
    """Serializer for recent activity metadata"""
    totalActivities = serializers.IntegerField(
        help_text="Total number of activities returned"
    )
    lastUpdated = serializers.CharField(
        help_text="Date when data was last updated (YYYY-MM-DD)"
    )


class NetworkRecentActivityResponseSerializer(serializers.Serializer):
    """Serializer for Network Recent Activity response"""
    metadata = NetworkRecentActivityMetadataSerializer()
    activities = NetworkRecentActivityDataSerializer(many=True)


# ==========================================
# Strengthened Competencies Serializers
# ==========================================

class NetworkStrengthenedCompetencyDataSerializer(serializers.Serializer):
    """
    Serializer for individual strengthened competency data.
    """
    competencyId = serializers.CharField(
        help_text="Unique identifier for the competency"
    )
    title = serializers.CharField(
        help_text="Display title (fallback if titleKey not translated)"
    )
    titleKey = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="i18n translation key for the competency title"
    )
    hours = serializers.IntegerField(
        min_value=0,
        help_text="Total competency hours invested"
    )
    escoUri = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="ESCO framework URI for standardized competency reference"
    )


class NetworkStrengthenedCompetenciesMetadataSerializer(serializers.Serializer):
    """Serializer for strengthened competencies metadata"""
    totalCompetencies = serializers.IntegerField(
        help_text="Total number of unique competencies in the network"
    )
    totalHours = serializers.IntegerField(
        help_text="Total competency hours across all competencies"
    )
    lastUpdated = serializers.CharField(
        help_text="Date when data was last updated (YYYY-MM-DD)"
    )


class NetworkStrengthenedCompetenciesResponseSerializer(serializers.Serializer):
    """Serializer for Network Strengthened Competencies response"""
    metadata = NetworkStrengthenedCompetenciesMetadataSerializer()
    competencies = NetworkStrengthenedCompetencyDataSerializer(many=True)


# ==========================================
# Badge Awards Timeline Serializers
# ==========================================

class NetworkBadgeAwardsByTypeSerializer(serializers.Serializer):
    """Serializer for badge type breakdown"""
    participation = serializers.IntegerField(
        min_value=0,
        help_text="Participation badges (Teilnahmezertifikate)"
    )
    competency = serializers.IntegerField(
        min_value=0,
        help_text="Competency badges (Kompetenzbadges)"
    )
    learningpath = serializers.IntegerField(
        min_value=0,
        help_text="Learning path badges (Micro Degrees)"
    )


class NetworkBadgeAwardTimelineEntrySerializer(serializers.Serializer):
    """
    Serializer for individual timeline entry.
    """
    date = serializers.CharField(
        help_text="Start date of the period (ISO 8601)"
    )
    count = serializers.IntegerField(
        min_value=0,
        help_text="Total badge count for this period"
    )
    byType = NetworkBadgeAwardsByTypeSerializer(
        required=False,
        help_text="Breakdown by badge type"
    )


class NetworkBadgeAwardsTimelineMetadataSerializer(serializers.Serializer):
    """Serializer for badge awards timeline metadata"""
    totalAwards = serializers.IntegerField(
        help_text="Total badge awards in the period"
    )
    year = serializers.IntegerField(
        allow_null=True,
        required=False,
        help_text="Year filter applied (null if not filtered)"
    )
    groupBy = serializers.ChoiceField(
        choices=['day', 'week', 'month'],
        help_text="Time grouping used"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkBadgeAwardsTimelineResponseSerializer(serializers.Serializer):
    """Serializer for Network Badge Awards Timeline response"""
    metadata = NetworkBadgeAwardsTimelineMetadataSerializer()
    timeline = NetworkBadgeAwardTimelineEntrySerializer(many=True)


# ==========================================
# Badge Type Distribution Serializers
# ==========================================

class NetworkBadgeTypeDistributionEntrySerializer(serializers.Serializer):
    """
    Serializer for badge type distribution entry.
    """
    type = serializers.ChoiceField(
        choices=['participation', 'competency', 'learningpath'],
        help_text="Badge type identifier"
    )
    typeKey = serializers.CharField(
        help_text="i18n translation key for badge type label"
    )
    count = serializers.IntegerField(
        min_value=0,
        help_text="Number of badges of this type"
    )
    percentage = serializers.FloatField(
        min_value=0,
        max_value=100,
        help_text="Percentage of total badges (0-100)"
    )


class NetworkBadgeTypeDistributionMetadataSerializer(serializers.Serializer):
    """Serializer for badge type distribution metadata"""
    totalBadges = serializers.IntegerField(
        help_text="Total number of badges"
    )
    year = serializers.IntegerField(
        allow_null=True,
        required=False,
        help_text="Year filter applied (null if not filtered)"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkBadgeTypeDistributionResponseSerializer(serializers.Serializer):
    """Serializer for Network Badge Type Distribution response"""
    metadata = NetworkBadgeTypeDistributionMetadataSerializer()
    distribution = NetworkBadgeTypeDistributionEntrySerializer(many=True)


# ==========================================
# Delivery Method Distribution Serializers
# ==========================================

class DeliveryMethodValueSerializer(serializers.Serializer):
    """
    Serializer for delivery method value with count and percentage.
    """
    value = serializers.IntegerField(
        min_value=0,
        help_text="Number of badges with this delivery method"
    )
    percentage = serializers.FloatField(
        min_value=0,
        max_value=100,
        help_text="Percentage of total badges (0-100)"
    )


class NetworkDeliveryMethodDistributionMetadataSerializer(serializers.Serializer):
    """Serializer for delivery method distribution metadata"""
    totalBadges = serializers.IntegerField(
        help_text="Total number of badges"
    )
    year = serializers.IntegerField(
        allow_null=True,
        required=False,
        help_text="Year filter applied (null if not filtered)"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkDeliveryMethodDistributionResponseSerializer(serializers.Serializer):
    """
    Serializer for Network Delivery Method Distribution response.

    Distribution of badges by delivery method (Online vs Präsenz/In-Person).
    Based on the activity_online field of BadgeInstance.
    """
    metadata = NetworkDeliveryMethodDistributionMetadataSerializer()
    total = serializers.IntegerField(
        min_value=0,
        help_text="Total number of badges across all delivery methods"
    )
    online = DeliveryMethodValueSerializer(
        help_text="Online/Remote delivery statistics"
    )
    inPerson = DeliveryMethodValueSerializer(
        help_text="In-person/Präsenz delivery statistics"
    )


# ==========================================
# Recent Badge Awards Serializers
# ==========================================

class BadgeCompetencyWithEscoSerializer(serializers.Serializer):
    """
    Serializer for a competency associated with a badge, including ESCO reference.
    """
    name = serializers.CharField(
        help_text="Human-readable name of the competency"
    )
    escoUri = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        help_text="ESCO framework URI for standardized competency reference"
    )


class NetworkRecentBadgeAwardEntrySerializer(serializers.Serializer):
    """
    Serializer for a badge award entry with competency details.
    """
    date = serializers.CharField(
        help_text="Date when the badge was awarded (ISO 8601)"
    )
    badgeId = serializers.CharField(
        help_text="Unique identifier (slug) for the badge"
    )
    badgeName = serializers.CharField(
        help_text="Human-readable badge title"
    )
    badgeImage = serializers.URLField(
        allow_blank=True,
        required=False,
        help_text="URL to the badge image"
    )
    badgeType = serializers.ChoiceField(
        choices=['participation', 'competency', 'learningpath'],
        required=False,
        help_text="Type of badge"
    )
    count = serializers.IntegerField(
        min_value=1,
        help_text="Number of times this badge was awarded on this date"
    )
    competencies = BadgeCompetencyWithEscoSerializer(
        many=True,
        required=False,
        help_text="List of competencies covered by this badge with ESCO URIs"
    )


class NetworkRecentBadgeAwardsMetadataSerializer(serializers.Serializer):
    """Serializer for recent badge awards metadata"""
    totalAwards = serializers.IntegerField(
        help_text="Total number of badge awards in the period"
    )
    periodStart = serializers.CharField(
        help_text="Start date of the period (ISO 8601)"
    )
    periodEnd = serializers.CharField(
        help_text="End date of the period (ISO 8601)"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkRecentBadgeAwardsResponseSerializer(serializers.Serializer):
    """Serializer for Network Recent Badge Awards response"""
    metadata = NetworkRecentBadgeAwardsMetadataSerializer()
    awards = NetworkRecentBadgeAwardEntrySerializer(many=True)


# ==========================================
# Badge Locations Serializers
# ==========================================

class NetworkBadgeLocationEntrySerializer(serializers.Serializer):
    """
    Serializer for individual badge location entry.

    Represents aggregated badge distribution for a geographic location (city).
    Data is aggregated by city name - a city with multiple ZIP codes will have all badges combined.
    """
    city = serializers.CharField(
        help_text="City name or 'other' for aggregated other locations"
    )
    badgeCount = serializers.IntegerField(
        min_value=0,
        help_text="Number of badges in this city"
    )
    badgePercentage = serializers.FloatField(
        help_text="Percentage of total badges in this city"
    )


class NetworkBadgeLocationsMetadataSerializer(serializers.Serializer):
    """Serializer for badge locations metadata"""
    totalLocations = serializers.IntegerField(
        help_text="Total number of distinct locations"
    )
    totalBadges = serializers.IntegerField(
        help_text="Total number of badges across all locations"
    )
    deliveryMethod = serializers.CharField(
        required=False,
        allow_null=True,
        help_text="Active delivery method filter (online, in-person, or null for all)"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkBadgeLocationsResponseSerializer(serializers.Serializer):
    """Serializer for Network Badge Locations response"""
    metadata = NetworkBadgeLocationsMetadataSerializer()
    locations = NetworkBadgeLocationEntrySerializer(many=True)


# ==========================================
# LERNENDE (LEARNERS) SERIALIZERS
# ==========================================

class LearnerResidenceStatisticSerializer(serializers.Serializer):
    """
    Serializer for individual learner residence statistics.

    Represents learner distribution for a specific city.
    Use city='other' to identify the aggregated 'other locations' category.
    Data is aggregated by city name - a city with multiple ZIP codes will have all learners combined.
    """
    city = serializers.CharField(
        help_text="City name or 'other' for aggregated other locations"
    )
    learnerCount = serializers.IntegerField(
        min_value=0,
        help_text="Number of learners from this city"
    )
    percentage = serializers.FloatField(
        min_value=0,
        max_value=100,
        help_text="Percentage of total learners (0-100)"
    )


class LearnerGenderStatisticSerializer(serializers.Serializer):
    """
    Serializer for individual learner gender statistics.

    Represents learner count for a specific gender category.
    Gender labels should be handled by i18n in the frontend.
    """
    gender = serializers.ChoiceField(
        choices=['male', 'female', 'diverse', 'noAnswer'],
        help_text="Gender category identifier for i18n translation"
    )
    count = serializers.IntegerField(
        min_value=0,
        help_text="Number of learners of this gender"
    )
    percentage = serializers.FloatField(
        min_value=0,
        max_value=100,
        help_text="Percentage of total learners (0-100)"
    )


class LearnerKPIDataSerializer(serializers.Serializer):
    """
    Serializer for KPI data with optional trend information.
    Matches the LearnerKPIData schema from learners.yaml.
    """
    value = serializers.IntegerField(
        min_value=0,
        help_text="The numeric value of the KPI"
    )
    trend = serializers.ChoiceField(
        choices=['up', 'down', 'stable'],
        required=False,
        allow_null=True,
        help_text="Trend direction indicator: up, down, or stable"
    )
    trendValue = serializers.FloatField(
        required=False,
        allow_null=True,
        help_text="Numeric change value, typically a percentage"
    )
    trendPeriod = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Time period for the trend calculation (e.g., 'lastMonth')"
    )


class NetworkLearnersOverviewKPIsSerializer(serializers.Serializer):
    """Serializer for learners overview KPIs with trend data"""
    totalLearners = LearnerKPIDataSerializer(
        help_text="Total number of learners with trend data"
    )
    totalCompetencyHours = LearnerKPIDataSerializer(
        help_text="Total competency hours with trend data"
    )


class NetworkLearnersOverviewMetadataSerializer(serializers.Serializer):
    """Serializer for learners overview metadata"""
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkLearnersOverviewResponseSerializer(serializers.Serializer):
    """
    Serializer for Network Learners Overview response.

    Returns comprehensive learner statistics for the Lernende tab.
    """
    metadata = NetworkLearnersOverviewMetadataSerializer(required=False)
    kpis = NetworkLearnersOverviewKPIsSerializer(
        help_text="Key performance indicators for learners"
    )
    residenceDistribution = LearnerResidenceStatisticSerializer(
        many=True,
        help_text="Learner distribution by residence (Wohnort)"
    )
    genderDistribution = LearnerGenderStatisticSerializer(
        many=True,
        help_text="Learner distribution by gender"
    )


class NetworkLearnersResidenceMetadataSerializer(serializers.Serializer):
    """Serializer for learners residence metadata"""
    totalLearners = serializers.IntegerField(
        help_text="Total number of learners across all cities"
    )
    totalCities = serializers.IntegerField(
        help_text="Total number of distinct cities (before grouping into Other)"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkLearnersResidenceResponseSerializer(serializers.Serializer):
    """Serializer for Network Learners Residence Distribution response"""
    metadata = NetworkLearnersResidenceMetadataSerializer()
    statistics = LearnerResidenceStatisticSerializer(many=True)


class ResidenceStrengthenedCompetencySerializer(serializers.Serializer):
    """
    Serializer for strengthened competency per residence/region.

    Used in the residence detail view to show top competencies for a specific region.
    """
    competencyId = serializers.CharField(
        help_text="Unique identifier for the competency"
    )
    competencyKey = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="i18n translation key for the competency"
    )
    title = serializers.CharField(
        help_text="Human-readable competency title"
    )
    areaKey = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="The competency area this competency belongs to"
    )
    count = serializers.IntegerField(
        min_value=0,
        help_text="Number of learners who strengthened this competency"
    )
    hours = serializers.IntegerField(
        min_value=0,
        help_text="Total hours invested in this competency"
    )
    badges = serializers.IntegerField(
        min_value=0,
        required=False,
        help_text="Number of badges awarded for this competency"
    )
    trend = serializers.ChoiceField(
        choices=['up', 'down', 'stable'],
        required=False,
        help_text="Trend direction compared to previous period"
    )
    trendValue = serializers.IntegerField(
        required=False,
        help_text="Numeric value of the trend change (percentage)"
    )
    escoUri = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        help_text="ESCO framework URI for standardized competency reference"
    )


class NetworkLearnersResidenceDetailMetadataSerializer(serializers.Serializer):
    """Serializer for residence detail metadata"""
    city = serializers.CharField(
        help_text="City name"
    )
    zipCodes = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="List of ZIP codes associated with this city"
    )
    totalLearners = serializers.IntegerField(
        min_value=0,
        help_text="Total learners from this city"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkLearnersResidenceDetailResponseSerializer(serializers.Serializer):
    """
    Serializer for Network Learners Residence Detail response.

    Drill-down view showing competency details for learners from a specific region.
    """
    metadata = NetworkLearnersResidenceDetailMetadataSerializer()
    topCompetencyAreas = NetworkCompetencyAreaDataSerializer(
        many=True,
        help_text="Top competency areas for learners from this region"
    )
    topStrengthenedCompetencies = ResidenceStrengthenedCompetencySerializer(
        many=True,
        help_text="Most strengthened individual competencies for learners from this region"
    )


class NetworkLearnersGenderMetadataSerializer(serializers.Serializer):
    """Serializer for learners gender metadata"""
    totalLearners = serializers.IntegerField(
        help_text="Total number of learners"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkLearnersGenderResponseSerializer(serializers.Serializer):
    """Serializer for Network Learners Gender Distribution response"""
    metadata = NetworkLearnersGenderMetadataSerializer()
    distribution = LearnerGenderStatisticSerializer(many=True)


class GenderIndividualCompetencySerializer(serializers.Serializer):
    """
    Serializer for individual competency per gender.

    Used in the gender detail view to show top competencies for a specific gender.
    """
    competencyId = serializers.CharField(
        help_text="Unique identifier for the competency"
    )
    name = serializers.CharField(
        help_text="Human-readable competency name"
    )
    count = serializers.IntegerField(
        min_value=0,
        help_text="Number of learners who strengthened this competency"
    )
    hours = serializers.IntegerField(
        min_value=0,
        help_text="Total hours invested in this competency"
    )
    escoUri = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        help_text="ESCO framework URI for standardized competency reference"
    )


class GenderTopBadgeSerializer(serializers.Serializer):
    """
    Serializer for top badge per gender.

    Used in the gender detail view to show top badges for a specific gender.
    """
    badgeId = serializers.CharField(
        help_text="Unique identifier for the badge"
    )
    name = serializers.CharField(
        help_text="Human-readable badge name"
    )
    count = serializers.IntegerField(
        min_value=0,
        help_text="Number of times this badge was awarded"
    )
    hours = serializers.IntegerField(
        min_value=0,
        required=False,
        help_text="Total hours for this badge"
    )
    image = serializers.URLField(
        allow_blank=True,
        required=False,
        help_text="URL to the badge image"
    )


class NetworkLearnersGenderDetailMetadataSerializer(serializers.Serializer):
    """Serializer for gender detail metadata. Gender labels should be handled by i18n."""
    gender = serializers.ChoiceField(
        choices=['male', 'female', 'diverse', 'noAnswer'],
        help_text="Gender category identifier for i18n translation"
    )
    totalLearners = serializers.IntegerField(
        min_value=0,
        help_text="Total learners of this gender"
    )
    totalBadges = serializers.IntegerField(
        min_value=0,
        help_text="Total badges awarded to this gender"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkLearnersGenderDetailResponseSerializer(serializers.Serializer):
    """
    Serializer for Network Learners Gender Detail response.

    Drill-down view showing competency and badge details for a specific gender.
    """
    metadata = NetworkLearnersGenderDetailMetadataSerializer()
    topCompetencyAreas = NetworkCompetencyAreaDataSerializer(
        many=True,
        help_text="Top competency areas for this gender"
    )
    topStrengthenedCompetencies = GenderIndividualCompetencySerializer(
        many=True,
        help_text="Most strengthened individual competencies for this gender"
    )
    topBadges = GenderTopBadgeSerializer(
        many=True,
        help_text="Top badges awarded to learners of this gender"
    )


# ==========================================
# SKILLS TREE SERIALIZERS
# ==========================================

class SkillBroaderCategorySerializer(serializers.Serializer):
    """
    Serializer for a broader category in the skill hierarchy.
    """
    uri = serializers.CharField(
        help_text="ESCO concept URI path"
    )
    pref_label = serializers.CharField(
        help_text="Preferred label for this category in the requested language"
    )


class SkillTreeEntrySerializer(serializers.Serializer):
    """
    Serializer for a skill entry with ESCO framework information and hierarchy.
    """
    concept_uri = serializers.CharField(
        help_text="ESCO skill URI path (relative to ESCO base URL)"
    )
    pref_label = serializers.CharField(
        help_text="Preferred skill label in the requested language"
    )
    studyLoad = serializers.IntegerField(
        min_value=0,
        help_text="Total study load in minutes for this skill across all badges"
    )
    broader = SkillBroaderCategorySerializer(
        many=True,
        required=False,
        help_text="Hierarchical parent categories (breadcrumbs) from root to this skill"
    )


class SkillsTreeFiltersSerializer(serializers.Serializer):
    """Serializer for skills tree applied filters"""
    region = serializers.CharField(
        allow_null=True,
        required=False,
        help_text="Region filter applied (null if not filtered)"
    )
    gender = serializers.CharField(
        allow_null=True,
        required=False,
        help_text="Gender filter applied (null if not filtered)"
    )


class NetworkSkillsTreeMetadataSerializer(serializers.Serializer):
    """Serializer for skills tree metadata"""
    totalSkills = serializers.IntegerField(
        help_text="Total number of unique skills in the result"
    )
    totalStudyLoad = serializers.IntegerField(
        help_text="Total study load (minutes) across all skills"
    )
    filters = SkillsTreeFiltersSerializer(
        required=False,
        help_text="Applied filters"
    )
    lastUpdated = serializers.CharField(
        help_text="Timestamp when data was last updated"
    )


class NetworkSkillsTreeResponseSerializer(serializers.Serializer):
    """
    Serializer for Network Skills Tree response.

    Returns skills with ESCO hierarchy, filterable by region and gender.
    """
    metadata = NetworkSkillsTreeMetadataSerializer()
    skills = SkillTreeEntrySerializer(many=True)
