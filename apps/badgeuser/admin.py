from django.db import models
from django.contrib.admin import ModelAdmin, TabularInline
from django.core.cache import cache
from django.utils import timezone
from django.utils.html import format_html
from django_object_actions import DjangoObjectActions

from mainsite.admin import badgr_admin
from mainsite.utils import backoff_cache_key
from .models import (
    BadgeUser,
    EmailAddressVariant,
    TermsVersion,
    TermsAgreement,
    CachedEmailAddress,
    UserPreference,
    UserRecipientIdentifier,
)
from issuer.models import Issuer


class TermsAgreementInline(TabularInline):
    model = TermsAgreement
    fk_name = "user"
    extra = 0
    max_num = 0
    can_delete = False
    readonly_fields = ("created_at", "terms_version")
    fields = ("created_at", "terms_version")


class EmailAddressInline(TabularInline):
    model = CachedEmailAddress
    fk_name = "user"
    extra = 0
    fields = ("email", "verified", "primary")


class UserRecipientIdentifierInline(TabularInline):
    model = UserRecipientIdentifier
    fk_name = "user"
    extra = 0
    fields = ("type", "identifier", "verified")


class BadgeUserAdmin(DjangoObjectActions, ModelAdmin):
    readonly_fields = (
        "entity_id",
        "date_joined",
        "last_login",
        "username",
        "entity_id",
        "agreed_terms_version",
        "login_backoff",
        "has_usable_password",
    )
    list_display = (
        "email",
        "first_name",
        "last_name",
        "is_active",
        "is_staff",
        "zip_code",
        "issuers",
        "assertion_count",
        "date_joined",
    )
    list_filter = ("is_active", "is_staff", "is_superuser", "date_joined", "last_login")
    search_fields = (
        "email",
        "first_name",
        "last_name",
        "username",
        "entity_id",
        "zip_code",
    )
    fieldsets = (
        (
            "Metadata",
            {
                "fields": (
                    "entity_id",
                    "username",
                    "date_joined",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            None,
            {
                "fields": (
                    "email",
                    "first_name",
                    "last_name",
                    "badgrapp",
                    "zip_code",
                    "agreed_terms_version",
                    "marketing_opt_in",
                    "secure_password_set",
                    "quota_release_informed",
                )
            },
        ),
        (
            "Access",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "has_usable_password",
                    "password",
                    "login_backoff",
                )
            },
        ),
        ("Permissions", {"fields": ("groups", "user_permissions")}),
    )
    inlines = [
        EmailAddressInline,
        UserRecipientIdentifierInline,
        TermsAgreementInline,
    ]
    change_actions = ["clear_login_backoff"]

    def get_queryset(self, request):
        qs = super(BadgeUserAdmin, self).get_queryset(request)
        qs = qs.annotate(number_of_assertions=models.Count("badgeinstance"))
        return qs

    def clear_login_backoff(self, request, obj):
        for email in obj.all_verified_recipient_identifiers:
            cache_key = backoff_cache_key(email)
            cache.delete(cache_key)

    clear_login_backoff.label = "Clear login backoffs"
    clear_login_backoff.short_description = (
        "Remove blocks created by failed login attempts"
    )

    def login_backoff(self, obj):
        blocks = []
        for email in obj.all_verified_recipient_identifiers:
            cache_key = backoff_cache_key(email)
            backoff = cache.get(cache_key)
            if backoff is not None:
                blocks += [
                    "{email} - {ip}: {until} ({count} attempts)".format(
                        email=email,
                        ip=key,
                        until=backoff[key]
                        .get("until")
                        .astimezone(timezone.get_current_timezone())
                        .strftime("%Y-%m-%d %H:%M:%S"),
                        count=backoff[key].get("count"),
                    )
                    for key in backoff.keys()
                ]
        if len(blocks):
            return format_html("<ul><li>{}</li></ul>".format("</li><li>".join(blocks)))
        return "None"

    login_backoff.allow_tags = True

    def assertion_count(self, obj):
        return obj.number_of_assertions

    assertion_count.admin_order_field = "number_of_assertions"

    def issuers(self, obj):
        issuers = Issuer.objects.filter(staff=obj)
        return ",".join([x.name for x in issuers])


badgr_admin.register(BadgeUser, BadgeUserAdmin)


class EmailAddressVariantAdmin(ModelAdmin):
    search_fields = (
        "canonical_email",
        "email",
    )
    list_display = (
        "email",
        "canonical_email",
    )
    raw_id_fields = ("canonical_email",)


badgr_admin.register(EmailAddressVariant, EmailAddressVariantAdmin)


class TermsVersionAdmin(ModelAdmin):
    list_display = ("version", "created_at", "is_active")
    readonly_fields = (
        "created_at",
        "created_by",
        "updated_at",
        "updated_by",
        "latest_terms_version",
    )
    fieldsets = (
        (
            "Metadata",
            {
                "fields": ("created_at", "created_by", "updated_at", "updated_by"),
                "classes": ("collapse",),
            },
        ),
        (
            None,
            {
                "fields": (
                    "latest_terms_version",
                    "is_active",
                    "version",
                    "short_description",
                )
            },
        ),
    )

    def latest_terms_version(self, obj):
        return TermsVersion.cached.latest_version()

    latest_terms_version.short_description = "Current Terms Version"


badgr_admin.register(TermsVersion, TermsVersionAdmin)


class RecipientIdentifierAdmin(ModelAdmin):
    list_display = ("type", "identifier", "user", "verified")
    list_filter = (
        "type",
        "verified",
    )
    search_fields = ("identifier", "user__email")
    raw_id_fields = ("user",)


badgr_admin.register(UserRecipientIdentifier, RecipientIdentifierAdmin)


class UserPreferencesAdmin(ModelAdmin):
    list_display = ("user",)
    raw_id_fields = ("user",)


badgr_admin.register(UserPreference, UserPreferencesAdmin)
