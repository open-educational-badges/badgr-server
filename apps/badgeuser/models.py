from itertools import chain

import cachemodel
from allauth.account.models import EmailAddress, EmailConfirmation
from basic_models.models import IsActive
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import URLValidator, RegexValidator
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from rest_framework.authtoken.models import Token

from backpack.models import BackpackCollection
from badgeuser.tasks import (
    process_post_recipient_id_deletion,
    process_post_recipient_id_verification_change,
)
from entity.models import BaseVersionedEntity
from issuer.models import (
    Issuer,
    BadgeInstance,
    BaseAuditedModel,
    BaseAuditedModelDeletedWithUser,
)
from badgeuser.managers import CachedEmailAddressManager, BadgeUserManager
from badgeuser.utils import generate_badgr_username
from mainsite.models import ApplicationInfo


AUTH_USER_MODEL = getattr(settings, "AUTH_USER_MODEL", "auth.User")


class CachedEmailAddress(EmailAddress, cachemodel.CacheModel):
    objects = CachedEmailAddressManager()

    class Meta:
        proxy = True
        verbose_name = _("email address")
        verbose_name_plural = _("email addresses")

    def generate_forgot_password_time_cache_key(self):
        return "{}_forgot_request_date".format(self.email)

    def get_last_forgot_password_sent_time(self):
        cached_time = cache.get(self.generate_forgot_password_time_cache_key())
        return cached_time

    def set_last_forgot_password_sent_time(self, new_datetime):
        cache.set(self.generate_forgot_password_time_cache_key(), new_datetime)

    def generate_verification_time_cache_key(self):
        return "{}_verification_request_date".format(self.email)

    def get_last_verification_sent_time(self):
        cached_time = cache.get(self.generate_verification_time_cache_key())
        return cached_time

    def set_last_verification_sent_time(self, new_datetime):
        cache.set(self.generate_verification_time_cache_key(), new_datetime)

    def publish(self):
        super(CachedEmailAddress, self).publish()
        self.publish_by("email")
        self.user.publish()

    def delete(self, *args, **kwargs):
        user = self.user
        self.publish_delete("email")
        self.publish_delete("pk")
        process_post_recipient_id_deletion.delay(self.email)
        super(CachedEmailAddress, self).delete(*args, **kwargs)
        user.publish()

    def set_as_primary(self, conditional=False):
        # shadow parent function, but use CachedEmailAddress manager to ensure cache gets updated
        old_primary = CachedEmailAddress.objects.get_primary(self.user)
        if old_primary:
            if conditional:
                return False
            old_primary.primary = False
            old_primary.save()
        return super(CachedEmailAddress, self).set_as_primary(conditional=conditional)

    def save(self, *args, **kwargs):
        super(CachedEmailAddress, self).save(*args, **kwargs)
        process_post_recipient_id_verification_change.delay(
            self.email, "email", self.verified
        )
        if (
            not self.emailaddressvariant_set.exists()
            and self.email != self.email.lower()
        ):
            self.add_variant(self.email.lower())

    @cachemodel.cached_method(auto_publish=True)
    def cached_variants(self):
        return self.emailaddressvariant_set.all()

    def cached_variant_emails(self):
        return [e.email for e in self.cached_variants()]

    def add_variant(self, email_variation):
        existing_variants = EmailAddressVariant.objects.filter(
            canonical_email=self, email=email_variation
        )
        if email_variation not in [e.email for e in existing_variants.all()]:
            return EmailAddressVariant.objects.create(
                canonical_email=self, email=email_variation
            )
        else:
            raise ValidationError(
                "Email variant {} already exists".format(email_variation)
            )


class ProxyEmailConfirmation(EmailConfirmation):
    class Meta:
        proxy = True
        verbose_name = _("email confirmation")
        verbose_name_plural = _("email confirmations")


class EmailAddressVariant(models.Model):
    email = models.EmailField(blank=False)
    canonical_email = models.ForeignKey(
        CachedEmailAddress, blank=False, on_delete=models.CASCADE
    )

    def save(self, *args, **kwargs):
        self.is_valid(raise_exception=True)

        super(EmailAddressVariant, self).save(*args, **kwargs)
        self.canonical_email.save()

    def __str__(self):
        return self.email

    @property
    def verified(self):
        return self.canonical_email.verified

    def is_valid(self, raise_exception=False):
        def fail(message):
            if raise_exception:
                raise ValidationError(message)
            else:
                self.error = message
                return False

        if not self.canonical_email_id:
            try:
                self.canonical_email = CachedEmailAddress.cached.get(email=self.email)
            except CachedEmailAddress.DoesNotExist:
                fail("Canonical Email Address not found")

        if not self.canonical_email.email.lower() == self.email.lower():
            fail("New EmailAddressVariant does not match stored email address.")

        return True


class UserRecipientIdentifier(cachemodel.CacheModel):
    """
    Holds recipient identifiers that are not email addresses (emails are in allauth.account.models.EmailAddress).

    In the long term, this should be extended to support email address identifiers as well.
    """

    IDENTIFIER_TYPE_URL = "url"
    IDENTIFIER_TYPE_TELEPHONE = "telephone"
    IDENTIFIER_TYPE_CHOICES = (
        (IDENTIFIER_TYPE_URL, "URL"),
        (IDENTIFIER_TYPE_TELEPHONE, "Phone Number"),
    )
    IDENTIFIER_VALIDATORS = {
        IDENTIFIER_TYPE_URL: (URLValidator(),),
        IDENTIFIER_TYPE_TELEPHONE: (
            RegexValidator(
                regex=r"^\+[1-9]\d{1,14}$",
                message="Enter a valid Phone Number in E.164 format, like +12225553333",
            ),
        ),
    }
    type = models.CharField(
        max_length=9, choices=IDENTIFIER_TYPE_CHOICES, default=IDENTIFIER_TYPE_URL
    )
    identifier = models.CharField(max_length=255)
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE)
    verified = models.BooleanField(default=False)

    class Meta:
        unique_together = ("user", "type", "identifier")

    def get_identifier_validators(self):
        return UserRecipientIdentifier.IDENTIFIER_VALIDATORS[self.type]

    def validate_identifier(self):
        # format-specific validation
        for validator in self.get_identifier_validators():
            validator(self.identifier)

        # regardless of format, only one user may have verified a given identifier
        if (
            self.verified
            and UserRecipientIdentifier.objects.filter(
                identifier=self.identifier, type=self.type, verified=True
            )
            .exclude(pk=self.pk)
            .exists()
        ):
            raise ValidationError("Identifier already verified by another user.")

    def clean_fields(self, exclude=None):
        super(UserRecipientIdentifier, self).clean_fields(exclude=exclude)
        self.validate_identifier()

    def save(self, *args, **kwargs):
        self.validate_identifier()
        super(UserRecipientIdentifier, self).save(*args, **kwargs)
        process_post_recipient_id_verification_change.delay(
            self.identifier, self.type, self.verified
        )

    def publish(self):
        super(UserRecipientIdentifier, self).publish()
        self.user.publish()

    def delete(self):
        self.publish_delete("identifier")
        super(UserRecipientIdentifier, self).delete()
        process_post_recipient_id_deletion.delay(self.identifier)


class BadgeUser(BaseVersionedEntity, AbstractUser, cachemodel.CacheModel):
    """
    A full-featured user model that can be an Earner, Issuer, or Consumer of Open Badges
    """

    entity_class_name = "BadgeUser"

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    badgrapp = models.ForeignKey(
        "mainsite.BadgrApp",
        blank=True,
        null=True,
        default=None,
        on_delete=models.SET_NULL,
    )

    marketing_opt_in = models.BooleanField(default=False)

    secure_password_set = models.BooleanField(default=True)

    quota_release_informed = models.BooleanField(default=False)

    zip_code = models.CharField(max_length=100, blank=True, default=None, null=True)

    objects = BadgeUserManager()

    class Meta:
        verbose_name = _("badge user")
        verbose_name_plural = _("badge users")
        db_table = "users"

    def __str__(self):
        primary_identifier = self.email or next(
            (e for e in self.all_verified_recipient_identifiers), ""
        )
        return "{} ({})".format(self.get_full_name(), primary_identifier)

    def get_full_name(self):
        return "%s %s" % (self.first_name, self.last_name)

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.primary_email], **kwargs)

    def publish(self):
        super(BadgeUser, self).publish()
        self.publish_by("username")

    def delete(self, *args, **kwargs):
        # If the user is staff for an institution, the ownership needs to be transferred.
        # Therefore we remember the pks of the relevant institutions
        staff_contact_pks = [
            o.pk for o in self.issuerstaff_set.all() if o.is_staff_contact()
        ]
        staff_issuers = Issuer.objects.filter(issuerstaff__in=staff_contact_pks)
        staff_issuers_pks = [o.pk for o in staff_issuers]

        cached_emails = self.cached_emails()
        if cached_emails.exists():
            for email in cached_emails:
                email.delete()
        super(BadgeUser, self).delete(*args, **kwargs)

        # Here we transfer the ownership by restoring a valid contact email
        # (which also makes sure ownership exists)
        staff_issuers = Issuer.objects.filter(pk__in=staff_issuers_pks)
        for staff_issuer in staff_issuers:
            staff_issuer.new_contact_email()

        self.publish_delete("username")

    @cachemodel.cached_method(auto_publish=True)
    def cached_verified_urls(self):
        return [
            r.identifier
            for r in self.userrecipientidentifier_set.filter(
                verified=True, type=UserRecipientIdentifier.IDENTIFIER_TYPE_URL
            )
        ]

    @cachemodel.cached_method(auto_publish=True)
    def cached_verified_phone_numbers(self):
        return [
            r.identifier
            for r in self.userrecipientidentifier_set.filter(
                verified=True, type=UserRecipientIdentifier.IDENTIFIER_TYPE_TELEPHONE
            )
        ]

    @cachemodel.cached_method(auto_publish=True)
    def cached_emails(self):
        if not self.pk:
            return []
        return CachedEmailAddress.objects.filter(user=self)

    @cachemodel.cached_method(auto_publish=True)
    def cached_backpackcollections(self):
        return BackpackCollection.objects.filter(created_by=self)

    @property
    def email_items(self):
        return self.cached_emails()

    @email_items.setter
    def email_items(self, value):
        """
        Update this users EmailAddress from a list of BadgeUserEmailSerializerV2 data
        :param value: list(BadgeUserEmailSerializerV2)
        :return: None
        """
        return self.set_email_items(value)

    def set_email_items(
        self,
        value,
        send_confirmations=True,
        allow_verify=False,
        is_privileged_user=False,
    ):
        """
        If value is empty and the user is privileged, assume they meant to remove the users email and allow it.
        E.g. They are preforming some sort of ELT use case
        """
        if is_privileged_user and len(value) == 0:
            for email_address in self.email_items:
                email_address.delete()
            self.email = ""
            self.save()

        else:
            if len(value) < 1:
                raise ValidationError("Must have at least 1 email")

            new_email_idx = {d["email"]: d for d in value}

            primary_count = sum(1 if d.get("primary", False) else 0 for d in value)

            if primary_count != 1:
                raise ValidationError("Must have exactly 1 primary email")
            requested_primary = [d for d in value if d.get("primary", False)][0]

            with transaction.atomic():
                # add or update existing items
                for email_data in value:
                    primary = email_data.get("primary", False)
                    verified = email_data.get("verified", False)
                    emailaddress, created = CachedEmailAddress.cached.get_or_create(
                        email=email_data["email"],
                        defaults={"user": self, "primary": primary},
                    )
                    if not created:
                        dirty = False

                        if emailaddress.user_id == self.id:
                            # existing email address owned by user
                            emailaddress.primary = primary
                            dirty = True
                        elif not emailaddress.verified:
                            # existing unverified email address, handover to this user
                            emailaddress.user = self
                            emailaddress.primary = primary
                            emailaddress.save()  # in this case, don't mark as dirty
                            emailaddress.send_confirmation()
                        else:
                            # existing email address used by someone else
                            raise ValidationError(
                                "Email '{}' may already be in use".format(
                                    email_data.get("email")
                                )
                            )

                        if allow_verify and verified != emailaddress.verified:
                            emailaddress.verified = verified
                            dirty = True

                        if dirty:
                            emailaddress.save()
                    else:
                        # email is new
                        if allow_verify and email_data.get("verified") is True:
                            emailaddress.verified = True
                            emailaddress.save()
                        if (
                            emailaddress.verified is False
                            and created is True
                            and send_confirmations is True
                        ):
                            # new email address send a confirmation
                            emailaddress.send_confirmation()

                    if not emailaddress.verified:
                        continue  # only verified email addresses may have variants. Don't bother trying otherwise.

                    requested_variants = email_data.get("cached_variant_emails", [])
                    existing_variant_emails = emailaddress.cached_variant_emails()
                    for requested_variant in requested_variants:
                        if requested_variant not in existing_variant_emails:
                            EmailAddressVariant.objects.create(
                                canonical_email=emailaddress, email=requested_variant
                            )

                # remove old items
                for emailaddress in self.email_items:
                    if emailaddress.email.lower() not in (
                        lower_case_idx.lower() for lower_case_idx in new_email_idx
                    ):
                        emailaddress.delete()

            if self.email != requested_primary:
                self.email = requested_primary["email"]
                self.save()

    def cached_email_variants(self):
        return chain.from_iterable(
            email.cached_variants() for email in self.cached_emails()
        )

    def can_add_variant(self, email):
        try:
            canonical_email = CachedEmailAddress.objects.get(
                email=email, user=self, verified=True
            )
        except CachedEmailAddress.DoesNotExist:
            return False

        if (
            email != canonical_email.email
            and email not in [e.email for e in canonical_email.cached_variants()]
            and EmailAddressVariant(
                email=email, canonical_email=canonical_email
            ).is_valid()
        ):
            return True
        return False

    @property
    def primary_email(self):
        primaries = [e for e in self.cached_emails() if e.primary]
        if len(primaries) > 0:
            return primaries[0].email
        return self.email

    @property
    def verified_emails(self):
        return [e for e in self.cached_emails() if e.verified]

    @property
    def verified(self):
        if self.is_superuser:
            return True

        if len(self.all_verified_recipient_identifiers) > 0:
            return True

        return False

    @property
    def all_recipient_identifiers(self):
        return (
            [e.email for e in self.cached_emails()]
            + [e.email for e in self.cached_email_variants()]
            + self.cached_verified_urls()
            + self.cached_verified_phone_numbers()
        )

    @property
    def all_verified_recipient_identifiers(self):
        return (
            [e.email for e in self.cached_emails() if e.verified]
            + [e.email for e in self.cached_email_variants()]
            + self.cached_verified_urls()
            + self.cached_verified_phone_numbers()
        )

    def is_email_verified(self, email):
        if email in self.all_verified_recipient_identifiers:
            return True

        try:
            app_infos = ApplicationInfo.objects.filter(application__user=self)
            if any(app_info.trust_email_verification for app_info in app_infos):
                return True
        except ApplicationInfo.DoesNotExist:
            return False

        return False

    @cachemodel.cached_method(auto_publish=True)
    def cached_issuers(self):
        return Issuer.objects.filter(staff__id=self.id).distinct()

    @property
    def peers(self):
        """
        a BadgeUser is a Peer of another BadgeUser if they appear in an IssuerStaff together
        """
        return set(
            chain(
                *[
                    [s.cached_user for s in i.cached_issuerstaff()]
                    for i in self.cached_issuers()
                ]
            )
        )

    def cached_badgeclasses(self):
        return chain.from_iterable(
            issuer.cached_badgeclasses() for issuer in self.cached_issuers()
        )

    @cachemodel.cached_method(auto_publish=True)
    def cached_badgeinstances(self):
        return BadgeInstance.objects.filter(
            recipient_identifier__in=self.all_recipient_identifiers
        )

    @cachemodel.cached_method(auto_publish=True)
    def get_badges_from_user(self):
        return BadgeInstance.objects.filter(
            recipient_identifier__in=self.all_recipient_identifiers
        )

    @cachemodel.cached_method(auto_publish=True)
    def cached_token(self):
        user_token, created = Token.objects.get_or_create(user=self)
        return user_token.key

    @cachemodel.cached_method(auto_publish=True)
    def cached_agreed_terms_version(self):
        try:
            return self.termsagreement_set.all().order_by("-terms_version")[0]
        except IndexError:
            pass
        return None

    @property
    def agreed_terms_version(self):
        v = self.cached_agreed_terms_version()
        if v is None:
            return 0
        return v.terms_version

    @agreed_terms_version.setter
    def agreed_terms_version(self, value):
        try:
            value = int(value)
        except ValueError:
            return

        # if value > self.agreed_terms_version:
        # Only automatically agree to the latest terms version during signup
        try:
            CachedEmailAddress.cached.get(email=self.primary_email)
        except CachedEmailAddress.DoesNotExist:
            if TermsVersion.active_objects.filter(version=value).exists():
                if not self.pk:
                    self.save()
                self.termsagreement_set.get_or_create(
                    terms_version=value, defaults=dict(agreed=True)
                )

    def replace_token(self):
        Token.objects.filter(user=self).delete()
        # user_token, created = \
        #         Token.objects.get_or_create(user=self)
        self.save()
        return self.cached_token()

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = generate_badgr_username(self.email)

        if getattr(settings, "BADGEUSER_SKIP_LAST_LOGIN_TIME", True):
            # skip saving last_login to the database
            if (
                "update_fields" in kwargs
                and kwargs["update_fields"] is not None
                and "last_login" in kwargs["update_fields"]
            ):
                kwargs["update_fields"].remove("last_login")
                if len(kwargs["update_fields"]) < 1:
                    # nothing to do, abort so we dont call .publish()
                    return
        return super(BadgeUser, self).save(*args, **kwargs)


class TermsVersionManager(cachemodel.CacheModelManager):
    latest_version_key = "badgr_server_cached_latest_version"

    def latest_version(self):
        latest = self.cached_latest()
        if latest is not None:
            return latest.version
        return 0

    def latest(self):
        try:
            return self.filter(is_active=True).order_by("-version")[0]
        except IndexError:
            pass

    def cached_latest(self):
        latest = cache.get(self.latest_version_key)
        if latest is None:
            return self.publish_latest()
        return latest

    def publish_latest(self):
        latest = self.latest()
        if latest is not None:
            cache.set(self.latest_version_key, latest, timeout=None)
        return latest


class TermsVersion(IsActive, BaseAuditedModel, cachemodel.CacheModel):
    version = models.PositiveIntegerField(unique=True)
    short_description = models.TextField(blank=True)
    cached = TermsVersionManager()

    def publish(self):
        super(TermsVersion, self).publish()
        TermsVersion.cached.publish_latest()


class TermsAgreement(BaseAuditedModelDeletedWithUser, cachemodel.CacheModel):
    user = models.ForeignKey("badgeuser.BadgeUser", on_delete=models.CASCADE)
    terms_version = models.PositiveIntegerField()
    agreed = models.BooleanField(default=True)

    class Meta:
        ordering = ("-terms_version",)
        unique_together = ("user", "terms_version")


class UserPreference(BaseAuditedModelDeletedWithUser, cachemodel.CacheModel):
    user = models.ForeignKey("badgeuser.BadgeUser", on_delete=models.CASCADE)
    key = models.CharField(max_length=255, db_index=True)
    value = models.TextField()

    class Meta:
        unique_together = ("user", "key")
