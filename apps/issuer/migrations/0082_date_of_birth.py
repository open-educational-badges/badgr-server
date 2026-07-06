from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("issuer", "0081_auto_20250903_2334"),
        ("issuer", "0064_issuer_quota_dashboard_quota_dashboard_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="badgeinstance",
            name="date_of_birth",
            field=models.DateField(
                blank=True,
                default=None,
                help_text="The recipient's date of birth, displayed on the badge PDF only",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="requestedbadge",
            name="dateOfBirth",
            field=models.DateField(blank=True, default=None, null=True),
        ),
    ]
