# Generated by Django 4.0.4 on 2022-05-04 22:10

import django.db.models.deletion
import django.db.models.expressions
import django.db.models.functions.text
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models

import temba.utils.fields
import temba.utils.uuid


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("orgs", "0094_alter_org_parent"),
        ("tickets", "0029_alter_ticketer_name_alter_ticketer_uuid"),
    ]

    operations = [
        migrations.CreateModel(
            name="Team",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "is_active",
                    models.BooleanField(
                        default=True, help_text="Whether this item is active, use this instead of deleting"
                    ),
                ),
                (
                    "created_on",
                    models.DateTimeField(
                        blank=True,
                        default=django.utils.timezone.now,
                        editable=False,
                        help_text="When this item was originally created",
                    ),
                ),
                (
                    "modified_on",
                    models.DateTimeField(
                        blank=True,
                        default=django.utils.timezone.now,
                        editable=False,
                        help_text="When this item was last modified",
                    ),
                ),
                ("uuid", models.UUIDField(default=temba.utils.uuid.uuid4, unique=True)),
                ("name", models.CharField(max_length=64, validators=[temba.utils.fields.NameValidator(64)])),
            ],
        ),
        migrations.CreateModel(
            name="TicketDailyCount",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("is_squashed", models.BooleanField(default=False)),
                ("count_type", models.CharField(max_length=1)),
                ("scope", models.CharField(max_length=32)),
                ("count", models.IntegerField()),
                ("day", models.DateField()),
            ],
        ),
        migrations.AddConstraint(
            model_name="topic",
            constraint=models.UniqueConstraint(
                django.db.models.expressions.F("org"),
                django.db.models.functions.text.Lower("name"),
                name="unique_topic_names",
            ),
        ),
        migrations.AddIndex(
            model_name="ticketdailycount",
            index=models.Index(fields=["count_type", "scope", "day"], name="tickets_dailycount_type_scope"),
        ),
        migrations.AddIndex(
            model_name="ticketdailycount",
            index=models.Index(
                condition=models.Q(("is_squashed", False)),
                fields=["count_type", "scope", "day"],
                name="tickets_dailycount_unsquashed",
            ),
        ),
        migrations.AddField(
            model_name="team",
            name="created_by",
            field=models.ForeignKey(
                help_text="The user which originally created this item",
                on_delete=django.db.models.deletion.PROTECT,
                related_name="%(app_label)s_%(class)s_creations",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="team",
            name="modified_by",
            field=models.ForeignKey(
                help_text="The user which last modified this item",
                on_delete=django.db.models.deletion.PROTECT,
                related_name="%(app_label)s_%(class)s_modifications",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="team",
            name="org",
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="teams", to="orgs.org"),
        ),
        migrations.AddField(
            model_name="team",
            name="topics",
            field=models.ManyToManyField(related_name="teams", to="tickets.topic"),
        ),
        migrations.AddConstraint(
            model_name="team",
            constraint=models.UniqueConstraint(
                django.db.models.expressions.F("org"),
                django.db.models.functions.text.Lower("name"),
                name="unique_team_names",
            ),
        ),
    ]
