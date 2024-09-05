# Generated by Django 4.2.15 on 2024-09-04 09:53

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import user_management.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('display_name', models.CharField(default='', max_length=50)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('active', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='profile', serialize=False, to=settings.AUTH_USER_MODEL)),
                ('join_date', models.DateField(default=datetime.date.today)),
                ('is_delete', models.BooleanField(default=False)),
                ('country', models.CharField(blank=True, null=True)),
                ('city', models.CharField(blank=True, null=True)),
                ('date_of_birth', models.DateField(blank=True, null=True)),
                ('about', models.TextField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('role', models.ForeignKey(default=user_management.models.Role.get_default_role, on_delete=django.db.models.deletion.CASCADE, related_name='user_role', to='user_management.role')),
            ],
            options={
                'db_table': 'profile',
            },
        ),
    ]