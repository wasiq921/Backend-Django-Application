# Generated by Django 4.2 on 2023-12-27 10:36

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('django_rest_passwordreset', '0004_profileotp'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserOfOTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp_verified', models.BooleanField(default=False)),
                ('otp_user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'user_otp_verify',
            },
        ),
    ]
