# Generated by Django 4.2.4 on 2024-09-04 14:33

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user_management', '0002_app'),
        ('subscription', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='membership',
            name='i_profile',
        ),
        migrations.AddField(
            model_name='membership',
            name='i_app',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='user_management.app'),
        ),
    ]