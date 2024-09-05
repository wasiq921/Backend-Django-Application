from django.contrib import admin
from .models import *
# Register your models here.


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name', 'display_name', 'created_on', 'active']
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'join_date', 'is_delete',  'is_active']

@admin.register(App)
class AppAdmin(admin.ModelAdmin):
    list_display = ['i_profile', 'name', 'description']