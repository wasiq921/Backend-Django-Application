""" contains basic admin views for MultiToken """
from django.contrib import admin
from .models import ResetPasswordToken
from .models import ProfileOTP,UserOfOTP

@admin.register(ResetPasswordToken)
class ResetPasswordTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'key', 'created_at', 'ip_address', 'user_agent')

@admin.register(ProfileOTP)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'otp']



@admin.register(UserOfOTP)
class UserOfOTPAdmin(admin.ModelAdmin):
    list_display = ['otp_user', 'otp_verified']