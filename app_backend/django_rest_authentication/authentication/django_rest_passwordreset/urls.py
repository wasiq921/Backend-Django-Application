""" URL Configuration for core auth """
from django.urls import path

from .views import ResetPasswordConfirmViewSet, ResetPasswordRequestTokenViewSet, \
    ResetPasswordValidateTokenViewSet, reset_password_confirm, reset_password_request_token, \
    reset_password_validate_token ,reset_password_request_token_otp,reset_password_confirm_token_otp,reset_password_confirmation, accont_confirm_otp

app_name = 'password_reset'


def add_reset_password_urls_to_router(router, base_path=''):
    router.register(
        base_path + "/validate_token",
        ResetPasswordValidateTokenViewSet,
        basename='reset-password-validate'
    )
    router.register(
        base_path + "/confirm",
        ResetPasswordConfirmViewSet,
        basename='reset-password-confirm'
    )
    router.register(
        base_path,
        ResetPasswordRequestTokenViewSet,
        basename='reset-password-request'
    )


urlpatterns = [
    path("validate_token/", reset_password_validate_token, name="reset-password-validate"),
    path("confirm/", reset_password_confirm, name="reset-password-confirm"),
    path("", reset_password_request_token, name="reset-password-request"),
    path("request_otp/", reset_password_request_token_otp, name="reset-password-request-otp"),
    path("confirm_otp/", reset_password_confirm_token_otp, name="reset-password-request-otp"),
    path("account_confirm_otp/", accont_confirm_otp, name="account-confirm-otp"),
    path("confirm_password/", reset_password_confirmation, name="reset-password-otp-confirm"),

]
