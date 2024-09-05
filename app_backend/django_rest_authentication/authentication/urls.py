from django.urls import path, include
from rest_framework_simplejwt.views import (TokenObtainPairView,TokenRefreshView,TokenVerifyView)
from .views import *
from .django_rest_passwordreset.urls import urlpatterns as password_reset_urls
auth_patterns = [
    # path('', include('allauth.urls')), Auth with templates HTML CSS
    # path('dj-rest-auth/registration/', include('dj_rest_auth.registration.urls')) Package provided Registration Based on email address and password
    path('', include('django_rest_authentication.dj_rest_auth.urls')), #Auth with restapi
    path('password_reset/', include(password_reset_urls), name = 'django_rest_passwordreset'),
    path('google/', GoogleLogin.as_view(), name='google_login'),
    path('google/code_post/', GetGoogleAccessToken.as_view(), name='code_post'),
    path('google/login/callback/', TrialView.as_view(), name='trial_view'),#creating this view so that whenever callback url hitted warning page doesn't appear and need to work on this
    path('google/login/', TrialView.as_view(), name='trial_view'),
    path('login_urls/', GetLoginUrls.as_view(), name='login_urls'),
    path('facebook/', FacebookLogin.as_view(), name='google_login'),
]

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('signup/', UserRegisterView.as_view(), name='user_register_view'),
    path('signin/', UserLoginView.as_view(), name='login_view'),
    path('signout/', LogoutAPIView.as_view(), name='logout_view'),
    path('social/login/', SocialLogin.as_view(), name='social_login'), 
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('',include(auth_patterns))
]
