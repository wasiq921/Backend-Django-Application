from django.contrib.auth.models import User
from rest_framework import (generics , permissions,status)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import MainRegisterSerializer ,GoogleCodeSerializer,CustomTokenObtainPairSerializer,LogoutSerializer, SocialTokenObtainPairSerializer
from django.conf import settings
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from django_rest_authentication.dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.models import SocialApp
from .utils import get_login_urls,get_google_id_token, get_google_jwt
from rest_framework_simplejwt.views import TokenObtainPairView

class UserLoginView(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomTokenObtainPairSerializer


class UserRegisterView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = MainRegisterSerializer

class GoogleLogin(SocialLoginView): # if you want to use Authorization Code Grant, use this
    permission_classes = [permissions.AllowAny]
    adapter_class = GoogleOAuth2Adapter
    callback_url = settings.CALLBACK_URL_YOU_SET_ON_GOOGLE
    client_class = OAuth2Client

class GetGoogleAccessToken(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = GoogleCodeSerializer
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        resp = get_google_id_token(validated_data)
        return Response(resp ,status= status.HTTP_201_CREATED)

class TrialView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request,*args, **kwargs):
        code = self.request.GET.get('code')
        code = {"message":"google login code","status":True,'data':{'code':code}} # get code from google login
        access_token = get_google_id_token(code) # convert google code to ID_token
        print(access_token)
        resp = get_google_jwt(access_token) # checking id_token and register or sign_in user
        print(resp)
        if resp["status"] is False:
            return Response(resp)
        pk = int(resp['data']['user']['pk'])
        print(pk)
        user_obj = User.objects.get(pk= pk)
        return Response(resp , status= status.HTTP_200_OK)

class GetLoginUrls(APIView): 
    permission_classes = [permissions.AllowAny]
    def get(self, request,*args, **kwargs):
        return Response(get_login_urls())

class FacebookLogin(SocialLoginView):
    permission_classes = [permissions.AllowAny]
    adapter_class = FacebookOAuth2Adapter

class FbCodeView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request,*args, **kwargs):
        code = self.request.GET.get('#access_token')
        # print(code)
        resp = {"message":"facebook login code","status":True,'access_token':code}
        return Response(resp , status= status.HTTP_200_OK)

class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        try:
            
            log_msg = f"{request.user.username} Logout Successfully"
            # save_system_logs(log_msg, request.user)
            

            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            response = {'status': True, "status_code" : status.HTTP_200_OK, 'message': 'User logged out successfully', "data" : {} }
        except AssertionError:
            response = {'status': False, "status_code" : status.HTTP_401_UNAUTHORIZED, 'message': 'Invalid or Expired Token', "data" : {} }

        return Response(response)
    


class SocialLogin(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = SocialTokenObtainPairSerializer
