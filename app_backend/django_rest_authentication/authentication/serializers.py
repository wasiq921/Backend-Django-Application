from django.contrib.auth.models import User
from django.core.validators import RegexValidator
from django.conf import settings
from rest_framework import serializers, status
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, BlacklistedToken
from django.contrib.auth.models import update_last_login
from django.contrib.auth import authenticate
from django.db.models import Q
from django.db import transaction
from django.forms.models import model_to_dict
from allauth.socialaccount import  providers
from allauth.socialaccount.models import SocialAccount
import random, re
from django_rest_authentication.authentication.django_rest_passwordreset.signals import user_signed_up
# from .models import UserOfOTP
from django_rest_authentication.authentication.django_rest_passwordreset.models import UserOfOTP,ProfileOTP
from django_rest_authentication.authentication.django_rest_passwordreset.views import generate_otp 
from .utils import generate_username, get_full_name,signup_otp_validation,signup_otp_request
from rest_framework import status
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.utils import timezone
from rest_framework_simplejwt.exceptions import TokenError
# from user_management.models import CustomToken
from datetime import datetime
from user_management.models import Profile

SPECIAL_CHARACTER = r'!"\#$%&()*+,-./:;<=>?@[\\]^_`{|}~\'•√π÷×§∆£¢€¥°©®™✓'

phone_regex = RegexValidator(
    regex=r'^\+1\d{10}$',
    message="Please enter a valid phone number."
)
class RoleField(serializers.RelatedField):
    def to_representation(self, value):
        return str(value.phone_number)

class CustomPasswordChangeSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resp = {'status' : False, 'message' : None,'data' : None,'status_code' : status.HTTP_200_OK} 
        request = self.context["request"]
        self.user = request.user
        self.fields["status"] = serializers.BooleanField(read_only=True)
        self.fields["data"] = serializers.DictField(read_only=True,default=None)
        self.fields["message"] = serializers.CharField(read_only=True,default=None)
        self.fields["status_code"] = serializers.IntegerField(read_only=True,default=status.HTTP_200_OK)
        self.fields["new_password1"] = serializers.CharField(write_only=True)
        self.fields["new_password2"] = serializers.CharField(write_only=True)
        self.fields["old_password"] = serializers.CharField(write_only=True)

    def validate(self, attrs):
        attrs['valid'] = True
        old_password = attrs['old_password']
        password = attrs['new_password1']
        confirm_password = attrs['new_password2']
        
        user_obj = authenticate(username=self.user.username,password=old_password)

        if attrs['valid'] and user_obj is None:
            self.resp['message'] = "Invalid old password"
            self.resp["status_code"] = status.HTTP_401_UNAUTHORIZED
            attrs['valid'] = False
        
        if attrs['valid'] and password != confirm_password:
            self.resp["message"] = "Both passwords must be same."
            self.resp["status_code"] = status.HTTP_400_BAD_REQUEST
            attrs['valid'] = False
        
        if attrs['valid'] and password == old_password:
            self.resp["message"] = "New passwords must be distinct then old password."
            self.resp["status_code"] = status.HTTP_400_BAD_REQUEST
            attrs['valid'] = False

        if attrs['valid'] and not any(char.islower() for char in password):
            self.resp["message"] = "Password must contain at least one lowercase letter."
            self.resp["status_code"] = status.HTTP_400_BAD_REQUEST
            attrs['valid'] = False

        if attrs['valid'] and not any(char.isupper() for char in password):
            self.resp["message"] = "Password must contain at least one uppercase letter."
            self.resp["status_code"] = status.HTTP_400_BAD_REQUEST
            attrs['valid'] = False

        if attrs['valid'] and not any(char in SPECIAL_CHARACTER for char in password):
            self.resp["message"] = "Password must contain at least one unique character."
            self.resp["status_code"] = status.HTTP_400_BAD_REQUEST
            attrs['valid'] = False  
        return attrs
    
    def create(self,validated_data):
        if validated_data['valid'] == True:
            self.user.set_password(validated_data['new_password2'])
            self.user.save()
            self.resp["status"] = True
            self.resp["status_code"] = status.HTTP_200_OK
            self.resp["message"] = "Password changed successfully"
        print("self.rep",self.resp)
        return self.resp

# class MainRegisterSerializer(serializers.Serializer):
#     token_class = RefreshToken
#     status_code = serializers.IntegerField(read_only = True,default =status.HTTP_400_BAD_REQUEST)
#     status = serializers.BooleanField(read_only=True,default=False)
#     message = serializers.CharField(read_only=True,default =None)
#     data = serializers.DictField(read_only=True,default = None)
    
#     @classmethod
#     def get_token(cls, user):
#         return cls.token_class.for_user(user)
    
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.resp = {
#             'status' : False,'status_code' : status.HTTP_400_BAD_REQUEST,
#             'message': None,'data' : None
#         }
#         self.fields['first_name'] = serializers.CharField(max_length= 100, required = True,write_only=True)
#         if settings.ENABLE_LAST_NAME == True:
#             self.fields['last_name'] = serializers.CharField(max_length=100, required = False,write_only=True)
#         self.fields['email'] = serializers.EmailField(required=True,write_only=True) #,validators=[UniqueValidator(queryset=User.objects.all())]
#         self.fields['password'] = serializers.CharField(write_only=True, required=True)#, validators=[cus_password_validator]
#         if settings.ENABLE_CONFIRM_PASSWORD == True:
#             self.fields['confirm_password'] = serializers.CharField(write_only=True, required=True)
#         if settings.USER_DEFINED_USERNAME == True:
#             self.fields['username'] = serializers.CharField(max_length=100, required = True,write_only=True)

#     def validate(self, attrs):
#         errors = None
#         password = attrs['password']
#         email = attrs['email'].lower()
#         attrs['valid'] = False
#         special_characters = r'!"\#$%&()*+,-./:;<=>?@[\\]^_`{|}~\'•√π÷×§∆£¢€¥°©®™✓'
#         is_valid = True
#         if settings.USER_DEFINED_USERNAME == True:
#             username = attrs['username']
#             if is_valid and User.objects.filter(username=username).exists():
#                 errors = "This username is already taken."
#                 is_valid = False
#         if is_valid and not re.match(r'^[a-zA-Z0-9 ]+$', attrs['first_name']):
#             errors = "First name must contain only alphabets and numeric characters."
#             is_valid = False
#         if settings.ENABLE_LAST_NAME:
#             if is_valid and not re.match(r'^[a-zA-Z0-9 ]+$', attrs['last_name']):
#                 errors = "Last name must contain only alphabets and numeric characters."
#                 is_valid = False
#         if is_valid and User.objects.filter(email=email).exists():
#             errors = "This email is already taken."
#             is_valid = False
#         if settings.ENABLE_CONFIRM_PASSWORD == True:
#             password2 = attrs['confirm_password']
#             if is_valid and password != password2:
#                 errors = "Password fields didn’t match."
#                 is_valid = False
#         if is_valid and not any(char.islower() for char in password):
#             errors = "Password must contain at least one lowercase letter."
#             is_valid = False
#         if is_valid and not any(char.isupper() for char in password):
#             errors = "Password must contain at least one uppercase letter."
#             is_valid = False
#         if is_valid and not any(char in special_characters for char in password):
#             errors = "Password must contain at least one Special character."
#             is_valid = False
        
#         if not is_valid:
#             attrs['error'] = errors
#         attrs['valid'] = is_valid
#         return attrs
    
#     def create(self, validated_data):
#         print("validated_data:", validated_data)
#         if validated_data['valid'] == True:
#             first_name = validated_data.get('first_name',None)
#             last_name = validated_data.get('last_name',None)
#             username = validated_data.get('username',None)
#             email = validated_data.get('email',None).lower()
#             password = validated_data.get('password',None)
#             if settings.USER_DEFINED_USERNAME == False:
#                 if settings.EMAIL_AS_USERNAME == True:
#                     username = email
#                 else:
#                     username = generate_username(first_name, last_name)
#             user_dict = {
#                 "username" : username,
#                 "email" : email,
#                 "first_name" : first_name
#             }
#             if settings.ENABLE_LAST_NAME and last_name is not None:
#                 user_dict['last_name'] = last_name
#             with transaction.atomic():
#                 user_obj = User(**user_dict)
#                 user_obj.set_password(password)
#                 user_obj.save()
#                 self.resp['status'] = True 
#                 self.resp['status_code'] = status.HTTP_201_CREATED
#                 self.resp['message'] = 'User created successfully'
#                 self.resp["data"] = user_dict
#                 self.resp["data"].update({'pk':user_obj.pk, 'full_name':get_full_name(user_obj)})
#                 refresh = self.get_token(user_obj)
#                 self.resp['data'].update({"access" : str(refresh.access_token),"refresh" : str(refresh),})
#         else:
#             self.resp['message'] = validated_data.get('error')
#         return self.resp


class MainRegisterSerializer(serializers.Serializer):
    token_class = RefreshToken
    status_code = serializers.IntegerField(read_only = True,default =status.HTTP_400_BAD_REQUEST)
    status = serializers.BooleanField(read_only=True,default=False)
    message = serializers.CharField(read_only=True,default =None)
    data = serializers.DictField(read_only=True,default = None)
    
    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resp = {
            'status' : False,'status_code' : status.HTTP_400_BAD_REQUEST,
            'message': None,'data' : None
        }
        self.fields['first_name'] = serializers.CharField(max_length= 100, required = True,write_only=True)
        if settings.ENABLE_LAST_NAME == True:
            self.fields['last_name'] = serializers.CharField(max_length=100, required = False,write_only=True)
        self.fields['email'] = serializers.EmailField(required=True,write_only=True) #,validators=[UniqueValidator(queryset=User.objects.all())]
        self.fields['password'] = serializers.CharField(write_only=True, required=True)#, validators=[cus_password_validator]
        self.fields['otp_required'] = serializers.BooleanField(write_only=True, required=False ,default = False)#, valid
        if settings.ENABLE_CONFIRM_PASSWORD == True:
            self.fields['confirm_password'] = serializers.CharField(write_only=True, required=True)
        if settings.USER_DEFINED_USERNAME == True:
            self.fields['username'] = serializers.CharField(max_length=100, required = True,write_only=True)

    def validate(self, attrs):
        errors = None
        password = attrs['password']
        email = attrs['email'].lower()
        attrs['valid'] = False
        special_characters = r'!"\#$%&()*+,-./:;<=>?@[\\]^_`{|}~\'•√π÷×§∆£¢€¥°©®™✓'
        is_valid = True

        otp_required = attrs.get('otp_required',False)
        if otp_required == True:
            attrs = signup_otp_validation(otp_required,attrs)
            # if 'error' in attrs:
            #     attrs['valid'] = is_valid
            # print(attrs,"++++++++++++++++")
            return attrs
        else:
            if settings.USER_DEFINED_USERNAME == True:
                username = attrs['username']
                if is_valid and User.objects.filter(username=username).exists():
                    errors = "This username is already taken."
                    is_valid = False
            if is_valid and not re.match(r'^[a-zA-Z0-9 ]+$', attrs['first_name']):
                errors = "First name must contain only alphabets and numeric characters."
                is_valid = False
            if settings.ENABLE_LAST_NAME:
                if is_valid and not re.match(r'^[a-zA-Z0-9 ]+$', attrs['last_name']):
                    errors = "Last name must contain only alphabets and numeric characters."
                    is_valid = False
            # if is_valid and User.objects.filter(email=email).exists():
            if is_valid and User.objects.filter(email=email).exists():
                errors = "This email is already taken."
                is_valid = False
            if settings.ENABLE_CONFIRM_PASSWORD == True:
                password2 = attrs['confirm_password']
                if is_valid and password != password2:
                    errors = "Password fields didn’t match."
                    is_valid = False
            if is_valid and not any(char.islower() for char in password):
                errors = "Password must contain at least one lowercase letter."
                is_valid = False
            if is_valid and not any(char.isupper() for char in password):
                errors = "Password must contain at least one uppercase letter."
                is_valid = False
            if is_valid and not any(char in special_characters for char in password):
                errors = "Password must contain at least one Special character."
                is_valid = False
            
            if not is_valid:
                attrs['error'] = errors
            if 'error' not in attrs:
                attrs['user_email'] = email
            attrs['valid'] = is_valid
            print(attrs,"[[[]]]")
            return attrs
        
    def create(self, validated_data):
        print("validated_data:", validated_data)
        if validated_data['valid'] == True:
            first_name = validated_data.get('first_name',None)
            last_name = validated_data.get('last_name',None)
            username = validated_data.get('username',None)
            email = validated_data.get('email',None).lower()
            password = validated_data.get('password',None)
            otp_required = validated_data.get('otp_required',False)
            if settings.USER_DEFINED_USERNAME == False:
                if settings.EMAIL_AS_USERNAME == True:
                    username = email
                else:
                    username = generate_username(first_name, last_name)
            user_dict = {
                "username" : username,
                "email" : email,
                "first_name" : first_name
            }
            if settings.ENABLE_LAST_NAME and last_name is not None:
                user_dict['last_name'] = last_name
            with transaction.atomic():
                if otp_required == True:
                    print(validated_data,"++++++222++++++++++")
                    if 'is_otp_verified' in validated_data:
                        otp_user = signup_otp_request(validated_data)
                        # if 
                        self.resp['status'] = True 
                        self.resp['status_code'] = status.HTTP_201_CREATED
                        self.resp['message'] = 'OTP sent to you successfully'
                        self.resp['data'] = otp_user
                        return self.resp
                    else:
                        print("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                        user_obj = User(**user_dict)
                        user_obj.set_password(password)
                        user_obj.save()
                        otp_verified = UserOfOTP.objects.create(
                        otp_user = user_obj)
                        otp = generate_otp()
                        ProfileOTP.objects.filter(user = user_obj).delete()
                        otp_obj = ProfileOTP.objects.create(user = user_obj,otp = otp)
                        user_signed_up.send(sender=user_obj.__class__, user=user_obj, otp_obj=otp_obj)
                        self.resp['status'] = True 
                        self.resp['status_code'] = status.HTTP_201_CREATED
                        self.resp['message'] = 'OTP sent to you successfully'
                        self.resp["data"] = {'pk':user_obj.pk, 'full_name':get_full_name(user_obj),'otp_required':True,'otp_verified':otp_verified.otp_verified,'first_signup':True}
                        return self.resp

                else:
                    user_obj = User(**user_dict)
                    user_obj.set_password(password)
                    user_obj.save()
                    profile_obj = Profile.objects.create(user = user_obj)
                    self.resp['status'] = True 
                    self.resp['status_code'] = status.HTTP_201_CREATED
                    self.resp['message'] = 'User created successfully'
                    self.resp["data"] = user_dict
                    self.resp["data"].update({'pk':user_obj.pk, 'full_name':get_full_name(user_obj)})
                    refresh = self.get_token(user_obj)

                    expires_at_timestamp = refresh.access_token['exp']

                    # Convert Unix timestamp to datetime object
                    expires_at_datetime = datetime.fromtimestamp(expires_at_timestamp)

                    # Convert datetime object to ISO-formatted string
                    expires_at_isoformat = expires_at_datetime.isoformat()
                    # custom_token_obj = CustomToken.objects.create(user = user_obj, token = str(refresh.access_token), expires_at = expires_at_isoformat )
                

                    self.resp['data'].update({"access" : str(refresh.access_token),"refresh" : str(refresh),})
        else:
            self.resp['message'] = validated_data.get('error')
        print("ttttttttttttttttttt")
        return self.resp

class GoogleCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=100,required=True, write_only=True,
                                help_text= "Enter Code from url params")
    provider = serializers.CharField(max_length=256, write_only=True,required=False,
                                    help_text= "Enter Provider Such as Google/Facebook/Apple")
    id_token = serializers.CharField(read_only=True)                 
    
    def validate(self, attrs):
        code = attrs['code']
        return attrs

   
# class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.user = None
#         self.fields["username"] = serializers.CharField(required=True, write_only=True)
#         self.fields["password"] = serializers.CharField(required=True, write_only=True)
    
#     def validate(self, attrs):
#         username = attrs.get('username').lower()
#         password = attrs.get('password')
#         try:
#             user_obj = User.objects.get(Q(email=username)|Q(username=username))
#         except User.DoesNotExist as e:
#             user_obj =  None
#         if user_obj is not None:
#             authenticate_kwargs = {
#                 "username": user_obj.username,
#                 "password": password,
#             }
#             print("authenticate_kwargs",authenticate_kwargs)
#             try:
#                 authenticate_kwargs["request"] = self.context["request"]
#             except KeyError:
#                 pass

#             self.user = authenticate(**authenticate_kwargs)
#             print("self.user", self.user)
#             if not api_settings.USER_AUTHENTICATION_RULE(self.user):
#                 return {'message': 'Invalid password'}
#             else:
#                 data = {
#                     'pk': user_obj.pk,
#                     'email' : self.user.email,
#                     'full_name': get_full_name(user_obj),
#                 }
#                 return data 
#         else:
#             return {'message': 'Invalid email or username'}
        
#         return  {}
#     @classmethod
#     def get_token(cls, user):
#         return super().get_token(user)
    

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.fields["username"] = serializers.CharField(required=True, write_only=True)
        self.fields["password"] = serializers.CharField(required=True, write_only=True)
    
    def validate(self, attrs):
        username = attrs.get('username').lower()
        password = attrs.get('password')
        try:
            user_obj = User.objects.get(Q(email=username)|Q(username=username))
        except User.DoesNotExist as e:
            user_obj =  None
        if user_obj is not None:
            if user_obj.is_active == False:
                    return {'valid' : False,'message' : 'User is not allowed to login. Contact admin', 'status_code' : status.HTTP_400_BAD_REQUEST}
            authenticate_kwargs = {
                "username": user_obj.username,
                "password": password,
            }
            print("authenticate_kwargs",authenticate_kwargs)
            try:
                authenticate_kwargs["request"] = self.context["request"]
            except KeyError:
                pass

            self.user = authenticate(**authenticate_kwargs)
            print("self.user", self.user)
            if not api_settings.USER_AUTHENTICATION_RULE(self.user):
                return {'message': 'Invalid password'}
            else:
                otp_user = UserOfOTP.objects.filter(otp_user = self.user)
                if otp_user.exists():
                    if otp_user.first().otp_verified == False:
                        return {'message': 'back to signup screen because you do not verify otp yet'}
                    else:
                        pass
                else:
                    pass
                

                data = {
                    'pk': user_obj.pk,
                    'email' : self.user.email,
                    'full_name': get_full_name(user_obj),
                }
                return data 
        else:
            return {'message': 'Invalid email or username'}
        
        return  {}
    @classmethod
    def get_token(cls, user):
        return super().get_token(user)


class CustomTokenObtainPairSerializer(MyTokenObtainPairSerializer):
    token_class = RefreshToken
    def validate(self, attrs):
        response = {"status" : False,"status_code"  : None, "message" : None, "data" : None}
        data = super().validate(attrs)
        if 'message' not in data.keys():
            print(data)
            refresh = self.get_token(self.user)
            response["status"] = True
            
            response["status_code"] = status.HTTP_200_OK
            response["message"] = "Login Successfully"
            response["data"] = data
            response['data']["refresh"] = str(refresh)
            response['data']["access"] = str(refresh.access_token)
            # firestore_id = get_firestore_id(self.user.profile)
            firestore_id = None
            response['data']["firestore_id"] = firestore_id
            # firebase_token = signin_firebase(self.user.profile)
            firebase_token = None
            response['data']["firebase_token"] = firebase_token
            if api_settings.UPDATE_LAST_LOGIN:
                update_last_login(None, self.user)
            log_msg = f"{self.user.username} Login Successfully"
        else:
            response["status"] = False
            response["message"] = data["message"]
            response["status_code"] = status.HTTP_400_BAD_REQUEST
            # save_system_logs(log_msg, self.user)
        return response



User = get_user_model()

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


    def validate(self, attrs):
        try:
            self.token = RefreshToken(attrs['refresh'])
            return attrs
        except TokenError as e:
            raise serializers.ValidationError({'error': str(e)})

    def save(self, **kwargs):
        user_id = self.token.payload['user_id']
        user = User.objects.get(id=user_id)

        # Blacklist all user's tokens
        OutstandingToken.objects.filter(user=user).delete()

        # Optionally, you can also blacklist the current refresh token
        self.token.blacklist()

        # CustomToken.objects.filter(user=user).delete()

        # Optionally, you can also blacklist all refresh tokens
        # BlacklistedToken.objects.bulk_create([BlacklistedToken(token=token) for token in RefreshToken.objects.filter(user=user)])

class SocialTokenObtainPairSerializer(serializers.Serializer):
    status_code = serializers.IntegerField(read_only=True,default= status.HTTP_201_CREATED)
    status = serializers.BooleanField(read_only=True)
    message = serializers.CharField(read_only=True,default = None)
    data = serializers.DictField(read_only=True,default = {})
    token_class = RefreshToken
    
    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resp = {'status' : False ,'status_code': status.HTTP_200_OK, 'message' : None,'data': {"access" : None,"refresh" : None,"firebase_token" : None}}
        self.resp = {"status" : False}
        self.user = None
        self.fields["uid"] = serializers.CharField(required = True,write_only=True)
        self.fields["email"] = serializers.EmailField(required = False,write_only=True,default=None)
        self.fields["full_name"] = serializers.CharField(required = False,write_only=True,default=None)
        self.fields["provider"] = serializers.ChoiceField(choices=providers.registry.as_choices(),required = False,write_only=True,default=None)

    def validate(self, attrs):
        attrs['valid'] = False
        attrs['login'] = False
        uid= attrs.get('uid')
        email= attrs.get('email')
        social_account_qs = SocialAccount.objects.filter(uid = uid)
        user_qs = User.objects.filter(email=email)
        if social_account_qs.exists():
            attrs['valid'] = True
            attrs['login'] = True
            if user_qs.first().is_active == False:
                attrs['valid'] = False
                self.resp['message'] = 'User is not allowed to login. Contact admin'
                self.resp['status_code'] = status.HTTP_400_BAD_REQUEST
        elif user_qs.exists():
            self.resp['message'] = 'User already exists with this email address'
            self.resp['status_code'] = status.HTTP_400_BAD_REQUEST
            

        else:
            attrs['valid'] = True
            attrs['login'] = False
        print("attr",attrs)
        print("self.resp",self.resp)
        return attrs
    
    def create(self, validated_data):
        if validated_data['valid'] == True:
            social_account = None
            if validated_data['login'] == False:
                with transaction.atomic():
                    full_name = validated_data.get('full_name')
                    email = validated_data.get('email')
                    uid = validated_data.get('uid')
                    provider = validated_data.get('provider')
                    if full_name is None:
                        self.resp['message'] = 'Full name is required'
                        self.resp['status_code'] = status.HTTP_400_BAD_REQUEST
                        return self.resp
                    elif email is None:
                        self.resp['message'] = 'Email is required'
                        self.resp['status_code'] = status.HTTP_400_BAD_REQUEST
                        return self.resp
                   
                    if full_name is not None:
                        user_obj = User.objects.create(username=email,email=email,first_name=full_name)
                        
                    social_account = SocialAccount.objects.create(user = user_obj,uid = uid, provider = provider)
                    self.resp['message'] = "Registration successfully"
                    self.resp['status_code'] = status.HTTP_201_CREATED

            else:
                social_account_qs = SocialAccount.objects.filter(uid = validated_data['uid'])
                social_account = social_account_qs.first()
                self.resp['message'] = "Login successfully"
                self.resp['status_code'] = status.HTTP_200_OK

            self.resp['status'] = True

            if self.resp['message'] == "Registration successfully":
                self.resp['status_code'] = status.HTTP_201_CREATED
            elif self.resp['message'] =="Login successfully":
                self.resp['status_code'] = status.HTTP_200_OK
                

            user = social_account.user
            refresh = self.get_token(user)
            self.resp['data'] = {
            "access" : str(refresh.access_token),"refresh" : str(refresh),
            }
            self.resp['data'].update({'email': user.email, 'pk': user.pk, 'full_name': get_full_name(user)})
        else:
            pass
        return self.resp