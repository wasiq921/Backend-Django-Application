import unicodedata , random
from datetime import timedelta
# from loggings.utils import save_system_logs,get_username_from_obj
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password, get_password_validators
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from django.urls import reverse
from rest_framework.views import APIView
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from .models import ProfileOTP,UserOfOTP
from rest_framework.generics import CreateAPIView
from rest_framework import permissions
from .serializers import PasswordConfirmSerializer
from .models import ResetPasswordToken, clear_expired, get_password_reset_token_expiry_time, \
    get_password_reset_lookup_field
from .serializers import EmailSerializer, PasswordTokenSerializer, ResetTokenSerializer
from .signals import reset_password_token_created, pre_password_reset, post_password_reset,otp_reset_password_token_created

User = get_user_model()

__all__ = [
    'ResetPasswordValidateToken',
    'ResetPasswordConfirm',
    'ResetPasswordRequestToken',
    'reset_password_validate_token',
    'reset_password_confirm',
    'reset_password_request_token',
    'ResetPasswordValidateTokenViewSet',
    'ResetPasswordConfirmViewSet',
    'ResetPasswordRequestTokenViewSet'
]

HTTP_USER_AGENT_HEADER = getattr(settings, 'DJANGO_REST_PASSWORDRESET_HTTP_USER_AGENT_HEADER', 'HTTP_USER_AGENT')
HTTP_IP_ADDRESS_HEADER = getattr(settings, 'DJANGO_REST_PASSWORDRESET_IP_ADDRESS_HEADER', 'REMOTE_ADDR')


def _unicode_ci_compare(s1, s2):
    """
    Perform case-insensitive comparison of two identifiers, using the
    recommended algorithm from Unicode Technical Report 36, section
    2.11.2(B)(2).
    """
    normalized1 = unicodedata.normalize('NFKC', s1)
    normalized2 = unicodedata.normalize('NFKC', s2)

    return normalized1.casefold() == normalized2.casefold()


class ResetPasswordValidateToken(GenericAPIView):
    """
    An Api View which provides a method to verify that a token is valid
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = ResetTokenSerializer
    authentication_classes = ()

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'status': 'OK'})
from .serializers import CustomPasswordTokenSerializer
class ResetPasswordConfirm(GenericAPIView):
    """
    An Api View which provides a method to reset a password based on a unique token
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = CustomPasswordTokenSerializer
    authentication_classes = ()

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid()
        password = serializer.validated_data.pop("password")
        token = serializer.validated_data.pop("token")
        if serializer.validated_data['status'] == True:
            reset_password_token = ResetPasswordToken.objects.filter(key=token).first()
            if reset_password_token.user.eligible_for_reset():
                pre_password_reset.send(sender=self.__class__, user=reset_password_token.user)
                reset_password_token.user.set_password(password)
                reset_password_token.user.save()
                post_password_reset.send(sender=self.__class__, user=reset_password_token.user)
            ResetPasswordToken.objects.filter(user=reset_password_token.user).delete()
            user_obj = reset_password_token.user
            # username =  get_username_from_obj(user_obj)
            # log_msg = f"{username} Reset Password Through Email"
            # save_system_logs(log_msg, username)
            serializer.validated_data['message'] = "Password reset successfully"
        return Response(serializer.validated_data)

class PasswordConfirm(CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PasswordConfirmSerializer

class ResetPasswordOTPConfirm(APIView):
    throttle_classes = ()
    permission_classes = ()
    serializer_class = ()
    authentication_classes = ()
    token_class = RefreshToken

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)
    def get(self, request, *args, **kwargs):
        return Response({"status":False,"message": "METHOD not allowed"})
    def post(self, request, *args, **kwargs):
        resp = {'status': False,'message': None, 'data' : None,'status_code': 200}
        otp = request.data.get('otp',None)
        if otp is not None:
            try:
                otp_obj = ProfileOTP.objects.get(otp=otp)
                user = otp_obj.user
                refresh = self.get_token(user)
                # resp = {'status': True, "refresh": str(refresh), "access": str(refresh.access_token),"message": "OTP Accepted", 
                        # "URL" : reverse('django_rest_passwordreset:reset-password-otp-confirm')}
                resp['status'] = True
                resp["message"] = "OTP Accepted"
                resp["data"] = {"refresh": str(refresh), "access": str(refresh.access_token)}
                otp_obj.delete()
            except ProfileOTP.DoesNotExist as e:
                resp['message'] = "Invalid or Expired OTP"
                resp['status_code'] = 400
        else:
            resp['message'] = "Please enter 4 digits OTP code"
            resp['status_code'] = 400

        return Response(resp)



def generate_otp():
    otp = str(random.randint(0, 9))+str(random.randint(0, 9))+str(random.randint(0, 9))+str(random.randint(0, 9))  # Generate a random 4-digit number
    return otp


class ResetPasswordRequestTokenOTP(GenericAPIView):
    """
    An Api View which provides a method to request a password reset token based on an e-mail address

    Sends a signal reset_password_token_created when a reset token was created
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = EmailSerializer
    authentication_classes = ()

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        print(":================================")
        if not serializer.is_valid():
            return Response({'status': False, 'message': 'Please enter a valid email address','data' : None,'status_code' : 400})
        email = serializer.validated_data['email']
        email = email.lower()
        # return Response({'status': True, 'message': 'Forget Password OTP has been sent'})

        # before we continue, delete all existing expired tokens
        # password_reset_token_validation_time = get_password_reset_token_expiry_time()

        # # datetime.now minus expiry hours
        # now_minus_expiry_time = timezone.now() - timedelta(hours=password_reset_token_validation_time)

        # # delete all tokens where created_at < now - 24 hours
        # clear_expired(now_minus_expiry_time)

        # find a user by email address (case insensitive search)
        users = User.objects.filter(**{'{}__iexact'.format(get_password_reset_lookup_field()): email})

        if len(users) == 0:
            return Response({'status': False,
                'message':"We couldn't find an account associated with that email. Please try a valid email.",'data' : None,'status_code' : 400
            })

        active_user_found = False

        # iterate over all users and check if there is any user that is active
        # also check whether the password can be changed (is useable), as there could be users that are not allowed
        # to change their password (e.g., LDAP user)
        # Usage
        otp = generate_otp()
        for user in users:
            if user.eligible_for_reset():
                active_user_found = True
                break
        # delete old tokens
        ProfileOTP.objects.filter(user = user).delete()
        otp_obj = ProfileOTP.objects.create(user = user,otp = otp)

        # No active user found, raise a validation message
        # but not if DJANGO_REST_PASSWORDRESET_NO_INFORMATION_LEAKAGE == True
        if not active_user_found:
            return Response({'status': False,
                'message':"We couldn't find an account associated with that email. Please try a valid email.",
                'data' : None,'status_code' : 400
            })
        else:
            otp_reset_password_token_created.send(sender=self.__class__,instance=self, user = user,otp_obj = otp_obj)
        # done
        user_obj= User.objects.get(email=email)
        # username =  get_username_from_obj(user_obj)
        # log_msg = f"Reset Password email sent to {username}"
        # save_system_logs(log_msg, username)
        return Response({'status': True, 'message': 'Forgot Password OTP has been sent','data' : None,'status_code' : 200})

class ResetPasswordRequestToken(GenericAPIView):
    """
    An Api View which provides a method to request a password reset token based on an e-mail address

    Sends a signal reset_password_token_created when a reset token was created
    """
    throttle_classes = ()
    permission_classes = ()
    serializer_class = EmailSerializer
    authentication_classes = ()

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response({'status_code':400,'status': False, 'message': 'Please enter a valid email address','data' : {}})
        email = serializer.validated_data['email']
        # before we continue, delete all existing expired tokens
        password_reset_token_validation_time = get_password_reset_token_expiry_time()

        # datetime.now minus expiry hours
        now_minus_expiry_time = timezone.now() - timedelta(hours=password_reset_token_validation_time)

        # delete all tokens where created_at < now - 24 hours
        clear_expired(now_minus_expiry_time)

        # find a user by email address (case insensitive search)
        users = User.objects.filter(**{'{}__iexact'.format(get_password_reset_lookup_field()): email})

        active_user_found = False

        # iterate over all users and check if there is any user that is active
        # also check whether the password can be changed (is useable), as there could be users that are not allowed
        # to change their password (e.g., LDAP user)
        for user in users:
            if user.eligible_for_reset():
                active_user_found = True
                break

        # No active user found, raise a validation error
        # but not if DJANGO_REST_PASSWORDRESET_NO_INFORMATION_LEAKAGE == True
        if not active_user_found and not getattr(settings, 'DJANGO_REST_PASSWORDRESET_NO_INFORMATION_LEAKAGE', False):
            return Response({ 'status_code':404,'Status': False,
                'message':"We couldn't find an account associated with that email. Please try a valid email.",
                'data':{}
            })

        # last but not least: iterate over all users that are active and can change their password
        # and create a Reset Password Token and send a signal with the created token
        for user in users:
            if user.eligible_for_reset() and \
                    _unicode_ci_compare(email, getattr(user, get_password_reset_lookup_field())):
                # define the token as none for now
                token = None

                # check if the user already has a token
                if user.password_reset_tokens.all().count() > 0:
                    # yes, already has a token, re-use this token
                    token = user.password_reset_tokens.all()[0]
                else:
                    # no token exists, generate a new token
                    token = ResetPasswordToken.objects.create(
                        user=user,
                        user_agent=request.META.get(HTTP_USER_AGENT_HEADER, ''),
                        ip_address=request.META.get(HTTP_IP_ADDRESS_HEADER, ''),
                    )
                # send a signal that the password token was created
                # let whoever receives this signal handle sending the email for the password reset
                reset_password_token_created.send(sender=self.__class__, instance=self, reset_password_token=token)
        # done
        user_obj= User.objects.get(email=email)
        # username =  get_username_from_obj(user_obj)
        # log_msg = f"Reset Password email sent to {username}"
        # save_system_logs(log_msg, username)
        return Response({'status_code':200,'status': True, 'message': 'Forgot password email has been sent','data':{}})
    

class UserOTPConfirm(APIView):
    throttle_classes = ()
    permission_classes = ()
    serializer_class = ()
    authentication_classes = ()
    token_class = RefreshToken

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)
    def get(self, request, *args, **kwargs):
        return Response({"status":False,"message": "METHOD not allowed"})
    def post(self, request, *args, **kwargs):
        resp = {'status': False,'message': None, 'data' : None,'status_code': 200}
        otp = request.data.get('otp',None)
        if otp is not None:
            try:
                otp_obj = ProfileOTP.objects.get(otp=otp)
                print(otp_obj,"sss")
                user = otp_obj.user
                print(user,"---")
                refresh = self.get_token(user)
                user_otp_obj = UserOfOTP.objects.get(otp_user=user)
                user_otp_obj.otp_verified = True
                user_otp_obj.save()
                # resp = {'status': True, "refresh": str(refresh), "access": str(refresh.access_token),"message": "OTP Accepted", 
                        # "URL" : reverse('django_rest_passwordreset:reset-password-otp-confirm')}
                resp['status'] = True
                resp["message"] = "OTP Accepted"
                resp["data"] = {"refresh": str(refresh), "access": str(refresh.access_token)}
                otp_obj.delete()
            except ProfileOTP.DoesNotExist as e:
                resp['message'] = "Invalid or Expired OTP"
                resp['status_code'] = 400
        else:
            resp['message'] = "Please enter 4 digits OTP code"
            resp['status_code'] = 400

        return Response(resp)


class ResetPasswordValidateTokenViewSet(ResetPasswordValidateToken, GenericViewSet):
    """
    An Api ViewSet which provides a method to verify that a token is valid
    """

    def create(self, request, *args, **kwargs):
        return super(ResetPasswordValidateTokenViewSet, self).post(request, *args, **kwargs)


class ResetPasswordConfirmViewSet(ResetPasswordConfirm, GenericViewSet):
    """
    An Api ViewSet which provides a method to reset a password based on a unique token
    """

    def create(self, request, *args, **kwargs):
        return super(ResetPasswordConfirmViewSet, self).post(request, *args, **kwargs)


class ResetPasswordRequestTokenViewSet(ResetPasswordRequestToken, GenericViewSet):
    """
    An Api ViewSet which provides a method to request a password reset token based on an e-mail address

    Sends a signal reset_password_token_created when a reset token was created
    """

    def create(self, request, *args, **kwargs):
        return super(ResetPasswordRequestTokenViewSet, self).post(request, *args, **kwargs)


reset_password_validate_token = ResetPasswordValidateToken.as_view()
reset_password_confirm = ResetPasswordConfirm.as_view()
reset_password_request_token = ResetPasswordRequestToken.as_view()
reset_password_request_token_otp = ResetPasswordRequestTokenOTP.as_view()
reset_password_confirm_token_otp = ResetPasswordOTPConfirm.as_view()
reset_password_confirmation = PasswordConfirm.as_view()
accont_confirm_otp = UserOTPConfirm.as_view()


