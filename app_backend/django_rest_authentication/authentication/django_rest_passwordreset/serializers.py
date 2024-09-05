from rest_framework import status
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404 as _get_object_or_404
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .models import get_password_reset_token_expiry_time
from . import models
import re

__all__ = [
    'EmailSerializer',
    'PasswordTokenSerializer',
    'ResetTokenSerializer',
]


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

from django.db import transaction
class PasswordConfirmSerializer(serializers.Serializer):
    
    status_code = serializers.IntegerField(read_only=True,default= 200)
    status = serializers.BooleanField(read_only=True)
    message = serializers.CharField(read_only=True,default = None)
    data = serializers.DictField(read_only=True,default = None)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        self.user = request.user
        self.resp = {'status' : False ,'status_code': 200, 'message' : None,'data': None}
        self.fields["password"] = serializers.CharField(max_length= 100, required = True,write_only=True)
        self.fields["confirm_password"] = serializers.CharField(max_length=100, required = True,write_only=True )
    
    def validate(self, attrs):
        attrs = super().validate(attrs)
        attrs['valid'] = False
        special_characters = r'!"\#$%&()*+,-./:;<=>?@[\\]^_`{|}~\'•√π÷×§∆£¢€¥°©®™✓'
        password = attrs['password']
        confirm_password = attrs['confirm_password']
        if password != confirm_password:
            self.resp["message"] = "Both passwords must be same."
            self.resp["status_code"] = 400
        elif not any(char.islower() for char in password):
            self.resp["message"] = "Password must contain at least one lowercase letter."
            self.resp["status_code"] = 400
        elif not any(char.isupper() for char in password):
            self.resp["message"] = "Password must contain at least one uppercase letter."
            self.resp["status_code"] = 400
        elif not any(char in special_characters for char in password):
            self.resp["message"] = "Password must contain at least one special character."
            self.resp["status_code"] = 400
        else:
            attrs['valid'] = True
        print("attrs: %s" % attrs)
        return attrs
    
    def create(self,validated_data):
        # validated_data = self.validated_data
        if validated_data['valid'] == True:
            with transaction.atomic():
                self.user.set_password(validated_data['password'])
                self.user.save()
            self.resp["status"] = True
            self.resp["message"] = "Password changed successfully"
            print("self.resp : ", self.resp)
        return self.resp
    
class PasswordValidateMixin:
    def validate(self, data):
        token = data.get('token')

        # get token validation time
        password_reset_token_validation_time = get_password_reset_token_expiry_time()

        # find token
        try:
            reset_password_token = _get_object_or_404(models.ResetPasswordToken, key=token)
        except (TypeError, ValueError, ValidationError, Http404,
                models.ResetPasswordToken.DoesNotExist):
            raise Http404(_("The OTP password entered is not valid. Please check and try again."))

        # check expiry date
        expiry_date = reset_password_token.created_at + timedelta(
            hours=password_reset_token_validation_time)

        if timezone.now() > expiry_date:
            # delete expired token
            reset_password_token.delete()
            raise Http404(_("The token has expired"))
        return data

class PasswordTokenSerializer(PasswordValidateMixin, serializers.Serializer):
    password = serializers.CharField(label=_("Password"), style={'input_type': 'password'})
    token = serializers.CharField()

class CustomPasswordTokenSerializer(serializers.Serializer):
    status = serializers.BooleanField(read_only=True)
    # error = serializers.CharField(read_only=True)
    message = serializers.CharField(read_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # self.resp = {'status' : False}
        self.fields["password"] = serializers.CharField(write_only=True,required = True)
        self.fields["token"] = serializers.CharField(write_only=True,required = True)

    def validate(self, attrs):
        attrs['status'] = False
        reset_password_token = None
        token = attrs.get('token')
        password = attrs.get('password')
        password_reset_token_validation_time = get_password_reset_token_expiry_time()
        try:
            reset_password_token = _get_object_or_404(models.ResetPasswordToken, key=token)
        except (TypeError, ValueError, ValidationError, Http404,models.ResetPasswordToken.DoesNotExist):
            attrs["error"] = "The OTP password entered is not valid. Please check and try again."
            attrs["status_code"] = status.HTTP_401_UNAUTHORIZED
        if reset_password_token is not None:
            expiry_date = reset_password_token.created_at + timedelta(hours=password_reset_token_validation_time)
            if timezone.now() > expiry_date:
                reset_password_token.delete()
                attrs["error"] = "The token has expired"
                attrs["status_code"] = status.HTTP_403_FORBIDDEN

            elif not any(char.islower() for char in password):
                attrs["error"] = "Password must contain at least one lowercase letter."
                attrs["status_code"] = status.HTTP_400_BAD_REQUEST

            elif not any(char.isupper() for char in password):
                attrs["error"] = "Password must contain at least one uppercase letter."
                attrs["status_code"] = status.HTTP_400_BAD_REQUEST

            elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                attrs["error"] = "Password must contain at least one unique character."
                attrs["status_code"] = status.HTTP_400_BAD_REQUEST

            else:
                attrs['status'] = True
                attrs['message'] = ""
        else:
            attrs["error"] = "Invalid Token."
        if 'error' in attrs:
            attrs['message'] = attrs.pop('error')
        attrs['data'] = {}
        return attrs 

class ResetTokenSerializer(PasswordValidateMixin, serializers.Serializer):
    token = serializers.CharField()
