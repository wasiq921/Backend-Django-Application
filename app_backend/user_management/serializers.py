from rest_framework import serializers
from .models import *
from django.db.models import Q
from django.db import transaction 
from rest_framework import status
from subscription.utils import create_subscription
from subscription.models import Plan, PlanCharges


class CreateAppSerializer(serializers.Serializer):
    status = serializers.BooleanField(read_only=True)
    data = serializers.DictField(read_only=True, default={})
    message = serializers.CharField(read_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resp = {'status': False}
        request = self.context["request"]
        self.user = request.user
        self.fields["name"] = serializers.CharField(write_only=True, required=True)
        self.fields["description"] = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        attrs['valid'] = False

        if attrs['name'] is not None and attrs['description'] is not None:
            attrs['valid'] = True
        else:
            attrs['valid'] = False
        
        return attrs

    def create(self, validated_data):
        if validated_data['valid']:
            with transaction.atomic():
                name = validated_data['name']
                description = validated_data['description']
                app_obj = App.objects.create(i_profile=self.user.profile, name = name, description = description)
                plan_obj = Plan.objects.get(name = 'Free')
                subscription_resp = create_subscription(self.user, app_obj, plan_obj, 'monthly')
                if subscription_resp['status'] == True:
                    self.resp["status"] = True
                    self.resp['status_code'] = status.HTTP_200_OK
                    self.resp["message"] = "App Created Successfully"
                    self.resp["data"] = {}
                    return self.resp
                else:
                    self.resp["status"] = False
                    self.resp['status_code'] = status.HTTP_400_BAD_REQUEST
                    self.resp["message"] = "App Created but error in Subscription"
                    self.resp["data"] = {}
                    return self.resp
        self.resp["status"] = False
        self.resp['status_code'] = status.HTTP_400_BAD_REQUEST
        self.resp["message"] = "Failed to Create App"
        self.resp["data"] = {}
        return self.resp