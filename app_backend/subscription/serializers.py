from rest_framework import serializers
from .models import *
from django.contrib.auth.models import User


# class ModuleSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Module
#         fields = '__all__'




    


class PlanSerializer(serializers.ModelSerializer):
    status = serializers.BooleanField(read_only= True)
    message = serializers.CharField(read_only= True)
    error = serializers.CharField(read_only= True)
    class Meta:
        model = Plan
        fields = ('name','price','description','status','message','error')
        extra_kwargs = {
            'description': {'required': True, 'write_only': True},
            'name': {'required': True,'write_only': True},
            'price': {'required': True,'write_only': True},
            'created_at': {'required': True,'write_only': True}
        }

    def create(self, validated_data):
        print("validated_data: ",validated_data)
        try:
            Plan.objects.create(
            name = validated_data['name'],
            price = validated_data['price'], 
            description = validated_data['description'])
            response_data = {
            'status': True,
            'message': 'Plan created successfully',
        }
        except Exception as e:
            response_data = {
            'status': False,
            'error': repr(e),
        }     
        return response_data

    def update(self, instance, validated_data):
        response_data = {}
        try:
            instance.name = validated_data.get('name', instance.name)
            instance.price = validated_data.get('price', instance.price)
            instance.description = validated_data.get('description', instance.description)
            instance.save()
            response_data["status"] = True
            response_data["message"] = "Plan updated successfully"
        except Exception as e:
            response_data['status'] = False
            response_data['error'] = repr(e)
        return response_data


