from django.shortcuts import render
from rest_framework import (generics , permissions,status)
from .serializers import *
from rest_framework.views import APIView
from subscription.models import Membership
from rest_framework.response import Response

# Create your views here.

class CreateApp(generics.CreateAPIView):
    serializer_class = CreateAppSerializer

class ViewApps(APIView):
    def get(self, request):
        resp = {'status' : False, 'status_code' : status.HTTP_400_BAD_REQUEST, 'message' : "No App Found", 'data' : {}}

        apps_qs = App.objects.filter(i_profile = request.user.profile)
        app_lst = []

        for app in apps_qs:
            membership = Membership.objects.filter(i_app = app, is_active = True).last()
            data = {
                "app_id" : app.pk,
                "profile_id" : app.i_profile.pk,
                "user_name" : app.i_profile.get_full_name(),
                "email" : app.i_profile.user.email,
                "app_name" : app.name,
                "app_description" : app.description,
                "app_membership" : membership.i_plan.name
            }
            app_lst.append(data)
        
        resp['status'] = True
        resp['status_code'] = status.HTTP_200_OK
        resp['message'] = "My Apps"
        resp['data'] = {'apps' : app_lst}

        return Response(resp, status=resp['status_code'])
    
class UpdateApp(APIView):
    def post(self, request):
        app_id = request.data.get('app_id', None)
        resp = {}
        if app_id is not None:
            app_qs  = App.objects.filter(pk = app_id, i_profile = request.user.profile).last()

        else:
            resp['status'] = True
            resp['status_code'] = status.HTTP_400_BAD_REQUEST
            resp['message'] = "App id is required"
            resp['data'] = {}

            return Response(resp, status=status.HTTP_400_BAD_REQUEST)
        if app_qs:
            name = request.data.get('name', app_qs.name)
            description = request.data.get('description', app_qs.description)

            app_qs.name = name
            app_qs.description = description
            app_qs.save()

            resp['status'] = True
            resp['status_code'] = status.HTTP_200_OK
            resp['message'] = "App Updated Successfully"
            resp['data'] = {}

            return Response(resp, status=status.HTTP_200_OK)
        else:
            resp['status'] = False
            resp['status_code'] = status.HTTP_400_BAD_REQUEST
            resp['message'] = "App not found"
            resp['data'] = {}

            return Response(resp, status=status.HTTP_400_BAD_REQUEST)
        
class DeleteApp(APIView):
    def post(self, request):
        app_id = request.data.get('app_id', None)
        resp = {}
        if app_id is not None:
            app_qs  = App.objects.filter(pk = app_id, i_profile = request.user.profile).last()

        else:
            resp['status'] = True
            resp['status_code'] = status.HTTP_400_BAD_REQUEST
            resp['message'] = "App id is required"
            resp['data'] = {}

            return Response(resp, status=status.HTTP_400_BAD_REQUEST)
        if app_qs:
            app_qs.delete()

            resp['status'] = True
            resp['status_code'] = status.HTTP_200_OK
            resp['message'] = "App deleted successfully"
            resp['data'] = {}
            return Response(resp, status=status.HTTP_200_OK)
        else:
            resp['status'] = False
            resp['status_code'] = status.HTTP_400_BAD_REQUEST
            resp['message'] = "App not found"
            resp['data'] = {}

            return Response(resp, status=status.HTTP_400_BAD_REQUEST)
        

