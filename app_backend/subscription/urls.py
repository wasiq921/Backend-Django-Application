from django.urls import path , include
from django.contrib import admin
from .views import *

urlpatterns = [
   
   path('create_plan/',CreatePlan.as_view(),name='create_plan'),
   path('update_plan/<int:pk>/',UpdatePlan.as_view(),name='update_plan'),
   path('delete_plan/<int:pk>/',DeletePlan.as_view(),name='delete_plan'),

   path('cancel_subscription/', CancelSubscription.as_view(), name='cancel_membership'),
   path('view_subscription/', ViewSubscription.as_view(), name='view_subscription'),
   path('upgrade_subscription/', UpgradeSubscription.as_view(), name='upgrade_subscription'),
   path('check_subscription/', CheckSubscription.as_view(), name='check_subscription'),
   path('get_subscription_details/', GetPackageDetails.as_view(), name='get_package_details'),
]
