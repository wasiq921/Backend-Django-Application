from .views import *
from django.urls import include, path
from django_rest_authentication.authentication.django_rest_passwordreset.urls import (
    urlpatterns as password_reset_urls,
)

app_name = 'user_management'

urlpatterns = [
   path('create_app/', CreateApp.as_view(), name='create_app'),
   path('view_apps/', ViewApps.as_view(), name='view_apps'),
   path('update_app/', UpdateApp.as_view(), name='update_app'),
   path('delete_app/', DeleteApp.as_view(), name='delete_app')
]