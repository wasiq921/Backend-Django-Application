from django.test import TestCase
from django.contrib.auth.models import User
from .utils import *
# Create your tests here.
user_obj = User.objects.get(pk=51)
xresp = get_driver_active_membership(user_obj.profile)
if xresp['status']:
    resp = get_driver_apply_status(xresp['data'])
    print(resp)