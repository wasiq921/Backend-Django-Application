from django.db import transaction
from django.contrib.auth.models import User
from django.utils import timezone
from dateutil.relativedelta import relativedelta
from user_management.models import Profile
from .models import Membership ,Plan
from rest_framework import status

def create_subscription(user_obj,app_obj,plan_obj, billing_cycle=None):
    response = {'status': False}
    time_period = 1
    try:
        if billing_cycle is not None:
            billing_cycle = 'monthly'
            time_period = 1
        else:
            billing_cycle = "monthly"
        current_date = timezone.now()
        next_date =current_date + relativedelta(months=+time_period)
        subscriptions_obj_qs = Membership.objects.filter(i_app=app_obj)
        if len(subscriptions_obj_qs) != 0:
            for subscriptions_obj in subscriptions_obj_qs:
                subscriptions_obj.is_active = False
                subscriptions_obj.save()
        with transaction.atomic():
            subscriptions_obj =  Membership.objects.create(i_plan = plan_obj,
                                    i_app=app_obj,starts_at=current_date,
                                    ends_at = next_date,is_active =False,
                                    billing_cycle = 'monthly')
            subscriptions_obj.is_active =True
            subscriptions_obj.save()
            response = {'status': True,'message': 'Subscription created successfully'}
                
    except Exception as e:
        import sys, os
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        response = {'status': False,'error': repr(e)}
    return response



def get_user_app_subscription(app):
    list_of_user_subscription = []
    subs_obj =  Membership.objects.filter(i_app = app,is_active = True).values()
    for subs in subs_obj:
        list_of_user_subscription.append(subs)
    for i in list_of_user_subscription:
        i['profile_id_id'] = app.i_profile.user.email
        # print(invoice['i_plan_id'])-
        plan_obj =  Plan.objects.get(pk = i["i_plan_id"])
        i['plan_id_id'] = plan_obj.name
    return list_of_user_subscription


def get_plan_of_customer(app):
    try:
        membership = Membership.objects.filter(i_app = app, is_active = True)
        if membership.exists():
            membership = membership.last()
            return membership.i_plan.pk
        return None
    except:
        return None
