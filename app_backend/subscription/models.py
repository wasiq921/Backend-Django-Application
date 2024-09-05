from django.db import models
from django.utils import timezone
from user_management.models import Profile, App


# Create your models here.
CHOICES = [('monthly', 'monthly'),('annually', 'annually')]
CHARGES_TYPE = [('monthly', 'Monthly'),('yearly', 'Yearly'),('extra', 'Extra'),('first_month', "First Month")]



class Plan(models.Model):
    name = models.CharField(max_length = 64)
    description = models.TextField(null=True, blank=True)
    meta = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return '%s' % self.name
    class Meta:
        db_table = 'plan'

class PlanCharges(models.Model):
    i_plan = models.ForeignKey(Plan,on_delete = models.CASCADE,related_name="plan_charges")
    code = models.CharField(max_length=50, null= True, blank=True)
    charges_type = models.CharField(max_length=20,choices=CHARGES_TYPE)
    description = models.TextField(null=True, blank=True)
    meta = models.JSONField(null=True, blank=True)
    price = models.FloatField(max_length=20)

    def __str__(self):
        return '%s' % self.i_plan
    
    class Meta:
        db_table = 'plan_Charges'


class Membership(models.Model):
    i_plan = models.ForeignKey(Plan, on_delete = models.CASCADE)
    i_app = models.ForeignKey(App, on_delete = models.CASCADE, null=True, blank=True)
    billing_cycle = models.CharField(max_length = 50,choices = CHOICES,default = 'monthly')
    starts_at = models.DateTimeField()
    ends_at = models.DateTimeField()
    renewed_at = models.DateTimeField(blank=True, null=True)
    cancelled_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    expired_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default = False)
    product_id = models.CharField(blank=True, null=True)
    reference_id = models.CharField(blank=True, null=True)
    provider = models.CharField(blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2 , default = 0)

    def __str__(self):
        return f'{self.i_app.i_profile.user.email}|{self.i_app.name}|{self.i_plan}|{self.billing_cycle}' 
    class Meta:
        db_table = 'membership'
