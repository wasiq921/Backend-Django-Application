from django.contrib import admin
from .models import *
# Register your models here.



@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    list_display = ('name','created_at')
    search_fields = ('name', 'created_at', 'description')
    ordering = ['id']
@admin.register(PlanCharges)
class PlanChargesAdmin(admin.ModelAdmin):
    list_display = ('i_plan', 'code','charges_type','price')
    search_fields = ('code','charges_type','price', 'description')
    ordering = ['pk']


@admin.register(Membership)
class MembershipsAdmin(admin.ModelAdmin):
    list_display = ('i_plan', 'i_app', 'billing_cycle','starts_at', 'ends_at', 'is_active')
    search_fields = ('i_plan__name','i_profile__user__username','i_customer__i_profile__user__email')
    ordering = ['id']
