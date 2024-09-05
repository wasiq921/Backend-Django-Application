from rest_framework import generics , status
from rest_framework.views import APIView
from rest_framework.response import Response
from user_management.permissions import AdminOrReadOnly, IsAdminOnly
from rest_framework.permissions import IsAuthenticated,AllowAny
# from loggings.utils import save_system_logs,get_username
from .serializers import *
from .utils import *
from datetime import datetime

# Create your views here.
BILLING_CYCLE_VALUE = {"monthly" : 1,"annually" : 12,"yearly" : 12}

class CreatePlan(generics.CreateAPIView):
    permission_classes = [IsAdminOnly]
    serializer_class = PlanSerializer

class UpdatePlan(APIView):
    permission_classes = [IsAdminOnly]
    serializer_class = PlanSerializer
    def post(self,request,*args,**kwargs):
        pk = kwargs.get('pk')
        response = {"status" :  False}
        try:
            instance = Plan.objects.get(pk=pk)  
            serializer = self.serializer_class(instance, data=request.data, context={'request': request})
            if serializer.is_valid():
                resp = serializer.update(instance, serializer.validated_data) 
                response = resp
            else:
                response["error"] = serializer.errors
        except Exception as e:
            print (e)
            response["error"] = "Plan does not exist"
        return Response(response)

class DeletePlan(APIView):
    permission_classes = [AdminOrReadOnly]
    def post(self,request,*args,**kwargs):
        pk = kwargs.get('pk')
        response = {"status" :  False}
        try:
            instance = Plan.objects.get(pk=pk)  
            instance.delete()
            response['status'] = True
            response['message'] = "Plan deleted successfully"
        except Exception as e:
            response["error"] = "Error deleting instance does not exist"
        return Response(response)




class CancelSubscription(APIView):
    def post(self, request):
        response = {"status" : False}
        user = self.request.user
        app_id = request.data.get('app_id', None)
        current_date = timezone.now()
        next_date = timezone.now() + relativedelta(months = +1)
        try:
            app_obj = App.objects.get(i_profile=user.profile, pk = app_id)
            subs_obj = Membership.objects.get(i_app = app_obj, is_active = True)
            subs_obj.cancelled_at = current_date
            subs_obj.is_active = False
            subs_obj.save()
            user_obj = request.user
            plan_obj = Plan.objects.get(name = 'Free')
            create_subscription(user_obj,app_obj,plan_obj, 'monthly')
            response['status'] = True
            response['message'] = "Subscription has been cancelled."
        except Exception as e:
            print('Exception' , repr(e))
            response['message'] = repr(e)

        return Response(response)


class ViewSubscription(APIView):
    def get(self, request):
        response = {'status' : False}
        print("view_subscription")
        app_id = request.GET.get('app_id', None)
        app_obj = App.objects.get(pk = app_id)
        list_of_user_subscriptions = get_user_app_subscription(app_obj)
        response['data'] = list_of_user_subscriptions
        response['status'] = True
        return Response(response)

class UpgradeSubscription(APIView):

    def post(self, request):
        response ={"status": False,"error": "Invalid request type"}
        plan_id  = self.request.data.get('plan_id', None)
        app_id  = self.request.data.get('app_id', None)
        billing_cycle = 'monthly'
        user_obj = self.request.user
        try:
            plan_obj = Plan.objects.get(pk = plan_id)
            app_obj =  App.objects.get(pk = app_id, i_profile = user_obj.profile)
            response = create_subscription(user_obj,app_obj,plan_obj, billing_cycle)
        except Exception as e:
           
            response ={"status": False,"error": repr(e)}
        
        return Response(response)



class CheckSubscription(APIView):
    def get(self, request):
        profile = request.user.profile
        try:
            plan = get_plan_of_customer(profile)
            if plan is not None:
                try:
                    plan_obj = Plan.objects.get(pk = plan).name
                    
                    response= {
                        "status" : True,
                        "status_code" : status.HTTP_200_OK,
                        "data" : {
                                "plan_name" : plan_obj
                        }
                    }
                    return Response(response, status= status.HTTP_200_OK)
                except Plan.DoesNotExist:
                    response= {
                        "status" : False,
                        "status_code" : status.HTTP_400_BAD_REQUEST,
                        "data" : {

                        },
                        "error" : "Invalid Plan"
                    }
                    return Response(response, status= status.HTTP_200_OK)
            else:
                response= {
                        "status" : False,
                        "status_code" : status.HTTP_400_BAD_REQUEST,
                        "data" : {

                        },
                        "error" : "No Membership Found."
                    }
                return Response(response, status= status.HTTP_200_OK)

        except Exception as e:
            print(repr(e))
            return Response({"status": True, "error": None, "status_code" : status.HTTP_400_BAD_REQUEST}, status= status.HTTP_200_OK)
        
class GetPackageDetails(APIView):
    def get(self, request):
        response = {"status": False, "message": "Default Error Message",
                    "status_code": status.HTTP_400_BAD_REQUEST, "data": None}
        subscription_qs = Membership.objects.filter(i_app__i_profile = request.user.profile)
        if subscription_qs:
            subscription_lst = []
            for subscription_obj in subscription_qs:
                plan_charges_obj = PlanCharges.objects.get(i_plan = subscription_obj.i_plan)
                            
                subscription_lst.append({"app_id" : subscription_obj.i_app.pk, 
                                         "app_name" : subscription_obj.i_app.name,
                                         "plan_id":subscription_obj.i_plan.pk,
                    "plan" : f"{subscription_obj.i_plan.name} Subscription",
                    "price" : plan_charges_obj.price,"details" :subscription_obj.i_plan.description.split(","),
                    "expire_at" : subscription_obj.expired_at,"billing_cycle" : plan_charges_obj.charges_type,
                    "metadata" : plan_charges_obj.meta,
                    "cancelled_at" : subscription_obj.cancelled_at, "is_active" : subscription_obj.is_active
                    })
            response['status'] = True
            response["status_code"] = status.HTTP_200_OK
            response["message"] = "Subscription Details"
            response["data"] = {"subscription_details" : subscription_lst}
        else:
            response["message"] = "No Subscription Details Available"
        
        return Response(response, status=response["status_code"])

    
