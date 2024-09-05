from allauth.socialaccount.models import SocialApp
from django.conf import settings
import requests, json, random
from django.contrib.auth.models import User
from .django_rest_passwordreset.signals import reset_password_token_created,otp_reset_password_token_created, user_signed_up
from django.conf import settings
from email.message import EmailMessage
from smtplib import SMTP_SSL
from django.dispatch import receiver
from django.urls import reverse
from django.conf import settings
from django_rest_authentication.authentication.django_rest_passwordreset.models import UserOfOTP,ProfileOTP
from django_rest_authentication.authentication.django_rest_passwordreset.views import generate_otp


def get_login_urls():
    url_dict = {}
    qs = SocialApp.objects.filter()
    provider_list =  list(qs.values_list('provider', flat= True).distinct())
    print(provider_list)
    if 'google' in provider_list:
        client_id = qs.filter(provider='google').first().client_id
        url = f'https://accounts.google.com/o/oauth2/v2/auth?redirect_uri={settings.CALLBACK_URL_YOU_SET_ON_GOOGLE}&prompt=consent&response_type=code&client_id={client_id}&scope=openid%20email%20profile&access_type=offline'
        url_dict['google_url'] = url
    if 'facebook'in provider_list: 
        client_id = qs.filter(provider='facebook').first().client_id
        url = f'https://www.facebook.com/v16.0/dialog/oauth?client_id={client_id}&redirect_uri={settings.CALLBACK_URL_YOU_SET_ON_FACEBOOK}&state=ds123456&response_type=token&scope=email'
        url_dict['facebook_url'] = url
    if 'apple' in provider_list:
        pass
    return url_dict

def get_google_id_token(validated_data):
    code = validated_data['code']
    print(code)
    url = "https://oauth2.googleapis.com/token"
    google_config_obj = SocialApp.objects.get(provider='google')
    # print(google_config_obj)
    payload={'client_id': str(google_config_obj.client_id),
        'client_secret': str(google_config_obj.secret),
        'redirect_uri': str(settings.CALLBACK_URL_YOU_SET_ON_GOOGLE),
        'grant_type': 'authorization_code',
        'code': code}
    files=[]
    payload = json.dumps(payload)
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload, files=files)
    print(response.status_code)
    content = response.json()
    id_token = content.get('id_token')
    return {'access_token': id_token}

def get_google_jwt(access_token):
    try:
        url = f"{settings.SERVER_HOST}auth/google/"
        print("url: ",url)

        payload = json.dumps(access_token)
        headers = {
        'content-type': 'application/json',
        }
        # print("headers: ",headers)
        # print("payload: ",payload)
        response = requests.request("POST",url, data=access_token)
        print ("<====response.status_code====>",response.status_code)
        if response.status_code==200:
            resp = {"status": True, 'data': response.json()}
        else:
            # print ("<====response.text====>",response.text)
            resp = {"status": False, 'data': "google authentication failed"}
    except Exception as e:
        print("Exception in get_google_jwt: ",repr(e))        
        resp = {"status": False, 'data': "google authentication failed"}
    return resp

def get_facebook_jwt(access_token):
    import requests
    import json

    url = f"{settings.EMAIL_HOST}auth/facebook/"

    payload = json.dumps({
    "access_token": access_token
    })
    headers = {
    'Content-Type': 'application/json',
    # 'Cookie': 'csrftoken=ldcsR1VCKtlv8vpY0AWMmnTQ4noIzAlN; messages=W1siX19qc29uX21lc3NhZ2UiLDAsMjUsIlN1Y2Nlc3NmdWxseSBzaWduZWQgaW4gYXMgbXVoYW1tYWRfYWxpLiIsIiJdXQ:1pxLUC:v-rtZAY6XVZ1ViyDP6RhwJP4rtfaskEkbJ11T1-zS48; sessionid=e2thvbu5x5tqi04mbtuu9eocg4yn4aks'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    # print(response.text)
    if response.status_code==200:
        resp = {"status": True, 'data': response.json()}
    else:
        resp = {"status": False, 'data': "facebook authentication failed"}
    return resp





def extract_name_components(name):
    components = name.split()  # Split the name into individual words
    # Extract the first name
    first_name = components[0]
    if len(components) == 1:
        # Only first name is available
        return first_name , None ,None
    elif len(components) == 2:
        # First name and last name are available
        last_name = components[1]
        return first_name,None, last_name 
    else:
        # First name, middle name, and last name are available
        middle_name = " ".join(components[1:-1])
        last_name = components[-1]
        return first_name, middle_name, last_name
    


def full_name_components(name):
    components = name.split()  # Split the name into individual words
    
    # Extract the first name
    first_name = components[0]
    
    if len(components) == 1:
        # Only first name is available
        return first_name, None
    else:
        # First name and last name are available
        last_name = ' '.join(components[1:])
        return first_name, last_name



@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    try:
        from user_management.models import GlobalConfiguration
        team_name = GlobalConfiguration.objects.filter(name="app_name")
        if team_name.exists():
            team = team_name.last().value
        else:
            team = ''
    except:
        team = ''
    email_host = settings.EMAIL_HOST

    if email_host.endswith('/'):
        email_host = email_host[:-1]
    email_plaintext_message = "{}{}?token={}".format(email_host,reverse('reset-password-confirm'), reset_password_token.key)
    email_body = f"Hello {get_full_name(reset_password_token.user)},\n\nPlease click on the following link to reset your password:\n\n{email_plaintext_message}\n\nIf you didn't request a password reset, please ignore this email.\n\nThank you,\nTeam {team}"

    email_subject = "Requested For Paswords Reset"
    send_email_to_user(reset_password_token.user, email_subject, email_body)

@receiver(otp_reset_password_token_created)
def password_reset_token_created(sender, instance,user,otp_obj, *args, **kwargs):
    try:
        from user_management.models import GlobalConfiguration
        team_name = GlobalConfiguration.objects.filter(name="app_name")
        if team_name.exists():
            team = team_name.last().value
        else:
            team = ''
    except:
        team = ''

    email_body = f"Hello {get_full_name(user)},\n\nHere is OTP for reset your password:\n\n{otp_obj.otp}\n\nIf you didn't request a password reset, please ignore this email.\n\nThank you,\nTeam {team}"
    email_subject = "Requested For Paswords Reset OTP"
    send_email_to_user(user, email_subject, email_body) 

def send_email_to_user(user_obj, email_subject, body):
    user_email = user_obj.email
    email_sender = settings.EMAIL_HOST_USER
    email_receiver = user_email
    subject = email_subject
    body = body
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    with SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        smtp.sendmail(settings.EMAIL_HOST_USER, user_obj.email, em.as_string())



@receiver(user_signed_up)
def send_signup_otp_email(sender, user, otp_obj, *args, **kwargs):
    email_body = f"Hello {get_full_name(user)},\n\nHere is your OTP for account verification:\n\n{otp_obj.otp}\n\nIf you didn't sign up, please ignore this email.\n\nThank you,\nTeam SoulScribe"
    email_subject = "Verify Your Account"
    send_email_to_user(user, email_subject, email_body)

def generate_username(first_name, last_name = None):
    username = None
    loop_status = True
    i = 100
    fullname = first_name.replace(" ", "").lower()
    if last_name is not None:
        fullname += last_name.replace(" ", "").lower()
    while loop_status:
        username =  fullname + str(random.randint(1, i))
        obj = User.objects.filter(username=username)
        if not obj.exists():
            loop_status = False
        else:
            i += i
    return username


def get_full_name(user_obj):
    fullname = ""
    if user_obj.first_name is not None:
        fullname += user_obj.first_name
    
        if user_obj.last_name is not None or user_obj.last_name != "" or user_obj.last_name != " ":
            fullname += " "+user_obj.last_name
    else:
        fullname += user_obj.email
    
    return fullname


def signup_otp_validation(otp_required,attrs):
    errors = None
    password = attrs['password']
    email = attrs['email'].lower()
    attrs['valid'] = False
    special_characters = r'!"\#$%&()*+,-./:;<=>?@[\\]^_`{|}~\'•√π÷×§∆£¢€¥°©®™✓'
    is_valid = True
    if otp_required == True:
        user_qs = User.objects.filter(email=email)
        print(user_qs,"+====")
        if user_qs.exists():
            user_obj = user_qs.first()
            otp_qs = UserOfOTP.objects.filter(otp_user = user_obj)
            if otp_qs.exists():
                otp_obj = otp_qs.first()
                if otp_obj.otp_verified == False:
                    attrs['is_otp_verified'] = False
                else:
                    attrs['is_otp_verified'] = True
            # attrs['user_email'] = email
            else:
                errors = "This email is already taken."
                is_valid = False
        else:
            pass
            # attrs['is_otp_verified'] = False
            
        if settings.ENABLE_CONFIRM_PASSWORD == True:
            password2 = attrs['confirm_password']
            if is_valid and password != password2:
                errors = "Password fields didn’t match."
                is_valid = False
        if is_valid and not any(char.islower() for char in password):
            errors = "Password must contain at least one lowercase letter."
            is_valid = False
        if is_valid and not any(char.isupper() for char in password):
            errors = "Password must contain at least one uppercase letter."
            is_valid = False
        if is_valid and not any(char in special_characters for char in password):
            errors = "Password must contain at least one Special character."
            is_valid = False

        if not is_valid:
            attrs['error'] = errors
        if 'error' not in attrs:
            attrs['user_email'] = email
        attrs['valid'] = is_valid
        return attrs
            

def signup_otp_request(validated_data):
    first_name = validated_data.get('first_name',None)
    last_name = validated_data.get('last_name',None)
    email = validated_data.get('email',None).lower()
    password = validated_data.get('password',None)
    user_obj = User.objects.filter(email = email).first()
    user_obj.set_password(password)
    user_obj.first_name = first_name
    if settings.USER_DEFINED_USERNAME == False:
        if settings.EMAIL_AS_USERNAME == True:
            username = email
        else:
            username = generate_username(first_name, last_name)
    user_obj.username = username
    user_obj.save()
    otp_obj_user = UserOfOTP.objects.filter(otp_user = user_obj)
    otp_verified = None
    if not otp_obj_user.exists():
        otp_verified = UserOfOTP.objects.create(
        otp_user = user_obj)
       

    otp = generate_otp()
    ProfileOTP.objects.filter(user = user_obj).delete()
    otp_obj = ProfileOTP.objects.create(user = user_obj,otp = otp)
    user_signed_up.send(sender=user_obj.__class__, user=user_obj, otp_obj=otp_obj)

    return {'pk':user_obj.pk, 'full_name':get_full_name(user_obj),'otp_required':True,'otp_verified':otp_verified.otp_verified if otp_verified else otp_obj_user.first().otp_verified}