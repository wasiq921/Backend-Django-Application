"""
Django settings for app_backend project.

Generated by 'django-admin startproject' using Django 4.2.15.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
from datetime import timedelta
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-eluhzxql%rv^ff30b3^n8y25o_k3-!7n&%4%f%kms%mni8y2l6'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'user_management',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'rest_framework.authtoken',
    'rest_framework',
    'django_rest_authentication.authentication.django_rest_passwordreset',
    'django_rest_authentication.dj_rest_auth',
    'django_rest_authentication.dj_rest_auth.registration',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.apple',
    'allauth.socialaccount.providers.facebook',
    'allauth.socialaccount.providers.google',
    'subscription'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',
]

ROOT_URLCONF = 'app_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'app_backend.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'app_backend_api',
        'USER': 'postgres',
        'PASSWORD': 'roOt@5',
        'HOST': '127.0.0.1',
        'PORT': ' 5432',
    }
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
       'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}


SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=1440),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': False,
    'UPDATE_LAST_LOGIN': False,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,

    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',
    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",

    'JTI_CLAIM': 'jti',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(days=1),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

REST_AUTH = {
    'LOGIN_SERIALIZER': 'django_rest_authentication.dj_rest_auth.serializers.LoginSerializer',
    'TOKEN_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenObtainPairSerializer',
    'JWT_SERIALIZER': 'django_rest_authentication.dj_rest_auth.serializers.JWTSerializer',
    'JWT_SERIALIZER_WITH_EXPIRATION': 'django_rest_authentication.dj_rest_auth.serializers.JWTSerializerWithExpiration',
    'JWT_TOKEN_CLAIMS_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenObtainPairSerializer',
    'USER_DETAILS_SERIALIZER': 'django_rest_authentication.dj_rest_auth.serializers.UserDetailsSerializer',
    'PASSWORD_RESET_SERIALIZER': 'django_rest_authentication.dj_rest_auth.serializers.PasswordResetSerializer',
    'PASSWORD_RESET_CONFIRM_SERIALIZER': 'django_rest_authentication.dj_rest_auth.serializers.PasswordResetConfirmSerializer',
    # 'PASSWORD_CHANGE_SERIALIZER': 'dj_rest_auth.serializers.PasswordChangeSerializer',
    'PASSWORD_CHANGE_SERIALIZER': 'django_rest_authentication.authentication.serializers.CustomPasswordChangeSerializer',
    'REGISTER_SERIALIZER': 'django_rest_authentication.dj_rest_auth.registration.serializers.RegisterSerializer',

    'REGISTER_PERMISSION_CLASSES': ('rest_framework.permissions.AllowAny',),

    'TOKEN_MODEL': None,
    'TOKEN_CREATOR': 'django_rest_authentication.dj_rest_auth.utils.default_create_token',

    'PASSWORD_RESET_USE_SITES_DOMAIN': False,
    'OLD_PASSWORD_FIELD_ENABLED': True,
    'LOGOUT_ON_PASSWORD_CHANGE': True,
    'SESSION_LOGIN': True,
    'USE_JWT': True,

    'JWT_AUTH_COOKIE': None,
    'JWT_AUTH_REFRESH_COOKIE': None,
    'JWT_AUTH_REFRESH_COOKIE_PATH': '/',
    'JWT_AUTH_SECURE': False,
    'JWT_AUTH_HTTPONLY': False,
    'JWT_AUTH_SAMESITE': 'Lax',
    'JWT_AUTH_RETURN_EXPIRATION': False,
    'JWT_AUTH_COOKIE_USE_CSRF': False,
    'JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED': False,
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

UPLOADS_DIR_NAME = 'media'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')
MEDIA_URL = '/media/'


CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
# CORS_ORIGIN_WHITELIST = (
#     'http://localhost:3006',
#     'http://127.0.0.1:8000'
# )
CORS_ALLOW_METHODS = [
    "DELETE","GET","OPTIONS",
    "PATCH","POST","PUT",
]
CORS_ALLOW_HEADERS = [
    "accept","accept-encoding","authorization",
    "content-type","dnt","origin","user-agent",
    "x-csrftoken","x-requested-with",
    "cache-control","pragma",
]
SITE_ID = 2
CALLBACK_URL_YOU_SET_ON_GOOGLE = "http://127.0.0.1:8000/dashboard/"
CALLBACK_URL_YOU_SET_ON_FACEBOOK = 'http://localhost:8000/'

ENABLE_LAST_NAME = False
ENABLE_CONFIRM_PASSWORD = False 
USER_DEFINED_USERNAME = False
EMAIL_AS_USERNAME = True