import os
from pathlib import Path

# BASE_DIR is the directory where manage.py is located
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
SECRET_KEY = 'your-secret-key'  # Pamiętaj, by w produkcji zmienić na coś bezpiecznego
DEBUG = True  # Ustaw na False w produkcji
ALLOWED_HOSTS = []  # Dostosuj do swoich domen w produkcji (np. ['yourdomain.com'])
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Applications
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'captcha',
    'twitter_app',
]

# Middleware configuration
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

]

# Root URL configuration
ROOT_URLCONF = 'twitter_app.urls'  # Zmieniamy na nazwę swojego projektu

# Templates configuration
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'twitter_app', 'templates')],
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

# WSGI and ASGI applications
WSGI_APPLICATION = 'twitter_app.wsgi.application'  # Zmieniamy na nazwę swojego projektu

# Database configuration (domyślna SQLite dla rozwoju)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',  # Zmieniamy na swoją bazę danych, np. PostgreSQL
    }
}
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
# Password validation
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

# Localization settings
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'twitter_app', 'static')]
# STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Authentication settings
LOGIN_URL = 'login'  # Przekierowanie do logowania, jeśli użytkownik nie jest zalogowany
LOGIN_REDIRECT_URL = 'home'  # Przekierowanie po zalogowaniu
LOGOUT_REDIRECT_URL = 'home'  # Przekierowanie po wylogowaniu

# Email settings (do wysyłania e-maili, np. w przypadku zapomnianego hasła)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'  # Do testów, zmień na prawdziwy backend w produkcji
