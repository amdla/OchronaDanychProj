import os

from django.core.wsgi import get_wsgi_application

# Ustawiamy domyślną konfigurację ustawień Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'twitter_app.settings')

# Tworzymy aplikację WSGI, którą serwer będzie wykorzystywał
application = get_wsgi_application()
