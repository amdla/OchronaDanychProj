# urls.py
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path

from twitter_app import views

urlpatterns = [
    path('', views.index, name='home'),  # Strona główna
    path('login/', views.login_view, name='login'),  # Strona logowania
    path('logout/', views.logout_view, name='logout'),  # Wylogowanie
    path('register/', views.register, name='register'),  # Rejestracja
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
