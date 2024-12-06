# urls.py
from django.urls import path

from twitter_app import views

urlpatterns = [
    path('', views.index, name='home'),  # Strona główna
    path('login/', views.login_view, name='login'),  # Strona logowania
    path('logout/', views.logout_view, name='logout'),  # Wylogowanie
    path('register/', views.register, name='register'),  # Rejestracja
    path('post_message/', views.post_message, name='post_message'),  # Dodawanie wiadomości
]
