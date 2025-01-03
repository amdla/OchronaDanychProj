# urls.py
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include

from twitter_app import views

urlpatterns = [
    path('', views.index, name='home'),  # Strona główna
    path('login/', views.login_view, name='login'),  # Strona logowania
    path('logout/', views.logout_view, name='logout'),  # Wylogowanie
    path('register/', views.register, name='register'),  # Rejestracja
    path('captcha/', include('captcha.urls')),  # Add this line
    path('delete/<int:message_id>/', views.delete_message, name='delete_message'),
    path('user/<str:username>/', views.user_profile, name='user_profile'),
    path('devices/', views.list_user_devices, name='list_user_devices'),
    path('devices/delete/<int:device_id>/', views.delete_device_cookie, name='delete_device_cookie'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
