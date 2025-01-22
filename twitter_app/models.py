import pyotp
from django.db import models
from django.utils import timezone

from twitter_app.utils import encrypt_totp_secret


class User(models.Model):
    username = models.CharField(max_length=20, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    avatar = models.ImageField(upload_to='avatars/', default='avatars/standard_avatar.jpg')
    created_at = models.DateTimeField(default=timezone.now)
    totp_secret = models.CharField(max_length=100, blank=True, null=True)
    two_factor_enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.username

    def generate_totp_secret(self):
        if not self.totp_secret:
            plain_secret = pyotp.random_base32()
            self.totp_secret = encrypt_totp_secret(plain_secret)
            self.save()


class Message(models.Model):
    content = models.TextField()
    image = models.ImageField(upload_to='uploads/', null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='messages')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.IntegerField(default=1)

    class Meta:
        ordering = ['-created_at']


class Device(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    device_name = models.CharField(max_length=255, default="Unknown Device")
    cookie_value = models.CharField(max_length=255, unique=True)
    last_login = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} - {self.device_name}"
