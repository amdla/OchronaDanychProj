import secrets

import pyotp
from django.db import models
from django.utils import timezone

from twitter_app.utils import encrypt_totp_secret, hash_password, check_password


class User(models.Model):
    username = models.CharField(max_length=20, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    avatar = models.ImageField(upload_to='avatars/', default='avatars/standard_avatar.jpg')
    created_at = models.DateTimeField(default=timezone.now)
    totp_secret = models.CharField(max_length=100, blank=True, null=True)
    two_factor_enabled = models.BooleanField(default=True)
    private_key_hashed = models.CharField(max_length=255, blank=True, null=True)

    def generate_private_key(self):
        raw_private_key = secrets.token_hex(32)
        self.private_key_hashed = hash_password(raw_private_key)
        self.save()
        return raw_private_key

    def verify_private_key(self, private_key):
        return check_password(private_key, self.private_key_hashed)

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
    signed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def mark_as_signed(self):
        self.signed = True
        self.save()


class Device(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    device_name = models.CharField(max_length=255, default="Unknown Device")
    cookie_value = models.CharField(max_length=255, unique=True)
    last_login = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} - {self.device_name}"
