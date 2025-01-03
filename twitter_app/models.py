from django.db import models
from django.utils import timezone
from django.utils.timezone import now


class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    avatar = models.ImageField(upload_to='avatars/', default='avatars/standard_avatar.jpg')
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.username


class Message(models.Model):
    content = models.TextField()
    image = models.ImageField(upload_to='uploads/', null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='messages')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.IntegerField(default=1)

    def __str__(self):
        return self.content[:50]  # Zwróci pierwsze 50 znaków wiadomości

    class Meta:
        ordering = ['-created_at']  # Domyślne sortowanie wiadomości od najnowszych

    def get_content_preview(self):
        """Method to display a preview of content with simple formatting (if needed)."""
        return self.content[:100]  # Zwraca pierwsze 100 znaków wiadomości


class LoginAttempt(models.Model):
    username = models.CharField(max_length=150, unique=True)
    failed_attempts = models.PositiveIntegerField(default=0)
    last_attempt_time = models.DateTimeField(auto_now=True)

    def is_locked_out(self, max_attempts, lockout_duration):
        if self.failed_attempts >= max_attempts:
            return now() - self.last_attempt_time < lockout_duration
        return False

    def reset_attempts(self):
        self.failed_attempts = 0
        self.save()


class Device(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    device_name = models.CharField(max_length=255, default="Unknown Device")
    cookie_value = models.CharField(max_length=255, unique=True)
    last_login = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} - {self.device_name}"
