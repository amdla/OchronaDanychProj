from django.db import models
from django.utils import timezone


class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.username


class Message(models.Model):
    content = models.TextField()
    image_url = models.URLField(null=True, blank=True)
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
