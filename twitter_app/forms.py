from captcha.fields import CaptchaField
from django import forms

from twitter_app.models import Message, User
from twitter_app.utils import IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES, MIN_POST_LENGTH


class MessageForm(forms.ModelForm):
    image = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs={'class': 'image-input'}),
        label="Upload Image"
    )

    class Meta:
        model = Message
        fields = ['content', 'image_url', 'image']

    def clean_content(self):
        content = self.cleaned_data.get('content')
        if len(content) < MIN_POST_LENGTH:
            raise forms.ValidationError("Message is too short!")
        return content

    def clean_image(self):
        image = self.cleaned_data.get('image')
        if image:
            # Check file extension
            if not image.name.endswith(('.jpg', '.jpeg', '.png', '.gif')):
                raise forms.ValidationError("Only image files (JPG, JPEG, PNG, GIF) are allowed.")

            if image.size > IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES:
                raise forms.ValidationError(
                    f"Image size should not exceed {IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES / 1024 / 1024} MB.")
        return image


class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    password_confirm = forms.CharField(widget=forms.PasswordInput)
    email = forms.EmailField(widget=forms.EmailInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean_password_confirm(self):
        password = self.cleaned_data.get("password")
        password_confirm = self.cleaned_data.get("password_confirm")

        if password != password_confirm:
            raise forms.ValidationError("Passwords don't match")

        return password_confirm


class LoginForm(forms.Form):
    username = forms.CharField(max_length=150, label='Username')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')
    captcha = CaptchaField(required=False)  # CAPTCHA field, initially optional
