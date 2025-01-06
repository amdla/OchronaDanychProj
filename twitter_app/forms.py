from captcha.fields import CaptchaField
from django import forms
from django.core.validators import RegexValidator
from django.forms import ValidationError

from twitter_app.models import Message, User
from twitter_app.utils import IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES


class MessageForm(forms.ModelForm):
    image = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs={'class': 'image-input'}),
        label="Upload Image"
    )

    class Meta:
        model = Message
        fields = ['content', 'image']

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
    password_validator = RegexValidator(
        regex='^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{8,}$',
        message='Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, '
                'a number, and a special character.'
    )

    password = forms.CharField(widget=forms.PasswordInput, validators=[password_validator])
    password_confirm = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean_password_confirm(self):
        password = self.cleaned_data.get("password")
        password_confirm = self.cleaned_data.get("password_confirm")
        if password and password_confirm and password != password_confirm:
            raise ValidationError("Passwords don't match")
        return password_confirm


class LoginForm(forms.Form):
    username = forms.CharField(max_length=20, label='Username')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')
    captcha = CaptchaField(required=False)


class AvatarForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['avatar']

    def clean_avatar(self):
        avatar = self.cleaned_data.get('avatar')
        if avatar:
            if not avatar.name.endswith(('.jpg', '.jpeg', '.png', '.gif')):
                raise forms.ValidationError("Only image files (JPG, JPEG, PNG, GIF) are allowed.")
            if avatar.size > IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES:
                raise forms.ValidationError(
                    f"Image size should not exceed {IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES / 1024 / 1024} MB.")
        return avatar


class PasswordResetForm(forms.Form):
    password = forms.CharField(
        widget=forms.PasswordInput,
        validators=[RegisterForm.password_validator],
        label='New Password'
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput,
        label='Confirm New Password'
    )

    def clean_password_confirm(self):
        password = self.cleaned_data.get("password")
        password_confirm = self.cleaned_data.get("password_confirm")
        if password and password_confirm and password != password_confirm:
            raise ValidationError("Passwords don't match")
        return password_confirm
