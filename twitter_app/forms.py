from django import forms

from twitter_app.models import Message, User


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
        if len(content) < 5:
            raise forms.ValidationError("Message is too short!")
        return content

    def clean_image(self):
        image = self.cleaned_data.get('image')
        if image:
            # Check file extension
            if not image.name.endswith(('.jpg', '.jpeg', '.png', '.gif')):
                raise forms.ValidationError("Only image files (JPG, JPEG, PNG, GIF) are allowed.")
            # Check file size (max 5MB)
            if image.size > 5 * 1024 * 1024:
                raise forms.ValidationError("Image size should not exceed 5MB.")
        return image


class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    password_confirm = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean_password_confirm(self):
        password = self.cleaned_data.get("password")
        password_confirm = self.cleaned_data.get("password_confirm")

        if password != password_confirm:
            raise forms.ValidationError("Passwords don't match")

        return password_confirm
