from django import forms

from twitter_app.models import Message, User


class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['content', 'image_url']  # Obsługuje zarówno treść wiadomości, jak i obrazek

    content = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Post a message...', 'class': 'message-input', 'rows': 4}),
        label="Message"
    )
    image_url = forms.URLField(
        required=False,  # Pole opcjonalne
        widget=forms.URLInput(attrs={'placeholder': 'Optional image URL', 'class': 'image-input'}),
        label="Image URL"
    )

    # Można dodać dodatkową walidację, jeśli potrzeba
    def clean_content(self):
        content = self.cleaned_data.get('content')
        if len(content) < 5:
            raise forms.ValidationError("Message is too short!")
        return content


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
