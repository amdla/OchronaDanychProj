import bleach
import markdown
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404

from twitter_app.forms import MessageForm, LoginForm, AvatarForm
from twitter_app.forms import RegisterForm
from twitter_app.models import Message
from twitter_app.models import User
from twitter_app.utils import check_password, hash_password, ALLOWED_TAGS, ALLOWED_ATTRIBUTES, COOKIE_MAX_AGE


def index(request):
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if not user_id or not username:
        return redirect('login')
    user = User.objects.get(id=user_id, username=username)
    request.user = user  # Manually set request.user

    # Handle form submission
    if request.method == 'POST':
        form = MessageForm(request.POST, request.FILES)
        if form.is_valid():
            message = form.save(commit=False)
            message.user = request.user
            message.save()
            messages.success(request, 'Your message has been posted!')
            return redirect('home')
        else:
            messages.error(request, 'There was an issue with your message.')
    else:
        form = MessageForm()

    # Fetch only active messages (status = 1)
    messages_list = Message.objects.filter(status=1).order_by('-created_at')
    for message in messages_list:
        safe_markdown = markdown.markdown(message.content, extensions=['extra', 'nl2br'])
        message.content = bleach.clean(safe_markdown, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)

    return render(request, 'index.html', {'messages': messages_list, 'username': username, 'form': form})


# Configuration constants


def login_view(request):
    form = LoginForm(request.POST or None)

    if request.method == 'POST':
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            try:
                user = User.objects.get(username=username)
                if check_password(password, user.password):
                    # Set cookies for user_id and username
                    response = redirect('home')
                    response.set_cookie('user_id', user.id, max_age=COOKIE_MAX_AGE)
                    response.set_cookie('username', user.username, max_age=COOKIE_MAX_AGE)
                    return response
                else:
                    messages.error(request, 'Invalid username or password.')
            except User.DoesNotExist:
                messages.error(request, 'Invalid username or password.')
        if 'captcha' in form.errors:
            # Remove the built-in CAPTCHA error
            form.errors.pop('captcha')
            # Add your custom error message
            messages.error(request, 'Invalid CAPTCHA. Please try again.')

    return render(request, 'login.html', {'form': form})


def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        print(form.fields)
        if form.is_valid():
            new_user = form.save(commit=False)

            new_user.password = hash_password(form.cleaned_data["password"])
            new_user.save()
            return redirect('login')
    else:
        form = RegisterForm()

    return render(request, 'register.html', {'form': form})


def home_view(request):
    # Sprawdzamy ciasteczka, aby sprawdzić, czy użytkownik jest zalogowany
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if user_id and username:
        # Jeśli ciasteczka są dostępne, uznajemy użytkownika za zalogowanego
        messages_list = Message.objects.all().order_by('-created_at')
        return render(request, 'index.html', {'messages': messages_list, 'username': username})
    else:
        # Jeśli nie ma ciasteczek, przekierowujemy do logowania

        return redirect('login')


def logout_view(request):
    response = redirect('login')
    response.delete_cookie('user_id')  # Usuwamy ciasteczka
    response.delete_cookie('username')
    messages.success(request, 'You have been logged out.')
    return response


def clear_messages(request):
    storage = messages.get_messages(request)
    storage.used = True  # Czyści wszystkie komunikaty


def delete_message(request, message_id):
    message = get_object_or_404(Message, id=message_id)

    message.status = 0  # Soft delete by setting status to 0
    message.save()
    messages.success(request, 'The message has been deleted.')
    return redirect('home')


def user_profile(request, username):
    user_id = request.COOKIES.get('user_id')
    if not user_id:
        return redirect('login')

    user = get_object_or_404(User, username=username)
    if str(user.id) != user_id:
        request.user = None  # Indicates no valid logged-in user
    else:
        request.user = user

    user_messages = Message.objects.filter(user=user, status=1).order_by('-created_at')
    form = AvatarForm()

    if request.method == 'POST' and request.user == user:
        form = AvatarForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            return redirect('user_profile', username=username)

    return render(request, 'user_profile.html', {
        'profile_user': user,
        'messages': user_messages,
        'form': form
    })
