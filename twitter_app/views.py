from datetime import timedelta, datetime

import bleach
import markdown
from django.contrib import messages
from django.shortcuts import render, redirect
from django.utils.timezone import now

from twitter_app.forms import MessageForm
from twitter_app.forms import RegisterForm
from twitter_app.models import Message
from twitter_app.models import User
from twitter_app.utils import check_password, hash_password, ALLOWED_TAGS, ALLOWED_ATTRIBUTES


def index(request):
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if not user_id or not username:
        messages.error(request, 'You must be logged in to view this page.')
        return redirect('login')

    # Handle form submission
    if request.method == 'POST':
        form = MessageForm(request.POST, request.FILES)
        if form.is_valid():
            message = form.save(commit=False)
            message.user_id = user_id
            message.save()
            messages.success(request, 'Your message has been posted!')
            return redirect('home')
        else:
            messages.error(request, 'There was an issue with your message.')
    else:
        form = MessageForm()

    # Fetch and clean messages
    messages_list = Message.objects.all().order_by('-created_at')
    for message in messages_list:
        safe_markdown = markdown.markdown(message.content)
        message.content = bleach.clean(safe_markdown, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)

    return render(request, 'index.html', {'messages': messages_list, 'username': username, 'form': form})


# Widok logowania
def login_view(request):
    clear_messages(request)  # Clear existing messages

    # Get failed attempts and last attempt time from cookies
    failed_attempts = int(request.COOKIES.get('failed_attempts', 0))
    last_attempt_time_str = request.COOKIES.get('last_attempt_time')

    # Convert last_attempt_time to a datetime object if it exists
    if last_attempt_time_str:
        last_attempt_time = datetime.fromisoformat(last_attempt_time_str)
    else:
        last_attempt_time = None

    # Lockout threshold and duration
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(seconds=10)

    # Check if the user is locked out
    if failed_attempts >= MAX_FAILED_ATTEMPTS and last_attempt_time:
        if now() - last_attempt_time < LOCKOUT_DURATION:
            messages.error(request, 'Too many failed attempts. Please try again later.')
            return render(request, 'login.html')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = User.objects.get(username=username)
            if check_password(password, user.password):
                response = redirect('home')
                response.set_cookie('user_id', user.id, max_age=1200)
                response.set_cookie('username', user.username, max_age=1200)

                # Reset failed attempts on successful login
                response.delete_cookie('failed_attempts')
                response.delete_cookie('last_attempt_time')
                return response
            else:
                messages.error(request, 'Invalid username or password.')
        except User.DoesNotExist:
            messages.error(request, 'Invalid username or password.')

        # Increment failed attempts and set the last attempt time
        failed_attempts += 1
        response = render(request, 'login.html')
        response.set_cookie('failed_attempts', failed_attempts, max_age=1200)
        response.set_cookie('last_attempt_time', now().isoformat(), max_age=1200)
        return response

    return render(request, 'login.html')


def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
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
        messages.error(request, 'You must be logged in to view this page.')
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
