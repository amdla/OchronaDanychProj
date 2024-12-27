from uuid import uuid4

import bleach
import markdown
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404

from twitter_app.forms import MessageForm, LoginForm, AvatarForm
from twitter_app.forms import RegisterForm
from twitter_app.models import Message, Device
from twitter_app.models import User
from twitter_app.utils import check_password, hash_password, ALLOWED_TAGS, ALLOWED_ATTRIBUTES, COOKIE_MAX_AGE


def index(request):
    username = request.COOKIES.get('username')
    device_cookie = request.COOKIES.get('device_cookie')

    if not username or not device_cookie:
        return redirect('login')

    try:
        user = User.objects.get(username=username)
        # Validate the device cookie
        if not user.devices.filter(cookie_value=device_cookie).exists():
            return redirect('login')
    except User.DoesNotExist:
        return redirect('login')

    # Fetch messages for the user
    messages_list = Message.objects.filter(status=1).order_by('-created_at')
    return render(request, 'index.html', {'messages': messages_list, 'username': username})


def login_view(request):
    form = LoginForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        try:
            user = User.objects.get(username=username)
            if check_password(password, user.password):
                # Generate a unique device cookie
                cookie_value = str(uuid4())
                Device.objects.create(user=user, device_name=request.META.get('HTTP_USER_AGENT', 'Unknown Device'),
                                      cookie_value=cookie_value)

                # Set cookies
                response = redirect('home')
                response.set_cookie('username', user.username, max_age=COOKIE_MAX_AGE)
                response.set_cookie('device_cookie', cookie_value, max_age=COOKIE_MAX_AGE)
                return response
            else:
                messages.error(request, 'Invalid username or password.')
        except User.DoesNotExist:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html', {'form': form})


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
    username = request.COOKIES.get('username')
    if not username:
        return redirect('login')

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return redirect('login')

    messages_list = Message.objects.filter(status=1).order_by('-created_at')
    return render(request, 'index.html', {'messages': messages_list, 'username': username})


def logout_view(request):
    response = redirect('login')
    response.delete_cookie('username')
    response.delete_cookie('device_cookie')
    messages.success(request, 'You have been logged out.')
    return response


def clear_messages(request):
    storage = messages.get_messages(request)
    storage.used = True


def delete_message(request, message_id):
    message = get_object_or_404(Message, id=message_id)
    message.status = 0  # Soft delete by setting status to 0
    message.save()
    messages.success(request, 'The message has been deleted.')
    return redirect('home')


def user_profile(request, username):
    cookie_username = request.COOKIES.get('username')
    if not cookie_username or cookie_username != username:
        return redirect('login')

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return redirect('login')

    user_messages = Message.objects.filter(user=user, status=1).order_by('-created_at')
    form = AvatarForm()

    if request.method == 'POST':
        form = AvatarForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            return redirect('user_profile', username=username)

    return render(request, 'user_profile.html', {
        'profile_user': user,
        'messages': user_messages,
        'form': form
    })


def list_user_devices(request):
    username = request.COOKIES.get('username')
    if not username:
        return redirect('login')

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return redirect('login')

    devices = user.devices.all()
    return render(request, 'device.html', {'devices': devices})


def delete_device_cookie(request, device_id):
    username = request.COOKIES.get('username')
    if not username:
        return redirect('login')

    try:
        user = User.objects.get(username=username)
        device = get_object_or_404(Device, id=device_id, user=user)
        device.delete()
    except User.DoesNotExist:
        return redirect('login')

    return redirect('list_user_devices')
