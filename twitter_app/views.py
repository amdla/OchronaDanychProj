from uuid import uuid4

from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.timezone import now

from twitter_app.forms import LoginForm, AvatarForm, MessageForm
from twitter_app.forms import RegisterForm
from twitter_app.models import Message, Device
from twitter_app.models import User
from twitter_app.utils import check_password, hash_password, COOKIE_MAX_AGE


def index(request):
    username = request.COOKIES.get('username')
    device_cookie = request.COOKIES.get('device_cookie')

    if not username or not device_cookie:
        return redirect('login')

    # Validate the user & device
    try:
        user = User.objects.get(username=username)
        if not user.devices.filter(cookie_value=device_cookie).exists():
            return redirect('login')
    except User.DoesNotExist:
        return redirect('login')

    if request.method == 'POST':
        # Instantiate the form with POST data and uploaded file(s)
        form = MessageForm(request.POST, request.FILES)
        if form.is_valid():
            # Create a new message object but don't save to DB yet
            new_message = form.save(commit=False)
            new_message.user = user  # Assign the user who posted the message
            new_message.save()

            # Optionally add a success message for feedback
            messages.success(request, "Message posted successfully!")

            # Redirect so the user sees the fresh list of messages
            return redirect('home')
        else:
            # If invalid, Django will show form errors in the template
            pass
    else:
        form = MessageForm()

    # Pull the full list of messages to display
    messages_list = Message.objects.filter(status=1).order_by('-created_at')
    return render(request, 'index.html', {
        'messages': messages_list,
        'username': username,
        'form': form
    })


def login_view(request):
    form = LoginForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        try:
            user = User.objects.get(username=username)
            if check_password(password, user.password):
                cookie_value = str(uuid4())
                device_name = request.META.get('HTTP_USER_AGENT', 'Unknown Device')

                # Check if the device already exists
                existing_device = user.devices.filter(device_name=device_name).first()
                if existing_device:
                    # Update the existing device's last login and cookie value
                    existing_device.cookie_value = cookie_value
                    existing_device.last_login = now()
                    existing_device.save()
                else:
                    # Create a new device with the last login set to now
                    Device.objects.create(
                        user=user,
                        device_name=device_name,
                        cookie_value=cookie_value,
                        last_login=now()
                    )

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


def logout_view(request):
    response = redirect('login')
    response.delete_cookie('username')
    response.delete_cookie('device_cookie')
    response.set_cookie('username', '', expires=0)
    response.set_cookie('device_cookie', '', expires=0)
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
    cookie_username = request.COOKIES.get('username')  # Get the logged-in user's username

    # Ensure the logged-in user is valid
    try:
        logged_in_user = User.objects.get(username=cookie_username)
    except User.DoesNotExist:
        return redirect('login')

    # Ensure the requested profile exists
    try:
        profile_user = User.objects.get(username=username)
    except User.DoesNotExist:
        return redirect('login')

    # Fetch messages for the requested profile
    user_messages = Message.objects.filter(user=profile_user, status=1).order_by('-created_at')
    form = AvatarForm()

    if request.method == 'POST':
        form = AvatarForm(request.POST, request.FILES, instance=profile_user)
        if form.is_valid():
            form.save()
            return redirect('user_profile', username=username)

    # Pass both the logged-in user and the profile user to the template
    return render(request, 'user_profile.html', {
        'profile_user': profile_user,  # The user whose profile is being viewed
        'messages': user_messages,  # Their messages
        'form': form,
        'username': cookie_username,  # The logged-in user's username
    })


def list_user_devices(request):
    username = request.COOKIES.get('username')
    if not username:
        return redirect('login')

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return redirect('login')

    devices = Device.objects.filter(user=user)
    return render(request, 'device.html', {'devices': devices, 'username': username})


def delete_device_cookie(request, device_id):
    username = request.COOKIES.get('username')
    device_cookie = request.COOKIES.get('device_cookie')
    if not username:
        return redirect('login')

    try:
        user = User.objects.get(username=username)
        device = get_object_or_404(Device, id=device_id, user=user)

        # Check if the current device matches the one being deleted
        response = redirect('list_user_devices')
        if device.cookie_value == device_cookie:
            # Delete cookies from the browser if they match
            response.delete_cookie('username')
            response.delete_cookie('device_cookie')

        # Remove the device from the database
        device.delete()
        messages.success(request, 'Device successfully removed.')
    except User.DoesNotExist:
        return redirect('login')

    return response
