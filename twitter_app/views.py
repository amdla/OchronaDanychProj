import base64
import io
import uuid

import bleach
import markdown
import pyotp
import qrcode
from django.contrib import messages
from django.shortcuts import (
    render,
    redirect,
    get_object_or_404
)
from django.utils.timezone import now

from twitter_app.forms import (
    LoginForm,
    AvatarForm,
    MessageForm,
    RegisterForm, PasswordResetForm
)
from twitter_app.models import (
    Message,
    Device,
    User
)
from twitter_app.utils import (
    check_password,
    hash_password,
    COOKIE_MAX_AGE,
    TWO_FA_COOKIE_MAX_AGE,
    ALLOWED_TAGS,
    ALLOWED_ATTRIBUTES
)


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
        form = MessageForm(request.POST, request.FILES)
        if form.is_valid():
            new_message = form.save(commit=False)
            new_message.user = user
            new_message.save()
            messages.success(request, "Message posted successfully!")
            return redirect('home')
    else:
        form = MessageForm()

    messages_list = Message.objects.filter(status=1).order_by('-created_at')
    for message in messages_list:
        html_content = markdown.markdown(message.content)
        sanitized_content = bleach.clean(
            html_content,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES
        )
        message.content = sanitized_content

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
        except User.DoesNotExist:
            user = None

        if user and check_password(password, user.password):

            # -------------------------------
            # 2FA Branching Logic
            # -------------------------------
            if user.two_factor_enabled:
                # If TFE is True, check if totp_secret exists
                if not user.totp_secret:
                    # Force them to set up 2FA
                    messages.info(request, "Please complete 2FA setup first.")

                    # Store the user ID in a special cookie for setup only
                    response = redirect('setup_2fa')
                    response.set_cookie('setup_2fa_user_id', str(user.id), max_age=300)
                    return response

                # Otherwise, TFE=True AND totp_secret is set => do normal 2FA verify
                cookie_value = str(uuid.uuid4())
                device_name = request.META.get('HTTP_USER_AGENT', 'Unknown Device')

                existing_device = user.devices.filter(device_name=device_name).first()
                if existing_device:
                    existing_device.cookie_value = cookie_value
                    existing_device.last_login = now()
                    existing_device.save()
                else:
                    Device.objects.create(
                        user=user,
                        device_name=device_name,
                        cookie_value=cookie_value,
                        last_login=now()
                    )

                # Temporarily store user info in cookies for TOTP verify
                response = redirect('verify_2fa')
                response.set_cookie('2fa_user_id', str(user.id), max_age=300)  # for verify_2fa
                response.set_cookie('pending_cookie_value', cookie_value, max_age=300)
                response.set_cookie('pending_device_name', device_name, max_age=300)
                return response

            else:
                # 2FA not enabled => finalize login
                cookie_value = str(uuid.uuid4())
                device_name = request.META.get('HTTP_USER_AGENT', 'Unknown Device')

                existing_device = user.devices.filter(device_name=device_name).first()
                if existing_device:
                    existing_device.cookie_value = cookie_value
                    existing_device.last_login = now()
                    existing_device.save()
                else:
                    Device.objects.create(
                        user=user,
                        device_name=device_name,
                        cookie_value=cookie_value,
                        last_login=now()
                    )

                response = redirect('home')
                response.set_cookie('username', user.username, max_age=COOKIE_MAX_AGE)
                response.set_cookie('device_cookie', cookie_value, max_age=COOKIE_MAX_AGE)
                messages.success(request, "Logged in successfully!")
                return response

        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'login.html', {'form': form})


def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            new_user = form.save(commit=False)
            new_user.password = hash_password(form.cleaned_data["password"])
            new_user.save()
            messages.success(request, "Registration successful! Please log in and set up two-factor authentication.")
            return redirect('login')
    else:
        form = RegisterForm()

    return render(request, 'register.html', {'form': form})


def logout_view(request):
    response = redirect('login')
    response.delete_cookie('username')
    response.delete_cookie('device_cookie')

    # delete any 2FA cookies if they exist
    response.delete_cookie('2fa_user_id')
    response.delete_cookie('pending_cookie_value')
    response.delete_cookie('pending_device_name')

    messages.success(request, 'You have been logged out.')
    return response


def user_profile(request, username):
    cookie_username = request.COOKIES.get('username')  # The logged-in user's username

    try:
        profile_user = User.objects.get(username=username)
    except User.DoesNotExist:
        return redirect('index')

    user_messages = Message.objects.filter(user=profile_user, status=1).order_by('-created_at')
    for message in user_messages:
        html_content = markdown.markdown(message.content)
        sanitized_content = bleach.clean(
            html_content,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES
        )
        message.content = sanitized_content
    form = AvatarForm()

    if request.method == 'POST':
        form = AvatarForm(request.POST, request.FILES, instance=profile_user)
        if form.is_valid():
            form.save()
            return redirect('user_profile', username=username)

    return render(request, 'user_profile.html', {
        'profile_user': profile_user,
        'messages': user_messages,
        'form': form,
        'username': cookie_username,
        'user_2fa_enabled': profile_user.two_factor_enabled
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

        response = redirect('list_user_devices')
        if device.cookie_value == device_cookie:
            # Delete cookies from the browser if they match
            response.delete_cookie('username')
            response.delete_cookie('device_cookie')

        device.delete()
        messages.success(request, 'Device successfully removed.')
    except User.DoesNotExist:
        return redirect('login')

    return response


def setup_2fa(request):
    user_id = request.COOKIES.get('setup_2fa_user_id')
    if not user_id:
        messages.error(request, "No 2FA setup data found. Please log in again.")
        return redirect('login')

    user = get_object_or_404(User, pk=user_id)

    # If user.totp_secret is missing, generate it
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)

    # Create provisioning URL
    otp_auth_url = totp.provisioning_uri(
        name=user.username,
        issuer_name="MyDjangoApp"
    )

    # Create
    img = qrcode.make(otp_auth_url, box_size=6, border=2)

    # Convert QR to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_code_bytes = buffer.getvalue()
    qr_code_base64 = base64.b64encode(qr_code_bytes).decode('utf-8')

    if request.method == 'POST':
        code = request.POST.get('code', '')
        if totp.verify(code):
            user.two_factor_enabled = True
            user.save()

            messages.success(request, "Two-factor authentication enabled. Please log in again.")
            response = redirect('login')

            # Clear the partial setup cookie
            response.delete_cookie('setup_2fa_user_id')

            return response

        else:
            messages.error(request, "Invalid code, please try again.")

    return render(request, 'setup_2fa.html', {
        'qr_code_base64': qr_code_base64
    })


def delete_message(request, message_id):
    message = get_object_or_404(Message, id=message_id)
    message.status = 0  # Soft delete by setting status to 0
    message.save()
    messages.success(request, 'The message has been deleted.')
    return redirect('home')


def reset_password(request):
    user_id = request.COOKIES.get('reset_user_id')
    user = get_object_or_404(User, pk=user_id)

    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['password']
            user.password = hash_password(new_password)
            user.save()
            response = redirect('login')
            response.delete_cookie('reset_user_id')
            messages.success(request, "Password reset successful. Please log in with your new password.")
            return response
    else:
        form = PasswordResetForm()
    return render(request, 'reset_password.html', {'form': form})


def toggle_2fa(request):
    if request.method == 'POST':
        cookie_username = request.COOKIES.get('username')

        user = get_object_or_404(User, username=cookie_username)
        user.two_factor_enabled = not user.two_factor_enabled
        user.save()
        return redirect('user_profile', username=cookie_username)


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)  # Fetch user by email
            response = redirect('verify_2fa')
            response.set_cookie('reset_user_id', str(user.id), max_age=TWO_FA_COOKIE_MAX_AGE)  # Store user_id in cookie
            response.set_cookie('reset_purpose', 'password_reset', max_age=TWO_FA_COOKIE_MAX_AGE)
            messages.info(request, "Please verify your 2FA code for password reset.")
            return response
        except User.DoesNotExist:
            messages.error(request, "No user with this email exists.")
    return render(request, 'forgot_password.html')


def verify_2fa(request):
    user_id = request.COOKIES.get('2fa_user_id')  # For login flow
    reset_user_id = request.COOKIES.get('reset_user_id')  # For password reset flow
    purpose = request.COOKIES.get('reset_purpose')

    if purpose == 'password_reset' and reset_user_id:
        # Password reset flow
        user = get_object_or_404(User, pk=reset_user_id)
        if request.method == 'POST':
            code = request.POST.get('code', '')
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(code):
                # 2FA verification successful
                response = redirect('reset_password')
                response.set_cookie('reset_user_id', str(user.id), max_age=COOKIE_MAX_AGE)
                response.delete_cookie('reset_purpose')
                messages.success(request, "2FA verification successful! Please set a new password.")
                return response
            else:
                messages.error(request, "Invalid TOTP code. Please try again.")
        return render(request, 'verify_2fa.html', {'purpose': purpose})

    # Login flow
    cookie_value = request.COOKIES.get('pending_cookie_value')
    device_name = request.COOKIES.get('pending_device_name')

    if not user_id or not cookie_value or not device_name:
        messages.error(request, "Could not find your pending 2FA data. Please log in again.")
        return redirect('login')

    user = get_object_or_404(User, pk=user_id)

    if request.method == 'POST':
        code = request.POST.get('code', '')
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code):
            # Code is valid -> finalize login
            response = redirect('home')
            # Set real login cookies
            response.set_cookie('username', user.username, max_age=COOKIE_MAX_AGE)
            response.set_cookie('device_cookie', cookie_value, max_age=COOKIE_MAX_AGE)
            # Remove temp cookies
            response.delete_cookie('2fa_user_id')
            response.delete_cookie('pending_cookie_value')
            response.delete_cookie('pending_device_name')
            messages.success(request, "2FA verification successful!")
            return response
        else:
            messages.error(request, "Invalid TOTP code. Please try again.")

    return render(request, 'verify_2fa.html')
