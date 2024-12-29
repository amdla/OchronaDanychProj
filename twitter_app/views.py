import base64
import uuid
from uuid import uuid4

import pyotp
import qrcode
import io
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
    """
    1) Check the username/password
    2) If user.two_factor_enabled, redirect to verify_2fa
    3) Otherwise, set device cookies and log in
    """
    form = LoginForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        if user and check_password(password, user.password):
            # If user has 2FA enabled, we do a partial login and redirect to 2FA verification
            if user.two_factor_enabled:
                # Generate a new cookie value for this device
                cookie_value = str(uuid.uuid4())
                device_name = request.META.get('HTTP_USER_AGENT', 'Unknown Device')

                # Store info in session until TOTP is verified
                request.session['2fa_user_id'] = user.id
                request.session['pending_cookie_value'] = cookie_value
                request.session['pending_device_name'] = device_name

                return redirect('verify_2fa')
            else:
                # 2FA not enabled – proceed to finalize the login
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

                # Create response and set cookies
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

    # Ensure the requested profile exists
    try:
        profile_user = User.objects.get(username=username)
    except User.DoesNotExist:
        return redirect('index')

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


def setup_2fa(request):
    """
    A view to let the user enable 2FA:
    1) Generate a TOTP secret if not present
    2) Generate a QR code as base64
    3) Prompt the user to verify the 6-digit code
    """
    user = request.user  # If you're using a custom auth system, ensure request.user is your custom User.

    # Generate or retrieve TOTP secret
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)

    # Create provisioning URL recognized by Google Authenticator
    # e.g., 'otpauth://totp/MyAppName:username?secret=SECRET&issuer=MyAppName'
    otp_auth_url = totp.provisioning_uri(
        name=user.username,
        issuer_name="MyDjangoApp"
    )

    # Generate QR code image
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(otp_auth_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert QR image to PNG bytes
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_code_bytes = buffer.getvalue()

    # Encode the PNG bytes to base64
    qr_code_base64 = base64.b64encode(qr_code_bytes).decode('utf-8')

    if request.method == 'POST':
        code = request.POST.get('code', '')
        if totp.verify(code):
            # Mark 2FA as enabled
            user.two_factor_enabled = True
            user.save()
            messages.success(request, "Two-factor authentication enabled successfully!")
            return redirect('home')  # or wherever you want
        else:
            messages.error(request, "Invalid code, please try again.")

    return render(request, 'setup_2fa.html', {
        'qr_code_base64': qr_code_base64
    })


def verify_2fa(request):
    """
    1) Retrieve user ID + pending device info from session
    2) If TOTP code is correct, finalize device/cookie
    3) If not, show error
    """
    user_id = request.session.get('2fa_user_id')
    if not user_id:
        # No user in session; go back to login
        return redirect('login')

    user = get_object_or_404(User, pk=user_id)

    if request.method == 'POST':
        code = request.POST.get('code', '')
        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code):
            # Code is valid
            cookie_value = request.session.get('pending_cookie_value')
            device_name = request.session.get('pending_device_name')

            if cookie_value and device_name:
                # Create or update the device
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

                # Create a response and set cookies
                response = redirect('home')
                response.set_cookie('username', user.username, max_age=COOKIE_MAX_AGE)
                response.set_cookie('device_cookie', cookie_value, max_age=COOKIE_MAX_AGE)

                # Clear the 2FA session data
                del request.session['2fa_user_id']
                del request.session['pending_cookie_value']
                del request.session['pending_device_name']

                messages.success(request, "2FA verification successful!")
                return response
            else:
                messages.error(request, "No device data found. Please log in again.")
                return redirect('login')
        else:
            messages.error(request, "Invalid TOTP code. Please try again.")

    return render(request, 'verify_2fa.html')
