from django.contrib import messages
from django.shortcuts import render, redirect

from twitter_app.forms import MessageForm
from twitter_app.forms import RegisterForm
from twitter_app.models import Message
from twitter_app.models import User
from twitter_app.utils import hash_pass, check_pass


def index(request):
    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    # Debugowanie - sprawdzenie ciasteczek
    print(f"User ID: {user_id}, Username: {username}")

    if user_id and username:
        messages_list = Message.objects.all().order_by('-created_at')  # Pobieramy wiadomości
        return render(request, 'index.html', {'messages': messages_list, 'username': username})
    else:
        # Jeśli użytkownik nie jest zalogowany, przekierowujemy do logowania
        messages.error(request, 'You must be logged in to view this page.')
        return redirect('login')


# Widok logowania
def login_view(request):
    clear_messages(request)  # Wyczyść wszystkie istniejące komunikaty
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = User.objects.get(username=username)
            # Use check_pass to validate the password
            if check_pass(password, user.password):
                response = redirect('home')
                response.set_cookie('user_id', user.id, max_age=10)
                response.set_cookie('username', user.username, max_age=10)
                return response
            else:
                messages.error(request, 'Invalid username or password.')
        except User.DoesNotExist:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html')


def post_message(request):
    clear_messages(request)  # Czyść komunikaty na początku

    user_id = request.COOKIES.get('user_id')
    username = request.COOKIES.get('username')

    if not user_id or not username:
        messages.error(request, 'You must be logged in to post a message.')
        return redirect('login')

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

    return render(request, 'post_message.html', {'form': form})


def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            new_user = form.save(commit=False)

            new_user.password = hash_pass(form.cleaned_data["password"])
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
