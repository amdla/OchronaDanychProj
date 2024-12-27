from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from uuid import uuid4

from twitter_app.models import Device

COOKIE_MAX_AGE = 60 * 60 * 24
IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES = 5 * 1024 * 1024
MIN_POST_LENGTH = 6
MAX_FAILED_ATTEMPTS = 3

# Initialize the Argon2 password hasher
ph = PasswordHasher()


def hash_password(password):
    # Hash the password
    return ph.hash(password)


def check_password(password, hashed_password):
    try:
        # Verify the password against the hash
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
        return False


ALLOWED_TAGS = [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'ul', 'ol', 'li', 'strong', 'em', 'a',
    'blockquote', 'code', 'pre', 'img', 'br', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'del'
]

ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'img': ['src', 'alt', 'title'],
    'th': ['colspan', 'rowspan'],
    'td': ['colspan', 'rowspan']
}


def generate_cookie_for_device(user, request):
    cookie_value = str(uuid4())
    device_name = request.META.get('HTTP_USER_AGENT', 'Unknown Device')

    Device.objects.create(user=user, device_name=device_name, cookie_value=cookie_value)
    return cookie_value
