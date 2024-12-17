from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(seconds=10)
COOKIE_MAX_AGE_THRESHOLD = 1200
IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES = 5 * 1024 * 1024
MIN_POST_LENGTH_THRESHOLD = 6

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

