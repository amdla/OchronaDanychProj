from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

COOKIE_MAX_AGE = 60 * 60 * 24
TWO_FA_COOKIE_MAX_AGE = 60
IMAGE_MAX_SIZE_THRESHOLD_IN_BYTES = 15 * 1024 * 1024

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
