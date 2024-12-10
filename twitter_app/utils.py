from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize the Argon2 password hasher
ph = PasswordHasher()


def hash_pass(password):
    # Hash the password
    return ph.hash(password)


def check_pass(password, hashed_password):
    try:
        # Verify the password against the hash
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
        return False


ALLOWED_TAGS = [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'ul', 'ol', 'li', 'strong', 'em', 'a',
    'blockquote', 'code', 'pre', 'img', 'br', 'hr'
]
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'img': ['src', 'alt', 'title']
}
