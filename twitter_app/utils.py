from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

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
