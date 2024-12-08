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
