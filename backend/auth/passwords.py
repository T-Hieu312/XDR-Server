import hashlib
import hmac
import secrets

PASSWORD_ITERATIONS = 600_000
PASSWORD_SALT_BYTES = 16
PASSWORD_HASH_BYTES = 32


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(PASSWORD_SALT_BYTES)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS, PASSWORD_HASH_BYTES
    )
    return password_hash.hex(), salt.hex()


def verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    try:
        expected = bytes.fromhex(password_hash)
        salt = bytes.fromhex(password_salt)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS, PASSWORD_HASH_BYTES
    )
    return hmac.compare_digest(actual, expected)
