import secrets
import string
import hashlib
import base64
from uuid import uuid4

# =============================
# OPCJA 1 – Najlepsza do prawdziwych API (kryptograficznie bezpieczna)
# =============================
def generate_secure_token(length=48):
    """Generuje losowy token z użyciem secrets (najbezpieczniejszy sposób w Pythonie)"""
    alphabet = string.ascii_letters + string.digits + "-_"
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    return token

# =============================
# OPCJA 2 – Token w stylu Bearer (hex)
# =============================
def generate_hex_token(bytes_length=32):
    """np. 64-znakowy token hex (32 bajty → 64 hex)"""
    return secrets.token_hex(bytes_length)

# =============================
# OPCJA 3 – Token URL-safe (jak w większości API)
# =============================
def generate_url_safe_token(bytes_length=32):
    """Bez = na końcu, idealny do headera Authorization: Bearer ..."""
    token = secrets.token_urlsafe(bytes_length)
    return token.rstrip("=")  # niektórzy lubią bez paddingu

# =============================
# OPCJA 4 – Coś w stylu UUID4 (krótsze, ale unikalne)
# =============================
def generate_uuid_token():
    return str(uuid4())

# =============================
# OPCJA 5 – Przykład „fake JWT” do testów (3 części base64)
# =============================
def generate_fake_jwt():
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"1234567890","name":"Jan Kowalski","iat":1516239022}').decode().rstrip("=")
    signature = secrets.token_urlsafe(32).rstrip("=")
    return f"{header}.{payload}.{signature}"

# =============================
# Testy – odpal to i zobacz co leci
# =============================
if __name__ == "__main__":
    print("Bezpieczny token (48 znaków):      ", generate_secure_token(48))
    print("Hex token (64 znaki):              ", generate_hex_token(32))
    print("URL-safe token:                    ", generate_url_safe_token(48))
    print("UUID4:                             ", generate_uuid_token())
    print("Fake JWT do testów:                ", generate_fake_jwt())