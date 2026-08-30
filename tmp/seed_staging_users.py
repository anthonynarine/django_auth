import json
import secrets
import uuid

import pyotp
from django.contrib.auth import get_user_model


User = get_user_model()

normal_email = f"a2-browser-{uuid.uuid4().hex[:12]}@example.invalid"
normal_password = secrets.token_urlsafe(18)
normal_user = User.objects.create_user(
    email=normal_email,
    password=normal_password,
)

twofa_email = f"a2-2fa-{uuid.uuid4().hex[:12]}@example.invalid"
twofa_password = secrets.token_urlsafe(18)
twofa_secret = pyotp.random_base32()
twofa_user = User.objects.create_user(
    email=twofa_email,
    password=twofa_password,
    is_2fa_enabled=True,
    tfa_secret=twofa_secret,
)

print(
    json.dumps(
        {
            "normal": {
                "email": normal_user.email,
                "password": normal_password,
            },
            "twofa": {
                "email": twofa_user.email,
                "password": twofa_password,
                "secret": twofa_secret,
            },
        }
    )
)
