import os
import subprocess
import sys


def main() -> int:
    os.environ.update(
        {
            "DATABASE_URL": "sqlite:///test.sqlite3",
            "SECRET_KEY": "ci-secret-key",
            "JWT_ACCESS_SECRET": "ci-access-secret",
            "JWT_REFRESH_SECRET": "ci-refresh-secret",
            "JWT_TEMP_SECRET": "ci-temp-secret",
            "REACT_APP_BASE_URL_DEV": "http://localhost:3000",
            "DEFAULT_FROM_EMAIL": "test@example.com",
            "EMAIL_HOST_USER": "test@example.com",
            "EMAIL_HOST_PASSWORD": "test-password",
        }
    )

    command = [
        sys.executable,
        "manage.py",
        "check",
        "--settings=authentication.test_settings",
    ]
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
