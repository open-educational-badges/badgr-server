# encoding: utf-8
from cryptography.fernet import Fernet

from .settings import *  # noqa: F403, F401

# disable logging for tests
LOGGING = {}

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "badgr",
        "USER": "root",
        "PASSWORD": "password",
        "HOST": "db",
        "PORT": "",
        "OPTIONS": {
            "init_command": "SET default_storage_engine=InnoDB",
        },
    }
}

CELERY_ALWAYS_EAGER = True
SECRET_KEY = "aninsecurekeyusedfortesting"
UNSUBSCRIBE_SECRET_KEY = str(SECRET_KEY)
AUTHCODE_SECRET_KEY = Fernet.generate_key()
FIELD_ENCRYPTION_KEY = Fernet.generate_key().decode()
