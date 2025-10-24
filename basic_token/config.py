import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
    ALGORITHM = "HS256"
    ACCESS_EXPIRES = timedelta(minutes=15)
    ISSUER = "jwt-learning-app"
    AUDIENCE = "jwt-clients"
