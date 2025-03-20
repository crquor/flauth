from flask import redirect, url_for, session
from functools import wraps
import requests
import logging
import re
from mysql.connector import connect

# Configure error logging
logging.basicConfig(level=logging.ERROR)


def get_db_connection():

    return connect(host="localhost", user="root", password="", database="auth_app")


def login_required(f):
    @wraps(f)  # This preserves the original function's name and metadata
    def wrapper(*args, **kwargs):
        if "id" not in session or not session.get("authenticated", False):
            session.clear()
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


# Email Validator
def validate_email(email):

    # API endpoint and key
    url = "https://api.hunter.io/v2/email-verifier"
    key = "51d09a0295f28215643c558045cd7254952840e5"

    # Parameters
    params = {"email": email, "api_key": key}

    try:
        response = requests.get(url, params=params)

        if response.status_code == 200:

            data = response.json()

            return data["data"]["status"] == "valid"

        else:
            return None

    except Exception as e:
        logging.error(f"Error: {e}")
        return None


# Check strong password
def ispwd_strong(password):

    pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+={}\[\]:;\"'<>,.?/~`|\\-]).{8,}$"

    return re.search(pattern, password)


# hcaptcha verification
def verify_hcaptcha(hcaptcha_response):

    url = "https://api.hcaptcha.com/siteverify"
    data = {
        "secret": "ES_75d8642d4d8746539866c0b2ebc5510d",
        "response": hcaptcha_response,
    }

    response = requests.post(url, data)

    if not response.status_code == 200:
        return False

    data = response.json()

    if data["success"]:
        return True

    return False
