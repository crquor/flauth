from flask import (
    Flask,
    session,
    redirect,
    render_template,
    request,
    url_for,
    flash,
    jsonify,
    abort,
)
from flask_session import Session
from helpers import (
    get_db_connection,
    login_required,
    validate_email,
    ispwd_strong,
    verify_hcaptcha,
)
from mysql.connector import connect, IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
import logging
import re
import pyotp
import qrcode
import io
import base64
import requests

# Configure the app
app = Flask(__name__)
app.secret_key = "ajfk+j93-uhjasn$"

# Configure Session for Authentication
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

if not app.debug:
    app.config["SESSION_COOKIE_SECURE"] = True  # Enforce secure cookies in production

Session(app)

# Configure error logging
logging.basicConfig(level=logging.ERROR)


@app.route("/")
@login_required
def index():

    return render_template("index.html")


# Registration handler
@app.route("/auth/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        if "id" in session:
            return redirect(url_for("login"))

        return render_template("register.html")

    # Handle form submission
    email = request.form.get("email").strip()
    username = request.form.get("username").strip()
    password = request.form.get("password").strip()
    confirmPassword = request.form.get("confirmPassword").strip()
    hcaptcha_response = request.form.get("h-captcha-response").strip()

    # Server Side Form Validation -> Start

    if not (email and username and password and confirmPassword and hcaptcha_response):
        return jsonify({"error": "All fields including captcha are required"})

    if not verify_hcaptcha(hcaptcha_response):
        return jsonify({"Captcha verification failed"})

    if not validate_email(email):
        return jsonify({"error": "Invalid Email"})

    if not 5 <= len(username) <= 15:
        return jsonify({"error": "Username must be 5-15 characters long"})

    if min(len(password), len(confirmPassword)) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"})

    if password != confirmPassword:
        return jsonify({"error": "Confirmation Password does not match"})

    if not ispwd_strong(password):
        return jsonify(
            {
                "error": "Password must contain at least a uppercase and a lowercase letter, a number, and a special symbol"
            }
        )

    # Server Side Form Validation -> End

    # Hash the password
    hash = generate_password_hash(password)

    # Get database connection
    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    # Update the database

    try:
        cursor.execute(
            "INSERT into users(username,email,password) VALUES(%s,%s,%s);",
            (
                username,
                email,
                hash,
            ),
        )
        con.commit()

        return jsonify({"success": True})
    except IntegrityError:
        return jsonify(
            {"error": "User with the given username or email address already exists"}
        )
    finally:
        cursor.close()
        con.close()


# Login handler
@app.route("/auth/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        # If user has already entered valid credentials
        if "id" in session:

            # Check if the user has completed 2FA, if turned on for their account
            if session["authenticated"]:
                return redirect(url_for("manage_account"))

            # If user has entered valid login credentials but has not completed 2FA
            session.clear()
            return redirect(url_for("login"))

        # Clear previous sessions
        session.clear()

        return render_template("login.html")

    # Handle form submission
    username = request.form.get("username").strip()
    password = request.form.get("password").strip()
    hcaptcha_response = request.form.get("h-captcha-response").strip()

    # Server Side Form Validation -> Start
    if not (username and password and hcaptcha_response):
        return jsonify({"error": "All fields including captcha are required"})
    
    if not verify_hcaptcha(hcaptcha_response):
        return jsonify({"error": "Captcha verification failed"})

    if not 5 <= len(username) <= 15:
        return jsonify({"error": "Username must have been 5-15 characters long"})

    if not ispwd_strong(password):
        return jsonify(
            {
                "error": "Password must have contained at least one lowercase and uppercase letter, one number, and one special symbol"
            }
        )

    # Server Side Form Validation -> End

    # Get database connection
    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    # Get the details for the username
    cursor.execute("SELECT * FROM users WHERE username = %s;", (username,))
    user = cursor.fetchone()

    cursor.close()
    con.close()

    if not user:
        return jsonify({"error": "User does not exist"})

    if check_password_hash(user["password"], password):
        session["id"] = user["id"]
        session["username"] = user["username"]

        # If 2FA is enabled
        if user["secondary_verification"]:
            session["authenticated"] = False
            return jsonify({"twofa": True})

        # If 2FA is not enabled
        session["authenticated"] = True
        return jsonify({"success": True})

    else:
        return jsonify({"error": "Invalid Password"})


# Secondary Verification Handler
@app.route("/auth/secondary-verification", methods=["GET", "POST"])
def secondary_verification():

    # If the user has not logged in yet
    if "id" not in session:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "GET":
        if session["authenticated"]:
            return redirect(url_for("manage_account"))
        return render_template("secondary-verification.html")

    totp_code = request.form.get("totp")

    # Server Side Form Validation -> Start

    if not totp_code or not re.search(r"\d{6}", totp_code):
        return jsonify(
            {"error": "Enter 6 digit code generated by your authenticator app"}
        )

    # Server Side Form Validation -> End

    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    # Get the secret key
    cursor.execute("SELECT secret_key FROM users WHERE id=%s;", (session["id"],))
    user = cursor.fetchone()

    totp = pyotp.TOTP(user["secret_key"])

    # Check if the user has entered valid TOTP code
    if totp.verify(totp_code):
        # Authenticate the user only after completing secondary verification
        session["authenticated"] = True

        return jsonify({"success": True})

    return jsonify({"error": "Invalid code"})


# Account Management
@app.route("/account")
@login_required
def manage_account():

    # Get database connection
    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute(
        "SELECT email,password_changed_on,secondary_verification FROM users WHERE id=%s;",
        (session["id"],),
    )
    user = cursor.fetchone()

    cursor.close()
    con.close()

    if user["secondary_verification"] == 0:
        secvfn_status = False
    else:
        secvfn_status = True

    if user["password_changed_on"]:
        pwdstatus = user["password_changed_on"]
    else:
        pwdstatus = "Never"

    return render_template(
        "account.html", email=user["email"], secvfn=secvfn_status, pwdstatus=pwdstatus
    )


# Logout Handler
@app.route("/account/logout")
@login_required
def logout():

    session.clear()
    return redirect(url_for("login"))


# Email Update handler
@app.route("/account/change-email", methods=["POST"])
@login_required
def change_email():

    newEmail = request.form.get("newEmail").strip()
    password = request.form.get("password").strip()

    # Validate form data
    if not newEmail or not password:
        return jsonify({"error": "All fields are required"})

    if not ispwd_strong(password):
        return jsonify(
            {
                "error": "Password must have contained at least a uppercase and a lowercase letter, a number, and a special symbol"
            }
        )

    if not validate_email(newEmail):
        return jsonify({"error": "Invalid email"})

    # Get database connection
    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute("SELECT email,password FROM users WHERE id=%s;", (session["id"],))
    user = cursor.fetchone()

    if newEmail == user["email"]:
        cursor.close()
        con.close()
        return jsonify({"error": "This email is already associated with your account"})

    if check_password_hash(user["password"], password):
        try:
            cursor.execute(
                "UPDATE users SET email=%s WHERE id=%s;",
                (
                    newEmail,
                    session["id"],
                ),
            )
            con.commit()
            return jsonify({"success": "Email updated successfully"})

        # If new email is already associated with another account, return an error
        except IntegrityError as ie:
            logging.error(f"Integrity error: {ie}")
            return jsonify(
                {"error": "The given email is already associated with an account"}
            )

        finally:
            cursor.close()
            con.close()
    else:
        return jsonify({"error": "Invalid password"})


# Password Update Handler
@app.route("/account/change-password", methods=["POST"])
@login_required
def change_password():

    currentPassword = request.form.get("currentPassword").strip()
    newPassword = request.form.get("newPassword").strip()

    # Validate form data
    if not currentPassword or not newPassword:
        return jsonify({"error": "All the fields are required"})

    if currentPassword == newPassword:
        return jsonify(
            {"error": "Current password and new password cannot be the same"}
        )

    if not ispwd_strong(newPassword):
        return jsonify(
            {
                "error": "Password must contain at least a uppercase and a lowercase letter, a number, and a special symbol"
            }
        )

    # Get database connection
    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute("SELECT password FROM users WHERE id=%s;", (session["id"],))
    user = cursor.fetchone()

    if not check_password_hash(user["password"], currentPassword):
        cursor.close()
        con.close()
        return jsonify({"error": "Invalid Current Password"})

    # Generate hash
    hash = generate_password_hash(newPassword)

    # Get the date
    mod_date = date.today()

    # Update password
    cursor.execute(
        "UPDATE users SET password=%s,password_changed_on=%s;",
        (
            hash,
            mod_date,
        ),
    )
    con.commit()

    cursor.close()
    con.close()

    return jsonify({"success": "Password changed successfully"})


# 2FA Handler
@app.route("/account/enable-secondary-verification", methods=["POST"])
@login_required
def enable_2FA():

    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute(
        "SELECT secondary_verification FROM users WHERE id=%s;", (session["id"],)
    )
    user = cursor.fetchone()

    # Generate the secret key
    secret_key = pyotp.random_base32()

    # Save the secret key to the database
    cursor.execute(
        "UPDATE users SET secret_key=%s WHERE id=%s;",
        (
            secret_key,
            session["id"],
        ),
    )
    con.commit()
    cursor.close()
    con.close()

    # Generate QR Code
    totp = pyotp.TOTP(secret_key)
    otp_auth_url = totp.provisioning_uri(name=session["username"], issuer_name="Flauth")

    print(secret_key, otp_auth_url)

    # Generate QR Code
    qr = qrcode.make(otp_auth_url)
    img_io = io.BytesIO()
    qr.save(img_io, "PNG")
    img_io.seek(0)

    # Convert the image to base64
    qr_code_base64 = base64.b64encode(img_io.getvalue()).decode("utf-8")

    return jsonify({"qr_code": qr_code_base64, "secret_key": secret_key})


# TOTP verification for enabling 2FA
@app.route("/account/verify-2fa", methods=["POST"])
@login_required
def verify_totp():

    totp = request.form.get("totp")

    if not totp:
        return jsonify({"error": "TOTP is required to enable 2FA"})

    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute("SELECT secret_key FROM users WHERE id=%s;", (session["id"],))
    user = cursor.fetchone()

    if not user["secret_key"]:
        cursor.close()
        con.close()
        return jsonify({"error": "Error: Refresh the page and try enabling it again"})

    gen_totp = pyotp.TOTP(user["secret_key"])

    if gen_totp.verify(totp):
        cursor.execute(
            "UPDATE users SET secondary_verification=True WHERE id=%s;",
            (session["id"],),
        )
        con.commit()
        cursor.close()
        con.close()
        return jsonify({"success": "2FA enabled successfully"})
    else:
        cursor.close()
        con.close()
        return jsonify({"error": "Invalid code"})


# Disable 2FA
@app.route("/account/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():

    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute(
        "UPDATE users SET secondary_verification=False, secret_key=NULL WHERE id=%s;",
        (session["id"],),
    )
    con.commit()

    cursor.close()
    con.close()

    return jsonify({"message": "2FA Disabled successfully"})


# Account Deletion Handler
@app.route("/account/delete-account", methods=["POST"])
@login_required
def delete_account():

    id = session["id"]
    password = request.form.get("password")

    if not password:
        return jsonify({"error": "Password cannot be empty"})

    # Get database connection
    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute("SELECT password FROM users WHERE id=%s;", (id,))
    user = cursor.fetchone()

    if check_password_hash(user["password"], password):
        cursor.execute("DELETE FROM users WHERE id=%s;", (id,))
        con.commit()

        cursor.close()
        con.close()

        session.clear()

        return jsonify(
            {
                "success": ":( Your account was deleted successfully. You'll be redirected to the login page."
            }
        )

    else:
        cursor.close()
        con.close()

        return jsonify({"error": "Invalid Password"})


if __name__ == "__main__":
    app.run()
