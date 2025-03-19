# Flauth
#
>  flask-based user authentication system


## Features

- User Login and Registration
- Account Management (Email and Password Update, Account Deletion)
- Two Factor Authentication (using Authenticator App)

    ### Upcoming
    
    - hcaptcha in login and registration pages
    - Sign out from all devices
    - Email Verification
    - Password Recovery

## Technologies

- [Bootstrap](https://getbootstrap.com) - frontend
- [jQuery](https://jquery.org) - AJAX form submissions
- [Flask](https://https://flask.palletsprojects.com/) - Backend

## Installation
1. Download zip from [here](https://github.com/crquor/flauth/archive/refs/heads/main.zip) or run ``` git clone https://github.com/crquor/flauth.git ```
2. Install virtual environment by running ` pip install venv `
3. Create a virtual environment using ` python -m venv venv`
4. Use ` .\venv\Scripts\activate ` to activate the virtual environment
5. Run ` pip install requirements.txt ` to install all the dependencies
6. Start MySQL server, create a database, and execute ` schema.sql ` file to create the database schema.
7. Modify the database name in `helpers.py` file
8. Finally, run ` flask run ` to start the flask server
