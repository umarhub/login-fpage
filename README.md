# Secure Login Web App

A Flask-based secure login application with:

- User registration and login using hashed passwords (`bcrypt` via Passlib)
- Protection against SQL injection using parameterized queries
- Session management and logout support
- Two-Factor Authentication (2FA) via TOTP

## Requirements

- Python 3.14+
- Flask
- passlib
- pyotp

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Setup

1. Open a terminal in `c:\Users\Dell\VSpython\login`
2. Run the app:

```bash
python app.py
```

3. Open your browser at `http://127.0.0.1:5000`

## Usage

- Register a new account with email and password
- Save the generated TOTP secret and add it to an authenticator app
- Log in with email/password, then enter the 2FA code
- Visit the dashboard and use the logout button to end the session

## Database

The app uses a local SQLite database file named `users.db`.

User data stored securely includes:

- email
- bcrypt password hash
- TOTP secret

## Security Notes

- Passwords are hashed before storage and never saved as plain text.
- All database queries use parameterized SQL to prevent SQL injection.
- Flask sessions are protected with a secret key and HTTP-only cookies.

## File Structure

- `app.py` — main Flask application
- `requirements.txt` — Python dependencies
- `README.md` — application documentation
- `templates/` — HTML templates for register, login, 2FA, and dashboard pages
