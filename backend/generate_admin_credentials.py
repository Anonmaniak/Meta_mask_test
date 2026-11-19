"""
Generate strong Admin Console credentials that satisfy the server's strength policy.

    python generate_admin_credentials.py

Copy the printed values into your host's environment settings (Render -> Environment) and your local
`backend/.env`. Never commit them, never paste them into chat or email.
"""

import secrets
import string

import admin_auth


def generate():
    # token_urlsafe() output can lack a symbol or a character class; build a password that always has all four.
    while True:
        login_id = "adm_" + secrets.token_urlsafe(9)
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
        password = "".join(secrets.choice(alphabet) for _ in range(28))
        if not admin_auth.credential_problems(login_id, password):
            return login_id, password, secrets.token_urlsafe(40)


if __name__ == "__main__":
    login_id, password, token = generate()
    print("Set these in your server environment (they are shown only once):\n")
    print(f"ADMIN_LOGIN_ID={login_id}")
    print(f"ADMIN_LOGIN_PASSWORD={password}")
    print(f"ADMIN_TOKEN={token}   # optional break-glass token; omit this line if you do not want one\n")
    print("Then restart the backend. Do not commit these values or share them in chat.")
