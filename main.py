from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
import requests, os
from urllib.parse import urlencode
from dotenv import load_dotenv
from jwt_utils import create_access_token
load_dotenv()
app = FastAPI()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
FRONTEND_URL = os.getenv("FRONTEND_URL")
USER_DB_SERVICE_URL = os.getenv("USER_DB_SERVICE_URL")

print("GOOGLE_CLIENT_ID:", GOOGLE_CLIENT_ID)
print("GOOGLE_CLIENT_SECRET:", GOOGLE_CLIENT_SECRET)
print("REDIRECT_URI:", REDIRECT_URI)
@app.get("/login")
def login():
    query = urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    })
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{query}")

from fastapi.responses import HTMLResponse

@app.get("/auth/callback")
def auth_callback(code: str):
    print("[CALLBACK] Starting OAuth callback handler")

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    token_res = requests.post(token_url, data=data)
    print('--------', token_res.text)
    token_res.raise_for_status()
    tokens = token_res.json()

    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    user_data = user_info.json()
    print(f"[INFO] User data received: {user_data}")

    # TODO: Store in DB here
    # 🔄 Send to user DB microservice
    user_payload = {
        "id": user_data["id"],
        "email": user_data["email"],
        "name": user_data["name"],
        "picture": user_data.get("picture")
    }

    try:
        user_exists = requests.get(f"{USER_DB_SERVICE_URL}/users/{user_data['id']}")
        if user_exists.status_code == 200:
            print(f"[INFO] User already exists in DB: {user_data['id']}")
            return HTMLResponse(content=f"""
                <html>
                    <head><title>Login Success</title></head>
                    <body>
                        <h2>Login Successful</h2>
                        <p>Welcome back, {user_data['name']}!</p>
                        <p>Email: {user_data['email']}</p>
                        <p>You may now close this tab.</p>
                    </body>
                </html>
            """)
        db_res = requests.post(f"{USER_DB_SERVICE_URL}/users/", json=user_payload)
        if db_res.status_code == 400:
            print(f"[INFO] User already exists in DB.")
        elif db_res.status_code == 200:
            print(f"[INFO] New user created.")
        else:
            print(f"[WARN] Unexpected DB response: {db_res.status_code}")
    except Exception as e:
        print(f"[ERROR] Failed to register user in DB: {e}")

    # ✅ Create JWT token
    token_data = {
        "user_id": user_data["id"],
        "email": user_data["email"],
        "name": user_data["name"]
    }
    access_token = create_access_token(token_data)
    print(f"[INFO] JWT token created for user {user_data['id']}, Token: {access_token}")

    # ✅ Return simple confirmation page instead of redirect
    return HTMLResponse(content=f"""
        <html>
            <head><title>Login Success</title></head>
            <body>
                <h2>Login Successful</h2>
                <p>Welcome, {user_data['name']}!</p>
                <p>Email: {user_data['email']}</p>
                <p>You may now close this tab.</p>
            </body>
        </html>
    """)