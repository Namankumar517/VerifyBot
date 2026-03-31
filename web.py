from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from motor.motor_asyncio import AsyncIOMotorClient
import httpx
import json
from datetime import datetime, timezone

# -------------------- LOAD CONFIG --------------------
with open("config.json", "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

CLIENT_ID = CONFIG["client_id"]
CLIENT_SECRET = CONFIG["client_secret"]
REDIRECT_URI = CONFIG["redirect_uri"]
BOT_API_URL = CONFIG["bot_api_url"]
INTERNAL_API_KEY = CONFIG["internal_api_key"]
MONGO_URI = CONFIG["mongo_uri"]
DATABASE_NAME = CONFIG["database_name"]
BRAND_NAME = CONFIG.get("default_brand_name", "Nexora Verify")

# -------------------- APP --------------------
app = FastAPI()

# -------------------- DB --------------------
mongo = AsyncIOMotorClient(MONGO_URI)
db = mongo[DATABASE_NAME]

oauth_sessions = db["oauth_sessions"]
oauth_tokens = db["oauth_tokens"]

# -------------------- HOME --------------------
@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(f"""
    <html>
    <head>
        <title>{BRAND_NAME}</title>
        <style>
            body {{
                margin: 0;
                background: #0b1020;
                color: white;
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }}
            .card {{
                background: #161b2e;
                padding: 30px;
                border-radius: 18px;
                width: 420px;
                text-align: center;
                box-shadow: 0 12px 32px rgba(0,0,0,0.35);
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>{BRAND_NAME}</h1>
            <p>OAuth callback service is running.</p>
        </div>
    </body>
    </html>
    """)

# -------------------- CALLBACK --------------------
@app.get("/callback")
async def callback(request: Request, code: str = None, state: str = None):
    try:
        if not code or not state:
            return HTMLResponse("<h2>Missing code or state</h2>", status_code=400)

        session = await oauth_sessions.find_one({"state": state})
        if not session:
            return HTMLResponse("<h2>Invalid or expired session</h2>", status_code=400)

        guild_id = session["guild_id"]

        await oauth_sessions.delete_one({"state": state})

        async with httpx.AsyncClient(timeout=20.0) as client:
            token_res = await client.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            token_text = token_res.text
            try:
                token_json = token_res.json()
            except Exception:
                return HTMLResponse(
                    f"<h2>Token Parse Error</h2><pre>{token_text}</pre>",
                    status_code=500
                )

            access_token = token_json.get("access_token")
            refresh_token = token_json.get("refresh_token")

            if not access_token:
                return HTMLResponse(
                    f"<h2>Token Error</h2><pre>{json.dumps(token_json, indent=2)}</pre>",
                    status_code=400
                )

            user_res = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            user_text = user_res.text
            try:
                user_data = user_res.json()
            except Exception:
                return HTMLResponse(
                    f"<h2>User Parse Error</h2><pre>{user_text}</pre>",
                    status_code=500
                )

            if "id" not in user_data:
                return HTMLResponse(
                    f"<h2>User Fetch Error</h2><pre>{json.dumps(user_data, indent=2)}</pre>",
                    status_code=400
                )

            user_id = int(user_data["id"])
            username = user_data.get("username", str(user_id))

            await oauth_tokens.update_one(
                {"guild_id": guild_id, "user_id": user_id},
                {
                    "$set": {
                        "guild_id": guild_id,
                        "user_id": user_id,
                        "username": username,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "saved_at": datetime.now(timezone.utc)
                    }
                },
                upsert=True
            )

            verify_message = "Authorization completed."
            verify_success = False

            if BOT_API_URL:
                verify_res = await client.post(
                    f"{BOT_API_URL}/internal/verify",
                    json={
                        "guild_id": guild_id,
                        "user_id": user_id,
                        "username": username,
                        "source": "oauth_callback"
                    },
                    headers={"x-api-key": INTERNAL_API_KEY}
                )

                verify_text = verify_res.text
                try:
                    verify_json = verify_res.json()
                    verify_success = bool(verify_json.get("success", False))
                    verify_message = verify_json.get("message", "Completed")
                except Exception:
                    verify_message = f"Bot API returned non-JSON response: {verify_text}"
            else:
                verify_message = "Token saved, but bot_api_url is not configured."

        status_label = "✅ Verification Complete" if verify_success else "⚠ Authorization Complete"

        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{BRAND_NAME}</title>
            <style>
                body {{
                    margin: 0;
                    background: #0b1020;
                    color: white;
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                }}
                .card {{
                    background: #161b2e;
                    padding: 30px;
                    border-radius: 18px;
                    width: 430px;
                    text-align: center;
                    box-shadow: 0 12px 32px rgba(0,0,0,0.35);
                }}
                .ok {{
                    color: #43b581;
                    font-size: 24px;
                    font-weight: bold;
                    margin-bottom: 12px;
                }}
                .muted {{
                    color: #cfd5e6;
                    line-height: 1.6;
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="ok">{status_label}</div>
                <p class="muted">User: <b>{username}</b></p>
                <p class="muted">{verify_message}</p>
                <p class="muted">You can now return to Discord.</p>
            </div>
        </body>
        </html>
        """)

    except Exception as e:
        return HTMLResponse(
            f"<h2>Callback Error</h2><pre>{str(e)}</pre>",
            status_code=500
        )