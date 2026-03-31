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

            token_json = token_res.json()
            access_token = token_json.get("access_token")
            refresh_token = token_json.get("refresh_token")

            if not access_token:
                return HTMLResponse(f"<h2>Token Error</h2><pre>{token_json}</pre>", status_code=400)

            user_res = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            user_data = user_res.json()

            user_id = int(user_data["id"])
            username = user_data["username"]

            # Save token
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

            # Call bot internal verify API
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

            verify_text = await verify_res.aread()
            try:
                verify_json = json.loads(verify_text.decode())
            except Exception:
                verify_json = {"success": False, "message": verify_text.decode(errors="ignore")}

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
                    width: 430px;
                    text-align: center;
                    box-shadow: 0 12px 32px rgba(0,0,0,0.35);
                }}
                .ok {{
                    color: #43b581;
                    font-size: 24px;
                    font-weight: bold;
                }}
                .muted {{
                    color: #cfd5e6;
                    line-height: 1.6;
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="ok">✅ Verification Complete</div>
                <p class="muted">User: <b>{username}</b></p>
                <p class="muted">{verify_json.get("message", "Completed")}</p>
                <p class="muted">You can now return to Discord.</p>
            </div>
        </body>
        </html>
        """)

    except Exception as e:
        return HTMLResponse(f"<h2>Callback Error</h2><pre>{str(e)}</pre>", status_code=500)