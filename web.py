from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import RedirectResponse, HTMLResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
import httpx
import json
import os
from datetime import datetime, timezone, timedelta
import secrets
import random
import io

from PIL import Image, ImageDraw, ImageFilter

# -------------------- SAFE CONFIG LOAD --------------------
CONFIG = {}
try:
    with open("config.json", "r", encoding="utf-8") as f:
        CONFIG = json.load(f)
except Exception as e:
    print(f"Config load error: {e}")
    CONFIG = {}

CLIENT_ID = CONFIG.get("client_id", "")
CLIENT_SECRET = CONFIG.get("client_secret", "")
REDIRECT_URI = CONFIG.get("redirect_uri", "")
MONGO_URI = CONFIG.get("mongo_uri", "")
DATABASE_NAME = CONFIG.get("database_name", "vault_verify_bot")

BOT_API_URL = CONFIG.get("bot_api_url", "")
INTERNAL_API_KEY = CONFIG.get("internal_api_key", "")

DEFAULT_RETRY_COOLDOWN = CONFIG.get("default_verify_retry_cooldown_seconds", 45)
DEFAULT_BRAND_NAME = CONFIG.get("default_brand_name", "Vault Style Verification")

DASHBOARD_ACCESS_KEY = CONFIG.get("dashboard_access_key", "")
TURNSTILE_ENABLED = CONFIG.get("turnstile_enabled", False)
TURNSTILE_SECRET_KEY = CONFIG.get("turnstile_secret_key", "")
TURNSTILE_SITE_KEY = CONFIG.get("turnstile_site_key", "")

# -------------------- APP --------------------
app = FastAPI()
templates = Jinja2Templates(directory="templates")

# -------------------- MONGO --------------------
mongo = None
db = None
sessions_collection = None
verified_collection = None
attempts_collection = None
guild_settings = None
join_records = None

if MONGO_URI:
    try:
        mongo = AsyncIOMotorClient(MONGO_URI)
        db = mongo[DATABASE_NAME]
        sessions_collection = db["verify_sessions"]
        verified_collection = db["verified_users"]
        attempts_collection = db["verify_attempts"]
        guild_settings = db["guild_settings"]
        join_records = db["join_records"]
        print("Mongo connected.")
    except Exception as e:
        print(f"Mongo init error: {e}")

# -------------------- HELPERS --------------------
def mongo_ready() -> bool:
    return all([
        sessions_collection is not None,
        verified_collection is not None,
        attempts_collection is not None,
        guild_settings is not None,
        join_records is not None,
    ])

async def get_guild_settings(guild_id: int):
    if mongo_ready():
        try:
            data = await guild_settings.find_one({"guild_id": guild_id})
            if data:
                return data
        except Exception as e:
            print(f"Guild settings fetch error: {e}")

    return {
        "guild_id": guild_id,
        "verify_retry_cooldown_seconds": DEFAULT_RETRY_COOLDOWN,
        "brand_name": DEFAULT_BRAND_NAME,
        "suspicious_kick_threshold": 80
    }

def make_captcha_text(length=5):
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(random.choice(chars) for _ in range(length))

def generate_captcha_image(text: str) -> bytes:
    image = Image.new("RGB", (220, 90), (20, 24, 36))
    draw = ImageDraw.Draw(image)

    for _ in range(8):
        x1, y1 = random.randint(0, 220), random.randint(0, 90)
        x2, y2 = random.randint(0, 220), random.randint(0, 90)
        draw.line((x1, y1, x2, y2), fill=(90, 100, 160), width=2)

    x = 20
    for char in text:
        y = random.randint(20, 35)
        draw.text((x, y), char, fill=(255, 255, 255))
        x += 35

    for _ in range(150):
        draw.point(
            (random.randint(0, 219), random.randint(0, 89)),
            fill=(random.randint(80, 255), random.randint(80, 255), random.randint(80, 255))
        )

    image = image.filter(ImageFilter.SMOOTH)
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()

async def verify_turnstile(token: str, remote_ip: str | None):
    if not TURNSTILE_ENABLED:
        return True

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={
                    "secret": TURNSTILE_SECRET_KEY,
                    "response": token,
                    "remoteip": remote_ip or ""
                }
            )
            data = response.json()
            return data.get("success", False)
    except Exception as e:
        print(f"Turnstile error: {e}")
        return False

def calculate_risk(user_data: dict):
    score = 0
    flags = []

    username = user_data.get("username", "")
    global_name = user_data.get("global_name") or ""

    if len(username) <= 3:
        score += 15
        flags.append("very_short_username")

    if any(ch.isdigit() for ch in username[-4:]):
        score += 15
        flags.append("digits_at_end")

    if not global_name:
        score += 10
        flags.append("no_global_name")

    avatar = user_data.get("avatar")
    if not avatar:
        score += 20
        flags.append("no_avatar")

    return score, flags

def bot_api_is_unusable() -> bool:
    if not BOT_API_URL:
        return True
    lowered = BOT_API_URL.lower()
    return (
        "127.0.0.1" in lowered
        or "localhost" in lowered
    )

# -------------------- BASIC ROUTES --------------------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "mongo_ready": mongo_ready(),
        "has_client_id": bool(CLIENT_ID),
        "has_redirect_uri": bool(REDIRECT_URI),
        "bot_api_url": BOT_API_URL,
    }

@app.get("/debug")
async def debug():
    return {
        "status": "running",
        "cwd": os.getcwd(),
        "files": os.listdir("."),
        "templates_exists": os.path.exists("templates"),
        "home_exists": os.path.exists("templates/home.html"),
        "verify_exists": os.path.exists("templates/verify.html"),
        "success_exists": os.path.exists("templates/success.html"),
        "failed_exists": os.path.exists("templates/failed.html"),
        "mongo_ready": mongo_ready(),
        "config_keys": list(CONFIG.keys()),
    }

# -------------------- ROUTES --------------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return HTMLResponse("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>VerifyBot</title>
        <style>
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #0b1020;
                color: white;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }
            .card {
                width: 420px;
                padding: 30px;
                border-radius: 18px;
                background: #161b2e;
                text-align: center;
                box-shadow: 0 12px 32px rgba(0,0,0,0.35);
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>VerifyBot Web is Working</h1>
            <p>Render deployment is successful.</p>
        </div>
    </body>
    </html>
    """)

@app.get("/verify/{guild_id}", response_class=HTMLResponse)
async def verify_page(request: Request, guild_id: int):
    try:
        state = secrets.token_urlsafe(32)

        await sessions_collection.insert_one({
            "state": state,
            "guild_id": guild_id,
            "created_at": datetime.now(timezone.utc),
            "used": False
        })

    except Exception as e:
        return HTMLResponse(f"<h2>DB Error: {str(e)}</h2>")

    return HTMLResponse(f"""
    <html>
    <head>
        <title>Verify</title>
        <style>
            body {{
                background: #0b1020;
                color: white;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                font-family: Arial;
            }}
            .card {{
                background: #161b2e;
                padding: 30px;
                border-radius: 15px;
                text-align: center;
            }}
            a {{
                display: inline-block;
                margin-top: 15px;
                padding: 12px 20px;
                background: #5865F2;
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🔐 Verification</h2>
            <p>Guild ID: {guild_id}</p>
            <a href="/start-oauth?state={state}">Start Verification</a>
        </div>
    </body>
    </html>
    """)

@app.get("/captcha/{state}")
async def captcha_image(state: str):
    if not mongo_ready():
        return Response(status_code=500)

    session = await sessions_collection.find_one({"state": state})
    if not session:
        return Response(status_code=404)

    text = session.get("captcha_answer", "ERROR")
    image_bytes = generate_captcha_image(text)
    return Response(content=image_bytes, media_type="image/png")

@app.get("/start-oauth")
async def start_oauth(state: str):
    redirect_uri = REDIRECT_URI

    discord_auth_url = (
        f"https://discord.com/oauth2/authorize"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope=identify"
        f"&state={state}"
    )

    return RedirectResponse(discord_auth_url)

@app.get("/callback")
async def callback(request: Request, code: str = None, state: str = None):
    try:
        return HTMLResponse(f"""
        <html>
        <head>
            <title>Verification Complete</title>
            <style>
                body {{
                    background: #0b1020;
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    font-family: Arial;
                    margin: 0;
                }}
                .card {{
                    background: #161b2e;
                    padding: 30px;
                    border-radius: 15px;
                    text-align: center;
                    width: 420px;
                    box-shadow: 0 12px 32px rgba(0,0,0,0.35);
                }}
                .ok {{
                    font-size: 22px;
                    font-weight: bold;
                    margin-bottom: 12px;
                    color: #43b581;
                }}
                .muted {{
                    color: #cfd5e6;
                    line-height: 1.6;
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="ok">✅ Authorization Success</div>
                <p class="muted">Discord OAuth callback reached successfully.</p>
                <p class="muted">Code: {code}</p>
                <p class="muted">State: {state}</p>
                <p class="muted">You can now return to Discord.</p>
            </div>
        </body>
        </html>
        """)
    except Exception as e:
        return HTMLResponse(f"<h2>Callback Error: {str(e)}</h2>", status_code=500)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, key: str = Query(default=""), guild_id: int = Query(default=0)):
    if not DASHBOARD_ACCESS_KEY or key != DASHBOARD_ACCESS_KEY:
        return HTMLResponse("Unauthorized dashboard access", status_code=401)

    if guild_id == 0:
        return HTMLResponse("Missing guild_id", status_code=400)

    if not mongo_ready():
        return HTMLResponse("Database is not ready.", status_code=500)

    settings = await get_guild_settings(guild_id)
    brand_name = settings.get("brand_name", DEFAULT_BRAND_NAME)

    total_verified = await verified_collection.count_documents({"guild_id": guild_id, "verified": True})
    pending = await join_records.count_documents({"guild_id": guild_id, "verified": False, "kicked": {"$ne": True}})
    kicked = await join_records.count_documents({"guild_id": guild_id, "kicked": True})
    captcha_failed = await attempts_collection.count_documents({"guild_id": guild_id, "status": "captcha_failed"})
    suspicious = await attempts_collection.count_documents({"guild_id": guild_id, "status": "blocked_suspicious"})

    logs_cursor = attempts_collection.find({"guild_id": guild_id}).sort("created_at", -1).limit(15)
    logs = []
    async for log in logs_cursor:
        logs.append(log)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "brand_name": brand_name,
        "guild_id": guild_id,
        "total_verified": total_verified,
        "pending": pending,
        "kicked": kicked,
        "captcha_failed": captcha_failed,
        "suspicious": suspicious,
        "logs": logs
    })