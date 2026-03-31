from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
import httpx
import json
from datetime import datetime, timezone, timedelta
import secrets
import random
import io

from PIL import Image, ImageDraw, ImageFilter

# -------------------- LOAD CONFIG --------------------
with open("config.json", "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

CLIENT_ID = CONFIG["client_id"]
CLIENT_SECRET = CONFIG["client_secret"]
REDIRECT_URI = CONFIG["redirect_uri"]
MONGO_URI = CONFIG["mongo_uri"]
DATABASE_NAME = CONFIG["database_name"]

BOT_API_URL = CONFIG["bot_api_url"]
INTERNAL_API_KEY = CONFIG["internal_api_key"]

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
mongo = AsyncIOMotorClient(MONGO_URI)
db = mongo[DATABASE_NAME]

sessions_collection = db["verify_sessions"]
verified_collection = db["verified_users"]
attempts_collection = db["verify_attempts"]
guild_settings = db["guild_settings"]
join_records = db["join_records"]

# -------------------- HELPERS --------------------
async def get_guild_settings(guild_id: int):
    data = await guild_settings.find_one({"guild_id": guild_id})
    if data:
        return data
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
    except:
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

# -------------------- ROUTES --------------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {
        "request": request,
        "brand_name": DEFAULT_BRAND_NAME
    })

@app.get("/verify/{guild_id}", response_class=HTMLResponse)
async def verify_page(request: Request, guild_id: int):
    settings = await get_guild_settings(guild_id)
    state = secrets.token_urlsafe(32)
    captcha_text = make_captcha_text()

    await sessions_collection.insert_one({
        "state": state,
        "guild_id": guild_id,
        "created_at": datetime.now(timezone.utc),
        "used": False,
        "captcha_answer": captcha_text
    })

    return templates.TemplateResponse("verify.html", {
        "request": request,
        "state": state,
        "guild_id": guild_id,
        "brand_name": settings.get("brand_name", DEFAULT_BRAND_NAME),
        "turnstile_enabled": TURNSTILE_ENABLED,
        "turnstile_site_key": TURNSTILE_SITE_KEY
    })

@app.get("/captcha/{state}")
async def captcha_image(state: str):
    session = await sessions_collection.find_one({"state": state})
    if not session:
        return Response(status_code=404)

    text = session.get("captcha_answer", "ERROR")
    image_bytes = generate_captcha_image(text)
    return Response(content=image_bytes, media_type="image/png")

@app.post("/start-oauth")
async def start_oauth(
    request: Request,
    state: str = Form(...),
    captcha_answer: str = Form(""),
    cf_turnstile_response: str = Form(default="")
):
    session = await sessions_collection.find_one({"state": state})
    if not session:
        return templates.TemplateResponse("failed.html", {
            "request": request,
            "message": "Invalid verification session.",
            "brand_name": DEFAULT_BRAND_NAME
        })

    guild_id = session["guild_id"]
    settings = await get_guild_settings(guild_id)
    brand_name = settings.get("brand_name", DEFAULT_BRAND_NAME)

    if session.get("used"):
        return templates.TemplateResponse("failed.html", {
            "request": request,
            "message": "This session was already used.",
            "brand_name": brand_name
        })

    if TURNSTILE_ENABLED:
        remote_ip = request.client.host if request.client else None
        ok = await verify_turnstile(cf_turnstile_response, remote_ip)
        if not ok:
            return templates.TemplateResponse("failed.html", {
                "request": request,
                "message": "Turnstile verification failed.",
                "brand_name": brand_name
            })
    else:
        if captcha_answer.strip().upper() != str(session.get("captcha_answer", "")).upper():
            await attempts_collection.insert_one({
                "guild_id": guild_id,
                "status": "captcha_failed",
                "created_at": datetime.now(timezone.utc),
                "state": state
            })
            return templates.TemplateResponse("failed.html", {
                "request": request,
                "message": "Captcha answer is incorrect.",
                "brand_name": brand_name
            })

    redirect_uri = REDIRECT_URI
    discord_auth_url = (
        f"https://discord.com/oauth2/authorize"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope=identify"
        f"&state={state}"
    )

    return RedirectResponse(discord_auth_url, status_code=302)

@app.get("/callback")
async def callback(request: Request, code: str = None, state: str = None):
    if not code or not state:
        return templates.TemplateResponse("failed.html", {
            "request": request,
            "message": "Missing code or state.",
            "brand_name": DEFAULT_BRAND_NAME
        })

    session = await sessions_collection.find_one({"state": state})
    if not session:
        return templates.TemplateResponse("failed.html", {
            "request": request,
            "message": "Invalid session state.",
            "brand_name": DEFAULT_BRAND_NAME
        })

    guild_id = session["guild_id"]
    settings = await get_guild_settings(guild_id)
    brand_name = settings.get("brand_name", DEFAULT_BRAND_NAME)
    retry_cooldown = settings.get("verify_retry_cooldown_seconds", DEFAULT_RETRY_COOLDOWN)

    if session.get("used"):
        return templates.TemplateResponse("failed.html", {
            "request": request,
            "message": "This verification session was already used.",
            "brand_name": brand_name
        })

    token_url = "https://discord.com/api/oauth2/token"
    user_url = "https://discord.com/api/users/@me"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            token_response = await client.post(token_url, data=data, headers=headers)
            token_json = token_response.json()

            access_token = token_json.get("access_token")
            if not access_token:
                return templates.TemplateResponse("failed.html", {
                    "request": request,
                    "message": "Could not get access token from Discord.",
                    "brand_name": brand_name
                })

            user_response = await client.get(
                user_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            user_data = user_response.json()

            discord_user_id = int(user_data["id"])
            discord_username = f'{user_data["username"]}'

            cooldown_threshold = datetime.now(timezone.utc) - timedelta(seconds=retry_cooldown)
            recent_attempt = await attempts_collection.find_one({
                "guild_id": guild_id,
                "user_id": discord_user_id,
                "created_at": {"$gte": cooldown_threshold}
            })

            if recent_attempt:
                return templates.TemplateResponse("failed.html", {
                    "request": request,
                    "message": f"Please wait {retry_cooldown} seconds before retrying verification.",
                    "brand_name": brand_name
                })

            already_verified = await verified_collection.find_one({
                "guild_id": guild_id,
                "user_id": discord_user_id,
                "verified": True
            })

            if already_verified:
                await sessions_collection.update_one(
                    {"state": state},
                    {
                        "$set": {
                            "used": True,
                            "user_id": discord_user_id,
                            "username": discord_username,
                            "completed_at": datetime.now(timezone.utc),
                            "result": "already_verified"
                        }
                    }
                )

                return templates.TemplateResponse("success.html", {
                    "request": request,
                    "username": discord_username,
                    "user_id": discord_user_id,
                    "message": "You are already verified.",
                    "brand_name": brand_name
                })

            risk_score, risk_flags = calculate_risk(user_data)

            verify_api_response = await client.post(
                f"{BOT_API_URL}/internal/verify",
                json={
                    "guild_id": guild_id,
                    "user_id": discord_user_id,
                    "username": discord_username,
                    "source": "website_oauth",
                    "risk_score": risk_score,
                    "risk_flags": risk_flags
                },
                headers={"x-api-key": INTERNAL_API_KEY}
            )

            verify_result = verify_api_response.json()

        await sessions_collection.update_one(
            {"state": state},
            {
                "$set": {
                    "used": True,
                    "guild_id": guild_id,
                    "user_id": discord_user_id,
                    "username": discord_username,
                    "completed_at": datetime.now(timezone.utc),
                    "result": verify_result.get("message", "unknown"),
                    "risk_score": risk_score,
                    "risk_flags": risk_flags
                }
            }
        )

        await attempts_collection.insert_one({
            "guild_id": guild_id,
            "user_id": discord_user_id,
            "username": discord_username,
            "status": "website_callback",
            "created_at": datetime.now(timezone.utc),
            "result": verify_result.get("message", "unknown"),
            "risk_score": risk_score,
            "risk_flags": risk_flags
        })

        if not verify_result.get("success"):
            return templates.TemplateResponse("failed.html", {
                "request": request,
                "message": verify_result.get("message", "Verification failed."),
                "brand_name": brand_name
            })

        await verified_collection.update_one(
            {"guild_id": guild_id, "user_id": discord_user_id},
            {
                "$set": {
                    "guild_id": guild_id,
                    "user_id": discord_user_id,
                    "username": discord_username,
                    "verified": True,
                    "verified_at": datetime.now(timezone.utc),
                    "source": "website_oauth",
                    "risk_score": risk_score,
                    "risk_flags": risk_flags
                }
            },
            upsert=True
        )

        return templates.TemplateResponse("success.html", {
            "request": request,
            "username": discord_username,
            "user_id": discord_user_id,
            "message": "Your Discord account has been verified successfully.",
            "brand_name": brand_name
        })

    except Exception as e:
        await attempts_collection.insert_one({
            "guild_id": guild_id,
            "status": "website_error",
            "created_at": datetime.now(timezone.utc),
            "error": str(e)
        })

        return templates.TemplateResponse("failed.html", {
            "request": request,
            "message": f"Verification failed: {str(e)}",
            "brand_name": brand_name
        })

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, key: str = Query(default=""), guild_id: int = Query(default=0)):
    if not DASHBOARD_ACCESS_KEY or key != DASHBOARD_ACCESS_KEY:
        return HTMLResponse("Unauthorized dashboard access", status_code=401)

    if guild_id == 0:
        return HTMLResponse("Missing guild_id", status_code=400)

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