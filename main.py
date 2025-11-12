import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db

# Auth settings
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

app = FastAPI(title="Trading Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------- Schemas ----------------------
class UserIn(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginIn(BaseModel):
    username: str
    password: str

class Indicator(BaseModel):
    key: str
    name: str

class Script(BaseModel):
    name: str
    language: str = "pine-like"
    code: str

# ---------------------- Auth helpers ----------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    if db is None:
        raise HTTPException(500, "Database not configured")

    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise credentials_exception

    user = db["user"].find_one({"_id": obj_id})
    if not user:
        raise credentials_exception
    user["id"] = str(user.pop("_id"))
    return user


# ---------------------- Routes ----------------------
@app.get("/")
def root():
    return {"message": "Trading Platform Backend Running"}

@app.get("/test")
def test_database():
    status_obj = {
        "backend": "running",
        "database": "connected" if db is not None else "not_connected",
    }
    if db is not None:
        try:
            status_obj["collections"] = db.list_collection_names()
        except Exception as e:
            status_obj["error"] = str(e)
    return status_obj

# ---- Auth ----
@app.post("/auth/signup", response_model=UserOut)
def signup(payload: UserIn):
    if db is None:
        raise HTTPException(500, "Database not configured")
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(400, "Email already registered")
    doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": get_password_hash(payload.password),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(doc)
    return {"id": str(res.inserted_id), "name": payload.name, "email": payload.email}


@app.post("/auth/token", response_model=Token)
def login(payload: LoginIn):
    if db is None:
        raise HTTPException(500, "Database not configured")
    user = db["user"].find_one({"email": payload.username})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    access_token = create_access_token({"sub": str(user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}


# ---- Config endpoints ----
AVAILABLE_INDICATORS = [
    {"key": "sma", "name": "Simple Moving Average"},
    {"key": "ema", "name": "Exponential Moving Average"},
    {"key": "rsi", "name": "Relative Strength Index"},
    {"key": "macd", "name": "MACD"},
    {"key": "bb", "name": "Bollinger Bands"},
    {"key": "vwap", "name": "VWAP"},
    {"key": "supertrend", "name": "SuperTrend"},
    {"key": "ichimoku", "name": "Ichimoku Cloud"},
]

DEFAULT_PINE = """
//@version=6
indicator('Chandelier Exit', shorttitle = 'CE', overlay = true)
const string calcGroup = 'Calculation'
length = input.int(22, title = 'ATR Period', group = calcGroup)
mult = input.float(3.0, step = 0.1, title = 'ATR Multiplier', group = calcGroup)
useClose = input.bool(true, title = 'Use Close Price for Extremums', group = calcGroup)
const string visualGroup = 'Visuals'
showLabels = input.bool(true, title = 'Show Buy/Sell Labels', group = visualGroup)
highlightState = input.bool(true, title = 'Highlight State', group = visualGroup)
const string alertGroup = 'Alerts'
awaitBarConfirmation = input.bool(true, title = 'Await Bar Confirmation', group = alertGroup)
atr = mult * ta.atr(length)
longStop = (useClose ? ta.highest(close, length) : ta.highest(length)) - atr
longStopPrev = nz(longStop[1], longStop)
longStop := close[1] > longStopPrev ? math.max(longStop, longStopPrev) : longStop
shortStop = (useClose ? ta.lowest(close, length) : ta.lowest(length)) + atr
shortStopPrev = nz(shortStop[1], shortStop)
shortStop := close[1] < shortStopPrev ? math.min(shortStop, shortStopPrev) : shortStop
var int dir = 1
dir := close > shortStopPrev ? 1 : close < longStopPrev ? -1 : dir
const color textColor = color.white
const color longColor = color.green
const color shortColor = color.red
const color longFillColor = color.new(color.green, 85)
const color shortFillColor = color.new(color.red, 85)
buySignal = dir == 1 and dir[1] == -1
longStopPlot = plot(dir == 1 ? longStop : na, title = 'Long Stop', style = plot.style_linebr, linewidth = 2, color = longColor)
plotshape(buySignal ? longStop : na, title = 'Long Stop Start', location = location.absolute, style = shape.circle, size = size.tiny, color = longColor)
plotshape(buySignal and showLabels ? longStop : na, title = 'Buy Label', text = 'Buy', location = location.absolute, style = shape.labelup, size = size.tiny, color = longColor, textcolor = textColor)
sellSignal = dir == -1 and dir[1] == 1
shortStopPlot = plot(dir == 1 ? na : shortStop, title = 'Short Stop', style = plot.style_linebr, linewidth = 2, color = shortColor)
plotshape(sellSignal ? shortStop : na, title = 'Short Stop Start', location = location.absolute, style = shape.circle, size = size.tiny, color = shortColor)
plotshape(sellSignal and showLabels ? shortStop : na, title = 'Sell Label', text = 'Sell', location = location.absolute, style = shape.labeldown, size = size.tiny, color = shortColor, textcolor = textColor)
midPricePlot = plot(ohlc4, title = '', display = display.none, editable = false)
fill(midPricePlot, longStopPlot, title = 'Long State Filling', color = (highlightState and dir == 1 ? longFillColor : na))
fill(midPricePlot, shortStopPlot, title = 'Short State Filling', color = (highlightState and dir == -1 ? shortFillColor : na))
await = awaitBarConfirmation ? barstate.isconfirmed : true
alertcondition(dir != dir[1] and await, title = 'CE Direction Change', message = 'Chandelier Exit has changed direction, {{exchange}}:{{ticker}}')
alertcondition(buySignal and await, title = 'CE Buy', message = 'Chandelier Exit Buy, {{exchange}}:{{ticker}}')
alertcondition(sellSignal and await, title = 'CE Sell', message = 'Chandelier Exit Sell, {{exchange}}:{{ticker}}')
""".strip()

@app.get("/config/indicators", response_model=List[Indicator])
def get_indicators():
    return [Indicator(**i) for i in AVAILABLE_INDICATORS]

@app.get("/config/default-script", response_model=Script)
def get_default_script():
    return Script(name="Chandelier Exit", language="pine-v6", code=DEFAULT_PINE)

# ---- Upstox streaming placeholders ----
class WsAuth(BaseModel):
    api_key: str
    api_secret: str
    access_token: Optional[str] = None

@app.post("/data/upstox/connect")
def connect_upstox(auth: WsAuth, current_user: dict = Depends(get_current_user)):
    # Store user-specific credentials for Upstox
    if db is None:
        raise HTTPException(500, "Database not configured")
    doc = {
        "user_id": current_user["id"],
        "provider": "upstox",
        "api_key": auth.api_key,
        "api_secret": auth.api_secret,
        "access_token": auth.access_token,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["broker_credential"].update_one({"user_id": current_user["id"], "provider": "upstox"}, {"$set": doc}, upsert=True)
    return {"status": "saved"}

# Dummy OHLC candles endpoint for initial chart wiring (1m timeframe)
class Candle(BaseModel):
    t: int
    o: float
    h: float
    l: float
    c: float
    v: float

@app.get("/market/candles/{symbol}", response_model=List[Candle])
def get_candles(symbol: str, timeframe: str = "1m", limit: int = 300):
    # Initially returns synthetic candles so frontend works now
    import math
    import random
    now = datetime.now(timezone.utc)
    candles: List[Candle] = []
    price = 20000.0 if symbol.upper() == "NIFTY" else 45000.0 if symbol.upper() == "BANKNIFTY" else 70000.0
    for i in range(limit):
        t = int((now - timedelta(minutes=limit - i)).timestamp())
        drift = math.sin(i / 10.0) * (5 if symbol.upper() == "NIFTY" else 8)
        noise = random.uniform(-3, 3)
        base = price + i * 0.1 + drift + noise
        o = base + random.uniform(-2, 2)
        h = max(o, base + random.uniform(0, 5))
        l = min(o, base - random.uniform(0, 5))
        c = base + random.uniform(-2, 2)
        v = random.uniform(1000, 5000)
        candles.append(Candle(t=t, o=o, h=h, l=l, c=c, v=v))
    return candles


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
