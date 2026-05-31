import os, asyncio, json, time, hmac, hashlib, base64, logging
from contextlib import asynccontextmanager
from collections import deque

import jwt as pyjwt
import websockets
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

# ── CONFIG ─────────────────────────────────────────────────────────────────────
SECRET  = os.environ.get("JWT_SECRET", "txv5_s3cr3t_ch4ng3_m3_NOW")
APASS   = os.environ.get("ADMIN_PASS", "1382")
UPWS    = "wss://wtxmd52.tele68.com/txmd5/?EIO=4&transport=websocket"
TTL     = int(os.environ.get("TOKEN_TTL", 86400))   # 24h

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tx")

# ── SHARED STATE ───────────────────────────────────────────────────────────────
# Lưu tối đa 50 kết quả gần nhất
results: deque = deque(maxlen=50)
ws_status = {"connected": False, "msg_count": 0}
_upstream_task = None

# ── CORE CALC ──────────────────────────────────────────────────────────────────
def _calc(sid: str, md5: str):
    raw_x = sum(int(c) for c in str(sid) if c.isdigit())
    mid_h  = str(md5)[6:8].lower()
    tail_h = str(md5)[-2:].lower()
    try:
        ry = int(mid_h, 16)
        rz = int(tail_h, 16)
    except ValueError:
        return None

    X  = raw_x * 1.25
    Y  = ry * 1.0
    Z  = rz / 4.2
    XY = X * Y
    K  = abs(XY - Z)
    T  = abs(XY) + abs(Z)
    C  = min(60 + (0 if T == 0 else (K / T) * 35), 99)
    Ki = round(K)

    if C < 65 or K < 0.001:
        p = 0   # skip
    else:
        p = 2 if Ki % 2 == 0 else 1   # 2=xiu 1=tai

    return {
        "p": p,               # prediction code
        "c": round(C, 2),     # confidence
        "k": Ki,              # K_int
        "x": round(X, 3),
        "y": round(Y, 3),
        "z": round(Z, 3),
        "q": round(XY, 3),    # XY product
    }

def _encode_result(sid, md5, duration, calc):
    """Obfuscate: đổi tên key thành mã ngắn, encode sid/md5 base64"""
    b = lambda s: base64.b64encode(s.encode()).decode()
    return {
        "t": int(time.time() * 1000),          # timestamp ms
        "a": b(str(sid)),                       # session id (b64)
        "b": b(str(md5)),                       # md5 (b64)
        "d": duration,
        "r": calc,                              # result sub-object
        "h": hmac.new(SECRET.encode(),          # integrity check
                      f"{sid}{md5}".encode(),
                      hashlib.sha256).hexdigest()[:8],
    }

# ── UPSTREAM WS LISTENER ───────────────────────────────────────────────────────
def _parse_session(raw: str):
    import re
    m = re.search(r'42(?:/[^,]+,)?(\[.+\])$', raw, re.S)
    if not m:
        i = raw.find('[')
        if i == -1:
            return None
        chunk = raw[i:]
    else:
        chunk = m.group(1)
    try:
        payload = json.loads(chunk)
    except Exception:
        return None
    if not isinstance(payload, list) or len(payload) < 2:
        return None
    evt, data = payload[0], payload[1]
    if evt != "new-session" or not isinstance(data, dict):
        return None
    return data

async def _run_upstream():
    global ws_status
    while True:
        try:
            log.info("Connecting upstream WS…")
            async with websockets.connect(UPWS, ping_interval=None, ping_timeout=None, close_timeout=5) as sock:
                ws_status["connected"] = True
                log.info("Upstream WS connected")
                ping_iv = 25
                last_ping = time.time()

                async for raw in sock:
                    ws_status["msg_count"] += 1

                    # Handshake
                    if isinstance(raw, str) and raw.startswith("0{"):
                        try:
                            hs = json.loads(raw[1:])
                            ping_iv = max(5, (hs.get("pingInterval", 25000) - 2000) // 1000)
                        except Exception:
                            pass
                        await sock.send("40/txmd5,")
                        continue

                    if raw == "2":
                        await sock.send("3")
                        continue

                    # Periodic ping
                    if time.time() - last_ping > ping_iv:
                        try:
                            await sock.send("3")
                        except Exception:
                            pass
                        last_ping = time.time()

                    if isinstance(raw, str) and "new-session" in raw:
                        data = _parse_session(raw)
                        if data:
                            sid = str(data.get("id") or data.get("sessionId") or "")
                            md5 = str(data.get("md5") or data.get("hash") or "")
                            dur = data.get("duration", "—")
                            if sid and md5 and len(md5) >= 32:
                                calc = _calc(sid, md5)
                                if calc:
                                    entry = _encode_result(sid, md5, dur, calc)
                                    results.appendleft(entry)
                                    log.info(f"Session #{len(results)} processed p={calc['p']} c={calc['c']}")

        except Exception as e:
            ws_status["connected"] = False
            log.error(f"Upstream error: {e} — retry in 5s")
            await asyncio.sleep(5)

# ── LIFESPAN ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_run_upstream())
    yield
    task.cancel()

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── JWT HELPERS ────────────────────────────────────────────────────────────────
def _issue(role="u"):
    return pyjwt.encode({"sub": role, "iat": int(time.time()), "exp": int(time.time()) + TTL}, SECRET, algorithm="HS256")

def _verify(token: str):
    try:
        return pyjwt.decode(token, SECRET, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "e")
    except Exception:
        raise HTTPException(401, "i")

def _bearer(req: Request):
    h = req.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        raise HTTPException(401, "x")
    return _verify(h[7:])

# ── ROUTES ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    p = Path(__file__).parent / "index.html"
    return HTMLResponse(p.read_text(encoding="utf-8") if p.exists() else "<h1>TX</h1>")

@app.post("/x/a")           # /x/a = auth endpoint (không rõ mục đích nếu nhìn URL)
async def auth(req: Request):
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(400, "bad")
    pw = body.get("k", "")
    if not hmac.compare_digest(str(pw), str(APASS)):
        await asyncio.sleep(2)          # anti-brute
        raise HTTPException(401, "x")
    return {"v": _issue(), "ttl": TTL}

@app.get("/x/s")            # /x/s = status
async def status(payload=None):
    # Public — chỉ trả trạng thái kết nối, không tiết lộ gì thêm
    return {"ok": ws_status["connected"], "n": ws_status["msg_count"]}

@app.get("/x/d")            # /x/d = data feed (cần JWT)
async def feed(req: Request, n: int = 20, _=None):
    _bearer(req)
    n = min(max(1, n), 50)
    return {"d": list(results)[:n]}

@app.get("/x/c")            # /x/c = check token
async def check(req: Request):
    p = _bearer(req)
    return {"ok": True, "exp": p["exp"]}

@app.get("/health")
async def health():
    return {"s": "ok"}

# Catch-all ─ ẩn mọi route không tồn tại
@app.api_route("/{path:path}", methods=["GET","POST","PUT","DELETE","PATCH"])
async def catch(_: str):
    raise HTTPException(404)
