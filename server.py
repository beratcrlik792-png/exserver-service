import json, os, secrets, hmac, hashlib, threading, tempfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
DATA_FILE = os.environ.get("KEYS_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "keys.json"))
PREFIX = "ex_key_"
LOCK = threading.Lock()
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()]
TYPES = ("yapay-zeka", "ceviri", "arama-motoru", "genel")
MODELS = ("ExAI 2.5 Flash", "ExAI 3 Flash", "ExAI 3.5 Flash", "ExAI 6.5 Max")
DEFAULT_MODEL = "ExAI 3 Flash"


def now():
    return datetime.now(timezone.utc).isoformat()


def load():
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save(db):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(DATA_FILE))
    with os.fdopen(fd, "w") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, DATA_FILE)


def digest(key):
    return hashlib.sha256(key.encode()).hexdigest()


def mask(key):
    return key[:len(PREFIX) + 4] + "..." + key[-4:]


PANEL_HTML = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.html"), encoding="utf-8").read()


def ai_reply(message, model):
    # Still a placeholder: no model provider is configured. A real provider call per model must replace this.
    return "[" + model + "] Mesajınız alındı: " + message


class Handler(BaseHTTPRequestHandler):
    server_version = "ExServer"

    def cors(self):
        origin = self.headers.get("Origin")
        if "*" in CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", "*")
        elif origin in CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key, ex-api-key")
        self.send_header("Access-Control-Max-Age", "86400")

    def do_OPTIONS(self):
        self.send_response(200)
        self.cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.cors()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n) or b"{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, json.JSONDecodeError):
            return {}

    def extract(self, b):
        k = self.headers.get("ex-api-key") or self.headers.get("x-api-key")
        auth = self.headers.get("Authorization", "")
        if not k and auth.lower().startswith("bearer "):
            k = auth[7:].strip()
        return k or b.get("api_key")

    def path_only(self):
        return self.path.split("?")[0].rstrip("/") or "/"

    def do_GET(self):
        p = self.path_only()
        if p in ("/", "/panel", "/api/keys/ai", "/api/keys/translate", "/api/keys/search"):
            body = PANEL_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if p == "/health":
            return self.send(200, {"status": "ok", "service": "ExServer Service", "time": now()})
        if p == "/api/models":
            return self.send(200, {"models": list(MODELS), "default": DEFAULT_MODEL})
        if p == "/api/keys":
            with LOCK:
                db = load()
            return self.send(200, {"keys": [
                {"id": h[:12], "label": r["label"], "type": r.get("type", "genel"), "key": r["masked"], "active": r["active"],
                 "created_at": r["created_at"], "revoked_at": r.get("revoked_at")}
                for h, r in db.items()]})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        p = self.path_only()
        b = self.body()
        if p == "/api/ai":
            key = self.extract(b)
            if not isinstance(key, str) or not key.startswith(PREFIX):
                return self.send(401, {"error": "missing or malformed api key (ex-api-key header)"})
            with LOCK:
                rec = load().get(digest(key))
            if not (rec and rec["active"]):
                return self.send(401, {"error": "invalid or revoked api key"})
            msg = b.get("message") or b.get("prompt")
            if not isinstance(msg, str) or not msg.strip():
                return self.send(400, {"error": "message required"})
            model = b.get("model") or DEFAULT_MODEL
            if model not in MODELS:
                return self.send(400, {"error": "invalid model", "models": list(MODELS)})
            return self.send(200, {"reply": ai_reply(msg.strip(), model), "model": model})
        if p == "/api/keys/create":
            label = str(b.get("label") or "").strip()
            if not label:
                return self.send(400, {"error": "label required"})
            ktype = str(b.get("type") or "genel").strip()
            if ktype not in TYPES:
                return self.send(400, {"error": "invalid type"})
            key = PREFIX + secrets.token_urlsafe(32)
            with LOCK:
                db = load()
                db[digest(key)] = {"label": label[:200], "masked": mask(key), "type": ktype, "active": True, "created_at": now()}
                save(db)
            return self.send(201, {"api_key": key, "label": label, "type": ktype, "active": True})
        if p in ("/api/keys/verify", "/api/keys/revoke"):
            if p.endswith("revoke") and isinstance(b.get("id"), str) and b.get("id"):
                with LOCK:
                    db = load()
                    h = next((x for x in db if x.startswith(b["id"]) and len(b["id"]) >= 12), None)
                    if not h:
                        return self.send(404, {"error": "key not found"})
                    rec = db[h]
                    if rec["active"]:
                        rec["active"] = False
                        rec["revoked_at"] = now()
                        save(db)
                return self.send(200, {"revoked": True, "key": rec["masked"]})
            key = self.extract(b) if p.endswith("verify") else (b.get("api_key") or self.extract(b))
            if not isinstance(key, str) or not key.startswith(PREFIX):
                return self.send(400 if p.endswith("revoke") else 401,
                                 {"valid": False, "error": "missing or malformed key"})
            h = digest(key)
            with LOCK:
                db = load()
                rec = db.get(h)
                if p.endswith("verify"):
                    ok = bool(rec and rec["active"])
                    return self.send(200 if ok else 401, {"valid": ok, "label": rec["label"] if ok else None})
                if not rec:
                    return self.send(404, {"error": "key not found"})
                if rec["active"]:
                    rec["active"] = False
                    rec["revoked_at"] = now()
                    save(db)
            return self.send(200, {"revoked": True, "key": rec["masked"]})
        self.send(404, {"error": "not found"})

    def log_message(self, fmt, *a):
        print("%s %s" % (self.address_string(), fmt % a), flush=True)


if __name__ == "__main__":
    print(f"ExServer Service listening on 0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
