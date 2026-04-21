import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

try:
    from pymongo import ASCENDING, MongoClient
    from pymongo.errors import DuplicateKeyError
except ImportError:  # pragma: no cover - optional dependency
    ASCENDING = None
    MongoClient = None
    DuplicateKeyError = Exception


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "spiceroute.db"
HOST = os.getenv("SPICEROUTE_HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", os.getenv("SPICEROUTE_PORT", "8000")))
SESSION_COOKIE = "spiceroute_session"
SESSION_SECRET = os.getenv("SESSION_SECRET", "spiceroute-demo-secret")
SESSION_MAX_AGE = 60 * 60 * 24 * 7
PASSWORD_ITERATIONS = 120_000
MONGODB_URI = os.getenv("MONGODB_URI", "").strip()
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "spiceroute")
USE_HTTPS_COOKIES = os.getenv("SPICEROUTE_SECURE_COOKIES", "0") == "1"
AUTH_WINDOW_SECONDS = 15 * 60
AUTH_MAX_ATTEMPTS = 8
AUTH_ATTEMPTS: Dict[str, list] = {}
mongo_db = None


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${derived}"


def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("pbkdf2_sha256$"):
        _, iterations, salt, digest = stored_hash.split("$", 3)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        ).hex()
        return hmac.compare_digest(derived, digest)

    legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy_hash, stored_hash)


def validate_password(password: str) -> Optional[str]:
    if len(password) < 8:
        return "Password must be at least 8 characters."

    if not any(char.isalpha() for char in password) or not any(char.isdigit() for char in password):
        return "Password must include letters and numbers."

    return None


def sign_session_value(payload: dict) -> str:
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{encoded_payload}.{signature}"


def verify_session_value(raw_value: Optional[str]) -> Optional[dict]:
    if not raw_value or "." not in raw_value:
        return None

    encoded_payload, signature = raw_value.rsplit(".", 1)
    expected_signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        return None

    try:
        payload = json.loads(base64.urlsafe_b64decode(encoded_payload.encode("ascii")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None

    if payload.get("exp", 0) < int(time.time()):
        return None

    return payload


def using_mongodb() -> bool:
    return bool(mongo_db is not None)


def init_storage() -> None:
    global mongo_db

    if MONGODB_URI and MongoClient is not None:
        try:
            client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
            client.admin.command("ping")
            mongo_db = client[MONGODB_DB_NAME]
            mongo_db.users.create_index([("email", ASCENDING)], unique=True)
            return
        except Exception as error:  # pragma: no cover - depends on runtime services
            print(f"MongoDB unavailable, falling back to SQLite: {error}")

    mongo_db = None
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            """
        )
        connection.commit()


def create_user(name: str, email: str, password_hash: str) -> dict:
    record = {
        "name": name,
        "email": normalize_email(email),
        "password_hash": password_hash,
        "created_at": int(time.time()),
    }

    if using_mongodb():
        mongo_db.users.insert_one(record)
        return {"name": record["name"], "email": record["email"]}

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (record["name"], record["email"], record["password_hash"], record["created_at"]),
        )
        connection.commit()

    return {"name": record["name"], "email": record["email"]}


def find_user_by_email(email: str) -> Optional[dict]:
    normalized_email = normalize_email(email)

    if using_mongodb():
        row = mongo_db.users.find_one({"email": normalized_email})
        if not row:
            return None
        return {
            "name": row["name"],
            "email": row["email"],
            "password_hash": row["password_hash"],
        }

    with sqlite3.connect(DB_PATH) as connection:
        row = connection.execute(
            "SELECT name, email, password_hash FROM users WHERE email = ?",
            (normalized_email,),
        ).fetchone()

    if not row:
        return None

    return {"name": row[0], "email": row[1], "password_hash": row[2]}


def get_client_key(ip_address: str, email: str) -> str:
    return f"{ip_address}:{normalize_email(email)}"


def is_rate_limited(client_key: str) -> bool:
    now = time.time()
    recent_attempts = [stamp for stamp in AUTH_ATTEMPTS.get(client_key, []) if now - stamp < AUTH_WINDOW_SECONDS]
    AUTH_ATTEMPTS[client_key] = recent_attempts
    return len(recent_attempts) >= AUTH_MAX_ATTEMPTS


def record_failed_attempt(client_key: str) -> None:
    AUTH_ATTEMPTS.setdefault(client_key, []).append(time.time())


def clear_failed_attempts(client_key: str) -> None:
    AUTH_ATTEMPTS.pop(client_key, None)


class SpiceRouteHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def get_origin_to_allow(self) -> Optional[str]:
        origin = self.headers.get("Origin")
        if not origin:
            return None

        parsed_origin = urlparse(origin)
        if parsed_origin.netloc == self.headers.get("Host"):
            return origin

        return None

    def end_headers(self) -> None:
        allow_origin = self.get_origin_to_allow()
        if allow_origin:
            self.send_header("Access-Control-Allow-Origin", allow_origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/health":
            self.send_json(
                {
                    "ok": True,
                    "service": "SpiceRoute API",
                    "storage": "mongodb" if using_mongodb() else "sqlite",
                }
            )
            return

        if parsed.path == "/api/session":
            user = self.get_current_user()
            if not user:
                self.send_json({"error": "No active session."}, status=HTTPStatus.UNAUTHORIZED)
                return

            self.send_json(user)
            return

        if parsed.path == "/robots.txt":
            self.send_text(
                "\n".join(
                    [
                        "User-agent: *",
                        "Allow: /",
                        f"Sitemap: {self.get_base_url()}/sitemap.xml",
                    ]
                )
                + "\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if parsed.path == "/sitemap.xml":
            base_url = self.get_base_url()
            sitemap = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                "  <url>\n"
                f"    <loc>{base_url}/</loc>\n"
                "    <changefreq>weekly</changefreq>\n"
                "    <priority>1.0</priority>\n"
                "  </url>\n"
                "</urlset>\n"
            )
            self.send_text(sitemap, content_type="application/xml; charset=utf-8")
            return

        if parsed.path in {"/", ""}:
            self.path = "/paste.html"

        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/signup":
            self.handle_signup()
            return

        if parsed.path == "/api/login":
            self.handle_login()
            return

        if parsed.path == "/api/logout":
            self.handle_logout()
            return

        self.send_json({"error": "Not found."}, status=HTTPStatus.NOT_FOUND)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"

        try:
            return json.loads(body or "{}")
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON payload.")

    def send_json(
        self,
        payload: dict,
        status: HTTPStatus = HTTPStatus.OK,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")

        for key, value in (headers or {}).items():
            self.send_header(key, value)

        self.end_headers()
        self.wfile.write(data)

    def send_text(
        self,
        payload: str,
        *,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        data = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=300")

        for key, value in (headers or {}).items():
            self.send_header(key, value)

        self.end_headers()
        self.wfile.write(data)

    def get_base_url(self) -> str:
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "").strip()
        if forwarded_proto:
            scheme = forwarded_proto.split(",")[0].strip()
        else:
            scheme = "https" if USE_HTTPS_COOKIES else "http"

        host = self.headers.get("Host", f"127.0.0.1:{PORT}")
        return f"{scheme}://{host}"

    def build_session_cookie(self, user: dict) -> str:
        payload = {
            "name": user["name"],
            "email": user["email"],
            "exp": int(time.time()) + SESSION_MAX_AGE,
        }
        secure = "; Secure" if USE_HTTPS_COOKIES else ""
        return (
            f"{SESSION_COOKIE}={sign_session_value(payload)}; "
            f"Path=/; Max-Age={SESSION_MAX_AGE}; SameSite=Lax; HttpOnly{secure}"
        )

    def build_logout_cookie(self) -> str:
        secure = "; Secure" if USE_HTTPS_COOKIES else ""
        return f"{SESSION_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly{secure}"

    def get_current_user(self) -> Optional[dict]:
        cookies = SimpleCookie(self.headers.get("Cookie") or "")
        session_cookie = cookies.get(SESSION_COOKIE)
        payload = verify_session_value(session_cookie.value if session_cookie else None)

        if not payload:
            return None

        return {"name": payload["name"], "email": payload["email"]}

    def get_client_identity(self, email: str) -> str:
        return get_client_key(self.client_address[0], email)

    def parse_auth_payload(self) -> Tuple[str, str, str]:
        payload = self.read_json()
        name = (payload.get("name") or "").strip()
        email = normalize_email(payload.get("email") or "")
        password = payload.get("password") or ""
        return name, email, password

    def handle_signup(self) -> None:
        try:
            name, email, password = self.parse_auth_payload()
        except ValueError as error:
            self.send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return

        client_key = self.get_client_identity(email)
        if is_rate_limited(client_key):
            self.send_json({"error": "Too many attempts. Please wait a few minutes."}, status=HTTPStatus.TOO_MANY_REQUESTS)
            return

        if not name or not email or not password:
            record_failed_attempt(client_key)
            self.send_json({"error": "Name, email, and password are required."}, status=HTTPStatus.BAD_REQUEST)
            return

        password_error = validate_password(password)
        if password_error:
            record_failed_attempt(client_key)
            self.send_json({"error": password_error}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            user = create_user(name, email, hash_password(password))
        except (sqlite3.IntegrityError, DuplicateKeyError):
            record_failed_attempt(client_key)
            self.send_json({"error": "Account already exists for this email."}, status=HTTPStatus.CONFLICT)
            return

        clear_failed_attempts(client_key)
        self.send_json(
            user,
            status=HTTPStatus.CREATED,
            headers={"Set-Cookie": self.build_session_cookie(user)},
        )

    def handle_login(self) -> None:
        try:
            _, email, password = self.parse_auth_payload()
        except ValueError as error:
            self.send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return

        client_key = self.get_client_identity(email)
        if is_rate_limited(client_key):
            self.send_json({"error": "Too many attempts. Please wait a few minutes."}, status=HTTPStatus.TOO_MANY_REQUESTS)
            return

        if not email or not password:
            record_failed_attempt(client_key)
            self.send_json({"error": "Email and password are required."}, status=HTTPStatus.BAD_REQUEST)
            return

        user = find_user_by_email(email)
        if not user or not verify_password(password, user["password_hash"]):
            record_failed_attempt(client_key)
            self.send_json({"error": "Invalid email or password."}, status=HTTPStatus.UNAUTHORIZED)
            return

        clear_failed_attempts(client_key)
        public_user = {"name": user["name"], "email": user["email"]}
        self.send_json(public_user, headers={"Set-Cookie": self.build_session_cookie(public_user)})

    def handle_logout(self) -> None:
        self.send_json(
            {"ok": True},
            headers={"Set-Cookie": self.build_logout_cookie()},
        )


def main() -> None:
    init_storage()
    server = ThreadingHTTPServer((HOST, PORT), SpiceRouteHandler)
    print(
        f"SpiceRoute server running at http://{HOST}:{PORT} "
        f"using {'MongoDB' if using_mongodb() else 'SQLite'} storage"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
