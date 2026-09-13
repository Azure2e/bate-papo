#!/usr/bin/env python3
"""Chat Aberto — HTTP + WebSocket em um único processo (stdlib)."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import urllib.request
import gzip
import subprocess
import threading
import time
import uuid
import base64
import struct
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, unquote, urlencode, urlparse

try:
    import jwt
except ImportError:
    jwt = None

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
UPLOADS = PUBLIC / "uploads"
DATA_DIR = ROOT / "data"
MESSAGES_FILE = DATA_DIR / "messages.json"
MESSAGES_BAK = DATA_DIR / "messages.bak.json"
PRESENCE_FILE = DATA_DIR / "presence.json"
MOD_FILE = DATA_DIR / "moderation.json"
LOG_FILE = DATA_DIR / "moderation-logs.json"
PUSH_FILE = DATA_DIR / "push-subs.json"
GROUPS_FILE = DATA_DIR / "groups.json"
DEFAULT_GROUP_ID = "aberto"
ADMIN_CODE = os.environ.get("ADMIN_CODE", "admin123")
JWT_ALG = "ES256"
JWT_ISS = "ft-chat"
JWT_AUD = "ft-chat"
JWT_ACCESS_TTL = int(os.environ.get("JWT_ACCESS_TTL", "900"))
JWT_REFRESH_TTL = int(os.environ.get("JWT_TTL", str(7 * 24 * 3600)))
JWT_ROTATE_SECONDS = int(os.environ.get("JWT_ROTATE_SECONDS", str(7 * 24 * 3600)))
JWT_SECRET_FILE = DATA_DIR / "jwt-secret.json"
JWT_KEYS_FILE = DATA_DIR / "jwt-keys.json"
REFRESH_FILE = DATA_DIR / "refresh.json"
GOOGLE_CLIENT_ID = (os.environ.get("GOOGLE_CLIENT_ID") or "").strip()
GOOGLE_CLIENT_SECRET = (os.environ.get("GOOGLE_CLIENT_SECRET") or "").strip()
GOOGLE_REDIRECT_URI = (os.environ.get("GOOGLE_REDIRECT_URI") or "").strip()
ALLOWED_ORIGINS = [o.strip() for o in (os.environ.get("ALLOWED_ORIGINS") or "").split(",") if o.strip()]
MAX_MOD_LOGS = 500
PORT = int(os.environ.get("PORT", "3000"))
MAX_VIDEO_BYTES = 80 * 1024 * 1024
MAX_HISTORY = 300
MAX_TEXT = 2000
STARTED_AT = time.time()

UPLOADS.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
try:
    import db as store
    store.connect(DATA_DIR)
except Exception as exc:
    print("sqlite off:", exc)


def _b64u_int(value: int, size: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).decode("ascii").rstrip("=")


def _new_ec_jwk(kid: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_numbers()
    pub = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u_int(pub.x, 32),
        "y": _b64u_int(pub.y, 32),
        "d": _b64u_int(priv.private_value, 32),
        "use": "sig",
        "alg": JWT_ALG,
        "kid": kid,
    }


def _public_jwk(jwk: dict) -> dict:
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": jwk.get("x"),
        "y": jwk.get("y"),
        "use": "sig",
        "alg": JWT_ALG,
        "kid": jwk.get("kid"),
    }


def _key_from_jwk(jwk: dict):
    return jwt.PyJWK.from_dict(jwk).key


class KeyRing:
    def __init__(self):
        self.lock = threading.Lock()
        self.current = ""
        self.keys = []
        self._load()
        if not self.current:
            self.rotate(force=True)

    def _load(self):
        try:
            raw = json.loads(JWT_KEYS_FILE.read_text("utf-8")) if JWT_KEYS_FILE.exists() else {}
        except Exception:
            raw = {}
        self.current = str(raw.get("current") or "")
        self.keys = list(raw.get("keys") or [])

    def persist(self):
        payload = {"current": self.current, "keys": self.keys[-6:]}
        tmp = JWT_KEYS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), "utf-8")
        tmp.replace(JWT_KEYS_FILE)

    def signing(self) -> dict:
        with self.lock:
            if JWT_ROTATE_SECONDS > 0:
                cur = next((k for k in self.keys if k.get("kid") == self.current), None)
                created = int((cur or {}).get("created") or 0)
                if not cur or (time.time() - created) >= JWT_ROTATE_SECONDS:
                    self._rotate()
            rec = next((k for k in self.keys if k.get("kid") == self.current), None)
            if not rec or not rec.get("d"):
                rec = self._rotate()
            return dict(rec)

    def rotate(self, force: bool = False) -> dict:
        with self.lock:
            return self._rotate()

    def _rotate(self) -> dict:
        kid = secrets.token_urlsafe(10)
        rec = {**_new_ec_jwk(kid), "created": int(time.time())}
        self.keys.append(rec)
        for old in self.keys[:-3]:
            old.pop("d", None)
        self.keys = self.keys[-6:]
        self.current = kid
        self.persist()
        return rec

    def public_for(self, kid: str):
        rec = next((k for k in self.keys if k.get("kid") == kid), None)
        return _public_jwk(rec) if rec else None

    def jwks(self) -> dict:
        return {"keys": [_public_jwk(k) for k in self.keys if k.get("x") and k.get("y")]}


KEYS = KeyRing()


def _encode_jwt(name: str, typ: str, ttl: int, jti: str, fid: str | None = None) -> str:
    if jwt is None:
        raise RuntimeError("Instale PyJWT: pip install -r requirements.txt")
    rec = KEYS.signing()
    now = int(time.time())
    payload = {
        "sub": name,
        "typ": typ,
        "jti": jti,
        "iat": now,
        "nbf": now - 5,
        "exp": now + int(ttl),
        "iss": JWT_ISS,
        "aud": JWT_AUD,
    }
    if fid:
        payload["fid"] = fid
    return jwt.encode(
        payload,
        _key_from_jwk(rec),
        algorithm=JWT_ALG,
        headers={"kid": rec["kid"], "typ": "JWT"},
    )


def issue_jwt(name: str) -> str:
    return issue_tokens(name)["accessToken"]


class TokenReuse(Exception):
    pass


def issue_tokens(name: str, rotate_jti: str | None = None, family: str | None = None) -> dict:
    fid = family or secrets.token_urlsafe(12)
    access_jti = secrets.token_urlsafe(16)
    refresh_jti = secrets.token_urlsafe(18)
    access = _encode_jwt(name, "access", JWT_ACCESS_TTL, access_jti)
    refresh = _encode_jwt(name, "refresh", JWT_REFRESH_TTL, refresh_jti, fid=fid)
    exp = int(time.time()) + JWT_REFRESH_TTL
    REFRESH.rollover(name, fid, refresh_jti, exp, old_jti=rotate_jti)
    return {
        "accessToken": access,
        "refreshToken": refresh,
        "token": access,
        "expiresIn": JWT_ACCESS_TTL,
        "refreshExpiresIn": JWT_REFRESH_TTL,
        "family": fid,
    }


def verify_jwt(token: str, expected_typ: str = "access"):
    if jwt is None or not token or not isinstance(token, str) or token.count(".") != 2:
        return None
    try:
        header = jwt.get_unverified_header(token)
        if str(header.get("alg") or "") != JWT_ALG:
            return None
        if str(header.get("typ") or "JWT").upper() != "JWT":
            return None
        kid = str(header.get("kid") or "")
        if not kid:
            return None
        pub = KEYS.public_for(kid)
        if not pub or pub.get("alg") != JWT_ALG:
            return None
        data = jwt.decode(
            token,
            _key_from_jwk(pub),
            algorithms=[JWT_ALG],
            issuer=JWT_ISS,
            audience=JWT_AUD,
            leeway=5,
            options={
                "require": ["sub", "exp", "iat", "nbf", "iss", "aud", "typ", "jti"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except Exception:
        return None
    typ = str(data.get("typ") or "")
    if typ != expected_typ:
        return None
    name = str(data.get("sub") or "").strip()[:24]
    if not name:
        return None
    jti = str(data.get("jti") or "")
    if expected_typ == "refresh":
        fid = str(data.get("fid") or "")
        if REFRESH.family_killed(fid):
            return None
        if not REFRESH.active(jti, name):
            return None
        return {"name": name, "jti": jti, "fid": fid}
    return name


def access_claims(token: str):
    name = verify_jwt(token, "access")
    if not name or jwt is None:
        return None
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False, "verify_aud": False, "verify_iss": False},
        )
        jti = str((payload or {}).get("jti") or "")
    except Exception:
        return None
    if not jti:
        return None
    return {"name": name, "jti": jti}


def connect_redis():
    url = (os.environ.get("REDIS_URL") or os.environ.get("REDIS_TLS_URL") or "").strip()
    if not url:
        return None
    try:
        import redis as redis_lib
        client = redis_lib.Redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        print("Refresh tokens no Redis")
        return client
    except Exception as exc:
        print("Redis indisponível, usando arquivo local:", exc)
        return None


class RefreshStore:
    PREFIX = "ftchat"

    def __init__(self):
        self.lock = threading.Lock()
        self.redis = connect_redis()
        self.rows = {"jtis": {}, "families": {}, "killed": {}}
        if not self.redis:
            self._load_file()

    def backend(self) -> str:
        return "redis" if self.redis is not None else "file"

    def _load_file(self):
        try:
            raw = json.loads(REFRESH_FILE.read_text("utf-8")) if REFRESH_FILE.exists() else {}
        except Exception:
            raw = {}
        if isinstance(raw, dict) and "jtis" in raw:
            self.rows = raw
        elif isinstance(raw, dict):
            self.rows = {"jtis": raw, "families": {}, "killed": {}}

    def _persist(self):
        if self.redis:
            return
        now = int(time.time())
        self.rows["jtis"] = {k: v for k, v in (self.rows.get("jtis") or {}).items() if int(v.get("exp") or 0) > now}
        try:
            tmp = REFRESH_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.rows), "utf-8")
            tmp.replace(REFRESH_FILE)
        except Exception as exc:
            print("refresh save:", exc)

    def _rkey(self, kind: str, ident: str) -> str:
        return f"{self.PREFIX}:{kind}:{ident}"

    def put(self, jti: str, name: str, exp: int, fid: str = ""):
        ttl = max(1, int(exp - time.time()))
        if self.redis:
            pipe = self.redis.pipeline()
            pipe.hset(self._rkey("rt", jti), mapping={"name": name, "fid": fid, "exp": str(exp)})
            pipe.expire(self._rkey("rt", jti), ttl)
            if fid:
                pipe.hset(self._rkey("fam", fid), mapping={"current": jti, "name": name})
                pipe.expire(self._rkey("fam", fid), ttl)
            pipe.execute()
            return
        with self.lock:
            self.rows.setdefault("jtis", {})[jti] = {"name": name, "fid": fid, "exp": exp}
            if fid:
                self.rows.setdefault("families", {})[fid] = {"current": jti, "name": name, "exp": exp}
            self._persist()

    def active(self, jti: str, name: str) -> bool:
        if not jti:
            return False
        if self.redis:
            rec = self.redis.hgetall(self._rkey("rt", jti)) or {}
            return str(rec.get("name") or "").lower() == name.lower()
        with self.lock:
            rec = (self.rows.get("jtis") or {}).get(jti) or {}
            if not rec or int(rec.get("exp") or 0) <= int(time.time()):
                return False
            return str(rec.get("name") or "").lower() == name.lower()

    def family_current(self, fid: str) -> str:
        if not fid:
            return ""
        if self.redis:
            return str(self.redis.hget(self._rkey("fam", fid), "current") or "")
        with self.lock:
            return str(((self.rows.get("families") or {}).get(fid) or {}).get("current") or "")

    def family_killed(self, fid: str) -> bool:
        if not fid:
            return False
        if self.redis:
            return bool(self.redis.exists(self._rkey("kill", fid)))
        with self.lock:
            exp = int(((self.rows.get("killed") or {}).get(fid) or 0))
            return exp > int(time.time())

    def kill_family(self, fid: str):
        if not fid:
            return
        ttl = JWT_REFRESH_TTL
        current = self.family_current(fid)
        if self.redis:
            pipe = self.redis.pipeline()
            pipe.setex(self._rkey("kill", fid), ttl, "1")
            if current:
                pipe.delete(self._rkey("rt", current))
            pipe.delete(self._rkey("fam", fid))
            pipe.execute()
            return
        with self.lock:
            self.rows.setdefault("killed", {})[fid] = int(time.time()) + ttl
            if current:
                (self.rows.get("jtis") or {}).pop(current, None)
            (self.rows.get("families") or {}).pop(fid, None)
            self._persist()

    def revoke(self, jti: str | None):
        if not jti:
            return
        if self.redis:
            self.redis.delete(self._rkey("rt", jti))
            return
        with self.lock:
            (self.rows.get("jtis") or {}).pop(jti, None)
            self._persist()

    def rollover(self, name: str, fid: str, new_jti: str, exp: int, old_jti: str | None = None):
        if self.family_killed(fid):
            raise TokenReuse("família revogada")
        current = self.family_current(fid)
        if old_jti:
            if current and current != old_jti:
                self.kill_family(fid)
                raise TokenReuse("refresh reutilizado")
            if not self.active(old_jti, name):
                if current:
                    self.kill_family(fid)
                raise TokenReuse("refresh já usado")
            self.revoke(old_jti)
        self.put(new_jti, name, exp, fid)


REFRESH = RefreshStore()


class RateLimiter:
    def __init__(self):
        self._hits = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        with self._lock:
            q = [t for t in self._hits[key] if now - t < window]
            if len(q) >= limit:
                self._hits[key] = q
                return False
            q.append(now)
            self._hits[key] = q
            return True


LIMITER = RateLimiter()

SESSION_SALT = b"ft-chat-session"
SESSION_INFO = b"ws-aesgcm"
SESSION_CLEAR_OPS = {"hello", "session_ok", "session_open", "ping"}


def _b64url(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.b64decode(text or "")


def new_session_keypair():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return priv, _b64url(pub)


def derive_session_key(priv, their_b64: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    raw = _b64url_decode(their_b64)
    their = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    shared = priv.exchange(ec.ECDH(), their)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SESSION_SALT,
        info=SESSION_INFO,
    ).derive(shared)


def session_aad(jti: str) -> bytes:
    return f"ft-session:{jti}".encode("utf-8")


def seal_session(key: bytes, payload: dict, aad: bytes | None = None) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(payload, ensure_ascii=False).encode("utf-8"), aad)
    return {"sess": True, "iv": _b64url(iv), "ct": _b64url(ct)}


def open_session(key: bytes, blob: dict, aad: bytes | None = None):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pt = AESGCM(key).decrypt(_b64url_decode(blob.get("iv") or ""), _b64url_decode(blob.get("ct") or ""), aad)
    data = json.loads(pt.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("sessão inválida")
    return data

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".ogv": "video/ogg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}

PALETTE = [
    "#0084FF", "#00A400", "#FF5CA8", "#F5A623",
    "#7B61FF", "#13C2C2", "#EB2F96", "#2F54EB",
    "#FA541C", "#52C41A",
]


def color_from_name(name: str) -> str:
    h = 0
    for ch in name:
        h = ord(ch) + ((h << 5) - h)
    return PALETTE[abs(h) % len(PALETTE)]


def _read_json_list(path: Path) -> list | None:
    try:
        data = json.loads(path.read_text("utf-8"))
        return data if isinstance(data, list) else None
    except Exception:
        return None


def _read_json_dict(path: Path) -> dict:
    try:
        data = json.loads(path.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def atomic_write(path: Path, payload) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), "utf-8")
    os.replace(tmp, path)


def load_messages() -> list:
    try:
        import db as store
        rows = store.load_messages()
        if rows:
            return rows
    except Exception:
        pass
    data = _read_json_list(MESSAGES_FILE)
    if data is not None:
        return data
    bak = _read_json_list(MESSAGES_BAK)
    return bak or []


def save_messages(messages: list) -> list:
    trimmed = messages[-MAX_HISTORY:]
    try:
        import db as store
        store.replace_messages(trimmed)
    except Exception as exc:
        print("sqlite save:", exc)
    try:
        atomic_write(MESSAGES_FILE, trimmed)
    except Exception:
        pass
    return trimmed


class Hub:
    def __init__(self):
        self.lock = threading.Lock()
        self.messages = load_messages()
        self.clients = {}
        self.presence = _read_json_dict(PRESENCE_FILE)
        self.seen_client_ids = {
            m.get("clientId") for m in self.messages if m.get("clientId")
        }
        mod = _read_json_dict(MOD_FILE)
        self.admins = {str(n).lower() for n in (mod.get("admins") or [])}
        self.muted = dict(mod.get("muted") or {})
        self.blocked = dict(mod.get("blocked") or {})
        self.banned = dict(mod.get("banned") or {})
        self.logs = _read_json_list(LOG_FILE) or []
        self.push_subs = _read_json_list(PUSH_FILE) or []
        gdata = _read_json_dict(GROUPS_FILE)
        self.groups = list(gdata.get("groups") or [])
        if not any(g.get("id") == DEFAULT_GROUP_ID for g in self.groups):
            self.groups.insert(0, {
                "id": DEFAULT_GROUP_ID,
                "name": "FT Chat",
                "kind": "public",
                "e2e": True,
                "members": [],
                "admins": [],
                "createdAt": int(time.time() * 1000),
            })
        self.pubkeys = dict(gdata.get("pubkeys") or {})
        self.wraps = dict(gdata.get("wraps") or {})
        self.key_log = list(gdata.get("key_log") or [])

    def persist_groups(self):
        with self.lock:
            payload = {
                "groups": list(self.groups),
                "pubkeys": dict(self.pubkeys),
                "wraps": dict(self.wraps),
                "key_log": list(self.key_log[-200:]),
            }
        try:
            atomic_write(GROUPS_FILE, payload)
        except Exception as exc:
            print("groups save:", exc)
        try:
            import db as store
            store.save_groups(payload.get("groups") or [])
        except Exception as exc:
            print("sqlite groups:", exc)

    def group_by_id(self, gid: str | None):
        gid = gid or DEFAULT_GROUP_ID
        with self.lock:
            for g in self.groups:
                if g.get("id") == gid:
                    return dict(g)
        return None

    def can_access(self, name: str | None, gid: str | None) -> bool:
        g = self.group_by_id(gid)
        if not g:
            return False
        if g.get("kind") == "public":
            return True
        if not name:
            return False
        return name.lower() in {m.lower() for m in (g.get("members") or [])}

    def groups_for(self, name: str | None):
        key = (name or "").lower()
        with self.lock:
            rows = []
            for g in self.groups:
                if g.get("kind") == "public" or key in {m.lower() for m in (g.get("members") or [])}:
                    rows.append(dict(g))
            return rows

    def create_group(self, actor: str, name: str, kind: str = "private"):
        name = (name or "").strip()[:40]
        if not name:
            return {"ok": False, "error": "Dê um nome ao grupo."}
        gid = uuid.uuid4().hex[:10]
        group = {
            "id": gid,
            "name": name,
            "kind": "public" if kind == "public" else "private",
            "e2e": True,
            "members": [actor],
            "admins": [actor],
            "createdAt": int(time.time() * 1000),
        }
        with self.lock:
            self.groups.append(group)
            self.wraps.setdefault(gid, {})
        self.persist_groups()
        return {"ok": True, "group": group}

    def add_member(self, actor: str, gid: str, target: str):
        target = (target or "").strip()[:24]
        g = self.group_by_id(gid)
        if not g:
            return {"ok": False, "error": "Grupo não existe."}
        if g.get("kind") == "public":
            return {"ok": False, "error": "Grupo público já inclui todo mundo."}
        admins = {a.lower() for a in (g.get("admins") or [])}
        if actor.lower() not in admins:
            return {"ok": False, "error": "Só admin do grupo adiciona membros."}
        if not target:
            return {"ok": False, "error": "Informe o nome."}
        with self.lock:
            for row in self.groups:
                if row.get("id") == gid:
                    members = list(row.get("members") or [])
                    if target.lower() not in {m.lower() for m in members}:
                        members.append(target)
                    row["members"] = members
                    g = dict(row)
                    break
        self.persist_groups()
        return {"ok": True, "group": g}

    def leave_group(self, actor: str, gid: str):
        if not gid or gid == DEFAULT_GROUP_ID:
            return {"ok": False, "error": "Não dá para sair do chat aberto."}
        g = self.group_by_id(gid)
        if not g:
            return {"ok": False, "error": "Grupo não existe."}
        with self.lock:
            for row in self.groups:
                if row.get("id") != gid:
                    continue
                row["members"] = [m for m in (row.get("members") or []) if m.lower() != actor.lower()]
                row["admins"] = [m for m in (row.get("admins") or []) if m.lower() != actor.lower()]
                g = dict(row)
                break
        self.persist_groups()
        return {"ok": True, "group": g, "left": actor}

    def open_dm(self, actor: str, target: str):
        target = (target or "").strip()[:24]
        actor = (actor or "").strip()[:24]
        if not target or target.lower() == actor.lower():
            return {"ok": False, "error": "Escolha outra pessoa."}
        key = "|".join(sorted([actor.lower(), target.lower()]))
        gid = "dm-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
        existing = self.group_by_id(gid)
        if existing:
            return {"ok": True, "group": existing}
        group = {
            "id": gid,
            "name": target,
            "kind": "dm",
            "e2e": True,
            "members": [actor, target],
            "admins": [actor, target],
            "createdAt": int(time.time() * 1000),
        }
        with self.lock:
            self.groups.append(group)
            self.wraps.setdefault(gid, {})
        self.persist_groups()
        return {"ok": True, "group": group}

    def set_pubkey(self, name: str, pubkey: str):
        if not name or not pubkey:
            return None
        key = pubkey[:400]
        changed = None
        with self.lock:
            prev = self.pubkeys.get(name.lower()) or {}
            old = prev.get("key")
            rec = {
                "name": name,
                "key": key,
                "updatedAt": int(time.time() * 1000),
            }
            if old and old != key:
                rec["previous"] = old
                changed = {
                    "name": name,
                    "previous": old,
                    "key": key,
                }
                self.key_log.append({
                    "name": name,
                    "previous": old,
                    "key": key,
                    "at": rec["updatedAt"],
                })
                self.key_log = self.key_log[-200:]
            self.pubkeys[name.lower()] = rec
        self.persist_groups()
        return changed

    def save_wraps(self, gid: str, from_name: str, wraps: dict):
        if not gid or not isinstance(wraps, dict):
            return
        with self.lock:
            bucket = dict(self.wraps.get(gid) or {})
            for who, blob in wraps.items():
                if not who or not isinstance(blob, dict):
                    continue
                bucket[who.lower()] = {
                    "from": from_name,
                    "iv": str(blob.get("iv") or "")[:64],
                    "ct": str(blob.get("ct") or "")[:400],
                }
            self.wraps[gid] = bucket
        self.persist_groups()

    def wraps_for(self, gid: str):
        with self.lock:
            return dict(self.wraps.get(gid) or {})

    def pubkeys_map(self):
        with self.lock:
            return {v.get("name") or k: v.get("key") for k, v in self.pubkeys.items()}

    def persist_push(self):
        with self.lock:
            rows = list(self.push_subs)
        try:
            atomic_write(PUSH_FILE, rows)
        except Exception as exc:
            print("push save:", exc)

    def save_push_sub(self, name: str, subscription: dict):
        endpoint = (subscription or {}).get("endpoint")
        if not endpoint:
            return False
        with self.lock:
            self.push_subs = [s for s in self.push_subs if s.get("endpoint") != endpoint]
            self.push_subs.append({
                "name": name,
                "endpoint": endpoint,
                "keys": subscription.get("keys") or {},
                "updatedAt": int(time.time() * 1000),
            })
        self.persist_push()
        return True

    def drop_push_sub(self, endpoint: str):
        with self.lock:
            self.push_subs = [s for s in self.push_subs if s.get("endpoint") != endpoint]
        self.persist_push()

    def admin_push_subs(self):
        with self.lock:
            admins = set(self.admins)
            return [s for s in self.push_subs if (s.get("name") or "").lower() in admins]

    def message_push_subs(self, sender: str | None):
        skip = (sender or "").lower()
        with self.lock:
            banned = set(self.banned.keys())
            rows = []
            seen = set()
            for s in self.push_subs:
                key = (s.get("name") or "").lower()
                endpoint = s.get("endpoint")
                if not key or not endpoint or key == skip or key in banned:
                    continue
                if endpoint in seen:
                    continue
                seen.add(endpoint)
                rows.append(s)
            return rows

    def persist_mod(self):
        with self.lock:
            payload = {
                "admins": sorted(self.admins),
                "muted": dict(self.muted),
                "blocked": dict(self.blocked),
                "banned": dict(self.banned),
            }
        try:
            atomic_write(MOD_FILE, payload)
        except Exception as exc:
            print("moderation save:", exc)

    def is_admin(self, name: str | None) -> bool:
        return bool(name) and name.lower() in self.admins

    def persist_logs(self):
        with self.lock:
            payload = list(self.logs[-MAX_MOD_LOGS:])
            self.logs = payload
        try:
            atomic_write(LOG_FILE, payload)
        except Exception as exc:
            print("moderation logs save:", exc)

    def add_log(self, action: str, actor: str | None, target: str | None = None, **extra):
        entry = {
            "id": str(uuid.uuid4()),
            "action": action,
            "actor": actor,
            "target": target,
            "createdAt": int(time.time() * 1000),
        }
        for key, value in extra.items():
            if value is not None:
                entry[key] = value
        with self.lock:
            self.logs.append(entry)
            self.logs = self.logs[-MAX_MOD_LOGS:]
        self.persist_logs()
        return entry

    def recent_logs(self, limit: int = 80):
        with self.lock:
            return list(self.logs[-limit:])[::-1]

    def grant_admin(self, name: str):
        already = self.is_admin(name)
        with self.lock:
            self.admins.add(name.lower())
        self.persist_mod()
        if not already:
            return self.add_log("admin_grant", name, name)
        return None

    def _clean_expired_locked(self):
        now = int(time.time() * 1000)
        expired = []
        for k, v in list(self.muted.items()):
            if v.get("until") and v["until"] <= now:
                expired.append(v.get("name") or k)
                self.muted.pop(k, None)
        return expired

    def user_flags(self, name: str | None) -> dict:
        if not name:
            return {"muted": False, "blocked": False, "banned": False, "admin": False}
        key = name.lower()
        with self.lock:
            expired = self._clean_expired_locked()
            flags = {
                "muted": key in self.muted,
                "blocked": key in self.blocked,
                "banned": key in self.banned,
                "admin": key in self.admins,
                "muteUntil": (self.muted.get(key) or {}).get("until"),
            }
        if expired:
            self.persist_mod()
            for who in expired:
                entry = self.add_log("mute_expired", "sistema", who)
                try:
                    moderation_alert("mute_expired", "sistema", who, admins_only=True)
                    broadcast_admins({"op": "moderation_log", "entry": entry, "logs": self.recent_logs()})
                except Exception:
                    pass
        return flags

    def restriction(self, name: str | None) -> str | None:
        flags = self.user_flags(name)
        if flags["banned"]:
            return "ban"
        if flags["blocked"]:
            return "block"
        if flags["muted"]:
            return "mute"
        return None

    def snapshot(self, viewer: str | None = None, group_id: str | None = None):
        gid = group_id or DEFAULT_GROUP_ID
        if not self.can_access(viewer, gid):
            return []
        with self.lock:
            blocked = set(self.blocked.keys())
            admin = bool(viewer) and viewer.lower() in self.admins
            rows = []
            for msg in reversed(self.messages):
                if (msg.get("groupId") or DEFAULT_GROUP_ID) != gid:
                    continue
                if not admin:
                    author = (msg.get("author") or "").lower()
                    if msg.get("type") != "system" and author in blocked:
                        continue
                rows.append(msg)
                if len(rows) >= MAX_HISTORY:
                    break
        rows.reverse()
        return rows

    def moderate(self, actor: str, target: str, action: str, minutes: int = 0, reason: str = ""):
        target = (target or "").strip()
        if not target:
            return {"ok": False, "error": "Informe o usuário."}
        if target.lower() == actor.lower():
            return {"ok": False, "error": "Você não pode moderar a si mesmo."}
        if self.is_admin(target):
            return {"ok": False, "error": "Não é possível moderar outro administrador."}
        key = target.lower()
        now = int(time.time() * 1000)
        rec = {
            "name": target,
            "by": actor,
            "reason": (reason or "")[:200],
            "at": now,
            "until": (now + minutes * 60 * 1000) if minutes and minutes > 0 else None,
        }
        with self.lock:
            if action == "mute":
                self.muted[key] = rec
                self.blocked.pop(key, None)
            elif action == "unmute":
                self.muted.pop(key, None)
            elif action == "block":
                self.blocked[key] = rec
                self.muted.pop(key, None)
            elif action == "unblock":
                self.blocked.pop(key, None)
            elif action == "ban":
                self.banned[key] = rec
                self.muted.pop(key, None)
                self.blocked.pop(key, None)
            elif action == "unban":
                self.banned.pop(key, None)
            else:
                return {"ok": False, "error": "Ação inválida."}
        self.persist_mod()
        entry = self.add_log(
            action,
            actor,
            target,
            minutes=minutes or None,
            reason=(reason or "")[:200] or None,
            until=rec.get("until"),
        )
        return {
            "ok": True,
            "action": action,
            "target": target,
            "flags": self.user_flags(target),
            "log": entry,
        }

    def sockets_of(self, name: str):
        key = name.lower()
        found = []
        with self.lock:
            for cid, c in self.clients.items():
                if c.get("name") and c["name"].lower() == key:
                    found.append((cid, c))
        return found

    def security_sessions(self):
        now = time.time()
        rows = []
        with self.lock:
            for cid, c in self.clients.items():
                if not c.get("name"):
                    continue
                loc = c.get("location")
                if loc and now > float(loc.get("until") or 0):
                    c["location"] = None
                    loc = None
                rows.append({
                    "sid": cid,
                    "name": c.get("name"),
                    "status": c.get("status") or "available",
                    "ip": c.get("ip") or "",
                    "ua": c.get("ua") or "",
                    "joinedAt": c.get("joinedAt"),
                    "lastBeat": int((c.get("lastBeat") or now) * 1000),
                    "sharing": bool(loc),
                    "location": {
                        "lat": loc.get("lat"),
                        "lng": loc.get("lng"),
                        "accuracy": loc.get("accuracy"),
                        "at": loc.get("at"),
                    } if loc else None,
                })
        rows.sort(key=lambda r: (str(r.get("name") or "").lower(), r.get("sid")))
        return rows

    def set_location(self, cid: str, lat, lng, accuracy=None, minutes=15):
        try:
            lat_f = float(lat)
            lng_f = float(lng)
        except Exception:
            return None
        if not (-90 <= lat_f <= 90 and -180 <= lng_f <= 180):
            return None
        acc = None
        try:
            if accuracy is not None:
                acc = max(0, min(float(accuracy), 5000))
        except Exception:
            acc = None
        until = time.time() + max(1, min(int(minutes or 15), 60)) * 60
        with self.lock:
            user = self.clients.get(cid)
            if not user or not user.get("name"):
                return None
            user["location"] = {
                "lat": round(lat_f, 5),
                "lng": round(lng_f, 5),
                "accuracy": acc,
                "at": int(time.time() * 1000),
                "until": until,
            }
            name = user["name"]
        return {"name": name, "until": int(until * 1000)}

    def clear_location(self, cid: str):
        with self.lock:
            user = self.clients.get(cid)
            if user:
                user["location"] = None
                return user.get("name")
        return None

    def kick_sid(self, sid: str, reason: str) -> bool:
        with self.lock:
            client = self.clients.get(sid)
        if not client:
            return False
        handler = client.get("handler")
        try:
            if handler:
                handler.ws_send_text(json.dumps({
                    "op": "kicked",
                    "reason": reason,
                }, ensure_ascii=False))
                handler._ws_open = False
        except Exception:
            pass
        self.unregister(sid)
        return True

    def kick(self, name: str, reason: str):
        for cid, client in self.sockets_of(name):
            handler = client.get("handler")
            try:
                if handler:
                    handler.ws_send_text(json.dumps({
                        "op": "banned",
                        "reason": reason,
                    }, ensure_ascii=False))
                    handler._ws_open = False
            except Exception:
                pass
            self.unregister(cid)

    def online(self):
        return self.presence_list(online_only=True)

    def presence_list(self, online_only=False):
        now = int(time.time() * 1000)
        live = {}
        with self.lock:
            for c in self.clients.values():
                if c.get("name"):
                    live[c["name"].lower()] = {
                        "name": c["name"],
                        "color": c["color"],
                        "status": c.get("status") or "available",
                        "lastSeen": now,
                    }
            merged = dict(self.presence)
            merged.update(live)
            rows = []
            for key, p in merged.items():
                status = p.get("status") or "offline"
                if key not in live:
                    status = "offline"
                elif status not in {"available", "away", "busy"}:
                    status = "available"
                nkey = (p.get("name") or key).lower()
                item = {
                    "name": p.get("name") or key,
                    "color": p.get("color") or "#0084FF",
                    "status": status,
                    "lastSeen": p.get("lastSeen") or 0,
                    "bio": p.get("bio") or "",
                    "avatar": p.get("avatar") or "",
                    "muted": nkey in self.muted,
                    "blocked": nkey in self.blocked,
                    "banned": nkey in self.banned,
                    "admin": nkey in self.admins,
                }
                if online_only and status == "offline":
                    continue
                rows.append(item)
        rows.sort(key=lambda x: (x["status"] == "offline", x["name"].lower()))
        return rows

    def persist_presence(self, immediate=False):
        def flush():
            with self.lock:
                snap = dict(self.presence)
            try:
                atomic_write(PRESENCE_FILE, snap)
            except Exception as exc:
                print("presence save:", exc)
        if immediate:
            flush()
            return
        timer = getattr(self, "_presence_timer", None)
        if timer:
            try:
                timer.cancel()
            except Exception:
                pass
        timer = threading.Timer(1.2, flush)
        timer.daemon = True
        self._presence_timer = timer
        timer.start()

    def schedule_save(self):
        def flush():
            with self.lock:
                trimmed = save_messages(self.messages)
                self.messages = trimmed
        timer = getattr(self, "_msg_timer", None)
        if timer:
            try:
                timer.cancel()
            except Exception:
                pass
        timer = threading.Timer(0.25, flush)
        timer.daemon = True
        self._msg_timer = timer
        timer.start()

    def touch(self, name, color, status="available"):
        if not name:
            return
        key = name.lower()
        now = int(time.time() * 1000)
        with self.lock:
            prev = self.presence.get(key) or {}
            self.presence[key] = {
                "name": name,
                "color": color,
                "status": status,
                "lastSeen": now,
                "bio": prev.get("bio") or "",
                "avatar": prev.get("avatar") or "",
            }
        self.persist_presence()

    def set_profile(self, name: str, bio: str = "", avatar: str = ""):
        if not name:
            return None
        key = name.lower()
        bio = str(bio or "")[:80]
        avatar = str(avatar or "")[:180]
        if avatar and not avatar.startswith("/uploads/"):
            avatar = ""
        with self.lock:
            prev = self.presence.get(key) or {"name": name, "color": "#0084FF", "status": "available"}
            prev["bio"] = bio
            if avatar:
                prev["avatar"] = avatar
            prev["name"] = name
            self.presence[key] = prev
        self.persist_presence(True)
        return dict(prev)

    def mark_offline(self, name, color=None):
        if not name:
            return
        key = name.lower()
        now = int(time.time() * 1000)
        with self.lock:
            prev = self.presence.get(key) or {}
            self.presence[key] = {
                "name": name,
                "color": color or prev.get("color") or "#0084FF",
                "status": "offline",
                "lastSeen": now,
            }
        self.persist_presence()

    def register(self, cid, handler):
        with self.lock:
            ip = ""
            ua = ""
            try:
                ip = handler.client_ip()
            except Exception:
                ip = ""
            try:
                ua = str(handler.headers.get("User-Agent") or "")[:180]
            except Exception:
                ua = ""
            self.clients[cid] = {
                "handler": handler,
                "name": None,
                "color": None,
                "status": "available",
                "lastBeat": time.time(),
                "ip": ip,
                "ua": ua,
                "joinedAt": int(time.time() * 1000),
                "location": None,
            }

    def unregister(self, cid):
        with self.lock:
            user = self.clients.pop(cid, None)
        return user

    def set_user(self, cid, name, status="available"):
        color = color_from_name(name)
        with self.lock:
            if cid in self.clients:
                self.clients[cid]["name"] = name
                self.clients[cid]["color"] = color
                self.clients[cid]["status"] = status
                self.clients[cid]["lastBeat"] = time.time()
        self.touch(name, color, status)
        return color

    def set_status(self, cid, status):
        if status not in {"available", "away", "busy"}:
            status = "available"
        with self.lock:
            user = self.clients.get(cid)
            if not user or not user.get("name"):
                return None
            user["status"] = status
            user["lastBeat"] = time.time()
            name, color = user["name"], user["color"]
        self.touch(name, color, status)
        return {"name": name, "color": color, "status": status}

    def beat(self, cid):
        with self.lock:
            user = self.clients.get(cid)
            if user:
                user["lastBeat"] = time.time()
                if user.get("name"):
                    key = user["name"].lower()
                    rec = self.presence.get(key) or {}
                    rec.update({
                        "name": user["name"],
                        "color": user["color"],
                        "status": user.get("status") or "available",
                        "lastSeen": int(time.time() * 1000),
                    })
                    self.presence[key] = rec
                    return dict(user)
        return None

    def get_user(self, cid):
        with self.lock:
            return dict(self.clients.get(cid) or {})

    def has_client_id(self, client_id):
        if not client_id:
            return False
        with self.lock:
            return client_id in self.seen_client_ids

    def add_message(self, msg):
        with self.lock:
            cid = msg.get("clientId")
            if cid and cid in self.seen_client_ids:
                existing = next((m for m in self.messages if m.get("clientId") == cid), None)
                return existing
            self.messages.append(msg)
            if cid:
                self.seen_client_ids.add(cid)
            others = [
                c.get("name")
                for c in self.clients.values()
                if c.get("name") and c["name"].lower() != str(msg.get("author") or "").lower()
            ]
            msg["deliveredTo"] = others
            msg["readBy"] = []
            msg["status"] = "delivered" if others else "sent"
        self.schedule_save()
        return msg

    def receipts(self, viewer: str, kind: str, ids: list):
        if not viewer or kind not in {"delivered", "read"}:
            return []
        wanted = {str(i) for i in (ids or []) if i}
        if not wanted:
            return []
        changed = []
        with self.lock:
            for msg in self.messages:
                mid = str(msg.get("id") or "")
                cid = str(msg.get("clientId") or "")
                if mid not in wanted and cid not in wanted:
                    continue
                if (msg.get("author") or "").lower() == viewer.lower():
                    continue
                if msg.get("deleted"):
                    continue
                bucket = "readBy" if kind == "read" else "deliveredTo"
                lst = list(msg.get(bucket) or [])
                if viewer not in lst:
                    lst.append(viewer)
                    msg[bucket] = lst[-80:]
                if msg.get("readBy"):
                    msg["status"] = "read"
                elif msg.get("deliveredTo"):
                    msg["status"] = "delivered"
                else:
                    msg["status"] = "sent"
                changed.append({
                    "id": msg.get("id"),
                    "clientId": msg.get("clientId"),
                    "status": msg.get("status"),
                    "deliveredTo": list(msg.get("deliveredTo") or []),
                    "readBy": list(msg.get("readBy") or []),
                })
            if changed:
                self.messages = save_messages(self.messages)
        return changed

    def delete_message(self, actor: str, mid: str):
        with self.lock:
            msg = next((m for m in self.messages if m.get("id") == mid or m.get("clientId") == mid), None)
            if not msg:
                return None
            author = msg.get("author") or ""
            if author.lower() != actor.lower() and actor.lower() not in self.admins:
                return False
            msg["deleted"] = True
            msg["text"] = ""
            msg["mediaUrl"] = None
            msg["thumb"] = None
            self.messages = save_messages(self.messages)
            return msg

    def edit_message(self, actor: str, mid: str, text: str, e2e=False, iv=None, ct=None):
        text = str(text or "").strip()[:MAX_TEXT]
        with self.lock:
            msg = next((m for m in self.messages if m.get("id") == mid or m.get("clientId") == mid), None)
            if not msg:
                return None
            if (msg.get("author") or "").lower() != actor.lower():
                return False
            if msg.get("deleted"):
                return False
            if e2e:
                msg["e2e"] = True
                msg["text"] = ""
                msg["iv"] = str(iv or "")[:64]
                msg["ct"] = str(ct or "")[:8000]
            else:
                if not text:
                    return False
                msg["text"] = text
            msg["edited"] = True
            msg["editedAt"] = int(time.time() * 1000)
            self.messages = save_messages(self.messages)
            return msg

    def clients_list(self):
        with self.lock:
            return list(self.clients.values())


HUB = Hub()


def broadcast_admins(payload: dict):
    raw = json.dumps(payload, ensure_ascii=False)
    for client in HUB.clients_list():
        if not HUB.is_admin(client.get("name")):
            continue
        try:
            client["handler"].ws_send_text(raw)
        except Exception:
            pass


def broadcast_group(group_id: str | None, payload: dict, exclude_id: str | None = None):
    gid = group_id or DEFAULT_GROUP_ID
    g = HUB.group_by_id(gid)
    raw = json.dumps(payload, ensure_ascii=False)
    members = None
    if g and g.get("kind") != "public":
        members = {m.lower() for m in (g.get("members") or [])}
    dead = []
    for cid, client in list(HUB.clients.items()):
        if exclude_id and cid == exclude_id:
            continue
        name = (client.get("name") or "").lower()
        if members is not None and name not in members:
            continue
        try:
            client["handler"].ws_send_text(raw)
        except Exception:
            dead.append(cid)
    for cid in dead:
        HUB.unregister(cid)


def broadcast(payload: dict, exclude_id: str | None = None):
    raw = json.dumps(payload, ensure_ascii=False)
    with HUB.lock:
        targets = [
            (cid, c.get("handler"))
            for cid, c in HUB.clients.items()
            if c.get("handler") and cid != exclude_id
        ]
    dead = []
    for cid, handler in targets:
        try:
            handler.ws_send_text(raw)
        except Exception:
            dead.append(cid)
    for cid in dead:
        HUB.unregister(cid)


ALERT_COPY = {
    "mute": ("warning", "Usuário silenciado", "{target} foi silenciado por {actor}"),
    "unmute": ("ok", "Silêncio removido", "{target} pode falar de novo"),
    "block": ("warning", "Usuário bloqueado", "{target} foi bloqueado por {actor}"),
    "unblock": ("ok", "Bloqueio removido", "{target} foi desbloqueado"),
    "ban": ("danger", "Usuário banido", "{target} foi banido por {actor}"),
    "unban": ("ok", "Banimento removido", "{target} pode entrar de novo"),
    "admin_grant": ("info", "Novo administrador", "{actor} agora é administrador"),
    "admin_auth_fail": ("danger", "Tentativa de admin", "{actor} errou o código de administrador"),
    "mute_expired": ("info", "Silêncio expirou", "O silêncio de {target} acabou"),
}


def moderation_alert(action: str, actor: str | None = None, target: str | None = None, **extra):
    level, title, tmpl = ALERT_COPY.get(action, ("info", "Moderação", "{actor} {action} {target}"))
    text = tmpl.format(actor=actor or "sistema", target=target or "", action=action)
    if extra.get("minutes"):
        text += f" ({extra['minutes']} min)"
    payload = {
        "op": "alert",
        "level": extra.get("level") or level,
        "title": title,
        "text": text.strip(),
        "action": action,
        "actor": actor,
        "target": target,
        "createdAt": int(time.time() * 1000),
    }
    if extra.get("admins_only"):
        broadcast_admins(payload)
    else:
        broadcast(payload)
    threading.Thread(target=push_admins, args=(payload,), daemon=True).start()
    return payload


def _deliver_push(subs: list, payload: dict):
    try:
        from pushutil import send_web_push
    except Exception as exc:
        print("push import:", exc)
        return
    dead = []
    for sub in subs:
        try:
            status = send_web_push(sub, payload)
            if status in {404, 410}:
                dead.append(sub.get("endpoint"))
            elif status >= 400:
                print("push status", status, sub.get("endpoint"))
        except Exception as exc:
            print("push erro:", exc)
    for endpoint in dead:
        if endpoint:
            HUB.drop_push_sub(endpoint)


def push_admins(alert: dict):
    _deliver_push(HUB.admin_push_subs(), {
        "title": alert.get("title") or "Moderação",
        "body": alert.get("text") or "",
        "level": alert.get("level") or "info",
        "action": alert.get("action"),
        "kind": "moderation",
    })


def push_message(msg: dict):
    author = msg.get("author") or "Alguém"
    if msg.get("e2e"):
        body = "Nova mensagem criptografada"
    elif msg.get("type") == "video":
        body = msg.get("text") or "Enviou um vídeo"
    elif msg.get("type") == "image":
        body = msg.get("text") or "Enviou uma foto"
    else:
        body = (msg.get("text") or "")[:120] or "Nova mensagem"
    _deliver_push(HUB.message_push_subs(author), {
        "title": author,
        "body": body,
        "kind": "message",
        "author": author,
        "messageId": msg.get("id"),
    })


def system_message(text: str):
    msg = {
        "id": str(uuid.uuid4()),
        "type": "system",
        "text": text,
        "createdAt": int(time.time() * 1000),
    }
    broadcast({"op": "system", **msg})


def guess_ext(filename: str, content_type: str) -> str:
    ext = Path(filename or "").suffix.lower()
    if ext:
        return ext
    mapping = {
        "video/mp4": ".mp4",
        "video/webm": ".webm",
        "audio/webm": ".webm",
        "audio/ogg": ".ogg",
        "audio/mpeg": ".mp3",
        "audio/mp4": ".m4a",
        "video/quicktime": ".mov",
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/webp": ".webp",
    }
    return mapping.get((content_type or "").split(";")[0].strip(), ".bin")


def process_video(path: Path, stem: str) -> dict:
    extra = {}
    thumb = UPLOADS / f"{stem}.jpg"
    try:
        subprocess.run(
            [
                "ffmpeg", "-y", "-ss", "00:00:01", "-i", str(path),
                "-frames:v", "1", "-q:v", "3", "-vf", "scale=640:-1", str(thumb),
            ],
            check=False,
            capture_output=True,
            timeout=20,
        )
        if thumb.exists() and thumb.stat().st_size > 0:
            extra["thumb"] = f"/uploads/{thumb.name}"
    except Exception:
        pass
    try:
        out = subprocess.run(
            [
                "ffprobe", "-v", "error", "-show_entries", "format=duration",
                "-of", "default=noprint_wrappers=1:nokey=1", str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        dur = float((out.stdout or "").strip() or "nan")
        if dur == dur:  # not NaN
            extra["duration"] = dur
    except Exception:
        pass
    return extra


def parse_multipart(body: bytes, content_type: str):
    if "boundary=" not in content_type:
        raise ValueError("multipart sem boundary")
    boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode()
    parts = body.split(b"--" + boundary)
    for part in parts:
        if b"Content-Disposition" not in part:
            continue
        header, _, data = part.partition(b"\r\n\r\n")
        if not data:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]
        headers = header.decode("utf-8", "ignore")
        if "filename=" not in headers:
            continue
        filename = ""
        for piece in headers.replace("\r\n", ";").split(";"):
            piece = piece.strip()
            if piece.lower().startswith("filename="):
                filename = piece.split("=", 1)[1].strip().strip('"')
        ctype = "application/octet-stream"
        for line in headers.split("\r\n"):
            if line.lower().startswith("content-type:"):
                ctype = line.split(":", 1)[1].strip()
        return filename, ctype, data
    raise ValueError("arquivo não encontrado no upload")


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept_key(key: str) -> str:
    digest = hashlib.sha1((key + GUID).encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


class ChatHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For") or self.headers.get("X-Real-IP") or ""
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
        return (self.client_address[0] if self.client_address else "0.0.0.0")[:64]

    def request_origin(self) -> str:
        return (self.headers.get("Origin") or self.headers.get("Referer") or "").rstrip("/")

    def origin_ok(self) -> bool:
        if not ALLOWED_ORIGINS:
            return True
        origin = self.request_origin()
        host = self.headers.get("Host") or ""
        if origin:
            return any(origin.startswith(o) for o in ALLOWED_ORIGINS)
        return True

    def require_api_user(self):
        if not self.origin_ok():
            self.send_json(403, {"error": "Origem não autorizada."})
            return None
        name = verify_jwt(self.bearer_token())
        if not name:
            self.send_json(401, {"error": "API exige JWT."})
            return None
        return name

    def bearer_token(self, body=None) -> str:
        header = self.headers.get("Authorization") or ""
        if header.lower().startswith("bearer "):
            return header.split(" ", 1)[1].strip()
        if isinstance(body, dict):
            return str(body.get("token") or "")
        return ""

    def google_redirect(self) -> str:
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"localhost:{PORT}"
        proto = self.headers.get("X-Forwarded-Proto") or ("http" if "localhost" in host or "127.0.0.1" in host else "https")
        return f"{proto}://{host}/api/auth/google/callback"

    def rate(self, bucket: str, limit: int, window: int) -> bool:
        return LIMITER.allow(f"{bucket}:{self.client_ip()}", limit, window)

    def send_bytes(self, status: int, body: bytes, content_type: str, extra=None):
        extra = extra or {}
        enc = (self.headers.get("Accept-Encoding") or "").lower()
        if "gzip" in enc and len(body) > 512 and content_type.split(";")[0] in {
            "text/html", "text/css", "text/javascript", "application/json", "application/javascript",
        }:
            body = gzip.compress(body, compresslevel=5)
            extra = {**extra, "Content-Encoding": "gzip", "Vary": "Accept-Encoding"}
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if "Cache-Control" not in extra:
            self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(self), microphone=(self)")
        origin = self.headers.get("Origin")
        if origin and self.origin_ok():
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, payload: dict):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, raw, "application/json; charset=utf-8")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path == "/ws":
            if not self.rate("ws", 30, 60):
                return self.send_json(429, {"error": "Muitas conexões. Espere um pouco."})
            return self.upgrade_websocket()

        if path in {"/api/jwks", "/.well-known/jwks.json"}:
            body = json.dumps(KEYS.jwks()).encode("utf-8")
            return self.send_bytes(
                200,
                body,
                "application/json; charset=utf-8",
                {"Cache-Control": "public, max-age=60"},
            )

        if path == "/api/auth/google/start":
            if not GOOGLE_CLIENT_ID:
                return self.send_json(400, {"error": "Defina GOOGLE_CLIENT_ID."})
            redirect = GOOGLE_REDIRECT_URI or self.google_redirect()
            params = {
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": redirect,
                "response_type": "code",
                "scope": "openid email profile",
                "access_type": "online",
                "prompt": "select_account",
            }
            loc = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return

        if path == "/api/auth/google/callback":
            qs = parse_qs(parsed.query)
            code = (qs.get("code") or [""])[0]
            err = (qs.get("error") or [""])[0]
            if err or not code:
                return self.send_json(401, {"error": err or "OAuth cancelado."})
            if not GOOGLE_CLIENT_SECRET:
                return self.send_json(500, {"error": "Defina GOOGLE_CLIENT_SECRET."})
            redirect = GOOGLE_REDIRECT_URI or self.google_redirect()
            body = urlencode({
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": redirect,
                "grant_type": "authorization_code",
            }).encode("utf-8")
            req = urllib.request.Request(
                "https://oauth2.googleapis.com/token",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    tok = json.loads(resp.read().decode("utf-8"))
            except Exception as exc:
                return self.send_json(401, {"error": f"Troca de código falhou: {exc}"})
            id_token = str(tok.get("id_token") or "")
            if not id_token:
                return self.send_json(401, {"error": "Google não devolveu id_token."})
            try:
                with urllib.request.urlopen(
                    "https://oauth2.googleapis.com/tokeninfo?id_token=" + id_token,
                    timeout=8,
                ) as resp:
                    info = json.loads(resp.read().decode("utf-8"))
            except Exception:
                return self.send_json(401, {"error": "id_token inválido."})
            name = str(info.get("given_name") or info.get("name") or info.get("email") or "Google")[:24]
            tokens = issue_tokens(name)
            loc = "/#gtok={}&gref={}&gname={}".format(
                quote_plus(tokens["accessToken"]),
                quote_plus(tokens["refreshToken"]),
                quote_plus(name),
            )
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return

        if path == "/api/config":
            return self.send_json(200, {
                "googleClientId": GOOGLE_CLIENT_ID,
                "google": bool(GOOGLE_CLIENT_ID),
                "googleOAuth": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            })

        if path == "/api/health" or path == "/api/ready":
            return self.send_json(200, {
                "ok": True,
                "ready": True,
                "uptime": int(time.time() - STARTED_AT),
                "online": len(HUB.clients),
                "db": "sqlite",
            })

        if path == "/api/push/public-key":
            try:
                from pushutil import public_key
                return self.send_json(200, {"publicKey": public_key()})
            except Exception as exc:
                return self.send_json(500, {"error": str(exc)})

        if path == "/api/presence":
            if not self.require_api_user():
                return
            return self.send_json(200, HUB.presence_list())

        if path == "/api/messages":
            user = self.require_api_user()
            if not user:
                return
            return self.send_json(200, HUB.snapshot(user))

        if path == "/api/net":
            user = self.require_api_user()
            if not user:
                return
            return self.send_json(200, {
                "ok": True,
                "ip": self.client_ip(),
                "online": len(HUB.clients),
                "proto": self.headers.get("X-Forwarded-Proto") or "http",
                "host": self.headers.get("Host"),
            })

        if path == "/":
            path = "/index.html"

        rel = path.lstrip("/")
        target = (PUBLIC / rel).resolve()
        if PUBLIC not in target.parents and target != PUBLIC:
            return self.send_json(403, {"error": "forbidden"})
        if not target.is_file():
            return self.send_json(404, {"error": "not found"})

        data = target.read_bytes()
        ctype = MIME.get(target.suffix.lower(), "application/octet-stream")
        ext = target.suffix.lower()
        if ext in {".png", ".jpg", ".jpeg", ".webp", ".mp4", ".webm", ".woff2"}:
            cache = "public, max-age=604800, immutable"
        elif ext in {".css", ".js"}:
            cache = "public, max-age=120"
        else:
            cache = "no-cache"
        self.send_bytes(200, data, ctype, {"Cache-Control": cache})

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.send_bytes(204, b"", "text/plain", {"Cache-Control": "no-store"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/") and parsed.path not in {
            "/api/auth", "/api/auth/refresh", "/api/auth/logout", "/api/auth/google",
        } and not self.origin_ok():
            return self.send_json(403, {"error": "Origem não autorizada."})
        if parsed.path == "/api/radio/lora":
            if not self.rate("lora", 30, 60):
                return self.send_json(429, {"error": "Muitos pacotes LoRa."})
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                packet = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                return self.send_json(400, {"error": "JSON inválido."})
            packet = {
                "name": str(packet.get("name") or "")[:24],
                "text": str(packet.get("text") or "")[:200],
                "groupId": str(packet.get("groupId") or DEFAULT_GROUP_ID)[:24],
                "via": "lora",
                "createdAt": int(packet.get("createdAt") or time.time() * 1000),
            }
            if not packet["text"]:
                return self.send_json(400, {"error": "Texto vazio."})
            outbox = DATA_DIR / "lora-outbox.json"
            rows = []
            try:
                rows = json.loads(outbox.read_text("utf-8")) if outbox.exists() else []
            except Exception:
                rows = []
            if not isinstance(rows, list):
                rows = []
            rows.append(packet)
            atomic_write(outbox, rows[-200:])
            forwarded = False
            gw = (os.environ.get("LORA_GATEWAY_URL") or "").strip()
            if gw:
                try:
                    req = urllib.request.Request(
                        gw,
                        data=json.dumps(packet).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=4) as resp:
                        forwarded = resp.status < 400
                except Exception as exc:
                    print("lora gateway:", exc)
            return self.send_json(200, {"ok": True, "queued": True, "forwarded": forwarded})
        if parsed.path == "/api/auth/google":
            if not self.rate("auth", 20, 60):
                return self.send_json(429, {"error": "Muitas tentativas."})
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                return self.send_json(400, {"error": "JSON inválido."})
            token = str(body.get("credential") or body.get("id_token") or "")
            if not token or not GOOGLE_CLIENT_ID:
                return self.send_json(400, {"error": "Google não configurado ou token ausente."})
            try:
                info_url = "https://oauth2.googleapis.com/tokeninfo?id_token=" + token
                with urllib.request.urlopen(info_url, timeout=8) as resp:
                    info = json.loads(resp.read().decode("utf-8"))
            except Exception:
                return self.send_json(401, {"error": "Token Google inválido."})
            if str(info.get("aud") or "") != GOOGLE_CLIENT_ID:
                return self.send_json(401, {"error": "Client ID do Google não confere."})
            if str(info.get("iss") or "") not in {"accounts.google.com", "https://accounts.google.com"}:
                return self.send_json(401, {"error": "Emissor Google inválido."})
            name = str(info.get("given_name") or info.get("name") or info.get("email") or "Google")[:24]
            if HUB.restriction(name) == "ban":
                return self.send_json(403, {"error": "Usuário banido."})
            try:
                tokens = issue_tokens(name)
            except Exception as exc:
                return self.send_json(500, {"error": str(exc)})
            return self.send_json(200, {"ok": True, "name": name, "email": info.get("email"), "picture": info.get("picture"), **tokens})
        if parsed.path == "/api/keys/rotate":
            if not self.rate("rotate", 6, 300):
                return self.send_json(429, {"error": "Muitas rotações."})
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                body = {}
            code = str(body.get("code") or self.headers.get("X-Admin-Code") or "")
            if code != ADMIN_CODE:
                return self.send_json(403, {"error": "Código de admin inválido."})
            rec = KEYS.rotate(force=True)
            return self.send_json(200, {
                "ok": True,
                "kid": rec.get("kid"),
                "jwks": KEYS.jwks(),
            })

        if parsed.path in {"/api/auth", "/api/auth/refresh", "/api/auth/logout"}:
            if not self.rate("auth", 30, 60):
                return self.send_json(429, {"error": "Muitas tentativas de login. Aguarde 1 minuto."})
            length = int(self.headers.get("Content-Length") or 0)
            if length > 8192:
                return self.send_json(413, {"error": "Pedido grande demais."})
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                return self.send_json(400, {"error": "JSON inválido."})

            if parsed.path == "/api/auth/logout":
                rec = verify_jwt(str(body.get("refreshToken") or ""), "refresh")
                if rec:
                    REFRESH.kill_family(rec.get("fid") or "")
                    REFRESH.revoke(rec["jti"])
                return self.send_json(200, {"ok": True})

            if parsed.path == "/api/auth/refresh":
                rec = verify_jwt(str(body.get("refreshToken") or ""), "refresh")
                if not rec:
                    return self.send_json(401, {"error": "Refresh token inválido ou expirado."})
                if HUB.restriction(rec["name"]) == "ban":
                    REFRESH.kill_family(rec.get("fid") or "")
                    return self.send_json(403, {"error": "Usuário banido."})
                try:
                    tokens = issue_tokens(rec["name"], rotate_jti=rec["jti"], family=rec.get("fid"))
                except TokenReuse:
                    return self.send_json(401, {"error": "Refresh reutilizado. Entre de novo."})
                except Exception as exc:
                    return self.send_json(500, {"error": str(exc)})
                return self.send_json(200, {"ok": True, "name": rec["name"], **tokens})

            name = str(body.get("name") or "").strip()[:24]
            if not name:
                return self.send_json(400, {"error": "Informe um nome."})
            if HUB.restriction(name) == "ban":
                return self.send_json(403, {"error": "Usuário banido."})
            try:
                tokens = issue_tokens(name)
            except Exception as exc:
                return self.send_json(500, {"error": str(exc)})
            return self.send_json(200, {"ok": True, "name": name, **tokens})

        if parsed.path in {"/api/push/subscribe", "/api/push/unsubscribe"}:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                return self.send_json(400, {"error": "JSON inválido."})
            name = str(body.get("name") or "").strip()
            sub = body.get("subscription") or body
            if parsed.path.endswith("unsubscribe"):
                endpoint = (sub.get("endpoint") if isinstance(sub, dict) else None) or body.get("endpoint")
                if endpoint:
                    HUB.drop_push_sub(endpoint)
                return self.send_json(200, {"ok": True})
            if not name:
                return self.send_json(403, {"error": "Entre no chat antes de ativar o push."})
            token_name = verify_jwt(self.bearer_token(body))
            if not token_name or token_name.lower() != name.lower():
                return self.send_json(401, {"error": "Token JWT inválido."})
            if HUB.restriction(name) == "ban":
                return self.send_json(403, {"error": "Usuário banido."})
            if not HUB.save_push_sub(name, sub if isinstance(sub, dict) else {}):
                return self.send_json(400, {"error": "Inscrição inválida."})
            return self.send_json(200, {"ok": True})

        if parsed.path != "/api/upload":
            return self.send_json(404, {"error": "not found"})

        if not self.rate("upload", 15, 60):
            return self.send_json(429, {"error": "Muitos uploads. Aguarde um pouco."})
        if not verify_jwt(self.bearer_token()):
            return self.send_json(401, {"error": "Faça login JWT antes de enviar mídia."})

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_VIDEO_BYTES + 1024 * 1024:
            return self.send_json(413, {"error": "Arquivo muito grande (máx. 80 MB)."})

        body = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        try:
            filename, file_mime, data = parse_multipart(body, ctype)
        except Exception as exc:
            return self.send_json(400, {"error": str(exc)})

        if not (file_mime.startswith("video/") or file_mime.startswith("image/") or file_mime.startswith("audio/")):
            return self.send_json(400, {"error": "Envie imagem, vídeo ou áudio."})

        ext = guess_ext(filename, file_mime)
        stem = f"{int(time.time()*1000)}-{uuid.uuid4().hex[:10]}"
        saved = UPLOADS / f"{stem}{ext}"
        saved.write_bytes(data)

        payload = {
            "url": f"/uploads/{saved.name}",
            "name": filename,
            "mime": file_mime,
            "size": len(data),
            "type": "video" if file_mime.startswith("video/") else ("radio" if file_mime.startswith("audio/") else "image"),
        }
        if payload["type"] == "video":
            payload.update(process_video(saved, stem))
        self.send_json(200, payload)

    def upgrade_websocket(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key or self.headers.get("Upgrade", "").lower() != "websocket":
            return self.send_json(400, {"error": "handshake inválido"})

        accept = ws_accept_key(key)
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        cid = uuid.uuid4().hex
        self._ws_open = True
        self.session_key = None
        self.session_user = None
        self.session_jti = None
        self.session_aad = None
        self.session_priv, self.session_pub = new_session_keypair()
        HUB.register(cid, self)
        try:
            self.ws_send_text(json.dumps({
                "op": "hello",
                "needAuth": True,
                "auth": "jwt",
                "session": "ecdh-aesgcm",
                "serverPub": self.session_pub,
            }, ensure_ascii=False))
            self.ws_loop(cid)
        finally:
            user = HUB.unregister(cid)
            if user and user.get("name"):
                still = any(
                    c.get("name") and c["name"].lower() == user["name"].lower()
                    for c in HUB.clients_list()
                )
                if not still:
                    HUB.mark_offline(user["name"], user.get("color"))
                    system_message(f"{user['name']} saiu do chat")
                broadcast({"op": "users", "users": HUB.presence_list()})

    def ws_loop(self, cid: str):
        while self._ws_open:
            msg = self.ws_recv_text()
            if msg is None:
                break
            if msg == "":
                continue
            try:
                payload = json.loads(msg)
            except json.JSONDecodeError:
                continue
            try:
                if payload.get("sess"):
                    if not self.session_key or not self.session_aad:
                        continue
                    payload = open_session(self.session_key, payload, self.session_aad)
                self.handle_event(cid, payload)
            except Exception as exc:
                print("handle_event erro:", exc)

    def handle_event(self, cid: str, payload: dict):
        op = payload.get("op")
        if op == "session_open":
            claims = access_claims(str(payload.get("token") or ""))
            if not claims:
                self.ws_send_text(json.dumps({
                    "op": "need_auth",
                    "text": "Sessão JWT inválida. Entre de novo.",
                }, ensure_ascii=False))
                return
            pub = str(payload.get("publicKey") or "")
            try:
                self.session_key = derive_session_key(self.session_priv, pub)
            except Exception:
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Falha ao abrir sessão criptografada.",
                }, ensure_ascii=False))
                return
            self.session_user = claims["name"]
            self.session_jti = claims["jti"]
            self.session_aad = session_aad(claims["jti"])
            self.ws_send_text(json.dumps({
                "op": "session_ok",
                "session": "ecdh-aesgcm",
                "name": claims["name"],
            }, ensure_ascii=False))
            return
        if self.session_user and op not in SESSION_CLEAR_OPS:
            token = str(payload.get("token") or "")
            if token:
                token_name = verify_jwt(token)
                if not token_name or token_name.lower() != self.session_user.lower():
                    self.ws_send_text(json.dumps({
                        "op": "need_auth",
                        "text": "JWT da sessão não confere.",
                    }, ensure_ascii=False))
                    return
        if op == "join":
            if not LIMITER.allow(f"join:{self.client_ip()}", 20, 60):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Muitas entradas. Aguarde um minuto.",
                }, ensure_ascii=False))
                return
            token_name = verify_jwt(str(payload.get("token") or ""))
            name = (token_name or str(payload.get("name") or "")).strip()[:24]
            if not token_name:
                self.ws_send_text(json.dumps({
                    "op": "need_auth",
                    "text": "Token JWT ausente ou inválido. Entre de novo.",
                }, ensure_ascii=False))
                return
            if payload.get("name") and str(payload.get("name")).strip()[:24].lower() != token_name.lower():
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "O token não confere com este nome.",
                }, ensure_ascii=False))
                return
            name = token_name
            if HUB.restriction(name) == "ban":
                self.ws_send_text(json.dumps({
                    "op": "banned",
                    "reason": "Você foi banido deste chat.",
                }, ensure_ascii=False))
                self._ws_open = False
                return
            status = payload.get("status") if payload.get("status") in {"available", "away", "busy"} else "available"
            color = HUB.set_user(cid, name, status)
            flags = HUB.user_flags(name)
            key_change = None
            if payload.get("publicKey"):
                key_change = HUB.set_pubkey(name, str(payload.get("publicKey")))
            gid = DEFAULT_GROUP_ID
            self.ws_send_text(json.dumps({
                "op": "joined",
                "name": name,
                "color": color,
                "status": status,
                "id": cid,
                "groupId": gid,
                "groups": HUB.groups_for(name),
                "pubkeys": HUB.pubkeys_map(),
                "wraps": HUB.wraps_for(gid),
                **flags,
            }, ensure_ascii=False))
            self.ws_send_text(json.dumps({
                "op": "history",
                "groupId": gid,
                "messages": HUB.snapshot(name, gid),
            }, ensure_ascii=False))
            self.ws_send_text(json.dumps({
                "op": "moderation",
                "self": flags,
            }, ensure_ascii=False))
            broadcast({"op": "users", "users": HUB.presence_list()})
            broadcast({"op": "pubkeys", "pubkeys": HUB.pubkeys_map()})
            if key_change:
                broadcast({"op": "key_changed", **key_change})
            system_message(f"{name} entrou no chat")
            return

        if op == "pubkey":
            user = HUB.get_user(cid)
            if user.get("name") and payload.get("publicKey"):
                changed = HUB.set_pubkey(user["name"], str(payload.get("publicKey")))
                broadcast({"op": "pubkeys", "pubkeys": HUB.pubkeys_map()})
                if changed:
                    broadcast({"op": "key_changed", **changed})
            return

        if op == "create_group":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            result = HUB.create_group(user["name"], str(payload.get("name") or ""), str(payload.get("kind") or "private"))
            if not result.get("ok"):
                self.ws_send_text(json.dumps({"op": "error", "text": result.get("error")}, ensure_ascii=False))
                return
            self.ws_send_text(json.dumps({
                "op": "group_created",
                "group": result["group"],
                "groups": HUB.groups_for(user["name"]),
            }, ensure_ascii=False))
            return

        if op == "add_member":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            result = HUB.add_member(user["name"], str(payload.get("groupId") or ""), str(payload.get("target") or ""))
            if not result.get("ok"):
                self.ws_send_text(json.dumps({"op": "error", "text": result.get("error")}, ensure_ascii=False))
                return
            broadcast_group(result["group"]["id"], {
                "op": "group_updated",
                "group": result["group"],
            })
            return

        if op == "leave_group":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            result = HUB.leave_group(user["name"], str(payload.get("groupId") or ""))
            if not result.get("ok"):
                self.ws_send_text(json.dumps({"op": "error", "text": result.get("error")}, ensure_ascii=False))
                return
            self.ws_send_text(json.dumps({
                "op": "group_left",
                "groupId": payload.get("groupId"),
                "groups": HUB.groups_for(user["name"]),
            }, ensure_ascii=False))
            broadcast({
                "op": "group_updated",
                "group": result["group"],
            })
            return

        if op == "open_dm":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            result = HUB.open_dm(user["name"], str(payload.get("target") or ""))
            if not result.get("ok"):
                self.ws_send_text(json.dumps({"op": "error", "text": result.get("error")}, ensure_ascii=False))
                return
            gid = result["group"]["id"]
            self.ws_send_text(json.dumps({
                "op": "dm_open",
                "group": result["group"],
                "groups": HUB.groups_for(user["name"]),
                "groupId": gid,
                "messages": HUB.snapshot(user["name"], gid),
                "wraps": HUB.wraps_for(gid),
                "pubkeys": HUB.pubkeys_map(),
            }, ensure_ascii=False))
            return

        if op == "join_group":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            gid = str(payload.get("groupId") or DEFAULT_GROUP_ID)
            if not HUB.can_access(user["name"], gid):
                self.ws_send_text(json.dumps({"op": "error", "text": "Você não faz parte deste grupo."}, ensure_ascii=False))
                return
            self.ws_send_text(json.dumps({
                "op": "history",
                "groupId": gid,
                "messages": HUB.snapshot(user["name"], gid),
                "wraps": HUB.wraps_for(gid),
                "pubkeys": HUB.pubkeys_map(),
                "group": HUB.group_by_id(gid),
            }, ensure_ascii=False))
            return

        if op == "key_wraps":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            gid = str(payload.get("groupId") or DEFAULT_GROUP_ID)
            if not HUB.can_access(user["name"], gid):
                return
            HUB.save_wraps(gid, user["name"], payload.get("wraps") or {})
            broadcast_group(gid, {
                "op": "key_wraps",
                "groupId": gid,
                "wraps": HUB.wraps_for(gid),
                "pubkeys": HUB.pubkeys_map(),
            })
            return

        if op == "admin_auth":
            if not LIMITER.allow(f"admin:{self.client_ip()}", 8, 300):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Muitas tentativas de admin. Aguarde 5 minutos.",
                }, ensure_ascii=False))
                return
            user = HUB.get_user(cid)
            if not user.get("name"):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Entre no chat antes.",
                }, ensure_ascii=False))
                return
            code = str(payload.get("code") or "")
            if code != ADMIN_CODE:
                fail = HUB.add_log("admin_auth_fail", user.get("name"), reason="código inválido")
                broadcast_admins({"op": "moderation_log", "entry": fail, "logs": HUB.recent_logs()})
                moderation_alert("admin_auth_fail", user.get("name"), admins_only=True)
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Código de administrador inválido.",
                }, ensure_ascii=False))
                return
            log = HUB.grant_admin(user["name"])
            self.ws_send_text(json.dumps({
                "op": "admin",
                "ok": True,
                "flags": HUB.user_flags(user["name"]),
                "logs": HUB.recent_logs(),
            }, ensure_ascii=False))
            if log:
                broadcast_admins({"op": "moderation_log", "entry": log, "logs": HUB.recent_logs()})
                moderation_alert("admin_grant", user["name"], user["name"])
            broadcast({"op": "users", "users": HUB.presence_list()})
            system_message(f"{user['name']} agora é administrador")
            return

        if op == "security_sessions":
            user = HUB.get_user(cid)
            if not HUB.is_admin(user.get("name")):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Só administrador vê o módulo de segurança.",
                }, ensure_ascii=False))
                return
            self.ws_send_text(json.dumps({
                "op": "security_sessions",
                "sessions": HUB.security_sessions(),
            }, ensure_ascii=False))
            return

        if op == "kick_session":
            user = HUB.get_user(cid)
            if not HUB.is_admin(user.get("name")):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Só administrador pode encerrar sessão.",
                }, ensure_ascii=False))
                return
            sid = str(payload.get("sid") or "")
            if not sid or sid == cid:
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Não é possível encerrar a própria sessão por aqui.",
                }, ensure_ascii=False))
                return
            ok = HUB.kick_sid(sid, "Um administrador encerrou esta sessão.")
            log = HUB.add_log("kick_session", user.get("name"), payload.get("target") or "", reason="sessão encerrada")
            broadcast_admins({
                "op": "security_sessions",
                "sessions": HUB.security_sessions(),
            })
            if log:
                broadcast_admins({"op": "moderation_log", "entry": log, "logs": HUB.recent_logs()})
            if not ok:
                self.ws_send_text(json.dumps({"op": "error", "text": "Sessão não encontrada."}, ensure_ascii=False))
            return

        if op == "share_location":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            if not LIMITER.allow(f"loc:{self.client_ip()}", 20, 60):
                self.ws_send_text(json.dumps({"op": "error", "text": "Muitos envios de localização."}, ensure_ascii=False))
                return
            saved = HUB.set_location(
                cid,
                payload.get("lat"),
                payload.get("lng"),
                payload.get("accuracy"),
                payload.get("minutes") or 15,
            )
            if not saved:
                self.ws_send_text(json.dumps({"op": "error", "text": "Localização inválida."}, ensure_ascii=False))
                return
            self.ws_send_text(json.dumps({"op": "location_on", **saved}, ensure_ascii=False))
            broadcast_admins({
                "op": "security_sessions",
                "sessions": HUB.security_sessions(),
            })
            return

        if op == "stop_location":
            name = HUB.clear_location(cid)
            if name:
                self.ws_send_text(json.dumps({"op": "location_off"}, ensure_ascii=False))
                broadcast_admins({
                    "op": "security_sessions",
                    "sessions": HUB.security_sessions(),
                })
            return

        if op == "logs":
            user = HUB.get_user(cid)
            if not HUB.is_admin(user.get("name")):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Apenas administradores veem os logs.",
                }, ensure_ascii=False))
                return
            self.ws_send_text(json.dumps({
                "op": "moderation_logs",
                "logs": HUB.recent_logs(),
            }, ensure_ascii=False))
            return

        if op == "moderate":
            user = HUB.get_user(cid)
            if not HUB.is_admin(user.get("name")):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Apenas administradores podem moderar.",
                }, ensure_ascii=False))
                return
            result = HUB.moderate(
                user["name"],
                str(payload.get("target") or ""),
                str(payload.get("action") or ""),
                int(payload.get("minutes") or 0),
                str(payload.get("reason") or ""),
            )
            if not result.get("ok"):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": result.get("error") or "Falha na moderação.",
                }, ensure_ascii=False))
                return
            action = result["action"]
            target = result["target"]
            labels = {
                "mute": "foi silenciado",
                "unmute": "pode falar de novo",
                "block": "foi bloqueado",
                "unblock": "foi desbloqueado",
                "ban": "foi banido",
                "unban": "foi desbanido",
            }
            system_message(f"{target} {labels.get(action, action)} por {user['name']}")
            moderation_alert(action, user["name"], target, minutes=payload.get("minutes") or 0)
            for _cid, client in HUB.sockets_of(target):
                try:
                    client["handler"].ws_send_text(json.dumps({
                        "op": "moderation",
                        "self": HUB.user_flags(target),
                        "action": action,
                    }, ensure_ascii=False))
                except Exception:
                    pass
            if action == "ban":
                HUB.kick(target, "Você foi banido por um administrador.")
            if result.get("log"):
                broadcast_admins({
                    "op": "moderation_log",
                    "entry": result["log"],
                    "logs": HUB.recent_logs(),
                })
            broadcast({"op": "users", "users": HUB.presence_list()})
            broadcast({"op": "moderation_state", "users": HUB.presence_list()})
            return

        if op == "shell":
            user = HUB.get_user(cid)
            name = user.get("name") or ""
            raw = str(payload.get("cmd") or "").strip()
            if not raw:
                return
            if not LIMITER.allow(f"shell:{self.client_ip()}", 20, 30):
                self.ws_send_text(json.dumps({"op": "shell_out", "text": "shell limitado. aguarde."}, ensure_ascii=False))
                return
            parts = raw.split()
            cmd = parts[0].lower().lstrip("/")
            arg = " ".join(parts[1:]).strip()
            if cmd in {"help", "?"}:
                out = "help status users health whoami net ip proto peers logs\nadmin: mute NOME | unmute NOME | kick NOME"
            elif cmd in {"net", "ip", "proto", "peers"}:
                ip = self.client_ip()
                proto = self.headers.get("X-Forwarded-Proto") or "http"
                host = self.headers.get("Host") or ""
                if cmd == "ip":
                    out = f"seu ip={ip}"
                elif cmd == "proto":
                    out = f"proto={proto} host={host}"
                elif cmd == "peers":
                    out = f"conexoes ws={len(HUB.clients)}"
                else:
                    out = f"ip={ip}\nproto={proto}\nhost={host}\nws={len(HUB.clients)}\nuptime={int(time.time()-STARTED_AT)}s"
            elif cmd == "whoami":
                flags = HUB.user_flags(name)
                out = f"{name} admin={bool(flags.get('admin'))} muted={bool(flags.get('muted'))} ip={self.client_ip()}"
            elif cmd == "status":
                out = f"online={len(HUB.clients)} mensagens={len(HUB.messages)} grupos={len(HUB.groups)}"
            elif cmd == "users":
                out = "\n".join(f"{u.get('name')} {u.get('status')}" for u in HUB.presence_list()[:40]) or "ninguem"
            elif cmd == "health":
                out = f"ok uptime={int(time.time()-STARTED_AT)}s db=sqlite"
            elif cmd == "logs":
                out = "so admin ve logs" if not HUB.is_admin(name) else (
                    "\n".join(f"{(x.get('action') or '')} {(x.get('target') or '')}" for x in (HUB.recent_logs() or [])[:12]) or "sem logs"
                )
            elif cmd in {"mute", "unmute", "kick"}:
                if not HUB.is_admin(name):
                    out = "so admin"
                elif not arg:
                    out = "informe o nome"
                elif cmd == "kick":
                    HUB.kick(arg, "Removido pelo shell.")
                    out = f"kick {arg}"
                else:
                    result = HUB.moderate(name, arg, cmd, 10 if cmd == "mute" else 0)
                    out = result.get("error") if not result.get("ok") else f"{cmd} {arg}"
            else:
                out = f"comando desconhecido: {cmd}. use /help"
            self.ws_send_text(json.dumps({"op": "shell_out", "cmd": raw, "text": out}, ensure_ascii=False))
            return

        if op == "ping":
            HUB.beat(cid)
            self.ws_send_text(json.dumps({"op": "pong", "t": payload.get("t")}, ensure_ascii=False))
            return

        if op == "profile":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            info = HUB.set_profile(user["name"], str(payload.get("bio") or ""), str(payload.get("avatar") or ""))
            self.ws_send_text(json.dumps({"op": "profile_ok", "profile": info}, ensure_ascii=False))
            broadcast({"op": "users", "users": HUB.presence_list()})
            return

        if op == "status":
            info = HUB.set_status(cid, payload.get("status"))
            if info:
                broadcast({"op": "users", "users": HUB.presence_list()})
            return

        if op == "receipts":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            changed = HUB.receipts(user["name"], str(payload.get("kind") or ""), payload.get("ids") or [])
            for row in changed:
                broadcast({"op": "receipt", **row})
            return

        if op == "delete":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            result = HUB.delete_message(user["name"], str(payload.get("id") or ""))
            if result is False:
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Você não pode apagar esta mensagem.",
                }, ensure_ascii=False))
                return
            if result:
                broadcast({
                    "op": "deleted",
                    "id": result.get("id"),
                    "clientId": result.get("clientId"),
                    "by": user["name"],
                    "forEveryone": True,
                })
            return

        if op == "edit":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            result = HUB.edit_message(
                user["name"],
                str(payload.get("id") or ""),
                str(payload.get("text") or ""),
                bool(payload.get("e2e")),
                payload.get("iv"),
                payload.get("ct"),
            )
            if result is False:
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Você não pode editar esta mensagem.",
                }, ensure_ascii=False))
                return
            if result:
                broadcast({"op": "edited", "message": result})
            return

        if op == "typing":
            user = HUB.get_user(cid)
            if not user.get("name"):
                return
            broadcast({
                "op": "typing",
                "name": user["name"],
                "typing": bool(payload.get("typing")),
            }, exclude_id=cid)
            return

        if op == "message":
            if not LIMITER.allow(f"msg:{self.client_ip()}", 25, 10):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Você está enviando rápido demais.",
                }, ensure_ascii=False))
                return
            user = HUB.get_user(cid)
            if not user.get("name"):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Entre com um nome antes de enviar.",
                }, ensure_ascii=False))
                return
            restriction = HUB.restriction(user.get("name"))
            if restriction == "ban":
                self.ws_send_text(json.dumps({
                    "op": "banned",
                    "reason": "Você foi banido deste chat.",
                }, ensure_ascii=False))
                return
            if restriction == "mute":
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Você está silenciado e não pode enviar mensagens.",
                }, ensure_ascii=False))
                return
            if restriction == "block":
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Você está bloqueado e não pode enviar mensagens.",
                }, ensure_ascii=False))
                return
            mtype = payload.get("type") if payload.get("type") in {"text", "video", "image", "radio"} else "text"
            e2e = bool(payload.get("e2e"))
            text = "" if e2e else str(payload.get("text") or "").strip()[:MAX_TEXT]
            media = payload.get("mediaUrl")
            gid = str(payload.get("groupId") or DEFAULT_GROUP_ID)
            if not HUB.can_access(user.get("name"), gid):
                self.ws_send_text(json.dumps({
                    "op": "error",
                    "text": "Você não faz parte deste grupo.",
                }, ensure_ascii=False))
                return
            if mtype == "text" and not text and not e2e:
                return
            if e2e and mtype == "text" and not payload.get("ct"):
                return
            if mtype in {"video", "image", "radio"} and not media:
                return
            if media and not str(media).startswith("/uploads/"):
                return
            client_id = str(payload.get("clientId") or "")[:80] or None
            reply = payload.get("replyTo") if isinstance(payload.get("replyTo"), dict) else None
            if reply:
                reply = {
                    "id": str(reply.get("id") or "")[:80],
                    "author": str(reply.get("author") or "")[:24],
                    "text": "" if e2e else str(reply.get("text") or "")[:140],
                    "type": reply.get("type") if reply.get("type") in {"text", "video", "image"} else "text",
                }
            msg = {
                "id": str(uuid.uuid4()),
                "clientId": client_id,
                "groupId": gid,
                "type": mtype,
                "text": text,
                "mediaUrl": media,
                "thumb": payload.get("thumb"),
                "duration": payload.get("duration"),
                "mime": payload.get("mime"),
                "author": user["name"],
                "color": user["color"],
                "createdAt": int(time.time() * 1000),
                "replyTo": reply,
                "status": "sent",
                "e2e": e2e,
                "iv": str(payload.get("iv") or "")[:64] if e2e else None,
                "ct": str(payload.get("ct") or "")[:8000] if e2e else None,
            }
            stored = HUB.add_message(msg) or msg
            HUB.beat(cid)
            broadcast_group(gid, {"op": "message", **stored})
            threading.Thread(target=push_message, args=(stored,), daemon=True).start()

    def ws_send_text(self, text: str):
        if self.session_key:
            try:
                obj = json.loads(text)
                if isinstance(obj, dict) and not obj.get("sess") and obj.get("op") not in SESSION_CLEAR_OPS:
                    text = json.dumps(seal_session(self.session_key, obj, self.session_aad), ensure_ascii=False)
            except Exception:
                pass
        data = text.encode("utf-8")
        header = bytearray([0x81])
        n = len(data)
        if n < 126:
            header.append(n)
        elif n < 65536:
            header.append(126)
            header.extend(struct.pack("!H", n))
        else:
            header.append(127)
            header.extend(struct.pack("!Q", n))
        self.wfile.write(header + data)
        self.wfile.flush()

    def ws_recv_text(self):
        try:
            hdr = self.rfile.read(2)
            if not hdr or len(hdr) < 2:
                return None
            b1, b2 = hdr
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self.rfile.read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.rfile.read(8))[0]
            mask = self.rfile.read(4) if masked else b""
            raw = self.rfile.read(length) if length else b""
            if masked:
                raw = bytes(b ^ mask[i % 4] for i, b in enumerate(raw))
            if opcode == 0x8:
                self._ws_open = False
                return None
            if opcode == 0x9:
                self.ws_send_pong(raw)
                return ""
            if opcode in (0x1, 0x2):
                return raw.decode("utf-8", "ignore")
            return ""
        except Exception:
            self._ws_open = False
            return None

    def ws_send_pong(self, data: bytes):
        header = bytearray([0x8A])
        n = len(data)
        if n < 126:
            header.append(n)
        else:
            header.append(126)
            header.extend(struct.pack("!H", n))
        self.wfile.write(header + data)
        self.wfile.flush()


class ReuseServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 512
    timeout = 30

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass
        super().server_bind()

    def process_request(self, request, client_address):
        try:
            request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        if len(HUB.clients) > int(os.environ.get("WS_MAX_CLIENTS", "800")):
            try:
                request.close()
            except Exception:
                pass
            return
        super().process_request(request, client_address)


def watchdog():
    """Marca ausente quem parou de responder e limpa sockets mortos."""
    while True:
        time.sleep(20)
        now = time.time()
        stale = []
        changed = False
        for cid, client in list(HUB.clients.items()):
            last = client.get("lastBeat") or 0
            if now - last > 90:
                stale.append(cid)
            elif now - last > 45 and client.get("name") and client.get("status") == "available":
                HUB.set_status(cid, "away")
                changed = True
        for cid in stale:
            user = HUB.unregister(cid)
            if user and user.get("name"):
                HUB.mark_offline(user["name"], user.get("color"))
                changed = True
        if changed:
            broadcast({"op": "users", "users": HUB.presence_list()})


def main():
    threading.Thread(target=watchdog, daemon=True).start()
    server = ReuseServer(("0.0.0.0", PORT), ChatHandler)
    print(f"Chat PWA rodando em http://localhost:{PORT}")
    print("Admin: use o código definido em ADMIN_CODE (padrão: admin123)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando…")
        server.shutdown()


if __name__ == "__main__":
    main()
