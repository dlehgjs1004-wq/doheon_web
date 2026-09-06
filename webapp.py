"""Production web service for the Ollama Hub.

The service uses PostgreSQL when ``DATABASE_URL`` is configured and falls back
to SQLite for local development.  Run locally with ``uvicorn webapp:app``.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import unquote
from uuid import uuid4

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, inspect, or_, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = PROJECT_ROOT / "static"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{PROJECT_ROOT / 'platform.sqlite3'}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL.removeprefix("postgres://")
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL.removeprefix("postgresql://")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")).rstrip("/")
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "7"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
STORAGE_ROOT = Path(os.getenv("STORAGE_ROOT", str(PROJECT_ROOT / "storage"))).resolve()
SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_hex(32)
PASSWORD_ROUNDS = 600_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
ALLOWED_EXTENSIONS = {".txt", ".md", ".csv", ".json", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip"}
BLOCKED_EXTENSIONS = {".html", ".htm", ".js", ".mjs", ".py", ".sh", ".bat", ".cmd", ".exe", ".dll", ".php"}

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    password_salt: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class LoginSession(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Friend(Base):
    __tablename__ = "friends"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    friend_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("user_id", "name"),)


class Upload(Base):
    __tablename__ = "uploads"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    original_name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(100), unique=True)
    content_type: Mapped[str] = mapped_column(String(120))
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


def init_database() -> None:
    Base.metadata.create_all(engine)
    # The original MVP used a smaller SQLite schema. Add the new session
    # column and invalidate old sessions rather than risking weak/invalid
    # authentication state during an in-place local upgrade.
    if DATABASE_URL.startswith("sqlite"):
        columns = {column["name"] for column in inspect(engine).get_columns("sessions")}
        with engine.begin() as connection:
            if "csrf_token" not in columns:
                connection.execute(text("ALTER TABLE sessions ADD COLUMN csrf_token VARCHAR(64)"))
            connection.execute(text("DELETE FROM sessions"))
    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DB = Annotated[Session, Depends(get_db)]


def password_digest(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ROUNDS).hex()


def make_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(32)
    return password_digest(password, salt), salt.hex()


def check_password(password: str, digest: str, salt_hex: str) -> bool:
    try:
        actual = password_digest(password, bytes.fromhex(salt_hex))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, digest)


def token_hash(token: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()


def json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def session_user(request: Request, db: Session) -> User | None:
    token = request.cookies.get("session")
    if not token:
        return None
    login = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_hash(token)))
    if not login or login.expires_at <= datetime.utcnow():
        return None
    return db.get(User, login.user_id)


def require_user(request: Request, db: Session) -> User:
    user = session_user(request, db)
    if user is None:
        raise HTTPException(401, "Login required")
    return user


def csrf_check(request: Request, db: Session) -> bool:
    token = request.cookies.get("session")
    csrf = request.headers.get("X-CSRF-Token")
    login = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_hash(token or "")))
    return bool(login and csrf and hmac.compare_digest(csrf, login.csrf_token))


def cookie_options(request: Request) -> dict[str, object]:
    secure = os.getenv("SECURE_COOKIES", "").lower() in {"1", "true", "yes"} or request.url.scheme == "https"
    return {"secure": secure, "httponly": True, "samesite": "lax", "path": "/"}


def set_login_cookies(response: JSONResponse, request: Request, user: User, db: Session) -> None:
    raw = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    db.add(LoginSession(token_hash=token_hash(raw), user_id=user.id, csrf_token=csrf,
                        expires_at=datetime.utcnow() + timedelta(days=SESSION_DAYS)))
    db.commit()
    options = cookie_options(request)
    response.set_cookie("session", raw, max_age=SESSION_DAYS * 86400, **options)
    response.set_cookie("csrf_token", csrf, max_age=SESSION_DAYS * 86400, httponly=False, **{k: v for k, v in options.items() if k != "httponly"})


def project_for_user(db: Session, user_id: int, project_id: int | None = None) -> Project:
    project = db.scalar(select(Project).where(Project.user_id == user_id, *( [Project.id == project_id] if project_id else [] )).order_by(Project.id))
    if project:
        return project
    if project_id:
        raise HTTPException(404, "Project not found")
    project = Project(user_id=user_id, name="기본 프로젝트")
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def storage_path(upload: Upload) -> Path:
    folder = STORAGE_ROOT / str(upload.user_id) / str(upload.project_id)
    folder.mkdir(parents=True, exist_ok=True)
    return folder / upload.stored_name


class Credentials(BaseModel):
    username: str
    password: str


class NotePayload(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(default="", max_length=100_000)


class FriendPayload(BaseModel):
    username: str = Field(min_length=3, max_length=32)


class MessagePayload(BaseModel):
    to: str
    body: str = Field(min_length=1, max_length=5_000)


class ChatPayload(BaseModel):
    message: str = Field(min_length=1, max_length=20_000)
    model: str = Field(default="llama3.2", max_length=100)


class ProjectPayload(BaseModel):
    name: str = Field(min_length=1, max_length=100)


app = FastAPI(title="Ollama Hub", version="2.0.0")
app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")
connections: dict[int, set[WebSocket]] = defaultdict(set)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method in {"POST", "PUT", "DELETE"} and request.url.path not in {"/api/login", "/api/signup"}:
        with SessionLocal() as db:
            if session_user(request, db) and not csrf_check(request, db):
                return json_error("Invalid CSRF token", 403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.on_event("startup")
def startup() -> None:
    init_database()


@app.get("/")
def index():
    return FileResponse(STATIC_ROOT / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "database": "postgresql" if DATABASE_URL.startswith("postgresql") else "sqlite", "ollama": OLLAMA_BASE_URL}


@app.post("/api/signup")
def signup(payload: Credentials, request: Request, db: DB):
    if not USERNAME_RE.fullmatch(payload.username) or not 8 <= len(payload.password) <= 256:
        return json_error("Username must be 3-32 letters, numbers, or underscores and password 8-256 characters")
    if db.scalar(select(User).where(User.username == payload.username)):
        return json_error("Username is already registered", 409)
    digest, salt = make_password(payload.password)
    user = User(username=payload.username, password_hash=digest, password_salt=salt)
    db.add(user)
    db.commit()
    db.refresh(user)
    response = JSONResponse({"user": {"id": user.id, "username": user.username}}, status_code=201)
    set_login_cookies(response, request, user, db)
    return response


@app.post("/api/login")
def login(payload: Credentials, request: Request, db: DB):
    user = db.scalar(select(User).where(User.username == payload.username.strip()))
    if not user or not check_password(payload.password, user.password_hash, user.password_salt):
        return json_error("Invalid username or password", 401)
    response = JSONResponse({"user": {"id": user.id, "username": user.username}})
    set_login_cookies(response, request, user, db)
    return response


@app.post("/api/logout")
def logout(request: Request, db: DB):
    token = request.cookies.get("session")
    if token:
        login = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_hash(token)))
        if login:
            db.delete(login)
            db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("session", path="/")
    response.delete_cookie("csrf_token", path="/")
    return response


@app.get("/api/me")
def me(request: Request, db: DB):
    user = require_user(request, db)
    return {"user": {"id": user.id, "username": user.username}}


@app.get("/api/notes")
def notes(request: Request, db: DB):
    user = require_user(request, db)
    rows = db.scalars(select(Note).where(Note.user_id == user.id).order_by(Note.updated_at.desc(), Note.id.desc())).all()
    return {"notes": [{"id": n.id, "title": n.title, "content": n.content, "created_at": n.created_at, "updated_at": n.updated_at} for n in rows]}


@app.post("/api/notes", status_code=201)
def create_note(payload: NotePayload, request: Request, db: DB):
    user = require_user(request, db)
    note = Note(user_id=user.id, title=payload.title.strip(), content=payload.content)
    if not note.title:
        return json_error("A title is required")
    db.add(note)
    db.commit()
    return {"id": note.id}


@app.put("/api/notes/{note_id}")
def update_note(note_id: int, payload: NotePayload, request: Request, db: DB):
    user = require_user(request, db)
    note = db.scalar(select(Note).where(Note.id == note_id, Note.user_id == user.id))
    if not note:
        return json_error("Note not found", 404)
    note.title, note.content, note.updated_at = payload.title.strip(), payload.content, datetime.utcnow()
    if not note.title:
        return json_error("A title is required")
    db.commit()
    return {"ok": True}


@app.delete("/api/notes/{note_id}")
def delete_note(note_id: int, request: Request, db: DB):
    user = require_user(request, db)
    note = db.scalar(select(Note).where(Note.id == note_id, Note.user_id == user.id))
    if not note:
        return json_error("Note not found", 404)
    db.delete(note)
    db.commit()
    return {"ok": True}


@app.get("/api/friends")
def friends(request: Request, db: DB):
    user = require_user(request, db)
    rows = db.execute(select(User.id, User.username, Friend.created_at).join(Friend, Friend.friend_id == User.id).where(Friend.user_id == user.id).order_by(User.username)).all()
    return {"friends": [{"id": r.id, "username": r.username, "created_at": r.created_at} for r in rows]}


@app.post("/api/friends", status_code=201)
def add_friend(payload: FriendPayload, request: Request, db: DB):
    user = require_user(request, db)
    friend = db.scalar(select(User).where(User.username == payload.username.strip()))
    if not friend:
        return json_error("User not found", 404)
    if friend.id == user.id:
        return json_error("You cannot add yourself")
    db.add_all([Friend(user_id=user.id, friend_id=friend.id), Friend(user_id=friend.id, friend_id=user.id)])
    try:
        db.commit()
    except Exception:
        db.rollback()
    return {"friend": {"id": friend.id, "username": friend.username}}


def get_friend(db: Session, user_id: int, username: str) -> User:
    friend = db.scalar(select(User).where(User.username == username))
    if not friend or not db.scalar(select(Friend).where(Friend.user_id == user_id, Friend.friend_id == friend.id)):
        raise HTTPException(403, "Add this user as a friend first")
    return friend


def message_json(message: Message, sender_name: str) -> dict:
    return {"id": message.id, "body": message.body, "created_at": message.created_at.isoformat() if message.created_at else None, "sender": sender_name}


@app.get("/api/messages")
def get_messages(friend: str, request: Request, db: DB):
    user = require_user(request, db)
    target = get_friend(db, user.id, friend.strip())
    rows = db.scalars(select(Message).where(or_(
        (Message.sender_id == user.id) & (Message.recipient_id == target.id),
        (Message.sender_id == target.id) & (Message.recipient_id == user.id),
    )).order_by(Message.id.desc()).limit(100)).all()
    names = {user.id: user.username, target.id: target.username}
    return {"messages": [message_json(m, names[m.sender_id]) for m in reversed(rows)], "friend": {"id": target.id, "username": target.username}}


async def broadcast(user_id: int, payload: dict) -> None:
    dead = []
    for socket in list(connections.get(user_id, ())):
        try:
            await socket.send_json(payload)
        except Exception:
            dead.append(socket)
    for socket in dead:
        connections[user_id].discard(socket)


def save_message(db: Session, user: User, target: User, body: str) -> Message:
    message = Message(sender_id=user.id, recipient_id=target.id, body=body)
    db.add(message)
    db.commit()
    db.refresh(message)
    return message


@app.post("/api/messages", status_code=201)
async def send_message(payload: MessagePayload, request: Request, db: DB):
    user = require_user(request, db)
    target = get_friend(db, user.id, payload.to.strip())
    message = save_message(db, user, target, payload.body.strip())
    data = message_json(message, user.username)
    await broadcast(user.id, data | {"type": "message"})
    await broadcast(target.id, data | {"type": "message"})
    return {"ok": True, "message": data}


@app.websocket("/ws/chat/{friend_username}")
async def chat_socket(websocket: WebSocket, friend_username: str):
    with SessionLocal() as db:
        token = websocket.cookies.get("session")
        login = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_hash(token or "")))
        user = db.get(User, login.user_id) if login and login.expires_at > datetime.utcnow() else None
        if not user:
            await websocket.close(code=1008)
            return
        try:
            target = get_friend(db, user.id, friend_username)
        except HTTPException:
            await websocket.close(code=1008)
            return
        await websocket.accept()
        connections[user.id].add(websocket)
        try:
            while True:
                payload = await websocket.receive_json()
                body = str(payload.get("body", "")).strip()
                if not body or len(body) > 5_000:
                    continue
                message = save_message(db, user, target, body)
                data = message_json(message, user.username) | {"type": "message"}
                # Echo directly to the sending socket; this also works with
                # ASGI test clients whose send queue is not shared by a
                # broadcast task.
                await websocket.send_json(data)
                await broadcast(target.id, data)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            connections[user.id].discard(websocket)


@app.post("/api/chat")
def ollama_chat(payload: ChatPayload, request: Request, db: DB):
    require_user(request, db)
    body = json.dumps({"model": payload.model, "messages": [
        {"role": "system", "content": "당신은 자연스럽고 친절한 한국어 AI 도우미입니다."},
        {"role": "user", "content": payload.message},
    ], "stream": False}).encode()
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/chat", data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=float(os.getenv("OLLAMA_TIMEOUT", "90"))) as response:
            result = json.loads(response.read().decode())
        answer = result.get("message", {}).get("content", "")
        if not answer:
            raise ValueError("Ollama returned no message")
        return {"reply": answer, "model": payload.model}
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return json_error(f"Ollama is unavailable: {exc}", 502)


@app.get("/api/projects")
def projects(request: Request, db: DB):
    user = require_user(request, db)
    project = project_for_user(db, user.id)
    rows = db.scalars(select(Project).where(Project.user_id == user.id).order_by(Project.id)).all()
    return {"projects": [{"id": p.id, "name": p.name} for p in rows], "current": project.id}


@app.post("/api/projects", status_code=201)
def create_project(payload: ProjectPayload, request: Request, db: DB):
    user = require_user(request, db)
    project = Project(user_id=user.id, name=payload.name.strip())
    if not project.name:
        return json_error("Project name is required")
    db.add(project)
    try:
        db.commit()
    except Exception:
        db.rollback()
        return json_error("Project name is already in use", 409)
    return {"id": project.id, "name": project.name}


def project_id_from(request: Request) -> int | None:
    raw = request.query_params.get("project_id")
    try:
        return int(raw) if raw else None
    except ValueError:
        raise HTTPException(400, "Invalid project id")


@app.get("/api/files")
def files(request: Request, db: DB):
    user = require_user(request, db)
    if request.query_params.get("path", ".") not in {".", ""}:
        return json_error("Only the project root is available", 400)
    project = project_for_user(db, user.id, project_id_from(request))
    rows = db.scalars(select(Upload).where(Upload.user_id == user.id, Upload.project_id == project.id).order_by(Upload.created_at.desc())).all()
    return {"path": ".", "entries": [{"name": u.original_name, "type": "file", "size": u.size, "path": f"upload/{u.id}", "content_type": u.content_type} for u in rows], "project_id": project.id}


@app.get("/api/file")
def file_preview(request: Request, db: DB):
    user = require_user(request, db)
    path = request.query_params.get("path", "")
    match = re.fullmatch(r"upload/(\d+)", path)
    if not match:
        return json_error("File is not available", 400)
    upload = db.scalar(select(Upload).where(Upload.id == int(match.group(1)), Upload.user_id == user.id))
    if not upload:
        return json_error("File not found", 404)
    if upload.content_type.startswith("text/") or Path(upload.original_name).suffix.lower() in {".md", ".json", ".csv"}:
        file_path = storage_path(upload)
        if upload.size > 512 * 1024:
            return json_error("File is larger than the 512 KB preview limit")
        return {"path": path, "content": file_path.read_text(encoding="utf-8", errors="replace")}
    return json_error("Only text files can be previewed", 415)


@app.post("/api/uploads", status_code=201)
async def upload_file(request: Request, db: DB, file: UploadFile = File(...), project_id: int | None = Form(None)):
    user = require_user(request, db)
    project = project_for_user(db, user.id, project_id)
    original = Path(file.filename or "").name
    suffix = Path(original).suffix.lower()
    if not original or suffix in BLOCKED_EXTENSIONS or suffix not in ALLOWED_EXTENSIONS:
        return json_error("Unsupported file type", 415)
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        return json_error(f"File is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB", 413)
    content_type = (file.content_type or mimetypes.guess_type(original)[0] or "application/octet-stream")[:120]
    stored = f"{uuid4().hex}{suffix}"
    upload = Upload(user_id=user.id, project_id=project.id, original_name=original[:255], stored_name=stored, content_type=content_type, size=len(data))
    db.add(upload)
    db.commit()
    try:
        storage_path(upload).write_bytes(data)
    except OSError:
        db.delete(upload)
        db.commit()
        return json_error("Unable to store upload", 507)
    return {"id": upload.id, "name": upload.original_name, "size": upload.size, "project_id": project.id}


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException):
    return json_error(str(exc.detail), exc.status_code)


if __name__ == "__main__":
    import uvicorn
    init_database()
    uvicorn.run("webapp:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
