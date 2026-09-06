# Ollama Hub

A FastAPI web service for notes, AI chat, friends, real-time WebSocket
messaging, projects, and scoped file uploads.

## Local development

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn webapp:app --reload --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. SQLite is used when `DATABASE_URL` is not
provided. Run Ollama locally, or set `OLLAMA_BASE_URL` to an Ollama-compatible
HTTP endpoint. The browser never connects to Ollama directly.

## Deploy on Render

1. Push this repository to GitHub and create a **Blueprint** using
   `render.yaml`.
2. Set the secret `OLLAMA_BASE_URL` in the Render dashboard to a reachable,
   private Ollama-compatible service URL. Do not expose Ollama without
   authentication/network controls.
3. Render provisions PostgreSQL and generates `SESSION_SECRET`. Keep both
   values private. The blueprint mounts a persistent disk at `/var/data` for
   uploads; use a paid web instance (as configured) or change uploads to
   object storage before using a free instance.
4. Set `SECURE_COOKIES=true` only when serving through HTTPS (Render's proxy
   normally makes this automatic based on the request scheme).

Production uses `DATABASE_URL`, `OLLAMA_BASE_URL`, and a generated
`SESSION_SECRET`. Passwords use salted PBKDF2-HMAC-SHA256, sessions are
opaque hashed tokens with CSRF protection and secure cookie flags, uploads are
extension/size validated and stored below a user/project directory, and chat
messages are delivered over authenticated WebSockets.

## Validation

```powershell
python -m py_compile webapp.py
```
