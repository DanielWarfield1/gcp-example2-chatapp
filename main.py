import hashlib
import os
import secrets
from datetime import datetime, UTC

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from google.cloud import firestore

app = FastAPI()
db = firestore.Client(project="chat-app-500821", database="chat-app-db")


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class RoomRequest(BaseModel):
    name: str


class MessageRequest(BaseModel):
    room_id: str
    message: str


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def get_username_from_token(authorization: str) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token = authorization.removeprefix("Bearer ")
    doc = db.collection("sessions").document(token).get()
    if not doc.exists:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return doc.to_dict()["username"]


# --- UI ---

@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.get("/admin", response_class=HTMLResponse)
def admin():
    collections = ["users", "sessions", "rooms", "messages"]
    rows = ""
    for col in collections:
        docs = db.collection(col).stream()
        for doc in docs:
            rows += f"<tr><td>{col}</td><td>{doc.id}</td><td><pre>{doc.to_dict()}</pre></td></tr>"
    return f"""
    <html><head><title>Admin</title>
    <style>
        body {{ font-family: monospace; padding: 2rem; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; vertical-align: top; }}
        th {{ background: #f0f0f0; }}
        pre {{ margin: 0; white-space: pre-wrap; }}
    </style></head>
    <body><h2>Firestore Data</h2>
    <table><tr><th>Collection</th><th>ID</th><th>Data</th></tr>
    {rows}
    </table></body></html>
    """


@app.get("/debug")
def debug():
    emulator_host = os.environ.get("FIRESTORE_EMULATOR_HOST")
    return {
        "firestore_project": db.project,
        "firestore_emulator_host": emulator_host,
        "mode": "emulator" if emulator_host else "production",
    }


# --- Auth ---

@app.post("/register")
def register(req: RegisterRequest):
    user_ref = db.collection("users").document(req.username)
    if user_ref.get().exists:
        raise HTTPException(status_code=400, detail="Username already taken")
    user_ref.set({
        "username": req.username,
        "password_hash": hash_password(req.password),
        "created_at": datetime.now(UTC),
    })
    return {"message": "User created"}


@app.post("/login")
def login(req: LoginRequest):
    doc = db.collection("users").document(req.username).get()
    if not doc.exists or doc.to_dict()["password_hash"] != hash_password(req.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(32)
    db.collection("sessions").document(token).set({
        "username": req.username,
        "created_at": datetime.now(UTC),
    })
    return {"token": token}


# --- Rooms ---

@app.post("/rooms")
def create_room(req: RoomRequest, authorization: str = Header(...)):
    username = get_username_from_token(authorization)
    _, ref = db.collection("rooms").add({
        "name": req.name,
        "created_by": username,
        "created_at": datetime.now(UTC),
    })
    return {"room_id": ref.id, "name": req.name}


@app.get("/rooms")
def list_rooms():
    docs = db.collection("rooms").stream()
    return [{"room_id": doc.id, "name": doc.to_dict()["name"], "created_by": doc.to_dict()["created_by"]} for doc in docs]


@app.delete("/rooms/{room_id}")
def delete_room(room_id: str, authorization: str = Header(...)):
    get_username_from_token(authorization)
    ref = db.collection("rooms").document(room_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Room not found")
    ref.delete()
    return {"message": "Room deleted"}


# --- Messages ---

@app.post("/messages")
def post_message(req: MessageRequest, authorization: str = Header(...)):
    username = get_username_from_token(authorization)
    if not db.collection("rooms").document(req.room_id).get().exists:
        raise HTTPException(status_code=404, detail="Room not found")
    _, ref = db.collection("messages").add({
        "room_id": req.room_id,
        "username": username,
        "message": req.message,
        "timestamp": datetime.now(UTC),
    })
    return {"message_id": ref.id}


@app.get("/messages/{room_id}")
def get_messages(room_id: str):
    docs = (
        db.collection("messages")
        .where("room_id", "==", room_id)
        .order_by("timestamp")
        .stream()
    )
    return [
        {
            "message_id": doc.id,
            "username": doc.to_dict()["username"],
            "message": doc.to_dict()["message"],
            "timestamp": doc.to_dict()["timestamp"].isoformat(),
        }
        for doc in docs
    ]


@app.delete("/messages/{message_id}")
def delete_message(message_id: str, authorization: str = Header(...)):
    get_username_from_token(authorization)
    ref = db.collection("messages").document(message_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Message not found")
    ref.delete()
    return {"message": "Message deleted"}
