# app.py
import os, secrets, hashlib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import jwt

# --- ENV CONFIG ---
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
DATABASE_URL = os.getenv("DATABASE_URL")

if not ADMIN_EMAIL or not DATABASE_URL:
    raise Exception("ADMIN_EMAIL and DATABASE_URL must be set")

ROOM_ID = os.getenv("ROOM_ID") or hashlib.sha256(ADMIN_EMAIL.encode()).hexdigest()[:16]
JWT_SECRET = os.getenv("JWT_SECRET") or secrets.token_hex(32)
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN") or os.getenv("RENDER_EXTERNAL_URL") or "http://localhost:3000"

print(f"Configured with ROOM_ID={ROOM_ID}, FRONTEND_ORIGIN={FRONTEND_ORIGIN}")

# --- DATABASE ---
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    role = Column(String, index=True)   # "X" or "Y"
    body = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- APP SETUP ---
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections = {}  # {role: WebSocket}

# --- AUTH HELPERS ---
def create_token(role: str, expires=30):
    payload = {"role": role, "exp": datetime.utcnow() + timedelta(minutes=expires)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token: str):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded["role"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- ROUTES ---
@app.get("/invite")
def invite(email: str):
    """X generates a one-time invite token for Y"""
    if email != ADMIN_EMAIL:
        raise HTTPException(403, "Only admin can create invite")
    return {"invite_token": create_token("Y", expires=30)}

@app.get("/login-x")
def login_x(email: str):
    """Login for X (admin)"""
    if email != ADMIN_EMAIL:
        raise HTTPException(403, "Unauthorized email")
    return {"token": create_token("X", expires=60)}

@app.post("/clear")
def clear_chat(token: str):
    role = verify_token(token)
    db = SessionLocal()
    db.query(Message).delete()
    db.commit()
    db.close()
    # notify clients
    for ws in connections.values():
        try: 
            import asyncio; asyncio.create_task(ws.send_json({"event": "cleared"}))
        except: pass
    return {"status": "cleared"}

# --- WEBSOCKET CHAT ---
@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    role = verify_token(token)
    await websocket.accept()
    connections[role] = websocket
    db = SessionLocal()

    # Send old messages
    for m in db.query(Message).order_by(Message.created_at).all():
        await websocket.send_json({"role": m.role, "body": m.body, "time": m.created_at.isoformat()})

    try:
        while True:
            data = await websocket.receive_text()
            msg = Message(role=role, body=data)
            db.add(msg)
            db.commit()
            for ws in connections.values():
                await ws.send_json({"role": role, "body": data, "time": msg.created_at.isoformat()})
    except WebSocketDisconnect:
        del connections[role]
    finally:
        db.close()
