from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import os
import uuid

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
SECRET = os.getenv("JWT_SECRET", "dev-secret")   t
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ---------------------------------------------------------------------
# FastAPI app setup
# ---------------------------------------------------------------------
app = FastAPI()
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://your-frontend.vercel.app",  
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------
class LoginIn(BaseModel):
    username: str
    password: str

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Create a signed JWT that expires after the given delta.
    Adds iat (issued at) and jti (unique ID) so each token is unique.
    """
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4())
    })
    return jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)

# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "Demo FastAPI service running"}

@app.get("/items")
def get_items():
    return [{"id": 1, "name": "apple"}, {"id": 2, "name": "banana"}]

@app.post("/login")
def login(payload: LoginIn):
    """
    Dummy login: accepts any username/password and returns a JWT.
    In real apps, verify credentials against a database.
    """
    token = create_access_token({"sub": payload.username})
    return {"access_token": token, "token_type": "bearer"}

def verify_token(auth_header: Optional[str] = Header(None)):
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid auth scheme")

    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.get("/protected")
def protected(payload=Depends(verify_token)):
    """Protected route that requires a valid Bearer token."""
    return {"message": f"Hello {payload.get('sub')}, you accessed a protected route!"}
