from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from pydantic import BaseModel
from passlib.context import CryptContext
import os
from typing import Optional, Dict
from datetime import datetime, timedelta

# --- Configuration ---
SECRET = os.getenv("JWT_SECRET", "dev-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://your-frontend.vercel.app"  # replace with your deployed frontend URL later
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- User management setup ---
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
users_db: Dict[str, Dict] = {}  # in-memory user store

class RegisterIn(BaseModel):
    username: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# --- Routes ---
@app.get("/")
def root():
    return {"message": "Demo FastAPI service running"}

@app.get("/items")
def get_items():
    return [{"id": 1, "name": "apple"}, {"id": 2, "name": "banana"}]

@app.post("/register")
def register(payload: RegisterIn):
    if payload.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    users_db[payload.username] = {"hashed_password": get_password_hash(payload.password)}
    return {"msg": f"User '{payload.username}' registered successfully"}

@app.post("/login")
def login(payload: LoginIn):
    user = users_db.get(payload.username)
    if not user or not verify_password(payload.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token({"sub": payload.username})
    return {"access_token": token, "token_type": "bearer"}

def verify_token(authorization: Optional[str] = Header(None, alias="Authorization")):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid auth scheme")
    try:
        return jwt.decode(token, SECRET, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/protected")
def protected(payload=Depends(verify_token)):
    return {"message": f"Hello {payload.get('sub')}, you accessed a protected route"}
