from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from pydantic import BaseModel
import os
from typing import Optional
from datetime import datetime, timedelta

SECRET = os.getenv("JWT_SECRET", "dev-secret")   # set in Render env vars
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI()

# CORS: allow your frontend origin (set on Vercel) or use "*" for demo (not for production)
origins = [
    "https://your-frontend.vercel.app",   # replace with actual Vercel URL after deploy
    "http://localhost:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginIn(BaseModel):
    username: str
    password: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)
    return encoded_jwt

@app.get("/")
def root():
    return {"message": "Demo FastAPI service running"}

@app.get("/items")
def get_items():
    return [{"id": 1, "name": "apple"}, {"id": 2, "name": "banana"}]

@app.post("/login")
def login(payload: LoginIn):
    # Demo: accept any username/password and return a JWT (use real auth in production)
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
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/protected")
def protected(payload=Depends(verify_token)):
    # payload contains the token claims
    return {"message": f"Hello {payload.get('sub')}, you accessed a protected route"}
