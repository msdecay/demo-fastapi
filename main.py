# main.py
from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from pydantic import BaseModel
import os
from typing import Optional, Dict
from datetime import datetime, timedelta
from dotenv import load_dotenv
from passlib.context import CryptContext

load_dotenv()

SECRET = os.getenv("JWT_SECRET", "dev-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simple in-memory user store for demo (username -> {hashed_password, other fields})
# In real systems use a database. You can pre-seed a user below.
users_db: Dict[str, Dict] = {}

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
    encoded_jwt = jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/register")
def register(payload: RegisterIn):
    # Optional helper: create a new user (for demo only)
    if payload.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed = get_password_hash(payload.password)
    users_db[payload.username] = {"hashed_password": hashed}
    return {"msg": "user created", "username": payload.username}

@app.post("/create-demo-user")
def create_demo_user():
    # Convenience endpoint to create a demo user (disable/remove in production)
    demo_user = "student"
    demo_pass = "demo"
    users_db[demo_user] = {"hashed_password": get_password_hash(demo_pass)}
    return {"msg": "demo user created", "username": demo_user, "password": demo_pass}

@app.post("/login")
def login(payload: LoginIn):
    user = users_db.get(payload.username)
    if not user:
        # do not reveal which part failed
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not verify_password(payload.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    # create JWT with subject claim
    token = create_access_token({"sub": payload.username})
    return {"access_token": token, "token_type": "bearer"}
    
def verify_token(authorization: Optional[str] = Header(None, alias="Authorization")):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
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
    
@app.get("/")
def root():
    return {"message": "Demo FastAPI service running"}

@app.get("/items")
def get_items():
    return [{"id": 1, "name": "apple"}, {"id": 2, "name": "banana"}]

