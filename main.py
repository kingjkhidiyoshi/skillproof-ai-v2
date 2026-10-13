import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("SKILLPROOF_DB", str(APP_DIR / "skillproof.db")))
SECRET_KEY = os.getenv("SKILLPROOF_SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    # Convenient for local demo only. Set a long random secret in deployment.
    SECRET_KEY = "LOCAL-DEMO-ONLY-change-this-secret-key-32chars"
ALGORITHM = "HS256"
TOKEN_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="SkillProof AI V2 API", version="2.0.0",
              description="HackHive RPL prototype API; evaluator is mock feedback.")
# For production, restrict this list to your actual hosted frontend origin.
allowed_origins = [x.strip() for x in os.getenv("SKILLPROOF_CORS_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins,
                   allow_credentials=False, allow_methods=["GET", "POST"],
                   allow_headers=["Authorization", "Content-Type"])

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
          created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS assessments(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
          skill TEXT NOT NULL, experience TEXT NOT NULL, evidence TEXT NOT NULL,
          score INTEGER NOT NULL, feedback TEXT NOT NULL, next_step TEXT NOT NULL,
          created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id))""")
init_db()

class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class AssessmentIn(BaseModel):
    skill: str = Field(min_length=1, max_length=80)
    experience: str = Field(min_length=20, max_length=4000)
    evidence: str = Field(default="", max_length=2000)

def make_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user_id), "iat": now,
                       "exp": now + timedelta(minutes=TOKEN_MINUTES)},
                      SECRET_KEY, algorithm=ALGORITHM)

def user_public(row):
    return {"id": row["id"], "name": row["name"], "email": row["email"]}

def current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload.get("sub", ""))
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired session",
                            headers={"WWW-Authenticate": "Bearer"})
    with db() as con:
        row = con.execute("SELECT id,name,email FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Account not found")
    return user_public(row)

@app.get("/")
def root():
    return {"app": "SkillProof AI V2", "team": "HackHive", "status": "running",
            "note": "Prototype only; evaluator is mock feedback."}

@app.post("/auth/register")
def register(body: RegisterIn):
    email = body.email.lower().strip()
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    try:
        hashed = pwd_context.hash(body.password)
        with db() as con:
            cur = con.execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
                              (body.name.strip(), email, hashed, datetime.now(timezone.utc).isoformat()))
            uid = cur.lastrowid
            row = con.execute("SELECT id,name,email FROM users WHERE id=?", (uid,)).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    return {"access_token": make_token(uid), "token_type": "bearer", "user": user_public(row)}

@app.post("/auth/login")
def login(body: LoginIn):
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (body.email.lower().strip(),)).fetchone()
    if not row or not pwd_context.verify(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    return {"access_token": make_token(row["id"]), "token_type": "bearer", "user": user_public(row)}

@app.get("/auth/me")
def me(user=Depends(current_user)):
    return user

def mock_evaluate(body: AssessmentIn):
    # Simple transparent demo rubric; not a real AI model or credential decision.
    text = (body.experience + " " + body.evidence).strip()
    score = 35
    if len(body.experience) >= 120: score += 15
    if len(body.experience) >= 400: score += 10
    if body.evidence.strip(): score += 15
    if re.search(r"\b(project|built|created|measured|tested|portfolio|certificate|demonstrated)\b", text, re.I):
        score += 15
    score = min(score, 90)
    if score >= 75:
        feedback = "Your description includes useful practical detail. Add verifiable work samples and explain your individual contribution."
        next_step = "Prepare a short practical demonstration and attach a portfolio link or redacted evidence."
    elif score >= 55:
        feedback = "You have a starting point. Make the description more specific with tools used, tasks completed, and outcomes."
        next_step = "Add one project example, your role, and what you learned."
    else:
        feedback = "The submission needs more detail to make your skills understandable."
        next_step = "Describe a real task step-by-step and include non-sensitive supporting evidence."
    return score, feedback, next_step

@app.post("/assessments")
def create_assessment(body: AssessmentIn, user=Depends(current_user)):
    score, feedback, next_step = mock_evaluate(body)
    with db() as con:
        cur = con.execute("""INSERT INTO assessments(user_id,skill,experience,evidence,score,feedback,next_step,created_at)
          VALUES(?,?,?,?,?,?,?,?)""",
          (user["id"], body.skill.strip(), body.experience.strip(), body.evidence.strip(),
           score, feedback, next_step, datetime.now(timezone.utc).isoformat()))
        item_id = cur.lastrowid
    return {"id": item_id, "skill": body.skill, "score": score,
            "feedback": feedback, "next_step": next_step}

@app.get("/assessments")
def list_assessments(user=Depends(current_user)):
    with db() as con:
        rows = con.execute("""SELECT id,skill,score,feedback,next_step,created_at
          FROM assessments WHERE user_id=? ORDER BY id DESC LIMIT 50""", (user["id"],)).fetchall()
    return {"items": [dict(r) for r in rows]}
