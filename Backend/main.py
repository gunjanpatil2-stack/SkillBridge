import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from supabase import create_client, Client
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv() # Load env vars securely (Principle #2)

app = FastAPI(title="Skillbridge API")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Supabase setup (Principles #1, #3)
supabase_url = os.getenv("SUPABASE_URL", "")
supabase_key = os.getenv("SUPABASE_KEY", "")
supabase: Client | None = create_client(supabase_url, supabase_key) if supabase_url and supabase_key else None


# Security Headers & CORS (Principle #19)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Error Handler (Principles #11, #12)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    is_prod = os.getenv("ENVIRONMENT") == "production"
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error" if is_prod else str(exc)}
    )

# Models for Validation (Principle #13 - Validate inputs server-side)
class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/api/auth/login")
@limiter.limit("5/minute") # Rate Limiting (Principle #17)
async def login(request: Request, payload: LoginRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    # Ponytail: One line validation via Pydantic payload, Supabase handles the rest
    res = supabase.auth.sign_in_with_password({"email": payload.email, "password": payload.password})
    if hasattr(res, 'error') and res.error:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Login successful", "user": res.user}
