import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.db import init_db
from app.api import auth_routes, scan_routes, blockchain_routes

app = FastAPI(
    title="SecureMailScope API",
    description="Passive email-domain security assessment platform (hackathon MVP).",
    version="0.1.0",
)

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


app.include_router(auth_routes.router)
app.include_router(scan_routes.router)
app.include_router(blockchain_routes.router)


@app.get("/")
def root():
    return {"service": "SecureMailScope API", "docs": "/docs"}
