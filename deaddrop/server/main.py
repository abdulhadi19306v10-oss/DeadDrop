"""FastAPI Relay Server Application Entry Point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from deaddrop.server.database import init_db
from deaddrop.server.routes.auth import router as auth_router
from deaddrop.server.routes.drops import router as drops_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes SQLite database and tables upon server startup."""
    await init_db()
    yield


app = FastAPI(
    title="DeadDrop Relay Server",
    description="Zero-knowledge cloud relay server for encrypted file delivery with TOTP access control.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware (allows desktop app and lab clients)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth_router)
app.include_router(drops_router)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "DeadDrop Relay Server", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("deaddrop.server.main:app", host="127.0.0.1", port=8000, reload=True)
