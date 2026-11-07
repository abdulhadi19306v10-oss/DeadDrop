"""Convenience script to launch DeadDrop Relay Server."""

import sys
import uvicorn
from deaddrop.server.main import app

if __name__ == "__main__":
    port = 8000
    host = "127.0.0.1"
    print(f"[*] Starting DeadDrop Relay Server on http://{host}:{port} ...")
    uvicorn.run("deaddrop.server.main:app", host=host, port=port, reload=True)
