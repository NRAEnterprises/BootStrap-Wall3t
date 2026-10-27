#!/usr/bin/env python3
"""A trivial paid endpoint. Aperture proxies to this."""
from fastapi import FastAPI

app = FastAPI()

@app.get("/v1/hello")
def hello():
    return {"message": "paid hello", "timestamp": __import__("time").time()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
