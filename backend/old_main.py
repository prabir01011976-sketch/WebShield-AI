from fastapi import FastAPI

app = FastAPI(
    title="WebShield AI",
    version="1.0.0"
)

@app.get("/")
def home():
    return {
        "message": "Welcome to WebShield AI",
        "status": "Running"
    }