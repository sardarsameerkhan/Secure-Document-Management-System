from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.core.database import Base, engine
from app.routes import auth_routes, doc_routes, admin_routes

# Create database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Document Management System (SDMS)",
    description="FAST-NUCES Information Security Semester Project",
    version="1.0.0",
)

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.include_router(auth_routes.router)
app.include_router(doc_routes.router)
app.include_router(admin_routes.router)


@app.get("/", response_class=HTMLResponse)
def serve_ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})