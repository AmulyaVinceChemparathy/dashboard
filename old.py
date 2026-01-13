
from common.exceptions.patient_registrations_exceptions import ConsentCreationException, ConsentNotFoundException, ConsentUpdateException, ImageUploadException, PatientNotFoundException, ValidationException
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import os
from sqlalchemy import text
from common.logger.logging import logger
from census_reconciliation.app.routers.census import router as census_router
from common.iris_db_engine import engine  
from fastapi.middleware.cors import CORSMiddleware
from coding_claim.app.routers.coding import router as coding_router
from patient_registration.routers.routes import router as api_router



app = FastAPI(title="Census Reconciliation and Claim Coding API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:3001",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8001",       # Local frontend (dev)
        "http://98.83.240.89:8001",
        "http://98.83.240.89:3000",
        "https://intake.staging.primrose.health",
        "https://intake.staging.iris-health.com",
        "http://34.201.97.37:3000"   # Remote/staging frontend
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(" Application startup: initializing SQLAlchemy connection pool.")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))  
        logger.info("🔌 SQLAlchemy DB connection pool initialized successfully.")
    except Exception as e:
        logger.error(f"❌ Failed to initialize DB connection pool: {e}")
    yield
    logger.info("🧹 Application shutdown complete.")



app.router.lifespan_context = lifespan

#  Jinja template setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "common", "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


#  Include your census router
app.include_router(coding_router)
app.include_router(census_router)
app.include_router(api_router)


@app.exception_handler(PatientNotFoundException)
async def patient_not_found_handler(request: Request, exc: PatientNotFoundException):
    return JSONResponse(status_code=404, content={"error": exc.message})

@app.exception_handler(ConsentNotFoundException)
async def consent_not_found_handler(request: Request, exc: ConsentNotFoundException):
    return JSONResponse(status_code=404, content={"error": exc.message})

@app.exception_handler(ValidationException)
async def validation_handler(request: Request, exc: ValidationException):
    return JSONResponse(status_code=400, content={"error": exc.message})

@app.exception_handler(Exception)
async def global_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": "Internal server error"})

@app.exception_handler(RuntimeError)
async def runtime_error_handler(request: Request, exc: RuntimeError):
    return JSONResponse(status_code=500,content={"error": str(exc)})


@app.exception_handler(ImageUploadException)
async def image_upload_handler(request: Request, exc: ImageUploadException):
    return JSONResponse(status_code=500,content={"error": exc.message})

@app.exception_handler(ConsentCreationException)
async def consent_creation_exception_handler(request, exc: ConsentCreationException):
    return JSONResponse(status_code=500,
        content={
            "error": "ConsentCreationException",
            "detail": exc.message
        },
    )

@app.exception_handler(ConsentUpdateException)
async def consent_update_exception_handler(request: Request, exc: ConsentUpdateException):
    return JSONResponse(status_code=500,content={"detail": exc.message},)
