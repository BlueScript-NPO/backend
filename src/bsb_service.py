
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from bsb_service_user import user_router
from bsb_service_login import login_router


service_app = FastAPI(
    root_path="/api/v0",
    title="BlueScript API",
    description="description",
    summary="summary",
    version="0.0.1",
    contact={
        "name": "SuhJae",
        "url": "https://github.com/BlueScript-NPO",
        "email": "j@suhjae.dev",
    },
    license_info={
        "name": "The MIT License",
        "identifier": "MIT",
    },    
)

service_app.include_router(user_router)
service_app.include_router(login_router)
