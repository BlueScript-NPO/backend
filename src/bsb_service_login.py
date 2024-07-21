
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from typing import Annotated

from sqlalchemy.orm import Session

from bsb_database import get_database_session
from bsb_database_user import get_user_by_username
from bsb_schema_user import User, UserCreate
from bsb_schema_token import Token
from bsb_util_authentication import verify_password, create_access_token


login_router = APIRouter(
    prefix="/login"
)


def authenticate_user(session, username: str, password: str):
    user = get_user_by_username(session, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


@login_router.post("/")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: Session = Depends(get_database_session)) -> Token:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"},)
    access_token = create_access_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")
