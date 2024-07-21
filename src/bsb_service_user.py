
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy.orm import Session

from bsb_database import get_database_session
from bsb_schema_user import UserBase, User, UserCreate
import bsb_database_user


user_router = APIRouter(
    prefix="/user"
)


@user_router.get("/{user_id}", response_model=User)
def get_user(user_id: int, session: Session = Depends(get_database_session)) -> bsb_database_user.UserTable | None:
    user = bsb_database_user.get_user(session, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user    


@user_router.get("/", response_model=list[User])
def search_user(full_name: str | None = None, username: str | None = None, email: str | None = None, session: Session = Depends(get_database_session)):
    return bsb_database_user.search_users(session, full_name=full_name, username=username, email=email)


@user_router.post("/", response_model=User)
def create_user(user: UserCreate, session: Session = Depends(get_database_session)) -> bsb_database_user.UserTable:
    return bsb_database_user.create_user(session, user)


@user_router.put("/{user_id}", response_model=User)
def update_user_endpoint(user_id: int, user: UserBase, session: Session = Depends(get_database_session)) -> bsb_database_user.UserTable:
    return bsb_database_user.update_user(session, user_id, user)
 