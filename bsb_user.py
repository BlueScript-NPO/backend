
from fastapi import FastAPI, Depends, HTTPException, status

from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, Result, String, Boolean
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from argon2 import PasswordHasher

from pydantic import BaseModel
from typing import Optional, Tuple

from bsb_database import Base, get_database_session, SessionLocal


class UserBase(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    class Config:
        from_attributes = True

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


class UserTable(Base):
    __tablename__: str = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)


def verify_password(plain_password, hashed_password) -> bool:
    password_hasher = PasswordHasher()
    return password_hasher.verify(plain_password, hashed_password)

def get_password_hash(password) -> str:
    password_hasher = PasswordHasher()
    return password_hasher.hash(password)


def get_user(session: Session, user_id: int) -> UserTable | None:
    return session.query(UserTable).filter(UserTable.id == user_id).first()

def get_user_by_username(session: Session, username: str) -> UserTable | None:
    return session.query(UserTable).filter(UserTable.username == username).first()

def create_user(session: Session, user: UserCreate) -> UserTable:
    hashed_password: str = get_password_hash(user.password)
    db_user = UserTable(username=user.username, email=user.email, full_name=user.full_name, hashed_password=hashed_password)
    if get_user_by_username(session, user.username) is None:
        try:
            session.add(db_user)
            session.commit()
            session.refresh(db_user)
        except IntegrityError:
            session.rollback()
            raise HTTPException(status_code=400, detail="Username already registered")
        except SQLAlchemyError:
            session.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred")
        except Exception as e:
            session.rollback()
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")     
    else:
        raise HTTPException(status_code=400, detail="Username already registered")           
    return db_user


app = FastAPI()


@app.post("/User/", response_model=User)
def create_new_user(user: UserCreate, session: Session = Depends(get_database_session)):
    db_user = create_user(session, user)
    return db_user


# if __name__ == "__main__":
#     user = UserCreate(
#         username="Macroft2",
#         email="macroft2@gmail.com",
#         full_name="Macroft Holmes",
#         password="1234"
#     )
#     create_user(SessionLocal(), user)
