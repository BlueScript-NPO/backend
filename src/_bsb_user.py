
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, Result, String, Boolean
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from argon2 import PasswordHasher
from jose import jwt

from pydantic import BaseModel
from typing import Optional, Tuple

from bsb_database import Base, get_database_session, SessionLocal


class UserBase(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    disabled: str | None = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    class Config:
        from_attributes = True

class UserInDB(User):
    hashed_password: str


class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


class UserTable(Base):
    __tablename__: str = "user"
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


SECRET_KEY: bytes = bytes.fromhex("552f7649de273c32eb3e457244c619f73bb60ec6f3c236fb7476508805ea1efa")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="authentication")


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.now() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


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


@app.post("/user/", response_model=User)
def create_new_user(user: UserCreate, session: Session = Depends(get_database_session)):
    db_user = create_user(session, user)
    return db_user


@app.post("/authentication", response_model=schemas.Token)
async def login_for_access_token(db: AsyncSession = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
        
    user = await crud.get_user_by_username(db, form_data.username)
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/user/login")
# def login(user: UserLogin, session: Session = Depends(get_database_session)):
#     db_user = get_user_by_username(session, username=user.username)
#     if not db_user or not verify_password(user.password, db_user.hashed_password):
#         raise HTTPException(status_code=400, detail="Invalid username or password")
#     return {"message": "Login successful"}


@app.get("/user/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user
