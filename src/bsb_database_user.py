
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from fastapi import HTTPException

from typing import List

from bsb_database import Base
from bsb_schema_user import UserBase, UserCreate
from bsb_util_authentication import get_password_hash


class UserTable(Base):
    __tablename__: str = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)


def get_user(session: Session, user_id: int) -> UserTable | None:
    return session.query(UserTable).filter(UserTable.id == user_id).first()


def get_user_by_username(session: Session, username: str) -> UserTable | None:
    return session.query(UserTable).filter(UserTable.username == username).first()


def get_user_by_email(session: Session, email: str) -> UserTable | None:
    return session.query(UserTable).filter(UserTable.email == email).first()


def get_users_by_full_name(session: Session, full_name: str) -> List[UserTable]:
    return session.query(UserTable).filter(UserTable.full_name.like(f"%{full_name}%")).all()


def get_users(session: Session, skip: int = 0, limit: int = 100):
    return session.query(UserTable).offset(skip).limit(limit).all()


def search_users(session: Session, full_name = None, username = None, email = None) -> List[UserTable]:
    query = session.query(UserTable)
    
    if full_name:
        query = query.filter(UserTable.full_name.ilike(f"%{full_name}%"))
    if username:
        query = query.filter(UserTable.username.ilike(f"%{username}%"))
    if email:
        query = query.filter(UserTable.email.ilike(f"%{email}%"))
        
    return query.all()


def create_user(session: Session, user: UserCreate) -> UserTable:
    db_user = UserTable(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.password)
    )
    if get_user_by_username(session, user.username) is None:
        db_user = UserTable(**user.model_dump(), hashed_password=get_password_hash(user.password), disabled=False)
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


def update_user(session: Session, user_id: int, user_update: UserBase) -> UserTable:
    db_user = session.query(UserTable).filter(UserTable.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.username:
        db_user.username = user_update.username
    if user_update.email:
        db_user.email = user_update.email
    if user_update.full_name:
        db_user.full_name = user_update.full_name

    try:
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
    return db_user
