
from pydantic import BaseModel


class UserBase(BaseModel):
    username: str
    email: str
    full_name: str | None = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    class Config:
        from_attributes = True

class UserInDB(User):
    hashed_password: str
