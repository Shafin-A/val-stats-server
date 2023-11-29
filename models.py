from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from sqlmodel import Field, SQLModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_name: str | None = None


class User(SQLModel):
    id: int = Field(default=None, primary_key=True)
    user_name: str = Field(unique=True)
    email: str
    disabled: bool


class UserInDB(User, table=True):
    __tablename__: str = 'users'
    hashed_password: str


class CreateUser(BaseModel):
    user_name: str
    email: str
    password: str


class Comments(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    user_id: int = Field(default=None, foreign_key="users.id")
    timestamp: datetime
    content: str
    depth: int
    parent_id: Optional[int] = Field(default=None, foreign_key="comments.id")
    puuid: str


class CommentsModel(BaseModel):
    id: int
    user_name: str
    timestamp: datetime
    content: str
    depth: int
    replies: list['CommentsModel'] = []
    puuid: str


class CreateComment(BaseModel):
    content: str
    parent_id: Optional[int] = None


class UpdateCommentContent(BaseModel):
    content: str
