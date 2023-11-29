import re
from datetime import datetime, timedelta
from typing import Annotated
import bleach

from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from database import get_session

from models import Comments, CommentsModel, CreateComment, CreateUser, Token, UpdateCommentContent, User, UserInDB
from security import ACCESS_TOKEN_EXPIRE_MINUTES, authenticate_user, create_access_token, get_current_active_user, get_password_hash, validate_password

import pytz

router = APIRouter()


@router.post("/auth/login", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_session),
):
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.user_name}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/auth/signup", response_model=Token)
async def sign_up_new_user(
    user: Annotated[
        CreateUser,
        Body(
            examples=[
                {
                    "user_name": "johndoe",
                    "email": "john@doe.com",
                    "password": "$ecreTpassw0rd"
                }
            ],
        )
    ],
    db: Session = Depends(get_session),
):
    if len(user.user_name) > 20:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Username cannot be more than 20 characters")

    if not re.match(r"(^[a-zA-Z0-9'_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", user.email, re.IGNORECASE):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email is not valid")

    found_user_name_or_email = db.exec(select(UserInDB).where(
        UserInDB.user_name == user.user_name or UserInDB.email == user.email)).first()

    if found_user_name_or_email is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Username or email is already taken")

    validate_password(user.password)

    hashed_password = get_password_hash(user.password)

    new_user = UserInDB(user_name=user.user_name, email=user.email,
                        disabled=False, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.user_name}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me", response_model=User)
async def get_current_user(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


def get_replies(db: Session, comment_id: int):
    replies = db.exec(select(Comments).where(
        Comments.parent_id == comment_id)).all()
    reply_models = []

    for reply in replies:
        reply_user = db.exec(select(UserInDB).where(
            UserInDB.id == reply.user_id)).first()

        if reply_user is None:
            raise HTTPException(
                status_code=404, detail="Could not find user for comment " + reply.content)

        reply_model = CommentsModel(
            id=reply.id,
            user_name=reply_user.user_name,
            timestamp=reply.timestamp,
            content=reply.content,
            depth=reply.depth,
            replies=get_replies(db, reply.id),
            puuid=reply.puuid
        )
        reply_models.append(reply_model)

    return reply_models


@router.get("/comments", response_model=list[CommentsModel])
async def get_all_comments(session: Session = Depends(get_session)):
    comments = session.exec(select(Comments).where(
        Comments.parent_id == None)).all()  # get only top level comments
    comments_models = []

    for comment in comments:
        comment_user = session.exec(select(UserInDB).where(
            UserInDB.id == comment.user_id)).first()

        if comment_user is None:
            raise HTTPException(
                status_code=404, detail="Could not find user for comment " + comment.content)

        comment_model = CommentsModel(
            id=comment.id,
            user_name=comment_user.user_name,
            timestamp=comment.timestamp,
            content=comment.content,
            depth=comment.depth,
            replies=get_replies(session, comment.id),
            puuid=comment.puuid

        )
        comments_models.append(comment_model)

    return comments_models


@router.get("/comments/puuid/{puuid}", response_model=list[CommentsModel])
async def get_all_puuid_comments(puuid: str, session: Session = Depends(get_session)):
    # get only top level comments
    comments = session.exec(
        select(Comments).where(
            (Comments.puuid == puuid) & (Comments.parent_id == None)
        ).order_by(Comments.timestamp.desc())  # type: ignore
    ).all()
    comments_models = []

    for comment in comments:
        comment_user = session.exec(select(UserInDB).where(
            UserInDB.id == comment.user_id)).first()
        if comment_user is None:
            raise HTTPException(
                status_code=404, detail="Could not find user for comment " + comment.content)

        comment_model = CommentsModel(
            id=comment.id,
            user_name=comment_user.user_name,
            timestamp=comment.timestamp,
            content=comment.content,
            depth=comment.depth,
            replies=get_replies(session, comment.id),
            puuid=comment.puuid

        )
        comments_models.append(comment_model)

    return comments_models


@router.get("/comments/{comment_id}", response_model=CommentsModel)
async def get_comment_by_id(comment_id: int, session: Session = Depends(get_session)):
    comment = session.exec(select(Comments).where(
        Comments.id == comment_id)).first()

    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    comment_user = session.exec(select(UserInDB).where(
        UserInDB.id == comment.user_id)).first()
    if comment_user is None:
        raise HTTPException(
            status_code=404, detail="Could not find user for comment " + comment.content)

    comment_model = CommentsModel(
        id=comment.id,
        user_name=comment_user.user_name,
        timestamp=comment.timestamp,
        content=comment.content,
        depth=comment.depth,
        replies=get_replies(session, comment.id),
        puuid=comment.puuid

    )

    return comment_model


@router.post("/comments/puuid/{puuid}", response_model=CommentsModel)
async def create_comment(current_user: Annotated[User, Depends(get_current_active_user)], puuid: str, comment: CreateComment, session: Session = Depends(get_session)):

    allowed_tags = ['em', 's', 'code', 'strong', 'p']
    sanitized_comment_content = bleach.clean(
        comment.content, tags=allowed_tags)

    comment_depth = 1

    if comment.parent_id is not None:
        parent_comment = session.exec(select(Comments).where(
            Comments.id == comment.parent_id)).first()
        if parent_comment is None:
            raise HTTPException(
                status_code=500, detail="Failed to retrieve parent comment")

        comment_depth = parent_comment.depth + 1

    new_comment = Comments(
        user_id=current_user.id,
        timestamp=datetime.now(pytz.timezone('America/Toronto')),
        content=sanitized_comment_content,
        depth=comment_depth,
        parent_id=comment.parent_id,
        puuid=puuid
    )

    session.add(new_comment)
    session.commit()

    created_comment = session.exec(select(Comments).where(
        Comments.id == new_comment.id)).first()
    if created_comment is None:
        raise HTTPException(
            status_code=500, detail="Failed to retrieve created comment")

    comment_user = session.exec(select(UserInDB).where(
        UserInDB.id == created_comment.user_id)).first()
    if comment_user is None:
        raise HTTPException(
            status_code=404, detail="Could not find user for comment " + created_comment.content)

    comment_model = CommentsModel(
        id=created_comment.id,
        user_name=comment_user.user_name,
        timestamp=created_comment.timestamp,
        content=created_comment.content,
        depth=created_comment.depth,
        replies=get_replies(session, created_comment.id),
        puuid=puuid
    )

    return comment_model


@router.delete("/comments/{comment_id}", response_model=CommentsModel)
async def delete_comment(current_user: Annotated[User, Depends(get_current_active_user)], comment_id: int, session: Session = Depends(get_session)):
    comment = session.exec(select(Comments).where(
        Comments.id == comment_id)).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if (current_user.id != comment.user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cannot delete another users comment")

    session.delete(comment)
    session.commit()

    comment_user = session.exec(select(UserInDB).where(
        UserInDB.id == comment.user_id)).first()
    if comment_user is None:
        raise HTTPException(
            status_code=404, detail="Could not find user for comment " + comment.content)

    comment_model = CommentsModel(
        id=comment.id,
        user_name=comment_user.user_name,
        timestamp=comment.timestamp,
        content=comment.content,
        depth=comment.depth,
        replies=get_replies(session, comment.id),
        puuid=comment.puuid

    )

    return comment_model


@router.put("/comments/{comment_id}", response_model=CommentsModel)
async def update_comment_content(
    current_user: Annotated[User, Depends(get_current_active_user)],
    comment_id: int, content_update: UpdateCommentContent,
    session: Session = Depends(get_session)
):

    comment = session.exec(select(Comments).where(
        Comments.id == comment_id)).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if (current_user.id != comment.user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cannot update another users comment")

    allowed_tags = ['em', 's', 'code', 'strong', 'p']
    sanitized_comment_content = bleach.clean(
        content_update.content, tags=allowed_tags)

    comment.content = sanitized_comment_content
    session.commit()

    updated_comment = session.exec(
        select(Comments).where(Comments.id == comment_id)).first()
    if updated_comment is None:
        raise HTTPException(
            status_code=500, detail="Failed to retrieve updated comment")

    comment_user = session.exec(select(UserInDB).where(
        UserInDB.id == updated_comment.user_id)).first()
    if comment_user is None:
        raise HTTPException(
            status_code=404, detail="Could not find user for comment " + updated_comment.content)

    comment_model = CommentsModel(
        id=comment.id,
        user_name=comment_user.user_name,
        timestamp=comment.timestamp,
        content=comment.content,
        depth=comment.depth,
        replies=get_replies(session, comment.id),
        puuid=comment.puuid
    )

    return comment_model
