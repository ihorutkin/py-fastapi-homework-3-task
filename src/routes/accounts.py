from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

# Write your code here


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_new_user(
    user_data: UserRegistrationRequestSchema, session: AsyncSession = Depends(get_db)
):
    db_user = await session.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    existing_user = db_user.scalar_one_or_none()

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    group_user_result = await session.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group_user = group_user_result.scalar_one_or_none()

    if group_user is None:
        group_user = UserGroupModel(name=UserGroupEnum.USER)
        session.add(group_user)

        await session.flush()

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=group_user.id,
        )

        session.add(new_user)
        await session.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        session.add(activation_token)

        await session.commit()
        await session.refresh(new_user)
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return new_user
