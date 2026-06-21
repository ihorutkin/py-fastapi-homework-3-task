from datetime import datetime, timezone, tzinfo
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
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
)
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


@router.post(
    "/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK
)
async def activate_account(
    activation_data: UserActivationRequestSchema,
    session: AsyncSession = Depends(get_db),
):
    result = await session.execute(
        select(UserModel).where(UserModel.email == activation_data.email)
    )
    db_user = result.scalar_one_or_none()

    token_result = await session.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == activation_data.token
        )
    )

    activation_token = token_result.scalar_one_or_none()

    if (
        db_user is None
        or activation_token is None
        or db_user.id != activation_token.user_id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    expires_at = cast(datetime, activation_token.expires_at).replace(
        tzinfo=timezone.utc
    )
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    db_user.is_active = True
    await session.delete(activation_token)
    await session.commit()

    return MessageResponseSchema(message="User account activated successfully.")
