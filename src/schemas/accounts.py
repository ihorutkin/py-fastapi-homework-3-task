from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators, UserGroupEnum

# Write your code here


class UserRegistrationRequestSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    pass


class MessageResponseSchema(BaseModel):
    pass


class PasswordResetRequestSchema(BaseModel):
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    pass


class UserLoginResponseSchema(BaseModel):
    pass


class UserLoginRequestSchema(BaseModel):
    pass


class TokenRefreshRequestSchema(BaseModel):
    pass


class TokenRefreshResponseSchema(BaseModel):
    pass
