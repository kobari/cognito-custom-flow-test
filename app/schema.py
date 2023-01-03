from pydantic import BaseModel, Field, validator

class Person(BaseModel):
    name: str
    sex: str = Field("man")
    weight: float
    height: float
    age: int

    @validator("sex")
    def validate_sex(cls, value):
        if value not in ["man", "woman"]:
            raise TypeError(f"{value} is an allowed value")
        return value


class User(BaseModel):
    username: str | None = None
    email: str | None = None
    password: str | None = None

class ConfirmationCode(BaseModel):
    username: str

class ResetPassword(BaseModel):
    username: str

class InitiateAuth(BaseModel):
    username: str
    password: str 
