from sqlmodel import SQLModel, Field
from typing import Optional

class users(SQLModel, table=True):
    u_id: int = Field(primary_key=True)
    username: str
    email: str
    password: str
    image: Optional[str] = Field(default="assets/defaultuser.png")

class product(SQLModel, table=True):
    p_id: int = Field(primary_key=True)
    name: str
    description: str
    price: float
    media: str 
    stock: int = Field(default=0)

class admin(SQLModel, table=True):
    a_id: int = Field(primary_key=True)
    username: str
    email: str
    password: str
    image: Optional[str] = Field(default="assets/defaultuser.png")