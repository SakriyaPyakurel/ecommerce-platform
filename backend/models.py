from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
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

class Order(SQLModel, table=True):
    o_id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.u_id")
    status: str = Field(default="Pending")
    order_date_time: datetime = Field(default_factory=datetime.utcnow)
    total_amount: float

class OrderItem(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    order_id: int = Field(foreign_key="order.o_id")
    product_id: int = Field(foreign_key="product.p_id")
    quantity: int
    price: float



