from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime, timezone

class Users(SQLModel, table=True):
    u_id: int = Field(primary_key=True)
    username: str
    email: str
    password: str
    image: Optional[str] = Field(default="assets/defaultuser.png")

class Admin(SQLModel, table=True):
    a_id: int = Field(primary_key=True)
    username: str
    email: str
    password: str
    image: Optional[str] = Field(default="assets/defaultuser.png")

class Product(SQLModel, table=True):
    p_id: int = Field(primary_key=True)
    name: str
    description: str
    price: float
    media: str
    stock: int = Field(default=0)
    category: str

class Order(SQLModel, table=True):
    o_id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.u_id")  # note: "user" not "users"
    status: str = Field(default="Pending")
    order_date_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_amount: float
    location_url: Optional[str] = None
    delivery: str
    esewa_pid: Optional[str] = None

class review(SQLModel, table=True):
    r_id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.u_id")
    product_id: int = Field(foreign_key="product.p_id")
    rating: int
    comment: Optional[str] = None
    review_date_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class OrderItem(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    order_id: int = Field(foreign_key="order.o_id")
    product_id: int = Field(foreign_key="product.p_id")
    quantity: int
    price: float

class CancelledOrder(SQLModel, table=True):
    co_id: Optional[int] = Field(default=None, primary_key=True)
    o_id: int = Field(foreign_key="order.o_id")
    user_id: int = Field(foreign_key="users.u_id")
    cancel_date_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: Optional[str] = None

class CancelledOrderItem(SQLModel, table=True):
    coi_id: Optional[int] = Field(default=None, primary_key=True)
    co_id: int = Field(foreign_key="cancelledorder.co_id")
    product_id: int = Field(foreign_key="product.p_id")
    quantity: int
    price: float

class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    entity: str
    entity_id: int
    action: str
    performed_by: Optional[int] = Field(default=None)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Optional[str] = None
