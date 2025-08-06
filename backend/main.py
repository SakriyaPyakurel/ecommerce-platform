import os
import random
import re
import bcrypt
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException, status, Depends, UploadFile, File, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from itsdangerous import URLSafeSerializer, BadSignature
from sqlmodel import create_engine, Session, select
from input_params import credentials
from models import users, admin , product , Order, OrderItem
from pathlib import Path
from typing import List
from datetime import datetime

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
serializer = URLSafeSerializer(SECRET_KEY)

app = FastAPI()
SAVE_DIR = Path("frontend/product")
# SAVE_DIR.mkdir(parents=True, exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_engine("mysql+pymysql://root:@127.0.0.1:3306/ecommerce_platform")

def is_password_valid(password: str) -> bool:
    return (
        len(password) >= 8 and
        bool(re.search(r"[0-9]", password)) and
        bool(re.search(r"[A-Z]", password)) and
        bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    )

def is_email_valid(email: str) -> bool:
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def get_current_user(request: Request):
    cookie = request.cookies.get("cookie")
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        data = serializer.loads(cookie)
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    user_id = data.get("u_id")
    admin_id = data.get("a_id")

    with Session(engine) as session:
        if user_id:
            user = session.exec(select(users).where(users.u_id == user_id)).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            return {"user": user, "type": "user"}
        elif admin_id:
            admin_user = session.exec(select(admin).where(admin.a_id == admin_id)).first()
            if not admin_user:
                raise HTTPException(status_code=404, detail="Admin not found")
            return {"user": admin_user, "type": "admin"}
        else:
            raise HTTPException(status_code=401, detail="Invalid session")

@app.post("/signup")
def signup(user: credentials):
    if not is_email_valid(user.email):
        return {"status": "error", "message": "Invalid email format"}
    if not is_password_valid(user.password):
        return {"status": "error", "message": "Weak password"}

    with Session(engine) as session:
        if session.exec(select(users).where(users.email == user.email)).first():
            return {"status": "error", "message": "Email already exists"}

        new_uid = random.randint(100, 100000)
        while session.exec(select(users).where(users.u_id == new_uid)).first():
            new_uid = random.randint(100, 100000)

        new_user = users(
            u_id=new_uid,
            username=user.username,
            email=user.email,
            password=hash_password(user.password),
            image="assets/defaultuser.png"
        )
        session.add(new_user)
        session.commit()
        session.refresh(new_user)

        return {"status": "success", "message": "User registered successfully"}

@app.post("/login")
def login(user: credentials):
    with Session(engine) as session:
        db_user = session.exec(select(users).where(users.email == user.email)).first()
        user_type = "user"
        if not db_user:
            db_user = session.exec(select(admin).where(admin.email == user.email)).first()
            user_type = "admin"

        if not db_user or db_user.username != user.username:
            return JSONResponse(content={"status": "error", "message": "Invalid email or username"})

        if not bcrypt.checkpw(user.password.encode(), db_user.password.encode()):
            return JSONResponse(content={"status": "error", "message": "Incorrect password"})

        session_data = serializer.dumps({"u_id": db_user.u_id} if user_type == "user" else {"a_id": db_user.a_id})
        response = JSONResponse(content={"status": "success", "message": "Login successful"})
        response.set_cookie(
            key="cookie",
            value=session_data,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=3600
        )
        return response
    
@app.post("/add_admin")
def add_admin(user: credentials):
    if not is_email_valid(user.email):
        return {"status": "error", "message": "Invalid email format"}
    if not is_password_valid(user.password):
        return {"status": "error", "message": "Weak password"}

    with Session(engine) as session:
        if session.exec(select(admin).where(admin.email == user.email)).first():
            return {"status": "error", "message": "Email already exists"}

        new_aid = random.randint(100, 10000)
        while session.exec(select(admin).where(admin.a_id == new_aid)).first():
            new_aid = random.randint(100, 10000)

        new_admin = admin(
            a_id=new_aid,
            username=user.username,
            email=user.email,
            password=hash_password(user.password),
            image="assets/default_admin.png"
        )
        session.add(new_admin)
        session.commit()
        session.refresh(new_admin)

        return {"status": "success", "message": "Admin registered successfully"}


@app.post("/profile")
def get_profile(current_info=Depends(get_current_user)):
    user_obj = current_info["user"]
    user_type = current_info["type"]

    data = {
        "status": "success",
        "user": {
            "type": user_type,
            "u_id": user_obj.u_id if user_type == "user" else user_obj.a_id,
            "username": user_obj.username,
            "email": user_obj.email,
            "image": user_obj.image
        }
    }
    response = JSONResponse(content=data)
    response.headers["Cache-Control"] = "no-store"
    return response

@app.post("/logout")
def logout():
    response = JSONResponse(content={"status": "success", "message": "Logged out"})
    response.delete_cookie("cookie")
    return response

@app.post("/update_profile")
async def update_profile(
    password: str = Form(...),
    username: str = Form(None),
    email: str = Form(None),
    image: UploadFile = File(None),
    current_info=Depends(get_current_user)
):
    try:
        current_user = current_info["user"]
        user_type = current_info["type"]

        if not bcrypt.checkpw(password.encode(), current_user.password.encode()):
            return JSONResponse(status_code=400, content={"status": "error", "message": "Incorrect password"})

        with Session(engine) as session:
            db_model = users if user_type == "user" else admin
            user_id = current_user.u_id if user_type == "user" else current_user.a_id

            db_obj = session.get(db_model, user_id)

            if email:
                if not is_email_valid(email):
                    return JSONResponse(status_code=400, content={"status": "error", "message": "Invalid email format"})

                id_field = users.u_id if user_type == "user" else admin.a_id
                existing = session.exec(
                    select(db_model).where(db_model.email == email, id_field != user_id)
                ).first()

                if existing:
                    return JSONResponse(status_code=400, content={"status": "error", "message": "Email already exists"})

                db_obj.email = email

            if username:
                db_obj.username = username

            if image and image.filename:
                folder_name = "userprofiles" if user_type == "user" else "adminprofiles"
                save_dir = os.path.join("..", "frontend", folder_name)
                os.makedirs(save_dir, exist_ok=True)

                filename = f"{user_id}_{image.filename}"
                full_path = os.path.join(save_dir, filename)

                with open(full_path, "wb") as f:
                    f.write(await image.read())

                db_obj.image = f"{folder_name}/{filename}"

            session.add(db_obj)
            session.commit()
        response = JSONResponse(content={"status": "success", "message": "Profile updated successfully"})
        response.headers["Cache-Control"] = "store"
        return response
    except Exception as e:
        print("[ERROR] update_profile:", e)
        return JSONResponse(status_code=500, content={"status": "error", "message": "Server error, please try again later."})

@app.post("/add_product")
async def add_product(
    name: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    image: UploadFile = File(None),
    quantity: int = Form(...),
    current_user=Depends(get_current_user)
):
    if current_user["type"] == "user":
        raise HTTPException(status_code=403, detail="Not authorized to add products")
    new_pid = random.randint(100, 100000)
    with Session(engine) as session:
      while session.exec(select(product).where(product.p_id == new_pid)).first():
        new_pid = random.randint(100, 100000)
    
    image_url = None
    if image and image.filename:
        save_dir = os.path.join('..','frontend','products') 
        os.makedirs(save_dir,exist_ok=True)
        filename = f"{new_pid}_{image.filename}"
        full_path = os.path.join(save_dir, filename)
        with open(full_path,'wb') as f:
            f.write(await image.read())
        image_url = os.path.join('products', filename).replace('\\', '/')

    new_product = product(
        p_id = new_pid,
        name=name,
        description=description,
        price=price,
        media=image_url,
        stock=quantity
    )

    with Session(engine) as session:
        session.add(new_product)
        session.commit()
        session.refresh(new_product)

    return JSONResponse(content={"status": "success", "product_id": new_product.p_id})

@app.get("/products")
def get_products():
    with Session(engine) as session:
        products_list = session.exec(select(product)).all()
        if not products_list:
            return JSONResponse(content={"status": "error", "message": "No products found"}, status_code=404)

        products_data = [
            {
                "p_id": prod.p_id,
                "name": prod.name,
                "description": prod.description,
                "price": prod.price,
                "media": prod.media,
                "stock": prod.stock
            } for prod in products_list
        ]
        return JSONResponse(content={"status": "success", "products": products_data})
    
@app.post("/checkout")
def checkout(request: Request, data: dict = Body(...), current_user=Depends(get_current_user)):
    items = data.get("items", [])
    latitude = data.get("latitude")
    longitude = data.get("longitude")
    payment_method = data.get("payment_method")
    cookie = request.cookies.get("cookie")
    data = serializer.loads(cookie)
    user_id = data.get("u_id")

    if not items or latitude is None or longitude is None or not payment_method:
        raise HTTPException(status_code=400, detail="Invalid input.")

    total = sum(item['qty'] * item['price'] for item in items)
    location_url = f"https://www.google.com/maps?q={latitude},{longitude}"

    with Session(engine) as session:
        order = Order(
            user_id=user_id,
            total_amount=total,
            order_date_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            location_url=location_url,
            payment_method=payment_method 
        )
        session.add(order)
        session.commit()
        session.refresh(order)

        for item in items:
            order_item = OrderItem(
                order_id=order.o_id,
                product_id=item["id"],
                quantity=item["qty"],
                price=item["price"]
            )
            session.add(order_item)

        session.commit()

    return {"status": "success", "order_id": order.o_id}
