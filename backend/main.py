import os
import random
import re
import bcrypt
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException, status, Depends, UploadFile, File, Form, Body
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from itsdangerous import URLSafeSerializer, BadSignature
from sqlmodel import create_engine, Session, select
from input_params import credentials
import uuid
from models import Users, Admin , Product , Order, OrderItem, CancelledOrder,CancelledOrderItem,AuditLog
from pathlib import Path
from datetime import datetime,timezone

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

def generate_esewa_pid():
    date_str = datetime.now().strftime("%Y%m%d%H%M%S")
    unique_id = uuid.uuid4().hex[:6].upper()
    return f"ORD-{date_str}-{unique_id}"

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
            user = session.exec(select(Users).where(Users.u_id == user_id)).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            return {"user": user, "type": "user"}
        elif admin_id:
            admin_user = session.exec(select(Admin).where(Admin.a_id == admin_id)).first()
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
        if session.exec(select(Users).where(Users.email == user.email)).first():
            return {"status": "error", "message": "Email already exists"}

        new_uid = random.randint(100, 100000)
        while session.exec(select(Users).where(Users.u_id == new_uid)).first():
            new_uid = random.randint(100, 100000)

        new_user = Users(
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
        db_user = session.exec(select(Users).where(Users.email == user.email)).first()
        user_type = "user"
        if not db_user:
            db_user = session.exec(select(Admin).where(Admin.email == user.email)).first()
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
            secure=True,
            samesite="None",
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
        if session.exec(select(Admin).where(Admin.email == user.email)).first():
            return {"status": "error", "message": "Email already exists"}

        new_aid = random.randint(100, 10000)
        while session.exec(select(Admin).where(Admin.a_id == new_aid)).first():
            new_aid = random.randint(100, 10000)

        new_admin = Admin(
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
            db_model = Users if user_type == "user" else Admin
            user_id = current_user.u_id if user_type == "user" else current_user.a_id

            db_obj = session.get(db_model, user_id)

            if email:
                if not is_email_valid(email):
                    return JSONResponse(status_code=400, content={"status": "error", "message": "Invalid email format"})

                id_field = Users.u_id if user_type == "user" else Admin.a_id
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
      while session.exec(select(Product).where(Product.p_id == new_pid)).first():
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

    new_product = Product(
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
        products_list = session.exec(select(Product)).all()
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

    if not items or latitude is None or longitude is None or not payment_method:
        raise HTTPException(status_code=400, detail="Invalid input.")

    user_id = current_user["user"].u_id

    total = sum(item['qty'] * item['price'] for item in items)
    location_url = f"https://www.google.com/maps?q={latitude},{longitude}"

    with Session(engine) as session:
        for item in items:
            prod_obj = session.get(Product,int(item['id'])) 
            if prod_obj.stock < item['qty']:
                raise HTTPException(status_code=400,detail=f'product-id:{item['id']} has no available ordered stock')
        esewa_pid = None
        if payment_method == "esewa":
            esewa_pid = generate_esewa_pid()
        for item in items:
            prod_obj = session.get(Product,int(item['id']))
            newstock = prod_obj.stock - item['qty'] 
            prod_obj.stock = newstock 
            session.add(prod_obj) 
            session.commit() 
            session.refresh(prod_obj)
        
        order = Order(
            user_id=user_id,
            total_amount=total,
            order_date_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            location_url=location_url,
            delivery=payment_method,
            esewa_pid=esewa_pid
        )
        session.add(order)
        session.commit()
        session.refresh(order)
        order_id = order.o_id 

        for item in items:
            order_item = OrderItem(
                order_id=order_id,
                product_id=item["id"],
                quantity=item["qty"],
                price=item["price"]
            )
            session.add(order_item)

        session.commit()

    return {"status": "success", "order_id": order_id, "esewa_pid": esewa_pid}

@app.post('/get_product') 
def get_product(data_dict = Body(...)):
    p_id = data_dict.get("pid")
    if not p_id:
        raise HTTPException(status_code=400, detail="Product ID is required")

    with Session(engine) as session:
        product_obj = session.get(Product, p_id)
        if not product_obj:
            raise HTTPException(status_code=404, detail="Product not found")

        product_data = {
            "name": product_obj.name,
            "description": product_obj.description,
            "price": product_obj.price,
        }

    return JSONResponse(content={"status": "success", "product": product_data})


@app.post('/update_product') 
def update_product(
    p_id: int = Form(...),
    name: str = Form(None),
    description: str = Form(None),
    price: float = Form(None),
    image: UploadFile = File(None),
    current_user=Depends(get_current_user)
):
    if current_user["type"] == "user":
        raise HTTPException(status_code=403, detail="Not authorized to update products")

    with Session(engine) as session:
        product_obj = session.get(Product, p_id)
        if not product_obj:
            raise HTTPException(status_code=404, detail="Product not found")

        if name:
            product_obj.name = name
        if description:
            product_obj.description = description
        if price is not None:
            product_obj.price = price

        if image and image.filename:
            save_dir = os.path.join('..','frontend','products') 
            os.makedirs(save_dir,exist_ok=True)
            ext = os.path.splitext(image.filename)[1]
            filename = f"{p_id}_{uuid.uuid4().hex}{ext}"
            full_path = os.path.join(save_dir, filename)
            with open(full_path,'wb') as f:
                f.write(image.file.read())
            product_obj.media = os.path.join('products', filename).replace('\\', '/')

        session.add(product_obj)
        session.commit()
        session.refresh(product_obj)

    return {
    "status": "success",
    "message": "Product updated successfully",
    }
@app.post('/get_stock')
def get_stock(
    data_dict = Body(...),
    current_user=Depends(get_current_user)
    ):
    if current_user['type'] == 'user':
        raise HTTPException(status_code=403, detail="Not authorized to add/deduct product's stock") 
    pid = data_dict.get('pid')
    with Session(engine) as session:
        product_obj = session.get(Product,pid) 
        if not product_obj:
            raise HTTPException(status_code=404, detail="Product not found")
        stock = product_obj.stock
    return {'status':'success','stock':stock}

@app.post('/edit_stock') 
def edit_stock(
    data_dict=Body(...),
    current_user=Depends(get_current_user)):
    if current_user['type'] == 'user':
        raise HTTPException(status_code=403, detail="Not authorized to update product's stock") 
    print(data_dict)
    pid = int(data_dict['pid'])
    qty = int(data_dict['stock'])
    fixer = data_dict.get('fixer') 
    with Session(engine) as session:
        product_obj = session.get(Product,pid) 
        if not product_obj:
            raise HTTPException(status_code=404, detail="Product not found.")
        stock = product_obj.stock
        newstock = None
        if fixer == '+':
            newstock = stock+qty
        elif fixer == '-':
            if stock<qty:
              raise HTTPException(status_code=404, detail="Invalid quantity supplied.") 
            else:
                newstock = stock-qty
        else:
            raise HTTPException(status_code=404, detail="Cannot update product stock.")
        product_obj.stock = newstock
        session.add(product_obj) 
        session.commit() 
        session.refresh(product_obj) 
    return {'status':'success','message':'Stock updated successfully','oldstock':stock,'newstock':newstock}

@app.get("/my_orders")
def get_user_orders(current_user=Depends(get_current_user)):
    if current_user["type"] != "user":
        raise HTTPException(status_code=403, detail="Not authorized")

    user_id = current_user["user"].u_id

    with Session(engine) as session:
        query = (
            select(Order, OrderItem, Product)
            .join(OrderItem, OrderItem.order_id == Order.o_id)
            .join(Product, Product.p_id == OrderItem.product_id)
            .where(Order.user_id == user_id)
        )
        results = session.exec(query).all()

        orders_dict = {}
        for order, orderitem, product in results:
            if order.o_id not in orders_dict:
                orders_dict[order.o_id] = {
                    "id": order.o_id,
                    "status": order.status,
                    "date": order.order_date_time.isoformat() if order.order_date_time else None,
                    "delivery": order.delivery,
                    "total_amount": order.total_amount,
                    "location": order.location_url,
                    "items": []
                }
            orders_dict[order.o_id]["items"].append({
                "name": product.name,
                "description": product.description,
                "media": product.media,
                "price": product.price,
                "quantity": orderitem.quantity,
            })

    return {"orders": list(orders_dict.values())}

@app.post('/delete_product') 
def delete_product(
    data_dict=Body(...),
    current_user=Depends(get_current_user)
    ):
    if current_user['type'] == 'user':
        raise HTTPException(status_code=403, detail="Not authorized to delete products") 
    pid = data_dict.get('pid')
    with Session(engine) as session:
        orderitems = session.query(OrderItem).filter(OrderItem.product_id == pid).first()
        if orderitems:
          raise HTTPException(status_code=400, detail="Product cannot be deleted because it is linked to orders")
        product_obj = session.get(Product,pid) 
        if not product_obj:
            raise HTTPException(status_code=404, detail="Product not found")
        session.delete(product_obj) 
        session.commit() 
    return {'status':'success','message':'Product deleted successfully'}

@app.post("/cancel_order")
def cancel_order(
    data: dict = Body(...),
    current_user=Depends(get_current_user)
):
    if current_user["type"] != "user":
        raise HTTPException(status_code=403, detail="Only users can cancel orders")

    order_id = data.get("order_id")
    if not order_id:
        raise HTTPException(status_code=400, detail="Order ID is required")

    with Session(engine) as session:
        # Fetch order
        order = session.exec(
            select(Order).where(Order.o_id == order_id, Order.user_id == current_user["user"].u_id)
        ).first()

        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        if order.status.lower() in ["cancelled", "completed"]:
            return {"status": "failed", "message": f"Order already {order.status}"}

        # Fetch order items
        order_items = session.exec(
            select(OrderItem).where(OrderItem.order_id == order.o_id)
        ).all()

        # Create CancelledOrder record
        cancelled_order = CancelledOrder(
            o_id=order.o_id,
            user_id=order.user_id,
            cancel_date_time=datetime.now(timezone.utc),
            reason=data.get("reason")  # optional
        )
        session.add(cancelled_order)
        session.commit()
        session.refresh(cancelled_order)

        # Copy items into CancelledOrderItem
        for item in order_items:
            cancelled_item = CancelledOrderItem(
                co_id=cancelled_order.co_id,
                product_id=item.product_id,
                quantity=item.quantity,
                price=item.price
            )
            session.add(cancelled_item)

        # Update original order status
        order.status = "Cancelled"
        session.add(order)

        # Audit log
        audit = AuditLog(
            entity="Order",
            entity_id=order.o_id,
            action="Cancel",
            performed_by=current_user["user"].u_id,
            details=f"Order {order.o_id} cancelled"
        )
        session.add(audit)

        session.commit()

        return {
            "status": "success",
            "message": "Order cancelled successfully",
            "order_id": order.o_id
        }

@app.post("/esewa_success")
async def esewa_success(request: Request):
    form = await request.form()
    amt = form.get("amt") or form.get("tAmt")  
    pid = form.get("pid")
    refId = form.get("refId")

    verify_url = "https://uat.esewa.com.np/epay/transrec"
    payload = {
        "amt": amt,
        "rid": refId,
        "pid": pid,
        "scd": "EPAYTEST"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(verify_url, data=payload)
        result = response.text

    if "<response_code>Success</response_code>" in result:
        return HTMLResponse(content="<h1>✅ eSewa Payment Verified Successfully!</h1>", status_code=200)
    else:
        return HTMLResponse(content="<h1>❌ Payment Verification Failed!</h1>", status_code=400)
    



@app.post("/esewa_failure")
async def esewa_failure(request: Request):
    return HTMLResponse(content="<h1>❌ Payment Failed or Cancelled.</h1>", status_code=400)    

