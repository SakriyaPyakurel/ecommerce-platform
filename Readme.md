# 🛒 E-Commerce Platform Project (All in One store)

🚀 <b>Project Overview</b>

- A full-stack e-commerce platform built with FastAPI (backend) and HTML/CSS + JavaScript/Tailwind (frontend).
- Users can browse products, add items to cart, checkout with Cash on Delivery or eSewa, and leave reviews with ratings. 
- Admins can manage products and stock.

💡 <b>Features</b>

User Side 🙋

- Browse products with categories 🎨

- Add to cart 🛒

- View and edit cart contents 👁️

- Checkout using Cash on Delivery or eSewa 💳

- Review products and see average ratings ⭐

- Search products by name or description 🔍

👨‍💻 Admin Side

- Add, edit, and delete products 📝❌

- Update product stock 📦

- View all orders 📋

⚡ Other Features

- Automatic category filtering

- Products sorted by average rating ⭐📈

- Real-time stock updates

- Responsive UI with Tailwind CSS

- Image preview modal for product images 🖼️

🛠 <b>Tech Stack</b>

| **Layers**          | **Technologies**                    |
| ------------------- | ----------------------------------- |
| **Backend**         | FastAPI, SQLModel, MySQL            |
| **Frontend**        | HTML, CSS, Tailwind, JavaScript     |
| **Authentication**  | Cookie-based authentication         |
| **Payment Gateway** | eSewa (test environment)            |
| **Storage**         | LocalStorage (for cart persistence) |


⚙️ </b>Setup</b>

1. Clone the repo 

-> git clone https://github.com/SakriyaPyakurel/ecommerce-platform.git<br>
-> cd ecommerce-platform

2. Create and activate virtual environment(inside backend after removing old venv)

-> python -m venv venv<br>
-> source venv/bin/activate<br>
-> venv\Scripts\activate

3. Installation of dependencies

-> pip install -r requirements.txt<br>

4. Alembic(data-migration setup inside backend) 

-> alembic init alembic<br>
-> alembic revision --autogenerate -m "describe change"<br>
-> alembic upgrade head<br>
-> alembic downgrade -1 (optional: for rollback)<br>


