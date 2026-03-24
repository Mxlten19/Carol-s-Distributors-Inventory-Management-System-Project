import os

JWT_SECRET = "IMS_SECRET_KEY"
SECRET_KEY = "IMS_SECRET_KEY"

DATABASE_URL = "postgresql://postgres:admin123@localhost:5433/ims_db"
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
RECEIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "receipts")