from flask import Flask, send_from_directory
from flask_cors import CORS
from config import SECRET_KEY
from routes.auth_routes import auth_bp
from routes.inventory_routes import inventory_bp
from routes.sales_routes import sales_bp
from routes.alert_routes import alert_bp
from routes.report_routes import report_bp
from routes.users_routes import users_bp
from database.connection import Base, engine
from database import models
from services.alert_service import AlertService
from routes.report_routes import init_report_scheduler
import os

app = Flask(
    __name__,
    static_folder="frontend",
    static_url_path=""
)

app.secret_key = SECRET_KEY
CORS(app)

# -------------------------
# CREATE DATABASE TABLES
# -------------------------
Base.metadata.create_all(engine)

# -------------------------
# REGISTER API ROUTES
# -------------------------
app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(inventory_bp, url_prefix="/inventory")
app.register_blueprint(sales_bp, url_prefix="/sales")
app.register_blueprint(alert_bp, url_prefix="/alerts")
app.register_blueprint(report_bp, url_prefix="/reports")
app.register_blueprint(users_bp, url_prefix="/users")

# -------------------------
# SERVE FRONTEND PAGES
# -------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")

@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(FRONTEND_DIR, path)

# -------------------------
# INIT ALERT CHECK
# -------------------------
with app.app_context():
    # Start scheduler here
    init_report_scheduler()

    # Run initial stock check
    AlertService.check_all_products()
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)