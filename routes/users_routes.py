from flask import Blueprint, jsonify, request
from database.connection import SessionLocal
from database.models import User, Role
from utils.auth_middleware import token_required
from utils.password_hash import hash_password
from datetime import datetime, timedelta

users_bp = Blueprint("users", __name__)

# ----------------------------------------
# GET ALL USERS (OWNER ONLY)
# ----------------------------------------
@users_bp.get("/")
@token_required(["OWNER"])
def get_users():
    session = SessionLocal()
    users = session.query(User).all()
    data = []
    for u in users:
        is_deactivated = (
            u.locked_until is not None and
            u.locked_until > datetime.utcnow() and
            u.failed_attempts == 999
        )
        data.append({
            "user_id": u.user_id,
            "username": u.username,
            "role": u.role.role_name if u.role else "N/A",
            "role_id": u.role_id,
            "status": "DEACTIVATED" if is_deactivated else "ACTIVE"
        })
    session.close()
    return jsonify(data)


# ----------------------------------------
# GET ALL ROLES (OWNER ONLY)
# ----------------------------------------
@users_bp.get("/roles")
@token_required(["OWNER"])
def get_roles():
    session = SessionLocal()
    roles = session.query(Role).all()
    data = [{"role_id": r.role_id, "role_name": r.role_name} for r in roles]
    session.close()
    return jsonify(data)


# ----------------------------------------
# ADD USER (OWNER ONLY)
# ----------------------------------------
@users_bp.post("/")
@token_required(["OWNER"])
def add_user():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role_id  = data.get("role_id")

    if not username or not password or not role_id:
        return jsonify({"error": "Username, password and role are required"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    session = SessionLocal()

    existing = session.query(User).filter_by(username=username).first()
    if existing:
        session.close()
        return jsonify({"error": "Username already exists"}), 400

    role = session.query(Role).filter_by(role_id=role_id).first()
    if not role:
        session.close()
        return jsonify({"error": "Invalid role selected"}), 400

    new_user = User(
        username=username,
        password_hash=hash_password(password),
        role_id=role_id,
        failed_attempts=0
    )
    session.add(new_user)
    session.commit()
    session.close()

    return jsonify({"message": f"User '{username}' created successfully"})


# ----------------------------------------
# EDIT USER (OWNER ONLY)
# ----------------------------------------
@users_bp.put("/<int:user_id>")
@token_required(["OWNER"])
def edit_user(user_id):
    data = request.get_json() or {}
    session = SessionLocal()

    user = session.query(User).filter_by(user_id=user_id).first()
    if not user:
        session.close()
        return jsonify({"error": "User not found"}), 404

    if "username" in data and data["username"].strip():
        new_username = data["username"].strip()
        existing = session.query(User).filter_by(username=new_username).first()
        if existing and existing.user_id != user_id:
            session.close()
            return jsonify({"error": "Username already taken"}), 400
        user.username = new_username

    if "password" in data and data["password"].strip():
        if len(data["password"]) < 6:
            session.close()
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        user.password_hash = hash_password(data["password"])

    if "role_id" in data:
        role = session.query(Role).filter_by(role_id=data["role_id"]).first()
        if not role:
            session.close()
            return jsonify({"error": "Invalid role"}), 400
        user.role_id = data["role_id"]

    session.commit()
    session.close()
    return jsonify({"message": "User updated successfully"})


# ----------------------------------------
# DEACTIVATE USER (OWNER ONLY)
# ----------------------------------------
@users_bp.put("/<int:user_id>/deactivate")
@token_required(["OWNER"])
def deactivate_user(user_id):
    session = SessionLocal()
    user = session.query(User).filter_by(user_id=user_id).first()
    if not user:
        session.close()
        return jsonify({"error": "User not found"}), 404

    user.locked_until = datetime.utcnow() + timedelta(days=36500)
    user.failed_attempts = 999

    session.commit()
    session.close()
    return jsonify({"message": f"User '{user.username}' has been deactivated"})


# ----------------------------------------
# REACTIVATE USER (OWNER ONLY)
# ----------------------------------------
@users_bp.put("/<int:user_id>/reactivate")
@token_required(["OWNER"])
def reactivate_user(user_id):
    session = SessionLocal()
    user = session.query(User).filter_by(user_id=user_id).first()
    if not user:
        session.close()
        return jsonify({"error": "User not found"}), 404

    user.locked_until = None
    user.failed_attempts = 0

    session.commit()
    session.close()
    return jsonify({"message": f"User '{user.username}' has been reactivated"})


# ----------------------------------------
# DELETE USER (OWNER ONLY)
# ----------------------------------------
@users_bp.delete("/<int:user_id>")
@token_required(["OWNER"])
def delete_user(user_id):
    session = SessionLocal()
    user = session.query(User).filter_by(user_id=user_id).first()
    if not user:
        session.close()
        return jsonify({"error": "User not found"}), 404

    session.delete(user)
    session.commit()
    session.close()
    return jsonify({"message": "User deleted successfully"})