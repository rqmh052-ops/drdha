"""
NEXUS Chat — Secure Messaging Backend
Flask + SocketIO + SQLAlchemy + JWT + Bcrypt + Fernet AES-128
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity, decode_token
)
from flask_cors import CORS
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os, uuid, random

app = Flask(__name__, static_folder=".")
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "nexus-secret-key-change-in-prod"),
    SQLALCHEMY_DATABASE_URI="sqlite:///nexus.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    JWT_SECRET_KEY=os.environ.get("JWT_SECRET", "nexus-jwt-secret-change-in-prod"),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=24),
)

# ── Persistent Fernet encryption key ────────────────────────────────────────
KEY_FILE = ".nexus.key"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        FERNET_KEY = f.read().strip()
else:
    FERNET_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(FERNET_KEY)

cipher = Fernet(FERNET_KEY)

db       = SQLAlchemy(app)
bcrypt   = Bcrypt(app)
jwt      = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
CORS(app)

AVATAR_COLORS = ["#0BBCE8", "#7434EB", "#13D87C", "#FF6B6B", "#FFA94D", "#63E6BE", "#F06595"]

# ─────────────────────────────────────────────────────────────────────────────
#  Models
# ─────────────────────────────────────────────────────────────────────────────

class User(db.Model):
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username   = db.Column(db.String(50), unique=True, nullable=False)
    pw_hash    = db.Column(db.String(128), nullable=False)
    color      = db.Column(db.String(7), default="#0BBCE8")
    status     = db.Column(db.String(20), default="offline")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def d(self):
        return {"id": self.id, "username": self.username,
                "color": self.color, "status": self.status}


class Room(db.Model):
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default="")
    kind        = db.Column(db.String(20), default="public")   # public | private | group
    emoji       = db.Column(db.String(10), default="#")
    owner_id    = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=True)
    code        = db.Column(db.String(12), unique=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def d(self):
        return {"id": self.id, "name": self.name, "description": self.description,
                "kind": self.kind, "emoji": self.emoji, "owner_id": self.owner_id,
                "code": self.code, "created_at": self.created_at.isoformat()}


class Member(db.Model):
    __tablename__ = "room_member"
    id        = db.Column(db.Integer, primary_key=True)
    room_id   = db.Column(db.String(36), db.ForeignKey("room.id"), nullable=False)
    user_id   = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    role      = db.Column(db.String(20), default="member")   # owner | admin | member
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    room_id    = db.Column(db.String(36), db.ForeignKey("room.id"), nullable=False)
    user_id    = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    body       = db.Column(db.Text, nullable=False)   # Fernet-encrypted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited     = db.Column(db.Boolean, default=False)
    reply_to   = db.Column(db.String(36), nullable=True)

    def write(self, text: str):
        self.body = cipher.encrypt(text.encode()).decode()

    def read(self) -> str:
        try:
            return cipher.decrypt(self.body.encode()).decode()
        except Exception:
            return "🔒 [encrypted]"

    def d(self):
        u = User.query.get(self.user_id)
        return {
            "id": self.id, "room_id": self.room_id,
            "user": u.d() if u else None,
            "text": self.read(),
            "created_at": self.created_at.isoformat(),
            "edited": self.edited,
            "reply_to": self.reply_to,
        }

# ─────────────────────────────────────────────────────────────────────────────
#  REST — Auth
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def root():
    return send_from_directory(".", "index.html")

@app.route("/api/register", methods=["POST"])
def register():
    d     = request.json or {}
    uname = d.get("username", "").strip()
    pw    = d.get("password", "")
    if len(uname) < 3:
        return jsonify(error="اسم المستخدم يجب أن يكون 3 أحرف على الأقل"), 400
    if len(pw) < 6:
        return jsonify(error="كلمة المرور يجب أن تكون 6 أحرف على الأقل"), 400
    if User.query.filter_by(username=uname).first():
        return jsonify(error="اسم المستخدم مأخوذ"), 409

    u = User(username=uname,
             pw_hash=bcrypt.generate_password_hash(pw).decode(),
             color=random.choice(AVATAR_COLORS))
    db.session.add(u)
    db.session.flush()

    # Auto-join public rooms
    for r in Room.query.filter_by(kind="public").all():
        db.session.add(Member(room_id=r.id, user_id=u.id))

    db.session.commit()
    return jsonify(token=create_access_token(u.id), user=u.d()), 201


@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    u = User.query.filter_by(username=d.get("username", "").strip()).first()
    if not u or not bcrypt.check_password_hash(u.pw_hash, d.get("password", "")):
        return jsonify(error="اسم المستخدم أو كلمة المرور خاطئة"), 401
    u.status = "online"
    db.session.commit()
    return jsonify(token=create_access_token(u.id), user=u.d())

# ─────────────────────────────────────────────────────────────────────────────
#  REST — Rooms
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/rooms")
@jwt_required()
def get_rooms():
    uid = get_jwt_identity()
    out = []
    for m in Member.query.filter_by(user_id=uid).all():
        r = Room.query.get(m.room_id)
        if not r:
            continue
        rd = r.d()
        rd["role"]    = m.role
        rd["members"] = Member.query.filter_by(room_id=r.id).count()
        lm = (Message.query.filter_by(room_id=r.id)
              .order_by(Message.created_at.desc()).first())
        if lm:
            rd["preview"]    = lm.read()[:60]
            rd["preview_at"] = lm.created_at.isoformat()
        out.append(rd)
    return jsonify(out)


@app.route("/api/rooms", methods=["POST"])
@jwt_required()
def create_room():
    uid = get_jwt_identity()
    d   = request.json or {}
    name = d.get("name", "").strip()
    if not name:
        return jsonify(error="اسم الغرفة مطلوب"), 400

    r = Room(name=name, description=d.get("description", ""),
             kind=d.get("kind", "public"), emoji=d.get("emoji", "#"),
             owner_id=uid, code=str(uuid.uuid4())[:10].upper())
    db.session.add(r)
    db.session.flush()
    db.session.add(Member(room_id=r.id, user_id=uid, role="owner"))
    db.session.commit()
    return jsonify(r.d()), 201


@app.route("/api/rooms/join", methods=["POST"])
@jwt_required()
def join_by_code():
    uid  = get_jwt_identity()
    code = (request.json or {}).get("code", "").strip().upper()
    r    = Room.query.filter_by(code=code).first()
    if not r:
        return jsonify(error="رمز الدعوة غير صالح"), 404
    if not Member.query.filter_by(room_id=r.id, user_id=uid).first():
        db.session.add(Member(room_id=r.id, user_id=uid))
        db.session.commit()
    return jsonify(room=r.d())


@app.route("/api/rooms/<rid>/messages")
@jwt_required()
def get_messages(rid):
    uid = get_jwt_identity()
    if not Member.query.filter_by(room_id=rid, user_id=uid).first():
        return jsonify(error="غير مصرح"), 403
    page = request.args.get("page", 1, type=int)
    pg = (Message.query.filter_by(room_id=rid)
          .order_by(Message.created_at.desc())
          .paginate(page=page, per_page=60, error_out=False))
    return jsonify([m.d() for m in reversed(pg.items)])


@app.route("/api/rooms/<rid>/members")
@jwt_required()
def get_members(rid):
    uid = get_jwt_identity()
    if not Member.query.filter_by(room_id=rid, user_id=uid).first():
        return jsonify(error="غير مصرح"), 403
    out = []
    for m in Member.query.filter_by(room_id=rid).all():
        u = User.query.get(m.user_id)
        if u:
            data = u.d()
            data["role"] = m.role
            out.append(data)
    return jsonify(out)

# ─────────────────────────────────────────────────────────────────────────────
#  Socket.IO — Real-time
# ─────────────────────────────────────────────────────────────────────────────

sessions: dict[str, str] = {}   # sid → user_id

@socketio.on("connect")
def sc():
    pass

@socketio.on("auth")
def s_auth(data):
    try:
        uid = decode_token(data.get("token", ""))["sub"]
        u   = User.query.get(uid)
        if u:
            sessions[request.sid] = uid
            u.status = "online"
            db.session.commit()
            emit("ready", u.d())
            emit("presence", {"uid": uid, "online": True}, broadcast=True)
    except Exception as e:
        emit("err", {"msg": str(e)})

@socketio.on("join")
def s_join(data):
    uid = sessions.get(request.sid)
    rid = data.get("rid")
    if uid and rid and Member.query.filter_by(room_id=rid, user_id=uid).first():
        join_room(rid)

@socketio.on("part")
def s_part(data):
    leave_room(data.get("rid"))

@socketio.on("msg")
def s_msg(data):
    uid  = sessions.get(request.sid)
    rid  = data.get("rid")
    text = (data.get("text") or "").strip()
    if not (uid and rid and text):
        return
    if not Member.query.filter_by(room_id=rid, user_id=uid).first():
        return
    m = Message(room_id=rid, user_id=uid, reply_to=data.get("reply_to"))
    m.write(text)
    db.session.add(m)
    db.session.commit()
    emit("msg", m.d(), room=rid)

@socketio.on("typing")
def s_typing(data):
    uid = sessions.get(request.sid)
    rid = data.get("rid")
    if uid and rid:
        u = User.query.get(uid)
        emit("typing", {
            "uid": uid,
            "name": u.username if u else "?",
            "rid": rid,
            "on": data.get("on", False)
        }, room=rid, include_self=False)

@socketio.on("disconnect")
def sd():
    uid = sessions.pop(request.sid, None)
    if uid:
        u = User.query.get(uid)
        if u:
            u.status = "offline"
            db.session.commit()
        emit("presence", {"uid": uid, "online": False}, broadcast=True)

# ─────────────────────────────────────────────────────────────────────────────
#  Boot
# ─────────────────────────────────────────────────────────────────────────────

def seed():
    with app.app_context():
        db.create_all()
        if not Room.query.first():
            db.session.add_all([
                Room(name="general",       description="الغرفة العامة — الجميع مرحب بهم",
                     kind="public", emoji="🌐", code="NEXUSGEN01"),
                Room(name="tech-lab",      description="تقنية · برمجة · أفكار",
                     kind="public", emoji="⚡", code="NEXUSLAB01"),
                Room(name="announcements", description="إعلانات المشرفين فقط",
                     kind="public", emoji="📡", code="NEXUSANN01"),
            ])
            db.session.commit()
            print("  ✓ Default rooms created")

if __name__ == "__main__":
    seed()
    print("\n" + "═" * 52)
    print("  🔐  NEXUS Chat Server")
    print("  🌐  http://localhost:5000")
    print("  🔑  Encryption: Fernet (AES-128-CBC)")
    print("═" * 52 + "\n")
    socketio.run(app, debug=True, host="0.0.0.0", port=5000,
                 allow_unsafe_werkzeug=True)
