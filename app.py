"""
NEXUS Chat — Secure Messaging Backend
Flask + SocketIO + SQLAlchemy + JWT + Bcrypt + Fernet AES-128

يدعم: محادثات خاصة (1 الى 1) + مجموعات/قنوات عامة، إرسال نص/صورة/صوت،
حالة الكتابة، الحضور (online/offline)، صلاحيات الغرف، تشفير محتوى الرسائل.
جاهز للتغليف كـ PWA (manifest + service worker) لتحويله لاحقًا الى APK.
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
    SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 15}},
    JWT_SECRET_KEY=os.environ.get("JWT_SECRET", "nexus-jwt-secret-change-in-prod"),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(days=30),
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,  # 8MB حد أعلى لأي طلب (صوت/صورة base64)
)

# ── مفتاح تشفير Fernet دائم ──────────────────────────────────────────────────
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
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                     max_http_buffer_size=8 * 1024 * 1024)
CORS(app)

AVATAR_COLORS = ["#0BBCE8", "#7434EB", "#13D87C", "#FF6B6B", "#FFA94D", "#63E6BE", "#F06595"]
MAX_TEXT_LEN  = 4000
MAX_MEDIA_LEN = 7 * 1024 * 1024  # حماية من تضخم القاعدة بقيم base64 ضخمة

# ─────────────────────────────────────────────────────────────────────────────
#  Models
# ─────────────────────────────────────────────────────────────────────────────

class User(db.Model):
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username   = db.Column(db.String(50), unique=True, nullable=False)
    pw_hash    = db.Column(db.String(128), nullable=False)
    color      = db.Column(db.String(7), default="#0BBCE8")
    status     = db.Column(db.String(20), default="offline")
    last_seen  = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def d(self):
        return {"id": self.id, "username": self.username,
                "color": self.color, "status": self.status,
                "last_seen": self.last_seen.isoformat() if self.last_seen else None}


class Room(db.Model):
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default="")
    kind        = db.Column(db.String(20), default="public")   # public | group | channel | dm
    emoji       = db.Column(db.String(10), default="#")
    owner_id    = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=True)
    code        = db.Column(db.String(12), unique=True)
    dm_key      = db.Column(db.String(80), unique=True, nullable=True)  # لمحادثات الخاص فقط
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
    last_read = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    room_id    = db.Column(db.String(36), db.ForeignKey("room.id"), nullable=False)
    user_id    = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    kind       = db.Column(db.String(10), default="text")   # text | image | voice
    body       = db.Column(db.Text, nullable=False)   # نص مشفّر أو data-url مشفّر
    duration   = db.Column(db.Integer, default=0)     # للصوت بالثواني
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited     = db.Column(db.Boolean, default=False)
    reply_to   = db.Column(db.String(36), nullable=True)

    def write(self, text: str):
        self.body = cipher.encrypt(text.encode()).decode()

    def read(self) -> str:
        try:
            return cipher.decrypt(self.body.encode()).decode()
        except Exception:
            return ""

    def d(self):
        u = User.query.get(self.user_id)
        return {
            "id": self.id, "room_id": self.room_id,
            "user": u.d() if u else None,
            "kind": self.kind,
            "text": self.read(),
            "duration": self.duration,
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

@app.route("/manifest.json")
def manifest():
    return send_from_directory(".", "manifest.json")

@app.route("/sw.js")
def sw():
    return send_from_directory(".", "sw.js")

@app.route("/api/register", methods=["POST"])
def register():
    d     = request.json or {}
    uname = d.get("username", "").strip()
    pw    = d.get("password", "")
    if len(uname) < 3 or len(uname) > 30:
        return jsonify(error="اسم المستخدم يجب أن يكون بين 3 و30 حرفًا"), 400
    if len(pw) < 6:
        return jsonify(error="كلمة المرور يجب أن تكون 6 أحرف على الأقل"), 400
    if User.query.filter_by(username=uname).first():
        return jsonify(error="اسم المستخدم مأخوذ"), 409

    u = User(username=uname,
             pw_hash=bcrypt.generate_password_hash(pw).decode(),
             color=random.choice(AVATAR_COLORS))
    db.session.add(u)
    db.session.flush()

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
#  REST — Rooms / Chats
# ─────────────────────────────────────────────────────────────────────────────

def _room_payload(r: Room, uid: str, m: Member):
    rd = r.d()
    rd["role"]    = m.role
    rd["members"] = Member.query.filter_by(room_id=r.id).count()

    if r.kind == "dm":
        other_id = next((p for p in r.dm_key.split("::") if p != uid), None)
        other    = User.query.get(other_id) if other_id else None
        if other:
            rd["name"]   = other.username
            rd["emoji"]  = ""
            rd["peer"]   = other.d()

    lm = (Message.query.filter_by(room_id=r.id)
          .order_by(Message.created_at.desc()).first())
    if lm:
        kind_labels = {"image": "📷 صورة", "voice": "🎤 رسالة صوتية"}
        rd["preview"]      = kind_labels.get(lm.kind) or (lm.read()[:60] or "")
        rd["preview_kind"] = lm.kind
        rd["preview_at"]   = lm.created_at.isoformat()
        rd["preview_user"] = lm.user_id
    unread = (Message.query.filter(Message.room_id == r.id,
                                    Message.created_at > m.last_read,
                                    Message.user_id != uid).count())
    rd["unread"] = unread
    return rd


@app.route("/api/rooms")
@jwt_required()
def get_rooms():
    uid = get_jwt_identity()
    out = []
    for m in Member.query.filter_by(user_id=uid).all():
        r = Room.query.get(m.room_id)
        if not r:
            continue
        out.append(_room_payload(r, uid, m))
    out.sort(key=lambda x: x.get("preview_at", x["created_at"]), reverse=True)
    return jsonify(out)


@app.route("/api/rooms", methods=["POST"])
@jwt_required()
def create_room():
    uid = get_jwt_identity()
    d   = request.json or {}
    name = d.get("name", "").strip()
    kind = d.get("kind", "group")
    if kind not in ("group", "channel"):
        kind = "group"
    if not name:
        return jsonify(error="اسم المجموعة مطلوب"), 400
    if len(name) > 80:
        return jsonify(error="الاسم طويل جدًا"), 400

    r = Room(name=name, description=d.get("description", "")[:500],
             kind=kind, emoji=d.get("emoji", "👥"),
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


@app.route("/api/dm/<username>", methods=["POST"])
@jwt_required()
def start_dm(username):
    """فتح أو إنشاء محادثة خاصة بين المستخدم الحالي ومستخدم آخر بالاسم."""
    uid   = get_jwt_identity()
    other = User.query.filter_by(username=username.strip()).first()
    if not other:
        return jsonify(error="المستخدم غير موجود"), 404
    if other.id == uid:
        return jsonify(error="لا يمكنك بدء محادثة مع نفسك"), 400

    key = "::".join(sorted([uid, other.id]))
    r = Room.query.filter_by(dm_key=key).first()
    if not r:
        r = Room(name=other.username, kind="dm", emoji="", code=str(uuid.uuid4())[:10].upper(),
                  dm_key=key)
        db.session.add(r)
        db.session.flush()
        db.session.add(Member(room_id=r.id, user_id=uid, role="member"))
        db.session.add(Member(room_id=r.id, user_id=other.id, role="member"))
        db.session.commit()

    m = Member.query.filter_by(room_id=r.id, user_id=uid).first()
    return jsonify(_room_payload(r, uid, m))


@app.route("/api/rooms/<rid>/messages")
@jwt_required()
def get_messages(rid):
    uid = get_jwt_identity()
    mem = Member.query.filter_by(room_id=rid, user_id=uid).first()
    if not mem:
        return jsonify(error="غير مصرح"), 403
    page = request.args.get("page", 1, type=int)
    pg = (Message.query.filter_by(room_id=rid)
          .order_by(Message.created_at.desc())
          .paginate(page=page, per_page=50, error_out=False))
    mem.last_read = datetime.utcnow()
    db.session.commit()
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


@app.route("/api/me", methods=["GET", "PATCH"])
@jwt_required()
def me():
    uid = get_jwt_identity()
    u   = User.query.get(uid)
    if not u:
        return jsonify(error="غير موجود"), 404
    if request.method == "PATCH":
        d = request.json or {}
        if "username" in d:
            new = d["username"].strip()
            if 3 <= len(new) <= 30 and not User.query.filter(User.username == new, User.id != uid).first():
                u.username = new
        db.session.commit()
    return jsonify(u.d())

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
    except Exception:
        emit("err", {"msg": "auth_failed"})

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
    kind = data.get("kind", "text")
    text = data.get("text") or ""
    if kind not in ("text", "image", "voice"):
        return
    if kind == "text":
        text = text.strip()[:MAX_TEXT_LEN]
    else:
        if len(text) > MAX_MEDIA_LEN:
            emit("err", {"msg": "media_too_large"})
            return
    if not (uid and rid and text):
        return
    if not Member.query.filter_by(room_id=rid, user_id=uid).first():
        return

    m = Message(room_id=rid, user_id=uid, kind=kind,
                duration=int(data.get("duration") or 0),
                reply_to=data.get("reply_to"))
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
            "name": u.username if u else "؟",
            "rid": rid,
            "on": bool(data.get("on", False))
        }, room=rid, include_self=False)

@socketio.on("disconnect")
def sd():
    uid = sessions.pop(request.sid, None)
    if uid:
        u = User.query.get(uid)
        if u:
            u.status = "offline"
            u.last_seen = datetime.utcnow()
            db.session.commit()
        emit("presence", {"uid": uid, "online": False, "last_seen": datetime.utcnow().isoformat()},
             broadcast=True)

# ─────────────────────────────────────────────────────────────────────────────
#  Boot
# ─────────────────────────────────────────────────────────────────────────────

def seed():
    with app.app_context():
        db.create_all()
        if not Room.query.filter_by(kind="public").first():
            db.session.add_all([
                Room(name="العامة", description="غرفة الجميع — رحب بنفسك 👋",
                     kind="public", emoji="🌐", code="NEXUSGEN01"),
                Room(name="تقنية وبرمجة", description="نقاشات تقنية وأفكار",
                     kind="public", emoji="⚡", code="NEXUSLAB01"),
            ])
            db.session.commit()
            print("  ✓ تم إنشاء الغرف الافتراضية")

if __name__ == "__main__":
    seed()
    print("\n" + "═" * 52)
    print("  🔐  NEXUS Chat Server")
    print("  🌐  http://localhost:5000")
    print("  🔑  التشفير: Fernet (AES-128-CBC)")
    print("═" * 52 + "\n")
    socketio.run(app, debug=False, host="0.0.0.0", port=5000,
                 allow_unsafe_werkzeug=True)
