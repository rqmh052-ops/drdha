# NEXUS Chat v2 🔐

تطبيق مراسلة فوري آمن ومشفّر — Flask + Socket.IO + PWA

---

## 🚀 النشر على Railway

### 1. رفع الكود على GitHub

```bash
git init
git add .
git commit -m "NEXUS Chat v2"
git remote add origin https://github.com/YOUR_USER/nexus-chat.git
git push -u origin main
```

### 2. إنشاء مشروع على Railway

1. اذهب إلى [railway.app](https://railway.app) وسجّل الدخول
2. اضغط **New Project** → **Deploy from GitHub repo**
3. اختر الـ repo

### 3. متغيّرات البيئة (مهم!)

في Railway، اذهب إلى **Variables** وأضف:

| Variable | القيمة |
|---|---|
| `SECRET_KEY` | سلسلة عشوائية طويلة |
| `JWT_SECRET` | سلسلة عشوائية مختلفة |
| `FERNET_KEY` | ناتج `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `PORT` | Railway يضيفها تلقائيًا |

> ⚠️ بدون `FERNET_KEY` سيُولَّد مفتاح جديد عند كل إعادة نشر، مما يجعل الرسائل القديمة غير قابلة للفكّ. أضفها كـ secret.

### 4. قاعدة البيانات (اختياري)

لحفظ البيانات بشكل دائم على Railway:
- اضغط **New** → **Database** → **PostgreSQL**
- Railway ستضيف `DATABASE_URL` تلقائيًا للتطبيق
- التطبيق يتعرّف عليها تلقائيًا

بدون PostgreSQL: التطبيق يستخدم SQLite داخل الحاوية (البيانات تُمسح عند إعادة النشر — مقبول حسب متطلباتك)

---

## 🔧 التشغيل المحلي

```bash
pip install -r requirements.txt
python app.py
```

افتح: http://localhost:5000

---

## ✨ المميزات

- 🔐 تشفير رسائل Fernet (AES-128)
- 💬 محادثات خاصة (DM)
- 👥 مجموعات وقنوات
- 🎤 رسائل صوتية
- 📷 إرسال صور
- ⚡ تحديثات فورية عبر Socket.IO
- 📱 PWA — قابل للتثبيت كتطبيق

---

## 📁 هيكل المشروع

```
nexus-chat/
├── app.py            # الخادم (Flask + SocketIO)
├── index.html        # الواجهة (SPA)
├── manifest.json     # PWA manifest
├── sw.js             # Service Worker
├── requirements.txt  # Python dependencies
├── Procfile          # للنشر
├── railway.json      # إعدادات Railway
└── .gitignore
```
