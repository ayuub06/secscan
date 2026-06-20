import sys
sys.path.insert(0, '.')
from web.app import app
from db.database import SessionLocal
from db.user_model import User

db = SessionLocal()
user = db.query(User).filter_by(email="workayoub6@gmail.com").first()
print("User found:", user.id, user.email, user.role)

with app.test_request_context():
    from flask import session
    session['user_id'] = user.id
    cookie_value = app.session_interface.get_signing_serializer(app).dumps(dict(session))
    print("SESSION_COOKIE=" + cookie_value)

db.close()