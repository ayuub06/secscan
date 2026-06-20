import sys
sys.path.insert(0, '.')
from db.database import SessionLocal
from db.user_model import User

db = SessionLocal()
user = db.query(User).filter_by(email="workayoub6@gmail.com").first()
user.role = "admin"
db.commit()
print("Updated:", user.id, user.email, user.role)
db.close()