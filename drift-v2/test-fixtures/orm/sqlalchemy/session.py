# SQLAlchemy session usage
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, User

engine = create_engine('sqlite:///drift.db')
Session = sessionmaker(bind=engine)

def get_user(user_id: int):
    session = Session()
    return session.query(User).filter(User.id == user_id).first()

def create_user(email: str, password: str, name: str):
    session = Session()
    user = User(email=email, password=password, name=name)
    session.add(user)
    session.commit()
    return user
