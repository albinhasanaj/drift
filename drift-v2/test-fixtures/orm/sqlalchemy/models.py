# SQLAlchemy declarative models with sensitive fields
from sqlalchemy import Column, String, Integer, ForeignKey, Enum
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)  # SENSITIVE
    password = Column(String, nullable=False)  # SENSITIVE
    ssn = Column(String)  # SENSITIVE
    name = Column(String, nullable=False)
    role = Column(Enum('admin', 'user'), default='user')
    posts = relationship('Post', back_populates='author')

class Post(Base):
    __tablename__ = 'posts'

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    content = Column(String)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')
