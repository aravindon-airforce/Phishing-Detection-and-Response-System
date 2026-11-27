from sqlalchemy import create_engine, Column, Integer, Text, Float, DateTime, String
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from argon2 import PasswordHasher
import pyotp

DATABASE_URL = "postgresql+psycopg://postgres:root@localhost:5432/pdrs_db"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=True)
    email = Column(Text, nullable=False)
    prediction = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    totp_secret = Column(String(100), nullable=False)
    role = Column(String(20), default="user", nullable=False)

class QuarantineEmail(Base):
    __tablename__ = "quarantine_emails"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=True)
    email = Column(Text, nullable=False)
    prediction = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False)
    status = Column(Text, default="Quarantined")
    feedback = Column(Text, default="Pending")
    timestamp = Column(DateTime, default=datetime.utcnow)

class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100), nullable=False)
    username = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

class SystemSetting(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    setting_name = Column(String(100), unique=True, nullable=False)
    setting_value = Column(Float, nullable=False)

Base.metadata.create_all(engine)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

print("Database and scan_history table ready!")