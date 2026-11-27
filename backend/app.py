from fastapi import FastAPI, UploadFile, File, Depends
from pydantic import BaseModel
from pydantic import Field
from argon2 import PasswordHasher
import pyotp
from fastapi.middleware.cors import CORSMiddleware
from bs4 import BeautifulSoup
from db import SessionLocal, ScanHistory, User, QuarantineEmail, SystemLog, SystemSetting
import re
import pickle 
import requests
import os
import imaplib
import email
import time
from collections import defaultdict
from email.header import decode_header
from dotenv import load_dotenv
import pandas as pd
from fastapi import HTTPException
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from fastapi.responses import FileResponse
from fastapi import Query
import jwt
from datetime import datetime, timedelta, timezone
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv(
    "GOOGLE_SAFE_BROWSING_API_KEY"
)

app = FastAPI()

rate_limit_store = defaultdict(list)

RATE_LIMIT = 60
RATE_WINDOW = 60


@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    client_ip = request.client.host

    current_time = time.time()

    request_times = rate_limit_store[client_ip]

    request_times[:] = [
        request_time
        for request_time in request_times
        if current_time - request_time < RATE_WINDOW
    ]

    if len(request_times) >= RATE_LIMIT:
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=429,
            content={
                "detail": "Too many requests. Please try again later."
            }
        )

    request_times.append(current_time)

    response = await call_next(request)

    return response

password_hasher = PasswordHasher()

SECRET_KEY = "Airforce@2901"
ALGORITHM = "HS256"

security = HTTPBearer()

class FeedbackRequest(BaseModel):
    feedback: str

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str


def create_access_token(username: str, role: str):
    expire = datetime.now(timezone.utc) + timedelta(hours=2)

    payload = {
        "username": username,
        "role": role,
        "exp": expire
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("username")
        role = payload.get("role")

        if not username or not role:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

        return {
            "username": username,
            "role": role
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Authentication token expired"
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token"
        )


def require_admin(
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )

    return current_user

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

with open("../models/tfidf_vectorizer.pkl", "rb") as file:
    vectorizer = pickle.load(file)

with open("../models/optimized_xgboost_model.pkl", "rb") as file:
    model = pickle.load(file)

def remove_html(text):
    soup = BeautifulSoup(text, "lxml")
    return soup.get_text("")

def replace_urls(text):
    return re.sub(r'http[s]?://\S+', ' URL ', text)

def remove_emails(text):
    return re.sub(r'\S+@\S+', ' EMAIL ', text)

def clean_symbols(text):
    return re.sub(r'[^a-zA-Z ]', ' ', text)

def remove_spaces(text):
    return re.sub(r'\s+', ' ', text).strip()

def lowercase_text(text):
    return text.lower()

def preprocess_email(text):
    text = lowercase_text(text)
    text = remove_html(text)
    text = replace_urls(text)
    text = remove_emails(text)
    text = clean_symbols(text)
    text = remove_spaces(text)

    return text

@app.get("/")
def home():
    return {"message": "Pdrs backend in rocking!!!"}

@app.post("/predict")
def predict(
    email: str,
    current_user: dict = Depends(get_current_user)
):

    username = current_user["username"]

    # Step 1: Preprocess the email
    cleaned_email = preprocess_email(email)

    # Step 2: Convert email text into TF-IDF features
    email_vector = vectorizer.transform([cleaned_email])

    # Step 3: Predict using optimized XGBoost model
    prediction = model.predict(email_vector)[0]

    # Step 4: Get prediction confidence
    probabilities = model.predict_proba(email_vector)[0]
    confidence = max(probabilities) * 100

    # Step 5: Convert prediction into readable result
    if prediction == 1:
        result = "Phishing"
    else:
        result = "Safe"

    # Save scan result to PostgreSQL
    db = SessionLocal()

    scan = ScanHistory(
        username=username,
        email=email,
        prediction=result,
        confidence=float(confidence)
    )

    db.add(scan)

    # Default alert
    alert = None

    if result == "Phishing":

        quarantine = QuarantineEmail(
            username=username,
            email=email,
            prediction=result,
            confidence=float(confidence),
            status="Quarantined"
        )

        db.add(quarantine)

        # Real-time phishing alert
        alert = {
            "type": "PHISHING_ALERT",
            "message": "Phishing email detected",
            "confidence": round(float(confidence), 2)
        }

    db.commit()
    db.close()

    return {
        "prediction": result,
        "confidence": round(float(confidence), 2),
        "processed_email": cleaned_email,
        "alert": alert
    }

@app.get("/history")
def get_history(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    role = current_user["role"]

    db = SessionLocal()

    if role == "admin":
        history = (
            db.query(ScanHistory)
            .order_by(ScanHistory.id.desc())
            .all()
        )
    else:
        history = (
            db.query(ScanHistory)
            .filter(ScanHistory.username == username)
            .order_by(ScanHistory.id.desc())
            .all()
        )

    result = [
        {
            "id": item.id,
            "username": item.username,
            "prediction": item.prediction,
            "confidence": round(float(item.confidence), 2),
            "timestamp": item.timestamp
        }
        for item in history
    ]

    db.close()
    return result

@app.get("/dashboard")
def get_dashboard(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    role = current_user["role"]

    db = SessionLocal()

    if role == "admin":
        scans = (
            db.query(ScanHistory)
            .order_by(ScanHistory.id.desc())
            .all()
        )
    else:
        scans = (
            db.query(ScanHistory)
            .filter(ScanHistory.username == username)
            .order_by(ScanHistory.id.desc())
            .all()
        )

    total_scans = len(scans)
    phishing_count = sum(
        1 for scan in scans if scan.prediction == "Phishing"
    )
    safe_count = sum(
        1 for scan in scans if scan.prediction == "Safe"
    )

    if total_scans > 0:
        average_confidence = (
            sum(float(scan.confidence) for scan in scans)
            / total_scans
        )
    else:
        average_confidence = 0

    recent_threats = [
        {
            "id": scan.id,
            "username": scan.username,
            "prediction": scan.prediction,
            "confidence": round(float(scan.confidence), 2),
            "timestamp": scan.timestamp
        }
        for scan in scans[:5]
    ]

    db.close()

    return {
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "safe_count": safe_count,
        "average_confidence": round(average_confidence, 2),
        "recent_threats": recent_threats
    }

@app.get("/quarantine")
def get_quarantine(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    role = current_user["role"]

    db = SessionLocal()

    if role == "admin":
        records = (
            db.query(QuarantineEmail)
            .order_by(QuarantineEmail.id.desc())
            .all()
        )
    else:
        records = (
            db.query(QuarantineEmail)
            .filter(QuarantineEmail.username == username)
            .order_by(QuarantineEmail.id.desc())
            .all()
        )

    result = [
        {
            "id": item.id,
            "username": item.username,
            "email": item.email,
            "prediction": item.prediction,
            "confidence": round(float(item.confidence), 2),
            "status": item.status,
            "feedback": item.feedback,
            "timestamp": item.timestamp
        }
        for item in records
    ]

    db.close()
    return result

@app.put("/quarantine/{quarantine_id}/feedback")
def update_feedback(
    quarantine_id: int,
    request: FeedbackRequest,
    current_user: dict = Depends(get_current_user)
):
    username = current_user["username"]

    db = SessionLocal()

    record = (
        db.query(QuarantineEmail)
        .filter(
            QuarantineEmail.id == quarantine_id,
            QuarantineEmail.username == username
        )
        .first()
    )

    if not record:
        db.close()
        raise HTTPException(
            status_code=404,
            detail="Quarantine record not found"
        )

    if request.feedback not in ["Safe", "Dangerous"]:
        db.close()
        raise HTTPException(
            status_code=400,
            detail="Invalid feedback"
        )

    record.feedback = request.feedback

    db.commit()

    db.close()

    return {
        "message": "Feedback updated successfully",
        "id": quarantine_id,
        "feedback": request.feedback
    }

@app.post("/analyze-header")
def analyze_header(
    sender: str,
    reply_to: str = "",
    return_path: str = ""
):

    sender_domain = ""

    if "@" in sender:
        sender_domain = sender.split("@")[-1].lower().strip()

    reply_domain = ""

    if "@" in reply_to:
        reply_domain = reply_to.split("@")[-1].lower().strip()

    return_path_domain = ""

    if "@" in return_path:
        return_path_domain = (
            return_path.split("@")[-1].lower().strip()
        )

    warnings = []

    if reply_domain and sender_domain:
        if reply_domain != sender_domain:
            warnings.append(
                "Sender and Reply-To domains do not match"
            )

    if return_path_domain and sender_domain:
        if return_path_domain != sender_domain:
            warnings.append(
                "Sender and Return-Path domains do not match"
            )

    if warnings:
        risk = "Suspicious"
    else:
        risk = "No obvious mismatch detected"

    return {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_path_domain,
        "risk": risk,
        "warnings": warnings
    }

@app.post("/analyze-url")
def analyze_url(url: str):

    virustotal_result = {
        "status": "Not checked",
        "details": None
    }

    google_result = {
        "status": "Not checked",
        "details": None
    }

    # VirusTotal
    if VIRUSTOTAL_API_KEY:

        try:
            response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={
                    "x-apikey": VIRUSTOTAL_API_KEY
                },
                data={
                    "url": url
                },
                timeout=10
            )

            if response.status_code in [200, 201]:
                virustotal_result["status"] = "Submitted"
                virustotal_result["details"] = response.json()
            else:
                virustotal_result["status"] = (
                    f"API Error: {response.status_code}"
                )

        except Exception as e:
            virustotal_result["status"] = "Request failed"
            virustotal_result["details"] = str(e)

    else:
        virustotal_result["status"] = "API key not configured"

    # Google Safe Browsing
    if GOOGLE_SAFE_BROWSING_API_KEY:

        try:
            google_url = "https://safebrowsing.googleapis.com/v5/urls:search"

            response = requests.get(
                google_url,
                params={
                    "key": GOOGLE_SAFE_BROWSING_API_KEY,
                    "urls": url
                },
                timeout=10
            )

            print("GOOGLE STATUS:", response.status_code)
            print("GOOGLE RESPONSE:", response.text)

            if response.status_code == 200:

                try:
                    data = response.json()
                except ValueError:
                    data = {}

                if data.get("threats"):
                    google_result["status"] = "Threat detected"
                    google_result["details"] = data["threats"]
                else:
                    google_result["status"] = "No threat detected"
                    google_result["details"] = None

            else:
                google_result["status"] = (
                    f"API Error: {response.status_code}"
                )
                google_result["details"] = response.text

        except Exception as e:
            google_result["status"] = "Request failed"
            google_result["details"] = str(e)

    else:
        google_result["status"] = "API key not configured"

    # Final response
    return {
        "url": url,
        "virustotal": virustotal_result,
        "google_safe_browsing": google_result
    }

@app.post("/analyze-attachment")
async def analyze_attachment(file: UploadFile = File(...)):

    filename = file.filename or ""
    extension = filename.lower().split(".")[-1] if "." in filename else ""

    dangerous_extensions = {
        "exe", "dll", "scr", "bat", "cmd",
        "com", "msi", "vbs", "vbe", "js",
        "jar", "ps1", "hta"
    }

    if extension in dangerous_extensions:
        status = "Suspicious"
        message = "Potentially dangerous file type detected"
    else:
        status = "No obvious threat"
        message = "File type is not in the suspicious extension list"

    return {
        "filename": filename,
        "extension": extension,
        "status": status,
        "message": message,
        "hybrid_analysis": "Not configured"
    }

@app.post("/analyze-nlp")
def analyze_nlp(email: str):

    text = email.lower()

    urgency_words = [
        "urgent", "immediately", "asap", "act now",
        "within 24 hours", "verify now", "limited time"
    ]

    threat_words = [
        "suspend", "blocked", "terminate", "warning",
        "security alert", "account locked", "legal action"
    ]

    impersonation_words = [
        "verify your account", "confirm your identity",
        "bank", "paypal", "microsoft", "amazon",
        "google", "administrator", "support team"
    ]

    urgency_matches = [
        word for word in urgency_words if word in text
    ]

    threat_matches = [
        word for word in threat_words if word in text
    ]

    impersonation_matches = [
        word for word in impersonation_words if word in text
    ]

    return {
        "urgency": {
            "detected": len(urgency_matches) > 0,
            "matches": urgency_matches
        },
        "threat": {
            "detected": len(threat_matches) > 0,
            "matches": threat_matches
        },
        "impersonation": {
            "detected": len(impersonation_matches) > 0,
            "matches": impersonation_matches
        }
    }

@app.post("/login")
def login_user(request: LoginRequest):

    db = SessionLocal()

    user = db.query(User).filter(
        User.username == request.username
    ).first()

    if not user:
        db.close()
        return {
            "message": "Invalid username or password"
        }

    try:
        password_hasher.verify(
            user.password_hash,
            request.password
        )
    except Exception:
        db.close()
        return {
            "message": "Invalid username or password"
        }

    totp = pyotp.TOTP(user.totp_secret)

    if not totp.verify(request.totp_code):
        db.close()
        return {
            "message": "Invalid TOTP code"
        }

    username = user.username
    role = user.role

    db.close()

    access_token = create_access_token(
        username,
        role
    )

    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "username": username,
        "role": role
    }

class TOTPVerifyRequest(BaseModel):
    username: str
    totp_code: str


@app.post("/verify-totp")
def verify_totp(request: TOTPVerifyRequest):

    db = SessionLocal()

    user = db.query(User).filter(
        User.username == request.username
    ).first()

    if not user:
        db.close()
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    totp = pyotp.TOTP(user.totp_secret)

    if not totp.verify(request.totp_code):
        db.close()
        raise HTTPException(
            status_code=400,
            detail="Invalid TOTP code"
        )

    db.close()

    return {
        "message": "TOTP verification successful",
        "username": user.username
    }

@app.post("/register")
def register_user(request: RegisterRequest):
    db = SessionLocal()

    existing_user = db.query(User).filter(
        User.username == request.username
    ).first()

    if existing_user:
        db.close()
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    password_hash = password_hasher.hash(request.password)

    # Generate unique TOTP secret
    totp_secret = pyotp.random_base32()

    user = User(
        username=request.username,
        password_hash=password_hash,
        totp_secret=totp_secret,
        role="user"
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # Create Google Authenticator setup URI
    totp = pyotp.TOTP(totp_secret)

    provisioning_uri = totp.provisioning_uri(
        name=user.username,
        issuer_name="PDRS"
    )

    db.close()

    return {
        "message": "User registered successfully",
        "username": user.username,
        "totp_secret": totp_secret,
        "provisioning_uri": provisioning_uri
    }

@app.get("/admin/users")
def get_admin_users(
    current_user: dict = Depends(require_admin)
):

    db = SessionLocal()

    users = db.query(User).all()

    result = []

    for item in users:
        result.append({
            "id": item.id,
            "username": item.username,
            "role": item.role
        })

    db.close()

    return {
        "users": result
    }

@app.put("/admin/users/{user_id}/role")
def update_user_role(
    user_id: int,
    role: str,
    current_user: dict = Depends(require_admin)
):
    db = SessionLocal()

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        db.close()
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if role not in ["user", "admin"]:
        db.close()
        raise HTTPException(
            status_code=400,
            detail="Invalid role"
        )

    old_role = user.role

    user.role = role

    db.commit()

    log = SystemLog(
        action="ROLE_UPDATED",
        username=current_user["username"],
        details=f"Changed {user.username} role from {old_role} to {role}"
    )

    db.add(log)
    db.commit()

    updated_username = user.username
    updated_role = user.role

    db.close()

    return {
        "message": "User role updated successfully",
        "username": updated_username,
        "role": updated_role
    }

@app.get("/fetch-emails")
def fetch_emails():

    try:
        mail = imaplib.IMAP4_SSL(
            os.getenv("IMAP_HOST"),
            int(os.getenv("IMAP_PORT", 993))
        )

        mail.login(
            os.getenv("IMAP_EMAIL"),
            os.getenv("IMAP_PASSWORD")
        )

        mail.select("INBOX")

        status, messages = mail.search(None, "ALL")

        email_ids = messages[0].split()
        emails = []

        for email_id in email_ids[-10:]:

            status, msg_data = mail.fetch(
                email_id,
                "(RFC822)"
            )

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            sender = msg.get("From", "")
            subject = msg.get("Subject", "")

            if subject:
                decoded_subject = decode_header(subject)[0]
                if isinstance(decoded_subject[0], bytes):
                    subject = decoded_subject[0].decode(
                        decoded_subject[1] or "utf-8",
                        errors="ignore"
                    )

            body = ""

            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(
                            decode=True
                        )
                        if payload:
                            body = payload.decode(
                                "utf-8",
                                errors="ignore"
                            )
                            break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(
                        "utf-8",
                        errors="ignore"
                    )

            email_text = f"{subject}\n{body}"

            prediction_result = predict(email_text)

            emails.append({
                "sender": sender,
                "subject": subject,
                "body": body,
                "prediction": prediction_result["prediction"],
                "confidence": prediction_result["confidence"],
                "alert": prediction_result["alert"]
            })

        mail.close()
        mail.logout()

        return {
            "status": "success",
            "count": len(emails),
            "emails": emails
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }

@app.post("/automated-response")
def automated_response(
    sender: str,
    prediction: str,
    confidence: float = Query(..., ge=0, le=100)
):
    db = SessionLocal()

    setting = db.query(SystemSetting).filter(
        SystemSetting.setting_name == "phishing_confidence"
    ).first()

    if setting:
        threshold = setting.setting_value
    else:
        threshold = 90

    prediction = prediction.strip().lower()

    if prediction != "phishing":
        db.close()
        return {
            "action": "None",
            "message": "No automated action required"
        }

    if confidence > threshold:
        action = "Quarantine"
        message = "High-confidence phishing email quarantined"
    else:
        action = "Review"
        message = "Confidence below automated response threshold"

    db.close()

    return {
        "action": action,
        "sender": sender,
        "confidence": round(float(confidence), 2),
        "threshold": threshold,
        "message": message
    }

@app.get("/admin/logs")
def get_admin_logs(
    current_user: dict = Depends(require_admin)
):
    db = SessionLocal()

    logs = db.query(SystemLog).order_by(
        SystemLog.timestamp.desc()
    ).all()

    result = []

    for log in logs:
        result.append({
            "id": log.id,
            "action": log.action,
            "username": log.username,
            "details": log.details,
            "timestamp": log.timestamp
        })

    db.close()

    return {
        "logs": result
    }


@app.get("/admin/settings")
def get_admin_settings(
    current_user: dict = Depends(require_admin)
):
    db = SessionLocal()

    setting = db.query(SystemSetting).filter(
        SystemSetting.setting_name == "phishing_confidence"
    ).first()

    if not setting:
        setting = SystemSetting(
            setting_name="phishing_confidence",
            setting_value=90
        )

        db.add(setting)
        db.commit()
        db.refresh(setting)

    value = setting.setting_value

    db.close()

    return {
        "setting_name": "phishing_confidence",
        "threshold": value
    }


@app.put("/admin/settings")
def update_admin_settings(
    threshold: float,
    current_user: dict = Depends(require_admin)
):
    db = SessionLocal()

    if threshold < 0 or threshold > 100:
        db.close()

        raise HTTPException(
            status_code=400,
            detail="Threshold must be between 0 and 100"
        )

    setting = db.query(SystemSetting).filter(
        SystemSetting.setting_name == "phishing_confidence"
    ).first()

    if not setting:
        setting = SystemSetting(
            setting_name="phishing_confidence",
            setting_value=threshold
        )

        db.add(setting)

    else:
        setting.setting_value = threshold

    db.commit()

    db.close()

    return {
        "message": "Threshold updated successfully",
        "threshold": threshold
    }