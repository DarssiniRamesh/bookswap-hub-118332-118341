from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, Text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime, timedelta
from typing import List, Optional
import jwt
import os
from passlib.context import CryptContext

# ======== SETTINGS & DB INIT ========
DATABASE_URL = os.getenv("POSTGRES_URL", "postgresql://localhost/bookswap")
SECRET_KEY = os.getenv("SECRET_KEY", "changemeplease")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# ============ ORM MODELS ============

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False, index=True)
    full_name = Column(String(128), nullable=True)
    hashed_password = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    books = relationship("Book", back_populates="owner")
    swap_requests_sent = relationship("SwapRequest", foreign_keys="SwapRequest.requester_id", back_populates="requester")
    swap_requests_received = relationship("SwapRequest", foreign_keys="SwapRequest.book_owner_id", back_populates="book_owner")
    notifications = relationship("Notification", back_populates="user")

class Book(Base):
    __tablename__ = "books"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), index=True)
    author = Column(String(180), nullable=True)
    description = Column(Text, nullable=True)
    listed_at = Column(DateTime, default=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    is_available = Column(Boolean, default=True)

    owner = relationship("User", back_populates="books")
    swap_requests = relationship("SwapRequest", back_populates="book")

class SwapRequest(Base):
    __tablename__ = "swap_requests"
    id = Column(Integer, primary_key=True, index=True)
    book_id = Column(Integer, ForeignKey('books.id'), nullable=False)
    requester_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    book_owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    status = Column(String(24), default="pending")  # pending, accepted, rejected, completed
    requested_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    book = relationship("Book", back_populates="swap_requests")
    requester = relationship("User", foreign_keys=[requester_id], back_populates="swap_requests_sent")
    book_owner = relationship("User", foreign_keys=[book_owner_id], back_populates="swap_requests_received")

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)

    user = relationship("User", back_populates="notifications")


# =========== SCHEMAS (Pydantic) ===========

class UserBase(BaseModel):
    username: str = Field(..., max_length=64)
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserPublic(UserBase):
    id: int
    full_name: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True

class UserProfile(UserPublic):
    books: List["BookPublic"] = []
    # No swap_requests

class BookBase(BaseModel):
    title: str
    author: Optional[str] = None
    description: Optional[str] = None

class BookCreate(BookBase):
    pass

class BookPublic(BookBase):
    id: int
    owner_id: int
    is_available: bool
    listed_at: datetime

    class Config:
        orm_mode = True

class SwapRequestBase(BaseModel):
    book_id: int

class SwapRequestCreate(SwapRequestBase):
    pass

class SwapRequestUpdate(BaseModel):
    status: str = Field(..., description="Must be one of: pending, accepted, rejected, completed")

class SwapRequestPublic(BaseModel):
    id: int
    book_id: int
    requester_id: int
    book_owner_id: int
    status: str
    requested_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class NotificationPublic(BaseModel):
    id: int
    user_id: int
    message: str
    created_at: datetime
    is_read: bool

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ============= UTILS =============

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    # PUBLIC_INTERFACE
    """Decode JWT and retrieve the current user from DB. Throws HTTPException on failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise credentials_exception
    return user

# ============== FASTAPI APP & CORS ==============
app = FastAPI(
    title="Bookswap Hub API",
    description="Backend API for the Bookswap Hub platform. Allows book listings, swaps, notifications and user management.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Auth", "description": "Authentication and registration operations."},
        {"name": "Users", "description": "User profile management."},
        {"name": "Books", "description": "Manage and browse books."},
        {"name": "SwapRequests", "description": "Initiate and track book swap requests."},
        {"name": "Notifications", "description": "User notifications."},
    ]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development -- restrict this in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------- DB Tables Create ------------
@app.on_event("startup")
def on_startup():
    """Ensure tables are created at startup."""
    Base.metadata.create_all(bind=engine)

# ============ AUTH ROUTES =============
@app.post("/auth/register", response_model=UserPublic, tags=["Auth"], summary="Register a new user")
# PUBLIC_INTERFACE
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user, checks for unique username/email, and returns the public user profile."""
    if db.query(User).filter((User.username == user.username) | (User.email == user.email)).first():
        raise HTTPException(400, "Username or email already registered.")
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/auth/token", response_model=Token, tags=["Auth"], summary="User login and JWT issuance")
# PUBLIC_INTERFACE
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate a user, return JWT token if successful."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is inactive.")
    access_token = create_access_token({"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

# ============ USER ROUTES =============
@app.get("/users/me", response_model=UserProfile, tags=["Users"], summary="Get current user's profile")
# PUBLIC_INTERFACE
def get_my_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user's profile along with listed books."""
    return current_user

@app.get("/users/{user_id}", response_model=UserProfile, tags=["Users"], summary="Get other user's public profile")
# PUBLIC_INTERFACE
def get_profile(user_id: int, db: Session = Depends(get_db)):
    """Get profile and books for a given user id."""
    db_user = db.query(User).filter(User.id == user_id, User.is_active).first()
    if not db_user:
        raise HTTPException(404, "User not found")
    return db_user

# ========== BOOK ROUTES ==============
@app.post("/books/", response_model=BookPublic, tags=["Books"], summary="Add a new book")
# PUBLIC_INTERFACE
def create_book(book: BookCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """List a new book for swapping (must be authenticated)."""
    db_book = Book(**book.model_dump(), owner_id=user.id)
    db.add(db_book)
    db.commit()
    db.refresh(db_book)
    return db_book

@app.get("/books/", response_model=List[BookPublic], tags=["Books"], summary="List all available books")
# PUBLIC_INTERFACE
def list_books(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List all books available for swap. Sorted newest-first."""
    books = db.query(Book).filter(Book.is_available).order_by(Book.listed_at.desc()).offset(skip).limit(limit).all()
    return books

@app.get("/books/{book_id}", response_model=BookPublic, tags=["Books"], summary="Get details for a book")
# PUBLIC_INTERFACE
def get_book(book_id: int, db: Session = Depends(get_db)):
    """Returns details about a specific book."""
    db_book = db.query(Book).filter(Book.id==book_id).first()
    if not db_book:
        raise HTTPException(404, "Book not found")
    return db_book

@app.patch("/books/{book_id}", response_model=BookPublic, tags=["Books"], summary="Update a listed book")
# PUBLIC_INTERFACE
def update_book(book_id: int, book: BookCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Allows the owner to update book details."""
    db_book = db.query(Book).filter(Book.id==book_id).first()
    if not db_book:
        raise HTTPException(404, "Book not found")
    if db_book.owner_id != user.id:
        raise HTTPException(403, "Not allowed to update this book")
    for attr, value in book.model_dump().items():
        setattr(db_book, attr, value)
    db.commit()
    db.refresh(db_book)
    return db_book

@app.delete("/books/{book_id}", tags=["Books"], summary="Delete book listing")
# PUBLIC_INTERFACE
def delete_book(book_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Allows the owner to delete (unlist) book."""
    db_book = db.query(Book).filter(Book.id==book_id).first()
    if not db_book or db_book.owner_id != user.id:
        raise HTTPException(403, "Not allowed or book missing")
    db.delete(db_book)
    db.commit()
    return {"message": "Book deleted."}

# =========== SWAP ROUTES =============
@app.post("/swaps/", response_model=SwapRequestPublic, tags=["SwapRequests"], summary="Request a swap for a book")
# PUBLIC_INTERFACE
def create_swap(swap: SwapRequestCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Request a swap for a book. The book must be available, and you can't request your own book."""
    db_book = db.query(Book).filter(Book.id == swap.book_id, Book.is_available).first()
    if not db_book:
        raise HTTPException(404, "Book not found/available")
    if db_book.owner_id == user.id:
        raise HTTPException(400, "You cannot request your own book")
    # Only one pending swap per book per user
    pending = db.query(SwapRequest).filter_by(
        book_id=db_book.id, requester_id=user.id, status="pending"
    ).first()
    if pending:
        raise HTTPException(400, "You already have a pending swap for this book.")
    swap_req = SwapRequest(book_id=db_book.id, requester_id=user.id, book_owner_id=db_book.owner_id)
    db.add(swap_req)
    db.commit()
    db.refresh(swap_req)
    # Notify owner
    notification = Notification(
        user_id=db_book.owner_id,
        message=f"New swap request for your book '{db_book.title}' from {user.username}"
    )
    db.add(notification)
    db.commit()
    return swap_req

@app.get("/swaps/sent", response_model=List[SwapRequestPublic], tags=["SwapRequests"], summary="My outgoing swap requests")
# PUBLIC_INTERFACE
def my_sent_swaps(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """List swap requests I have sent."""
    return db.query(SwapRequest).filter(SwapRequest.requester_id == user.id).order_by(SwapRequest.requested_at.desc()).all()

@app.get("/swaps/received", response_model=List[SwapRequestPublic], tags=["SwapRequests"], summary="Requests for my books")
# PUBLIC_INTERFACE
def my_received_swaps(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """List swap requests received for my books."""
    return db.query(SwapRequest).filter(SwapRequest.book_owner_id == user.id).order_by(SwapRequest.requested_at.desc()).all()

@app.patch("/swaps/{swap_id}", response_model=SwapRequestPublic, tags=["SwapRequests"], summary="Update (accept/reject/complete) swap request")
# PUBLIC_INTERFACE
def act_on_swap(
    swap_id: int,
    update: SwapRequestUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Book owner can accept or reject; requester can mark complete after swap."""
    swap = db.query(SwapRequest).filter(SwapRequest.id==swap_id).first()
    if not swap:
        raise HTTPException(404, "Swap request not found")
    if update.status not in ["pending", "accepted", "rejected", "completed"]:
        raise HTTPException(400, "Invalid status update")
    old_status = swap.status
    # Permissions by operation
    if update.status in ["accepted", "rejected"]:
        if swap.book_owner_id != user.id:
            raise HTTPException(403, "Only the book owner can accept/reject swaps")
        swap.status = update.status
        swap.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(swap)
        # Notify requester
        notif_msg = f"Your swap request for '{swap.book.title}' has been {update.status}."
        notification = Notification(user_id=swap.requester_id, message=notif_msg)
        db.add(notification)
        db.commit()
        # On accepted, set book unavailable
        if update.status == "accepted":
            swap.book.is_available = False
            db.commit()
        return swap
    elif update.status == "completed":
        if swap.requester_id != user.id or old_status != "accepted":
            raise HTTPException(403, "Requester may only mark as completed after accepted")
        swap.status = "completed"
        swap.updated_at = datetime.utcnow()
        db.commit()
        swap.book.is_available = True
        db.commit()
        # Notify owner
        notification = Notification(user_id=swap.book_owner_id, message=f"Swap for '{swap.book.title}' completed!")
        db.add(notification)
        db.commit()
        return swap
    else:
        raise HTTPException(400, "Unsupported operation.")

# ========== NOTIFICATIONS =============
@app.get("/notifications/", response_model=List[NotificationPublic], tags=["Notifications"], summary="View my notifications")
# PUBLIC_INTERFACE
def list_my_notifications(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Get all notifications for the current user, newest first."""
    return db.query(Notification).filter(Notification.user_id == user.id).order_by(Notification.created_at.desc()).all()

@app.patch("/notifications/{notification_id}/read", tags=["Notifications"], summary="Mark notification as read")
# PUBLIC_INTERFACE
def mark_notification_read(notification_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Mark a notification as read."""
    notif = db.query(Notification).filter(Notification.id == notification_id, Notification.user_id == user.id).first()
    if not notif:
        raise HTTPException(404, "Notification not found")
    notif.is_read = True
    db.commit()
    return {"message": "Notification marked as read."}

# --------- HEALTH ----------
@app.get("/", summary="Health check", tags=["Users"])
def health_check():
    """Basic health check endpoint."""
    return {"message": "Healthy"}

# ========= OPENAPI PATCHES =========
# Swagger will have full schema, routes, request & response models, JWT security doc.

# ========== SCHEMA ADJUSTMENTS ======
UserProfile.model_rebuild()
BookPublic.model_rebuild()
SwapRequestPublic.model_rebuild()
NotificationPublic.model_rebuild()
