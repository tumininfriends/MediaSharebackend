# Backend - FastAPI

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, func, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
from pydantic import BaseModel
import jwt
import redis
import os
from azure.storage.blob import BlobServiceClient
from datetime import datetime, timedelta
from typing import List
from fastapi.security import OAuth2PasswordBearer
from jwt import decode, ExpiredSignatureError, InvalidTokenError
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Load environment variables
load_dotenv()

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (replace "*" with your frontend URL in production)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"],  # Allows all headers
)
@app.get("/")
def home():
    return {
        "message": "Welcome to the FastAPI Video Sharing App!",
        "endpoints": {
            "Register": "/register",
            "Login": "/login",
            "Upload Media": "/upload",
            "Get Media": "/media",
            "Add Comment": "/comment",
            "Rate Media": "/rate"
        }
    }


# Database Setup
database_url = "mysql+pymysql://rotbun:Rot456bun!@localhost:3306/video1"
engine = create_engine(database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis Cache
cache = redis.Redis(host='localhost', port=6379, db=0)

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)  # Added length
    password_hash = Column(String(255))  # Added length
    role = Column(String(50))  # Added length

class Media(Base):
    __tablename__ = "media"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255))  # Added length
    caption = Column(String(500))  # Added length
    location = Column(String(255))  # Added length
    url = Column(String(2083))  # Added length (max URL length for compatibility)
    media_type = Column(String(50))  # Added length
    upload_time = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    media_id = Column(Integer, ForeignKey("media.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(String(1000))  # Added length

class Rating(Base):
    __tablename__ = "ratings"
    id = Column(Integer, primary_key=True, index=True)
    media_id = Column(Integer, ForeignKey("media.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Integer)  # Integer type doesn't require length


# Authentication
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class UserLogin(BaseModel):
    username: str
    password: str

class CommentCreate(BaseModel):
    media_id: int
    content: str

class RatingCreate(BaseModel):
    media_id: int
    rating: int

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/register")
@app.options("/register")  # Explicitly allow OPTIONS method
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the username already exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Hash the password and create a new user
    hashed_password = password_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password, role=user.role)
    db.add(new_user)
    db.commit()

    # Return a success message with a redirect URL
    return {
        "message": "User registered successfully",
        "redirect_url": "/login"  # Frontend will handle the redirection
    }

@app.post("/login")
@app.options("/login")  # Explicitly allow OPTIONS method
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not password_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Include the user's role in the token
    access_token = create_access_token(
        {"sub": user.username, "role": db_user.role},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    media_type: str = "photo",
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    try:
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if role != "creator":
            raise HTTPException(status_code=403, detail="Only creators can upload media")

        # Get the user ID from the database
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Upload to Azure Blob Storage
        connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
        if not connection_string:
            raise HTTPException(status_code=500, detail="Azure Storage connection string is not set")

        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.get_container_client("media")
        blob_client = container_client.get_blob_client(file.filename)
        blob_client.upload_blob(file.file.read())

        # Save metadata
        new_media = Media(
            title=file.filename,
            caption="Sample Caption",
            location="Unknown",
            url=blob_client.url,
            media_type=media_type,
            user_id=user.id  # Use the authenticated user's ID
        )

        db.add(new_media)
        db.commit()
        return {"url": blob_client.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/media")
def get_media(
    db: Session = Depends(get_db),
    title: str = Query(None),
    location: str = Query(None),
    media_type: str = Query(None),
    min_rating: int = Query(None),
    sort_by: str = Query("upload_time"),
    sort_order: str = Query("desc"),
    skip: int = Query(0),
    limit: int = Query(10)
):
    # Base query
    query = db.query(Media)

    # Apply filters
    if title:
        query = query.filter(Media.title.ilike(f"%{title}%"))
    if location:
        query = query.filter(Media.location.ilike(f"%{location}%"))
    if media_type:
        query = query.filter(Media.media_type == media_type)
    if min_rating:
        query = query.join(Rating).group_by(Media.id).having(func.avg(Rating.rating) >= min_rating)

    # Apply sorting
    if sort_by in ["upload_time", "title"] and sort_order in ["asc", "desc"]:
        query = query.order_by(getattr(getattr(Media, sort_by), sort_order)())

    # Apply pagination
    media_items = query.offset(skip).limit(limit).all()

    # Include comments and ratings for each media item
    for media in media_items:
        media.comments = db.query(Comment).filter(Comment.media_id == media.id).all()
        media.ratings = db.query(Rating).filter(Rating.media_id == media.id).all()

    return media_items

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"username": username, "role": role}
    except (ExpiredSignatureError, InvalidTokenError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/comment")
def add_comment(comment: CommentCreate, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_comment = Comment(media_id=comment.media_id, content=comment.content, user_id=user.id)
    db.add(new_comment)
    db.commit()
    return {"message": "Comment added"}

@app.post("/rate")
def rate_media(rating: RatingCreate, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_rating = Rating(media_id=rating.media_id, rating=rating.rating, user_id=user.id)
    db.add(new_rating)
    db.commit()
    return {"message": "Rating added"}

def seed_database(db: Session):
    # Add default users
    users = [
        User(username="user1", password_hash=password_context.hash("password1"), role="user"),
        User(username="creator1", password_hash=password_context.hash("password1"), role="creator"),
    ]
    db.add_all(users)
    db.commit()

    # Add default media
    media = [
        Media(title="Sunset at the Beach", caption="Beautiful sunset", location="Beach", url="https://via.placeholder.com/300x200", media_type="photo", user_id=1),
        Media(title="Mountain Adventure", caption="Hiking in the mountains", location="Mountains", url="https://www.w3schools.com/html/mov_bbb.mp4", media_type="video", user_id=2),
    ]
    db.add_all(media)
    db.commit()

    # Add default comments and ratings
    comments = [
        Comment(media_id=1, user_id=1, content="Amazing photo!"),
        Comment(media_id=2, user_id=2, content="Great video!"),
    ]
    ratings = [
        Rating(media_id=1, user_id=1, rating=5),
        Rating(media_id=2, user_id=2, rating=4),
    ]
    db.add_all(comments)
    db.add_all(ratings)
    db.commit()

# Call this function to seed the database
if __name__ == "__main__":
    db = SessionLocal()
   
def init_db():
    Base.metadata.create_all(bind=engine)
if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
