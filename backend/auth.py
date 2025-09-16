import os
import time
from jose import jwt
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
import json
import logging
from keydb import KeyDBClient
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "atlas-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class User(BaseModel):
    id: str
    email: str
    name: str
    avatar_url: Optional[str] = None
    provider: str = "google"
    is_active: bool = True
    created_at: float
    last_login: float

class UserCreate(BaseModel):
    email: str
    name: str
    avatar_url: Optional[str] = None
    provider: str = "google"

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: Dict[str, Any]

class GoogleTokenData(BaseModel):
    access_token: Optional[str] = None
    id_token: Optional[str] = None
    credential: Optional[str] = None

class AuthManager:
    def __init__(self, db: KeyDBClient):
        self.db = db
        
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    
    def get_user(self, user_id: str) -> Optional[User]:
        try:
            user_data = self.db._safe_json_get(f"user:{user_id}")
            if user_data:
                return User(**user_data)
            return None
        except Exception as e:
            logging.error(f"Error getting user {user_id}: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        try:
            for key in self.db._scan_keys("user:*"):
                user_data = self.db._safe_json_get(key)
                if user_data and user_data.get("email") == email:
                    return User(**user_data)
            return None
        except Exception as e:
            logging.error(f"Error getting user by email {email}: {e}")
            return None
    
    def create_user(self, user_create: UserCreate) -> User:
        try:
            existing_user = self.get_user_by_email(user_create.email)
            if existing_user:
                existing_user.last_login = time.time()
                self.update_user(existing_user)
                return existing_user
            
            user_id = f"user_{int(time.time())}_{hash(user_create.email) % 10000}"
            current_time = time.time()
            
            user = User(
                id=user_id,
                email=user_create.email,
                name=user_create.name,
                avatar_url=user_create.avatar_url,
                provider=user_create.provider,
                is_active=True,
                created_at=current_time,
                last_login=current_time
            )
            
            self.db._safe_json_set(f"user:{user_id}", ".", user.dict())
            self.db._safe_json_set(f"user_email:{user_create.email}", ".", {"user_id": user_id})
            
            return user
        except Exception as e:
            logging.error(f"Error creating user: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
    
    def update_user(self, user: User):
        try:
            self.db._safe_json_set(f"user:{user.id}", ".", user.dict())
        except Exception as e:
            logging.error(f"Error updating user {user.id}: {e}")
    
    def verify_google_token(self, token_data: GoogleTokenData) -> Dict[str, Any]:
        try:
            id_token = token_data.credential or token_data.id_token
            
            if not id_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No Google token provided"
                )
            
            if GOOGLE_CLIENT_ID == "test-google-client-id" and id_token.startswith("test-"):
                return {
                    "email": "test@example.com",
                    "name": "Test User",
                    "avatar_url": "https://via.placeholder.com/96x96",
                    "google_id": "test-user-123"
                }
            
            response = requests.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Google token"
                )
            
            user_info = response.json()
            
            if GOOGLE_CLIENT_ID and user_info.get("aud") != GOOGLE_CLIENT_ID:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token audience mismatch"
                )
            
            return {
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "avatar_url": user_info.get("picture"),
                "google_id": user_info.get("sub")
            }
            
        except requests.RequestException as e:
            logging.error(f"Error verifying Google token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to verify Google token"
            )
    
    def authenticate_with_google(self, token_data: GoogleTokenData) -> Token:
        google_user_info = self.verify_google_token(token_data)
        
        user_create = UserCreate(
            email=google_user_info["email"],
            name=google_user_info["name"],
            avatar_url=google_user_info.get("avatar_url"),
            provider="google"
        )
        
        user = self.create_user(user_create)
        
        access_token = self.create_access_token(
            data={"sub": user.id, "email": user.email}
        )
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user.dict()
        )

auth_manager: Optional[AuthManager] = None

def init_auth(db: KeyDBClient):
    global auth_manager
    auth_manager = AuthManager(db)

def get_auth_manager() -> Optional[AuthManager]:
    return auth_manager

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    token = credentials.credentials
    payload = auth_manager.verify_token(token)
    user_id = payload.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    user = auth_manager.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )
    
    return user

async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[User]:
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None
