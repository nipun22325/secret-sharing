"""
main.py - A FastAPI-based service for secure, disposable secret sharing.

This API allows clients to create secrets that can be retrieved only once and
expire after a set duration. Optional password protection and QR code generation
are supported.
"""

import os
import io
import asyncio
import base64
import string
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pymongo import MongoClient
import qrcode
import uvicorn
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

app = FastAPI(title="Disposable Secret Sharing API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB setup
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://admin:123456@localhost:27017/?authSource=admin")
client = MongoClient(MONGODB_URL)
db = client["secrets_db"]
secrets_collection = db.secrets
stats_collection = db.stats

# Encryption key setup
key_env = os.getenv("SECRET_ENCRYPTION_KEY")
if key_env:
    key = base64.b64decode(key_env)
else:
    key = ChaCha20Poly1305.generate_key()
    print(f"Generated encryption key (store this securely!): {base64.b64encode(key).decode()}")

chacha = ChaCha20Poly1305(key)


class SecretCreate(BaseModel):
    """Model for creating a secret."""
    content: str = Field(..., min_length=1, max_length=10000)
    ttl_hours: Optional[int] = Field(default=24, ge=1, le=168)
    password_protected: Optional[bool] = False
    access_password: Optional[str] = None


class SecretResponse(BaseModel):
    """Model returned after a secret is created."""
    secret_id: str
    expires_at: datetime
    qr_code: Optional[str] = None


class SecretRetrieve(BaseModel):
    """Model used to retrieve a secret."""
    access_password: Optional[str] = None


class SecretContent(BaseModel):
    """Model containing decrypted secret content."""
    content: str
    created_at: datetime
    expires_at: datetime


class StatsResponse(BaseModel):
    """Model for statistics reporting."""
    total_secrets_created: int
    total_secrets_viewed: int
    active_secrets: int


def generate_secret_id(length: int = 8) -> str:
    """
    Generates a random alphanumeric secret ID.

    Args:
        length (int): The desired length of the secret ID.

    Returns:
        str: A randomly generated string.
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_password(password: str) -> str:
    """
    Hashes a password using SHA-256.

    Args:
        password (str): The plain text password.

    Returns:
        str: The hashed password.
    """
    return hashlib.sha256(password.encode()).hexdigest()


def encrypt_content(content: str) -> tuple:
    """
    Encrypts content using ChaCha20Poly1305.

    Args:
        content (str): Plain text content.

    Returns:
        tuple: A tuple of base64-encoded encrypted content and nonce.
    """
    nonce = os.urandom(12)
    encrypted = chacha.encrypt(nonce, content.encode(), None)
    return base64.b64encode(encrypted).decode(), base64.b64encode(nonce).decode()


def decrypt_content(encrypted_content_b64: str, nonce_b64: str) -> str:
    """
    Decrypts base64-encoded encrypted content using ChaCha20Poly1305.

    Args:
        encrypted_content_b64 (str): Base64 encoded ciphertext.
        nonce_b64 (str): Base64 encoded nonce.

    Returns:
        str: Decrypted plain text.
    """
    encrypted_content = base64.b64decode(encrypted_content_b64)
    nonce = base64.b64decode(nonce_b64)
    return chacha.decrypt(nonce, encrypted_content, None).decode()


def generate_qr_code(url: str) -> str:
    """
    Generates a base64-encoded PNG QR code from a URL.

    Args:
        url (str): The URL to encode.

    Returns:
        str: Base64-encoded PNG image.
    """
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode()


async def cleanup_expired_secrets():
    """
    Deletes expired secrets from the database.

    Returns:
        int: The number of secrets that were deleted.
    """
    current_time = datetime.utcnow()
    result = await asyncio.to_thread(
        secrets_collection.delete_many,
        {"expires_at": {"$lt": current_time}}
    )
    return result.deleted_count


@app.on_event("startup")
async def startup_event():
    """
    Initializes database indexes and sets up initial statistics on application startup.
    """
    await asyncio.to_thread(secrets_collection.create_index, "secret_id", unique=True)
    await asyncio.to_thread(secrets_collection.create_index, "expires_at", expireAfterSeconds=0)
    existing_stats = await asyncio.to_thread(stats_collection.find_one, {"_id": "global"})
    if not existing_stats:
        await asyncio.to_thread(
            stats_collection.insert_one,
            {"_id": "global", "total_created": 0, "total_viewed": 0}
        )


@app.post("/api/secrets", response_model=SecretResponse)
async def create_secret(secret_data: SecretCreate):
    """
    Creates a new encrypted secret with optional password protection and TTL.

    Args:
        secret_data (SecretCreate): The secret payload and settings.

    Returns:
        SecretResponse: Metadata including ID, expiration, and QR code.
    """
    while True:
        secret_id = generate_secret_id()
        existing = await asyncio.to_thread(secrets_collection.find_one, {"secret_id": secret_id})
        if not existing:
            break

    expires_at = datetime.utcnow() + timedelta(hours=secret_data.ttl_hours)
    encrypted_content, nonce = encrypt_content(secret_data.content)

    secret_doc = {
        "secret_id": secret_id,
        "encrypted_content": encrypted_content,
        "nonce": nonce,
        "created_at": datetime.utcnow(),
        "expires_at": expires_at,
        "viewed": False,
        "password_protected": secret_data.password_protected
    }

    if secret_data.password_protected and secret_data.access_password:
        secret_doc["password_hash"] = hash_password(secret_data.access_password)

    await asyncio.to_thread(secrets_collection.insert_one, secret_doc)
    await asyncio.to_thread(
        stats_collection.update_one,
        {"_id": "global"},
        {"$inc": {"total_created": 1}}
    )

    secret_url = f"http://localhost:8000/view/{secret_id}"
    qr_code = generate_qr_code(secret_url)

    return SecretResponse(secret_id=secret_id, expires_at=expires_at, qr_code=qr_code)


@app.post("/api/secrets/{secret_id}", response_model=SecretContent)
async def get_secret(secret_id: str, retrieve_data: SecretRetrieve = SecretRetrieve()):
    """
    Retrieves and decrypts a secret if it exists and hasn't been viewed.

    Args:
        secret_id (str): The unique identifier of the secret.
        retrieve_data (SecretRetrieve): Optional password data for validation.

    Returns:
        SecretContent: The decrypted secret and metadata.

    Raises:
        HTTPException: If secret not found, expired, viewed, or invalid password.
    """
    await cleanup_expired_secrets()
    secret_doc = await asyncio.to_thread(secrets_collection.find_one, {"secret_id": secret_id})

    if not secret_doc:
        raise HTTPException(status_code=404, detail="Secret not found or has expired")

    if secret_doc.get("viewed", False):
        raise HTTPException(status_code=410, detail="Secret has already been viewed")

    if secret_doc.get("password_protected", False):
        if not retrieve_data.access_password:
            raise HTTPException(status_code=401, detail="Password required")
        if hash_password(retrieve_data.access_password) != secret_doc.get("password_hash"):
            raise HTTPException(status_code=401, detail="Invalid password")

    try:
        decrypted_content = decrypt_content(
            secret_doc["encrypted_content"],
            secret_doc["nonce"]
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to decrypt secret") from exc

    await asyncio.to_thread(
        secrets_collection.update_one,
        {"secret_id": secret_id},
        {"$set": {"viewed": True}}
    )
    await asyncio.to_thread(
        stats_collection.update_one,
        {"_id": "global"},
        {"$inc": {"total_viewed": 1}}
    )

    return SecretContent(
        content=decrypted_content,
        created_at=secret_doc["created_at"],
        expires_at=secret_doc["expires_at"]
    )


@app.get("/api/secrets/{secret_id}/info")
async def get_secret_info(secret_id: str):
    """
    Returns metadata for a given secret without revealing its content.

    Args:
        secret_id (str): The unique identifier of the secret.

    Returns:
        dict: Info including timestamps, protection, and view status.
    """
    secret_doc = await asyncio.to_thread(
        secrets_collection.find_one,
        {"secret_id": secret_id},
        {"created_at": 1, "expires_at": 1, "password_protected": 1, "viewed": 1}
    )

    if not secret_doc:
        raise HTTPException(status_code=404, detail="Secret not found or has expired")

    return {
        "exists": True,
        "created_at": secret_doc["created_at"],
        "expires_at": secret_doc["expires_at"],
        "password_protected": secret_doc.get("password_protected", False),
        "viewed": secret_doc.get("viewed", False)
    }


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """
    Returns usage statistics such as total secrets created/viewed and currently active secrets.

    Returns:
        StatsResponse: Statistics object with aggregated counters.
    """
    await cleanup_expired_secrets()
    stats_doc = await asyncio.to_thread(stats_collection.find_one, {"_id": "global"})
    active_count = await asyncio.to_thread(secrets_collection.count_documents, {})

    if not stats_doc:
        stats_doc = {"total_created": 0, "total_viewed": 0}

    return StatsResponse(
        total_secrets_created=stats_doc.get("total_created", 0),
        total_secrets_viewed=stats_doc.get("total_viewed", 0),
        active_secrets=active_count
    )


@app.delete("/api/admin/cleanup")
async def cleanup_expired():
    """
    Manually triggers cleanup of all expired secrets.

    Returns:
        dict: Count of deleted documents.
    """
    deleted_count = await cleanup_expired_secrets()
    return {"deleted_count": deleted_count}


@app.get("/")
async def root():
    """
    Health check route for the API root.

    Returns:
        dict: A simple status message.
    """
    return {"message": "Disposable Secret Sharing API is running"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
