# 🔐 Phantom Share

A secure, self-destructing secret sharing service built with FastAPI and MongoDB using the ChaCha20Poly1305 encryption scheme. Share sensitive information with automatic expiration and "burn after reading" functionality.

## Overview

Phantom Share is a secure service for sharing sensitive information through time-limited, one-time-access links. Each secret is:

- Encrypted with Fernet symmetric encryption
- Self-destructing after being viewed
- Protected with optional passwords
- Accessible via generated QR codes
- Automatically expired after a set time period (1-168 hours)

The service provides a REST API built with FastAPI and uses MongoDB for temporary secret storage. All stored data is automatically cleaned up after expiration.

## Features

- 🔥 Burn After Reading: Secrets are automatically destroyed after they are viewed and their TTL runs out
- ⏰ Time-based Expiration: Set custom TTL (1-168 hours) for secrets
- 🔒 Password Protection: Optional password protection for sensitive secrets
- 📱 QR Code Generation: Automatic QR codes for easy mobile sharing
- 🔐 End-to-End Encryption: All secrets encrypted with Fernet symmetric encryption
- 📊 Usage Statistics: Track total secrets created, viewed, and active
- 🧹 Auto-cleanup: Automatic removal of expired secrets
- 🌐 CORS Enabled: Ready for web frontend integration

## Requirements

- Python 3.8+
- Docker Desktop
- pip

## Usage

### Installation

1. Clone the repository:

```bash
git clone https://github.com/nipun22325/secret-sharing
cd secret-sharing
```

2. Install the required dependencies:

```bash
pip install requirements.txt
```

3. Start MongoDB with Docker:

Using Docker (recommended)

```bash
docker run -d -p 27017:27017 --name mongo-test -e MONGO_INITDB_ROOT_USERNAME=admin -e MONGO_INITDB_ROOT_PASSWORD=password123 mongo
```

Or install MongoDB locally

Make sure your database is running and then continue with the next step.

4. Start the FastAPI server:

```bash
python main.py
```

The API will be available at `http://127.0.0.1:8000`

### API Usage using cURL

```bash
# Create a new secret
curl -X POST "http://127.0.0.1:8000/api/secrets" -H "Content-Type: application/json" -d '{"content": "This is a secret from curl", "ttl_hours": 24, "password_protected": true, "access_password" : "pass"}'
```

The response is like this:
{
  "secret_id": "AbC123Xy",
  "expires_at": "2025-05-27T12:00:00.000000",
  "qr_code": "base64-encoded-qr-code-image"
}

```bash
# Get info about a secret like when it was created and when it expires without viewing the contents
curl http://127.0.0.1:8000/api/secrets/{secret_id}/info 
```

The response is like this:
{
  "exists": true,
  "created_at": "2025-05-26T12:00:00.000000",
  "expires_at": "2025-05-27T12:00:00.000000",
  "password_protected": true,
  "viewed": false
}

```bash
#Get stats about total secrets created/viewed and number of active secrets
curl http://127.0.0.1:8000/api/stats
```

The response is like this:
{
  "total_secrets_created": 42,
  "total_secrets_viewed": 35,
  "active_secrets": 7
}

```bash
# Retrieve a password protected secret
curl -X POST http://127.0.0.1:8000/api/secrets/{secret_id} -H "Content-Type: application/json" -d '{"access_password": "pass"}'
```

The response is like this:
{
  "content": "Your secret message here",
  "created_at": "2025-05-26T12:00:00.000000",
  "expires_at": "2025-05-27T12:00:00.000000"
}

## Security Considerations

This implementation should be used with caution in production environments. Always ensure proper security measures are in place when handling sensitive information.
