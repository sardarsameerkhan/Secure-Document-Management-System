import os
import base64
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Storage Boundary: Encrypted binary files are stored on disk outside the database
STORAGE_DIR = BASE_DIR / "storage" / "vault"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Metadata Boundary: User accounts, ACLs, wrapped keys, and audit logs live in SQLite
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'sdms.db'}")

# Session signing secret
SECRET_KEY = os.getenv("SECRET_KEY", "sdms-fast-nuces-session-secret-2026-x9z8")

# Cryptographic Boundary: 256-bit Master Key Encryption Key (KEK)
# Used ONLY to wrap/unwrap per-document Data Encryption Keys (DEKs).
_RAW_KEK = os.getenv("MASTER_KEK_B64")
if _RAW_KEK:
    MASTER_KEK = base64.b64decode(_RAW_KEK)
else:
    # 32-byte deterministic dev key so evaluators can run the ZIP out-of-the-box
    MASTER_KEK = b"FAST_NUCES_SDMS_MASTER_KEK_2026!"

# HMAC key for tamper-evident audit log chaining
AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY", "sdms-audit-hmac-integrity-key-2026").encode()