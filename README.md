# Secure Document Management System (SDMS)

A zero-trust, enterprise-grade document management web application engineered with envelope encryption, discretionary and role-based access control, strict storage separation, and tamper-evident cryptographic audit logging.

---

## Table of Contents
1. [System Overview](#system-overview)
2. [Core Security Architecture](#core-security-architecture)
3. [Project Structure](#project-structure)
4. [Quick Setup & Execution](#quick-setup--execution)
5. [User Roles & Access Control Matrix](#user-roles--access-control-matrix)
6. [REST API Reference](#rest-api-reference)
7. [Adversarial Security Test Suite](#adversarial-security-test-suite)
8. [Design Decision Records (Summary)](#design-decision-records-summary)

---

## System Overview

Standard web file-storage applications frequently store uploaded files directly on disk in plaintext, expose sequential database identifiers vulnerable to enumeration, or rely on mutable logs that attackers can alter to hide intrusions.

**SDMS** eliminates these vulnerabilities by enforcing four isolated security boundaries:
- **Identity & Session Boundary:** Memory-hard **Argon2id** password hashing paired with cryptographically signed, timed `HttpOnly` + `SameSite=Lax` cookies.
- **Cryptographic Envelope Boundary:** Per-document 256-bit **AES-256-GCM** Data Encryption Keys (DEKs) bound to each document's UUID via Associated Authenticated Data (AAD), wrapped by a separated Master Key Encryption Key (KEK).
- **Storage Separation Boundary:** Encrypted binary payloads (`*.enc`) are written to `storage/vault/` under random hexadecimal filenames, completely decoupled from relational metadata in SQLite (`sdms.db`).
- **Tamper-Evident Audit Boundary:** Every security event is appended to an **HMAC-SHA256 hash-chained ledger**, enabling instant detection of unauthorized SQL edits or row deletions.

---

## Core Security Architecture

```text
┌──────────────────────────────────────────────────────────────────────┐
│                        Browser Client (Workspace UI)                 │
│     • Drag-and-drop encrypted upload   • Share & revocation modal    │
│     • Cryptographic metadata drawer    • Admin audit ledger viewer   │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │ Signed HttpOnly Session Cookie
                                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     FastAPI Application & Security Layer             │
│  ┌────────────────┐  ┌───────────────────┐  ┌─────────────────────┐  │
│  │ Auth Service   │  │ DAC / RBAC Guard  │  │ HMAC Audit Service  │  │
│  │ (Argon2id +    │  │ (Server-side ACL  │  │ (Hash-chained       │  │
│  │  itsdangerous) │  │  & UUIDv4 lookup) │  │  tamper detection)  │  │
│  └────────────────┘  └───────────────────┘  └─────────────────────┘  │
└──────────────┬───────────────────────────────────┬───────────────────┘
               │                                   │
               ▼                                   ▼
┌──────────────────────────────┐    ┌──────────────────────────────────┐
│   SQLite Metadata Database   │    │    Isolated Encrypted Vault      │
│          (sdms.db)           │    │       (storage/vault/*.enc)      │
│ • Users & Argon2id hashes    │    │ • Pure AES-256-GCM ciphertext    │
│ • Document ACL permissions   │    │ • Random 32-hex blob filenames   │
│ • KEK-wrapped DEKs & nonces  │    │ • Zero plaintext or keys on disk │
│ • Dual SHA-256 digests       │    │                                  │
│ • HMAC-chained audit records │    │                                  │
└──────────────────────────────┘    └──────────────────────────────────┘
Cryptographic Lifecycle (Upload & Download)
Upload:

Computes plaintext_sha256 of the incoming byte stream.

Generates a fresh 256-bit random DEK and 96-bit random nonces (file_nonce, dek_nonce).

Encrypts file contents using AES-256-GCM with the document's UUIDv4 passed as AAD (preventing ciphertext swapping across records).

Wraps the DEK with the server's MASTER_KEK using AES-256-GCM.

Writes ciphertext to storage/vault/<random_hex>.enc and stores only the wrapped DEK, nonces, and SHA-256 seals in SQLite.

Download & Integrity Verification:

Verifies the user's server-side permission (Owner, Editor, or Viewer).

Validates ciphertext_sha256 of the vault file before decryption.

Unwraps the DEK with MASTER_KEK, decrypts the payload while verifying the GCM 16-byte authentication tag and AAD, and confirms plaintext_sha256.

Any external byte modification triggers an HTTP 409 Conflict (INTEGRITY_ALERT) and records an alert in the audit log.

Project Structure
Secure-Document-Management-System/
├── app/
│   ├── core/
│   │   ├── config.py              # Environment configuration & cryptographic key loading
│   │   └── database.py            # SQLAlchemy engine & session lifecycle
│   ├── models/
│   │   └── entities.py            # User, Document, DocumentPermission, and AuditLog schemas
│   ├── routes/
│   │   ├── auth_routes.py         # Registration, login, logout, and session identity endpoints
│   │   ├── doc_routes.py          # Encrypted upload, download, update, share, revoke, delete
│   │   └── admin_routes.py        # Audit ledger retrieval & HMAC chain verification endpoints
│   ├── services/
│   │   ├── auth_service.py        # Argon2id password hashing & signed HttpOnly cookie tokens
│   │   ├── crypto_service.py      # AES-256-GCM envelope encryption, key wrapping & SHA-256 checks
│   │   ├── document_service.py    # Server-side DAC enforcement & vault file orchestration
│   │   └── audit_service.py       # Append-only HMAC-SHA256 hash-chained audit logging
│   ├── templates/
│   │   └── index.html             # Single-page enterprise workspace & admin audit UI
│   └── main.py                    # FastAPI application entrypoint & security headers middleware
├── docs/
│   └── sample_data/               # Non-sensitive sample files for testing & demonstration
├── storage/
│   └── vault/                     # Isolated directory for encrypted *.enc binary blobs
├── tests/
│   └── test_security_scenarios.py # Automated pytest suite covering all 7 adversarial scenarios
├── pytest.ini                     # Pytest configuration
├── requirements.txt               # Pinned Python dependencies
└── README.md                      # Project documentation
Quick Setup & Execution
Prerequisites
Python 3.11 or higher

Git
# 1. Clone the repository
git clone [https://github.com/sardarsameer74/Secure-Document-Management-System.git](https://github.com/sardarsameer74/Secure-Document-Management-System.git)
cd Secure-Document-Management-System

# 2. Create and activate a virtual environment
python -m venv venv
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
# source venv/bin/activate

# 3. Install required packages
pip install -r requirements.txt

# 4. Start the FastAPI server
python -m uvicorn app.main:app --reload
Open http://127.0.0.1:8000 in your web browser.
User Roles & Access Control MatrixSDMS combines Discretionary Access Control (DAC) at the document level with Role-Based Access Control (RBAC) and Least Privilege at the system level:CapabilityDocument OwnerShared EditorShared ViewerSystem Admin (Auditor)Unauthenticated / Other UserDecrypt & Download DocumentYesYesYesNo (403)No (403)Upload Updated File VersionYesYesNo (403)No (403)No (403)Share / Grant AccessYesNo (403)No (403)No (403)No (403)Revoke Shared AccessYesNo (403)No (403)No (403)No (403)Permanently Delete DocumentYesNo (403)No (403)No (403)No (403)View & Verify Audit LedgerNo (403)No (403)No (403)YesNo (403)

Design Decision Records (Summary)
DDR-01 — Envelope Encryption (AES-256-GCM + Wrapped DEKs): Isolates per-document encryption keys from the Master KEK, enables per-file key rotation without re-encrypting the entire vault, and binds ciphertext to its document UUID via AAD.

DDR-02 — Argon2id for Credential Storage: Selected over SHA-256 and bcrypt due to configurable memory-hardness (argon2-cffi), mitigating GPU and ASIC offline cracking attacks.

DDR-03 — Storage Separation (SQLite Metadata vs. Opaque Disk Blobs): Prevents directory-traversal filename leaks and ensures database backups alone never expose file contents.

DDR-04 — Separation of Duties (Admin vs. Owner): System administrators can inspect security audit logs and verify chain integrity without gaining implicit read access to user documents.

DDR-05 — HMAC-SHA256 Hash-Chained Audit Ledger: Cryptographically links sequential log rows (prev_hash + current fields) so post-incident tampering or log deletion is mathematically detectable
<img width="937" height="488" alt="image" src="https://github.com/user-attachments/assets/d84a3d01-b789-4cc5-8538-08ee4b0daa65" />
<img width="940" height="484" alt="image" src="https://github.com/user-attachments/assets/da9fc097-6dba-47bd-98b0-122b11a2c5ac" />
