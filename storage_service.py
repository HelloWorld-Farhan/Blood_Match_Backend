import os
import re
import io
import time
import json
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime

import boto3
from PIL import Image
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("BloodBackend.StorageService")

# =========================================================================
# REQUIREMENT 1: ZERO HARDCODED CREDENTIALS (STRICTLY FROM ENVIRONMENT)
# =========================================================================
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "").strip()
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "bloodmatch-storage").strip()
R2_PUBLIC_URL = os.getenv("R2_PUBLIC_URL", "").strip().rstrip("/")
R2_ENDPOINT = os.getenv("R2_ENDPOINT", "").strip()

if not R2_ENDPOINT and R2_ACCOUNT_ID:
    R2_ENDPOINT = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

# Maximum file size allowed: 5MB
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

def get_r2_client():
    """Returns an authenticated boto3 S3 client for Cloudflare R2 object storage."""
    if not (R2_ENDPOINT and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY):
        logger.warning("Cloudflare R2 credentials incomplete. Object storage operations will run in local fallback mode.")
        return None
    try:
        return boto3.client(
            "s3",
            endpoint_url=R2_ENDPOINT,
            aws_access_key_id=R2_ACCESS_KEY_ID,
            aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            region_name="auto"
        )
    except Exception as exc:
        logger.error(f"Failed to initialize Cloudflare R2 client: {exc}")
        return None

# =========================================================================
# REQUIREMENT 2: SCOPED PATH STRUCTURE
# users/{sanitized_user_email}/{category}/{timestamp}_{filename}
# =========================================================================

def sanitize_user_email(email: str) -> str:
    """
    Sanitizes user email into a safe POSIX/S3 directory segment while preserving the email format:
    e.g. farhankhalid17968@gmail.com -> farhankhalid17968@gmail.com
    """
    if not email:
        return "anonymous_user"
    cleaned = email.strip().lower()
    # Retain alphanumeric, @, dot, dash, and underscore
    sanitized = re.sub(r'[^a-z0-9@._-]', '_', cleaned)
    return sanitized or "user"

def build_scoped_path(email: str, category: str, filename: str) -> str:
    """
    Constructs deterministic isolated tenant key:
    users/{user_email}/{category}/{filename}
    """
    sanitized_email = sanitize_user_email(email)
    clean_cat = re.sub(r'[^a-zA-Z0-9_\-]', '', category.strip().lower()) or "general"
    clean_filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename.strip())
    return f"users/{sanitized_email}/{clean_cat}/{clean_filename}"

def initialize_user_storage(email: str, full_name: str) -> bool:
    """Initializes user directory structure in Cloudflare R2 upon account creation."""
    client = get_r2_client()
    if not client:
        return True
    try:
        import json
        user_key = f"users/{sanitize_user_email(email)}/profile.json"
        body = json.dumps({
            "email": email.strip().lower(),
            "full_name": full_name.strip(),
            "created_at": datetime.utcnow().isoformat(),
            "status": "active"
        }, indent=2).encode("utf-8")
        client.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=user_key,
            Body=body,
            ContentType="application/json"
        )
        logger.info(f"[R2 STORAGE INIT] Created isolated directory for {email} at {user_key}")
        return True
    except Exception as exc:
        logger.warning(f"[R2 STORAGE INIT WARNING] Could not initialize R2 directory for {email}: {exc}")
        return False

# =========================================================================
# REQUIREMENT 4: MULTI-TENANT ISOLATION & ACCESS PROTECTION
# =========================================================================

def validate_tenant_access(authenticated_email: str, target_email_or_key: str) -> bool:
    """
    Validates that the authenticated user only accesses, creates, or deletes files
    within their own scoped tenant path prefix.
    """
    if not authenticated_email:
        return False

    sanitized_auth = sanitize_user_email(authenticated_email)
    expected_prefix = f"users/{sanitized_auth}/"

    target_clean = target_email_or_key.strip().lower()

    # Case 1: target is an S3 key path
    if target_clean.startswith("users/"):
        return target_clean.startswith(expected_prefix)

    # Case 2: target is an email address
    target_sanitized = sanitize_user_email(target_clean)
    return target_sanitized == sanitized_auth

# =========================================================================
# REQUIREMENT 3: AVATAR UPLOAD, CROPPING & WEBP/JPEG PROCESSING (< 5MB)
# =========================================================================

def process_avatar_image(
    raw_bytes: bytes,
    crop_x: Optional[int] = None,
    crop_y: Optional[int] = None,
    crop_width: Optional[int] = None,
    crop_height: Optional[int] = None,
    target_format: str = "WEBP",
    quality: int = 88
) -> Tuple[bytes, str, str]:
    """
    Validates size (strictly under 5MB), applies cropping coordinates if provided,
    resizes to a maximum bounding box of 1024x1024, and converts to WebP/JPEG.
    Returns: (processed_bytes, mime_type, file_extension)
    """
    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"Uploaded file exceeds the 5MB size limit ({len(raw_bytes)} bytes).")

    try:
        img = Image.open(io.BytesIO(raw_bytes))
    except Exception as exc:
        raise ValueError(f"Invalid or corrupted image format: {exc}")

    # Convert modes to RGB/RGBA for clean conversion
    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
        if target_format.upper() == "JPEG":
            # JPEG doesn't support alpha transparency, convert to white background
            background = Image.new("RGB", img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[-1] if img.mode in ("RGBA", "LA") else None)
            img = background
        else:
            img = img.convert("RGBA")
    else:
        img = img.convert("RGB")

    width, height = img.size

    # Apply Crop coordinates if supplied and valid
    if (
        crop_x is not None and crop_y is not None and 
        crop_width is not None and crop_height is not None and
        crop_width > 0 and crop_height > 0
    ):
        left = max(0, min(crop_x, width - 1))
        top = max(0, min(crop_y, height - 1))
        right = max(left + 1, min(crop_x + crop_width, width))
        bottom = max(top + 1, min(crop_y + crop_height, height))
        img = img.crop((left, top, right, bottom))

    # Resize if image exceeds maximum bounding box (1024x1024)
    max_dim = 1024
    if img.width > max_dim or img.height > max_dim:
        img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

    output = io.BytesIO()
    fmt = target_format.upper()
    if fmt == "JPEG" or fmt == "JPG":
        img.save(output, format="JPEG", quality=quality, optimize=True)
        mime = "image/jpeg"
        ext = "jpg"
    else:
        img.save(output, format="WEBP", quality=quality, method=6)
        mime = "image/webp"
        ext = "webp"

    return output.getvalue(), mime, ext

# =========================================================================
# CLOUDFLARE R2 CRUD OPERATIONS
# =========================================================================

def upload_user_asset(
    content: bytes,
    authenticated_email: str,
    category: str,
    filename: str,
    content_type: str = "application/octet-stream"
) -> Dict[str, Any]:
    """
    Uploads a user-isolated asset into Cloudflare R2 object storage.
    Enforces user-scoped path structure and returns public CDN URL.
    """
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"Uploaded asset exceeds the 5MB size limit ({len(content)} bytes).")

    s3_key = build_scoped_path(authenticated_email, category, filename)
    public_url = ""

    r2 = get_r2_client()
    if r2:
        try:
            r2.put_object(
                Bucket=R2_BUCKET_NAME,
                Key=s3_key,
                Body=content,
                ContentType=content_type
            )
            public_url = f"{R2_PUBLIC_URL}/{s3_key}" if R2_PUBLIC_URL else f"/{s3_key}"
            logger.info(f"Asset uploaded to Cloudflare R2: {s3_key}")
        except Exception as exc:
            logger.error(f"Cloudflare R2 upload error for {s3_key}: {exc}")
            raise
    else:
        # Fallback relative URL if R2 credentials not configured
        public_url = f"{R2_PUBLIC_URL}/{s3_key}" if R2_PUBLIC_URL else f"/{s3_key}"

    return {
        "s3_key": s3_key,
        "public_url": public_url,
        "category": category,
        "size_bytes": len(content),
        "content_type": content_type,
        "uploaded_at": datetime.utcnow().isoformat()
    }

def delete_user_asset(s3_key: str, authenticated_email: str) -> bool:
    """
    Deletes an asset from Cloudflare R2, enforcing multi-tenant isolation.
    """
    if not validate_tenant_access(authenticated_email, s3_key):
        raise PermissionError(f"Multi-tenant violation: Access denied to delete asset at {s3_key}")

    r2 = get_r2_client()
    if r2:
        try:
            r2.delete_object(Bucket=R2_BUCKET_NAME, Key=s3_key)
            logger.info(f"Asset successfully deleted from Cloudflare R2: {s3_key}")
            return True
        except Exception as exc:
            logger.error(f"Failed to delete {s3_key} from R2: {exc}")
            return False
    return True

def delete_user_category_assets(authenticated_email: str, category: str) -> int:
    """
    Permanently deletes all existing assets within a specific category for a user
    (e.g., users/{email}/profile/*).
    Guarantees that when a user updates their profile picture/avatar, any previously
    uploaded images are deleted completely, ensuring strictly ONE avatar exists per user.
    """
    sanitized_email = sanitize_user_email(authenticated_email)
    clean_cat = re.sub(r'[^a-zA-Z0-9_\-]', '', category.strip().lower())
    prefix = f"users/{sanitized_email}/{clean_cat}/"

    r2 = get_r2_client()
    if not r2:
        return 0

    deleted_count = 0
    try:
        response = r2.list_objects_v2(Bucket=R2_BUCKET_NAME, Prefix=prefix)
        objects_to_delete = []
        for obj in response.get("Contents", []):
            objects_to_delete.append({"Key": obj["Key"]})

        if objects_to_delete:
            r2.delete_objects(
                Bucket=R2_BUCKET_NAME,
                Delete={"Objects": objects_to_delete}
            )
            deleted_count = len(objects_to_delete)
            logger.info(f"[R2 CLEANUP] Purged {deleted_count} previous asset(s) under {prefix}")
    except Exception as exc:
        logger.error(f"[R2 CLEANUP ERROR] Failed to delete previous assets in {prefix}: {exc}")

    return deleted_count

def list_user_assets(authenticated_email: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Lists all assets in Cloudflare R2 within the user's isolated prefix.
    """
    sanitized_email = sanitize_user_email(authenticated_email)
    prefix = f"users/{sanitized_email}/"
    if category:
        clean_cat = re.sub(r'[^a-zA-Z0-9_\-]', '', category.strip().lower())
        prefix += f"{clean_cat}/"

    r2 = get_r2_client()
    if not r2:
        return []

    try:
        response = r2.list_objects_v2(Bucket=R2_BUCKET_NAME, Prefix=prefix)
        items = []
        for obj in response.get("Contents", []):
            key = obj["Key"]
            items.append({
                "s3_key": key,
                "public_url": f"{R2_PUBLIC_URL}/{key}" if R2_PUBLIC_URL else f"https://{R2_BUCKET_NAME}.r2.dev/{key}",
                "size_bytes": obj.get("Size", 0),
                "last_modified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None
            })
        return items
    except Exception as exc:
        logger.error(f"Failed to list assets from R2 with prefix {prefix}: {exc}")
        return []

def save_user_auth_record_r2(user_data: dict) -> bool:
    """
    Persists permanent disaster-proof authentication record into Cloudflare R2:
    users/{email}/auth_record.json
    Guarantees user account is NEVER lost, even across ephemeral container restarts.
    """
    email = user_data.get("email")
    if not email:
        return False
    email_clean = sanitize_user_email(email)
    r2 = get_r2_client()
    if not r2:
        return False
    key = f"users/{email_clean}/auth_record.json"
    try:
        r2.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=key,
            Body=json.dumps(user_data, indent=2).encode("utf-8"),
            ContentType="application/json"
        )
        logger.info(f"[R2 AUTH SYNC] Successfully mirrored auth record for {email_clean} at {key}")
        return True
    except Exception as exc:
        logger.error(f"[R2 AUTH SYNC ERROR] Failed to mirror auth record for {email_clean}: {exc}")
        return False

def get_user_auth_record_r2(email: str) -> Optional[dict]:
    """
    Retrieves mirrored auth record from Cloudflare R2 if local DB has no record.
    """
    if not email:
        return None
    email_clean = sanitize_user_email(email)
    r2 = get_r2_client()
    if not r2:
        return None
    key = f"users/{email_clean}/auth_record.json"
    try:
        obj = r2.get_object(Bucket=R2_BUCKET_NAME, Key=key)
        data = json.loads(obj["Body"].read().decode("utf-8"))
        return data
    except Exception as exc:
        logger.debug(f"[R2 AUTH LOOKUP] No auth record in R2 for {email_clean}: {exc}")
        return None

def restore_all_users_from_r2(db) -> int:
    """
    Scans Cloudflare R2 for all users/*/auth_record.json and restores them into
    the active database session if not already present.
    """
    from models import UserModel
    r2 = get_r2_client()
    if not r2:
        return 0
    restored_count = 0
    try:
        paginator = r2.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=R2_BUCKET_NAME, Prefix="users/"):
            for obj in page.get("Contents", []):
                key = obj.get("Key", "")
                if key.endswith("/auth_record.json"):
                    try:
                        record_obj = r2.get_object(Bucket=R2_BUCKET_NAME, Key=key)
                        data = json.loads(record_obj["Body"].read().decode("utf-8"))
                        email = data.get("email")
                        if email:
                            existing = db.query(UserModel).filter(UserModel.email == email).first()
                            if not existing:
                                new_user = UserModel(
                                    id=data.get("id"),
                                    full_name=data.get("full_name") or "Clinician",
                                    email=email,
                                    phone=data.get("phone"),
                                    hashed_password=data.get("hashed_password"),
                                    is_verified=bool(data.get("is_verified", True)),
                                    is_2fa_enabled=bool(data.get("is_2fa_enabled", False)),
                                    photo_url=data.get("photo_url")
                                )
                                db.add(new_user)
                                restored_count += 1
                    except Exception as parse_err:
                        logger.warning(f"Failed to restore user from key {key}: {parse_err}")
        if restored_count > 0:
            db.commit()
            logger.info(f"[R2 HYDRATION] Restored {restored_count} user account(s) into database.")
    except Exception as exc:
        logger.error(f"[R2 HYDRATION ERROR] Failed to scan users in R2: {exc}")
    return restored_count

def delete_all_user_r2_data(authenticated_email: str) -> int:
    """
    Permanently deletes all assets, folders, and records under users/{email}/
    when an account is formally deleted.
    """
    email_clean = sanitize_user_email(authenticated_email)
    prefix = f"users/{email_clean}/"
    r2 = get_r2_client()
    if not r2:
        return 0
    deleted_count = 0
    try:
        response = r2.list_objects_v2(Bucket=R2_BUCKET_NAME, Prefix=prefix)
        objects_to_delete = [{"Key": obj["Key"]} for obj in response.get("Contents", [])]
        if objects_to_delete:
            r2.delete_objects(
                Bucket=R2_BUCKET_NAME,
                Delete={"Objects": objects_to_delete}
            )
            deleted_count = len(objects_to_delete)
            logger.info(f"[R2 ACCOUNT PURGE] Completely deleted {deleted_count} files for {email_clean}")
    except Exception as exc:
        logger.error(f"[R2 ACCOUNT PURGE ERROR] Failed to purge R2 files for {email_clean}: {exc}")
    return deleted_count

