import os
import re
import io
import time
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
    Sanitizes user email into a safe POSIX/S3 directory segment.
    e.g. dr.jenkins+test@bloodmatch.io -> dr_jenkins_test_bloodmatch_io
    """
    if not email:
        return "anonymous_user"
    cleaned = email.strip().lower()
    # Replace @, +, dots, and special characters with underscores
    sanitized = re.sub(r'[^a-z0-9_-]', '_', cleaned)
    # Deduplicate consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized).strip('_')
    return sanitized or "user"

def build_scoped_path(email: str, category: str, filename: str) -> str:
    """
    Constructs deterministic isolated tenant key:
    users/{sanitized_user_email}/{category}/{timestamp}_{clean_filename}
    """
    sanitized_email = sanitize_user_email(email)
    clean_cat = re.sub(r'[^a-zA-Z0-9_\-]', '', category.strip().lower()) or "general"
    clean_filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename.strip())
    timestamp = int(datetime.utcnow().timestamp())
    return f"users/{sanitized_email}/{clean_cat}/{timestamp}_{clean_filename}"

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
            public_url = f"{R2_PUBLIC_URL}/{s3_key}" if R2_PUBLIC_URL else f"https://{R2_BUCKET_NAME}.r2.dev/{s3_key}"
            logger.info(f"Asset uploaded to Cloudflare R2: {s3_key}")
        except Exception as exc:
            logger.error(f"Cloudflare R2 upload error for {s3_key}: {exc}")
            raise
    else:
        # Fallback simulated URL if credentials missing
        public_url = f"https://bloodmatch-storage.local/{s3_key}"

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
