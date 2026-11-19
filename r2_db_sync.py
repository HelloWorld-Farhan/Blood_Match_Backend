import os
import tempfile
import sqlite3
import logging
import threading
import time
from typing import Optional

logger = logging.getLogger("BloodBackend.R2DBSync")

R2_DB_KEY = "database/bloodmatch_persistent.db"

_sync_lock = threading.Lock()
_last_sync_time = 0.0
_MIN_SYNC_INTERVAL_SEC = 2.0  # Prevent slamming R2 on tight write bursts


def is_testing() -> bool:
    return os.environ.get("TESTING", "").lower() in ("1", "true", "yes")


def restore_db_from_r2(local_path: str) -> bool:
    """
    Downloads the persistent SQLite database from Cloudflare R2 if it exists.
    Executed once upon backend startup to preserve data across Render container restarts.
    """
    if is_testing():
        logger.info("[R2DBSync] Testing mode active - skipping R2 download.")
        return False

    try:
        from storage_service import get_r2_client, R2_BUCKET_NAME
        r2 = get_r2_client()

        # Check if the persistent database object exists in Cloudflare R2
        try:
            head = r2.head_object(Bucket=R2_BUCKET_NAME, Key=R2_DB_KEY)
            size = head.get("ContentLength", 0)
            logger.info(f"[R2DBSync] Remote persistent database found in R2 ({size} bytes). Downloading...")
        except Exception as e:
            logger.info(f"[R2DBSync] No existing database in Cloudflare R2 ({e}). A fresh one will be seeded.")
            return False

        obj = r2.get_object(Bucket=R2_BUCKET_NAME, Key=R2_DB_KEY)
        data = obj["Body"].read()

        os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
        # Write to temporary file first, then atomic rename
        tmp_target = local_path + ".download_tmp"
        with open(tmp_target, "wb") as f:
            f.write(data)

        if os.path.exists(local_path):
            os.remove(local_path)
        os.rename(tmp_target, local_path)

        logger.info(f"[R2DBSync] Successfully restored persistent database to {local_path} ({len(data)} bytes).")
        return True
    except Exception as exc:
        logger.warning(f"[R2DBSync] Failed to restore database from R2: {exc}")
        return False


def sync_db_to_r2(local_path: str, force: bool = False) -> bool:
    """
    Safely captures a point-in-time SQLite snapshot via sqlite3 backup API
    and persists it to Cloudflare R2 object storage.
    """
    if is_testing():
        return False

    global _last_sync_time
    now = time.time()
    if not force and (now - _last_sync_time) < _MIN_SYNC_INTERVAL_SEC:
        logger.debug("[R2DBSync] Debouncing sync call.")
        return False

    with _sync_lock:
        if not os.path.exists(local_path):
            logger.warning(f"[R2DBSync] Local database path {local_path} does not exist.")
            return False

        backup_file = None
        try:
            from storage_service import get_r2_client, R2_BUCKET_NAME
            r2 = get_r2_client()

            # Create clean atomic snapshot using SQLite online backup API
            fd, backup_file = tempfile.mkstemp(suffix="_r2_backup.db")
            os.close(fd)

            src_conn = sqlite3.connect(local_path)
            dst_conn = sqlite3.connect(backup_file)
            src_conn.backup(dst_conn)
            dst_conn.close()
            src_conn.close()

            with open(backup_file, "rb") as f:
                payload = f.read()

            r2.put_object(
                Bucket=R2_BUCKET_NAME,
                Key=R2_DB_KEY,
                Body=payload,
                ContentType="application/x-sqlite3"
            )

            _last_sync_time = time.time()
            logger.info(f"[R2DBSync] Successfully synced {len(payload)} bytes of persistent database to Cloudflare R2.")
            return True
        except Exception as exc:
            logger.warning(f"[R2DBSync] Failed to sync database to Cloudflare R2: {exc}")
            return False
        finally:
            if backup_file and os.path.exists(backup_file):
                try:
                    os.remove(backup_file)
                except Exception:
                    pass


def trigger_db_sync_async(local_path: str):
    """
    Spawns background thread for immediate non-blocking sync.
    """
    if is_testing():
        return
    threading.Thread(target=sync_db_to_r2, args=(local_path, False), daemon=True).start()
