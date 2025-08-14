import argparse
import os
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pymongo import MongoClient, errors as mongo_errors
from dotenv import load_dotenv

ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
BLACKLIST_URL = f"{ABUSE_BASE}/blacklist"
CHECK_URL = f"{ABUSE_BASE}/check"

# -----------------------
# Logging
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
log = logging.getLogger("abuseipdb_etl")


# -----------------------
# HTTP Session with Retries (handles 429, 5xx, timeouts)
# -----------------------
def build_session(total_retries: int = 5, backoff_factor: float = 1.0) -> requests.Session:
    retry = Retry(
        total=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s = requests.Session()
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"Accept": "application/json"})
    return s


# -----------------------
# ENV + Config
# -----------------------
def load_config() -> Dict[str, Any]:
    load_dotenv()
    cfg = {
        "api_key": os.getenv("ABUSEIPDB_API_KEY", "").strip(),
        "mongo_uri": os.getenv("MONGODB_URI", "").strip(),
        "mongo_db": os.getenv("MONGODB_DB", "threat_intel").strip(),
        "mongo_coll": os.getenv("MONGODB_COLLECTION", "abuseipdb_raw").strip(),
        "confidence_min": int(os.getenv("CONFIDENCE_MIN", "90")),
        "max_age_days": int(os.getenv("MAX_AGE_DAYS", "90")),
    }
    if not cfg["api_key"]:
        raise EnvironmentError("ABUSEIPDB_API_KEY not set.")
    if not cfg["mongo_uri"]:
        raise EnvironmentError("MONGODB_URI not set.")
    return cfg


# -----------------------
# Extract
# -----------------------
def extract_blacklist(session: requests.Session, api_key: str, confidence_min: int, limit: int) -> Dict[str, Any]:
    """
    Get blacklist IPs (JSON) with optional limit and confidenceMinimum.
    """
    headers = {"Key": api_key}
    params = {"confidenceMinimum": confidence_min, "limit": limit}
    log.info(f"Extracting blacklist: confidence >= {confidence_min}, limit={limit}")
    resp = session.get(BLACKLIST_URL, headers=headers, params=params, timeout=15)
    if resp.status_code == 401:
        raise PermissionError("Unauthorized (401): Check ABUSEIPDB_API_KEY.")
    if resp.status_code == 429:
        # If Retry didn't recover, surface a clear message
        raise RuntimeError("Rate limited (429). Reduce rate or wait and retry.")
    resp.raise_for_status()
    return resp.json()


def extract_check_many(
    session: requests.Session,
    api_key: str,
    ips: Iterable[str],
    max_age_days: int,
    sleep_between: float = 0.5,
) -> List[Dict[str, Any]]:
    """
    Check a list of IPs using /check.
    Each response is one JSON object with 'data' details for that IP.
    """
    headers = {"Key": api_key}
    results: List[Dict[str, Any]] = []
    for ip in ips:
        ip = ip.strip()
        if not ip or ip.startswith("#"):
            continue
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
        log.info(f"Checking IP: {ip} (last {max_age_days} days)")
        resp = session.get(CHECK_URL, headers=headers, params=params, timeout=15)
        if resp.status_code == 401:
            raise PermissionError("Unauthorized (401): Check ABUSEIPDB_API_KEY.")
        if resp.status_code == 429:
            log.warning("Hit rate limit (429). Sleeping 5s and retrying once...")
            time.sleep(5)
            resp = session.get(CHECK_URL, headers=headers, params=params, timeout=15)
        if not resp.ok:
            log.error(f"Failed to check {ip}: {resp.status_code} {resp.text[:200]}")
            continue
        try:
            results.append(resp.json())
        except ValueError:
            log.error(f"Non-JSON response for {ip}: {resp.text[:200]}")
        time.sleep(sleep_between)
    return results


# -----------------------
# Transform
# -----------------------
def transform_blacklist(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normalize /blacklist payload into Mongo-ready documents.
    """
    data = payload.get("data", [])
    out: List[Dict[str, Any]] = []
    ingested_at = datetime.now(timezone.utc)
    for r in data:
        out.append({
            "source": "abuseipdb_blacklist",
            "ipAddress": r.get("ipAddress"),
            "abuseConfidenceScore": r.get("abuseConfidenceScore"),
            "countryCode": r.get("countryCode"),
            "lastReportedAt": r.get("lastReportedAt"),
            "ingestedAt": ingested_at,
        })
    return out


def transform_check_many(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize list of /check payloads into Mongo-ready documents.
    """
    out: List[Dict[str, Any]] = []
    ingested_at = datetime.now(timezone.utc)
    for p in payloads:
        d = p.get("data") or {}
        if not d:
            continue
        out.append({
            "source": "abuseipdb_check",
            "ipAddress": d.get("ipAddress"),
            "abuseConfidenceScore": d.get("abuseConfidenceScore"),
            "countryCode": d.get("countryCode"),
            "domain": d.get("domain"),
            "isWhitelisted": d.get("isWhitelisted"),
            "usageType": d.get("usageType"),
            "isp": d.get("isp"),
            "totalReports": d.get("totalReports"),
            "lastReportedAt": d.get("lastReportedAt"),
            "ingestedAt": ingested_at,
        })
    return out


# -----------------------
# Load
# -----------------------
def load_to_mongo(
    docs: List[Dict[str, Any]],
    mongo_uri: str,
    db_name: str,
    coll_name: str
) -> Tuple[int, Optional[str]]:
    if not docs:
        log.info("No documents to insert.")
        return 0, None
    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=8000)
        # Trigger connection check early
        client.admin.command("ping")
        coll = client[db_name][coll_name]
        res = coll.insert_many(docs, ordered=False)
        return len(res.inserted_ids), None
    except mongo_errors.ServerSelectionTimeoutError as e:
        return 0, f"Mongo connection failed: {e}"
    except mongo_errors.BulkWriteError as e:
        # Partial success
        inserted = len(e.details.get("writeErrors", []))
        return inserted, f"Bulk write issue: {e.details}"
    except Exception as e:
        return 0, f"Mongo insert failed: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass


# -----------------------
# CLI
# -----------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="AbuseIPDB ETL: Extract → Transform → Load into MongoDB"
    )
    sub = p.add_subparsers(dest="mode", required=True)

    # Mode 1: blacklist
    p_bl = sub.add_parser("blacklist", help="Ingest /blacklist")
    p_bl.add_argument("--limit", type=int, default=50, help="Max records to fetch (1-10000).")
    p_bl.add_argument("--confidence-min", type=int, default=None, help="Override confidenceMinimum.")

    # Mode 2: check
    p_ck = sub.add_parser("check", help="Ingest /check for IPs from a file")
    p_ck.add_argument("--ips-file", required=True, help="Path to a file containing IPs (one per line).")
    p_ck.add_argument("--max-age-days", type=int, default=None, help="Override maxAgeInDays.")
    p_ck.add_argument("--sleep", type=float, default=0.5, help="Seconds to sleep between requests.")

    return p.parse_args()


def read_ips(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def main():
    args = parse_args()
    cfg = load_config()

    session = build_session()

    if args.mode == "blacklist":
        limit = max(1, min(int(args.limit), 10000))
        confidence = args.confidence_min if args.confidence_min is not None else cfg["confidence_min"]
        payload = extract_blacklist(session, cfg["api_key"], confidence, limit)
        docs = transform_blacklist(payload)
        n, err = load_to_mongo(docs, cfg["mongo_uri"], cfg["mongo_db"], cfg["mongo_coll"])
        if err:
            log.error(err)
        log.info(f"Inserted {n} documents into {cfg['mongo_db']}.{cfg['mongo_coll']}")

    elif args.mode == "check":
        ips = read_ips(args.ips_file)
        max_age = args.max_age_days if args.max_age_days is not None else cfg["max_age_days"]
        payloads = extract_check_many(session, cfg["api_key"], ips, max_age_days=max_age, sleep_between=args.sleep)
        docs = transform_check_many(payloads)
        n, err = load_to_mongo(docs, cfg["mongo_uri"], cfg["mongo_db"], cfg["mongo_coll"])
        if err:
            log.error(err)
        log.info(f"Inserted {n} documents into {cfg['mongo_db']}.{cfg['mongo_coll']}")


if __name__ == "__main__":
    main()
