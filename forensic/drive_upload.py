#!/usr/bin/env python3
"""
Google Drive uploader via REST API met requests.

Gebruik:
  python3 forensic/drive_upload.py [opties]

Authenticatie (kies één):
  A) Service account (aanbevolen):
     GOOGLE_SERVICE_ACCOUNT_JSON of GOOGLE_APPLICATION_CREDENTIALS

  B) OAuth2 refresh token:
     GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET + GOOGLE_REFRESH_TOKEN

  C) Access token:
     GOOGLE_ACCESS_TOKEN=ya29....

Voorbeelden:
  python3 forensic/drive_upload.py --mode dir --pattern "*.md"
  python3 forensic/drive_upload.py --mode single --file rapport.md
"""

import os
import sys
import json
import time
import argparse
import base64
from pathlib import Path

try:
    import requests
except ImportError:
    print("FOUT: pip3 install requests")
    sys.exit(1)

ROOT = Path(__file__).parent.parent
EXTRACTED = ROOT / "extracted_docs"

DRIVE_API = "https://www.googleapis.com/drive/v3"
DRIVE_UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"
TOKEN_URL = "https://oauth2.googleapis.com/token"

DEFAULT_FOLDER = os.environ.get("DRIVE_FOLDER_ID", "")


def get_access_token() -> str:
    token = os.environ.get("GOOGLE_ACCESS_TOKEN", "").strip()
    if token:
        return token

    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    refresh_token = os.environ.get("GOOGLE_REFRESH_TOKEN", "").strip()
    if client_id and client_secret and refresh_token:
        resp = requests.post(TOKEN_URL, data={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }, timeout=15)
        resp.raise_for_status()
        return resp.json()["access_token"]

    sa_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()
    if not sa_json:
        sa_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if sa_file and Path(sa_file).exists():
            sa_json = Path(sa_file).read_text()

    if sa_json:
        return _service_account_token(json.loads(sa_json))

    print("FOUT: geen Google credentials gevonden.")
    print("  GOOGLE_ACCESS_TOKEN=ya29....")
    print("  GOOGLE_REFRESH_TOKEN + GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET")
    print("  GOOGLE_APPLICATION_CREDENTIALS=/pad/naar/service-account.json")
    sys.exit(1)


def _service_account_token(sa: dict) -> str:
    now = int(time.time())
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "iss": sa["client_email"],
        "scope": "https://www.googleapis.com/auth/drive.file",
        "aud": TOKEN_URL,
        "iat": now,
        "exp": now + 3600,
    }).encode()).rstrip(b"=").decode()

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        private_key = serialization.load_pem_private_key(
            sa["private_key"].encode(), password=None
        )
        sig = private_key.sign(
            f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
        )
        jwt = f"{header}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    except ImportError:
        print("FOUT: pip3 install cryptography")
        sys.exit(1)

    resp = requests.post(TOKEN_URL, data={
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt,
    }, timeout=15)
    resp.raise_for_status()
    return resp.json()["access_token"]


def upload_file(token: str, folder_id: str, name: str, content: str,
                mime: str = "text/plain") -> dict:
    boundary = "upload_boundary_nd2026"
    meta = json.dumps({"name": name, "parents": [folder_id]})
    body = (
        f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
        f"{meta}\r\n--{boundary}\r\nContent-Type: {mime}\r\n\r\n"
        f"{content}\r\n--{boundary}--"
    ).encode("utf-8")

    resp = requests.post(
        f"{DRIVE_UPLOAD}?uploadType=multipart",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/related; boundary={boundary}",
        },
        data=body,
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Upload mislukt {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def list_existing(token: str, folder_id: str) -> set:
    resp = requests.get(f"{DRIVE_API}/files", headers={
        "Authorization": f"Bearer {token}"
    }, params={
        "q": f"'{folder_id}' in parents and trashed=false",
        "fields": "files(name)",
        "pageSize": 1000,
    }, timeout=15)
    resp.raise_for_status()
    return {f["name"] for f in resp.json().get("files", [])}


def chunk_text(text: str, max_bytes: int = 11000) -> list:
    encoded = text.encode("utf-8")
    chunks, pos = [], 0
    while pos < len(encoded):
        chunk = encoded[pos:pos + max_bytes]
        while len(chunk) > 0 and chunk[-1] & 0x80 and not chunk[-1] & 0x40:
            chunk = chunk[:-1]
        chunks.append(chunk.decode("utf-8"))
        pos += len(chunk.encode("utf-8"))
    return chunks


def upload_dir(token: str, folder_id: str, source_dir: Path,
               pattern: str = "*.md", overwrite: bool = False):
    files = list(source_dir.glob(pattern))
    if not files:
        print(f"Geen bestanden: {source_dir}/{pattern}")
        return

    existing = list_existing(token, folder_id)
    print(f"{len(files)} bestanden, {len(existing)} al op Drive")

    for f in sorted(files):
        if f.name in existing and not overwrite:
            print(f"  SKIP  {f.name}")
            continue
        content = f.read_text(encoding="utf-8", errors="replace")
        if len(content.encode()) > 13000:
            parts = chunk_text(content)
            for j, part in enumerate(parts, 1):
                name = f"{f.stem}_deel{j:02d}{f.suffix}"
                try:
                    r = upload_file(token, folder_id, name, part)
                    print(f"  OK    {name} → {r.get('id','?')}")
                    time.sleep(0.3)
                except Exception as e:
                    print(f"  ERR   {name}: {e}")
        else:
            try:
                r = upload_file(token, folder_id, f.name, content)
                print(f"  OK    {f.name} → {r.get('id','?')}")
                time.sleep(0.3)
            except Exception as e:
                print(f"  ERR   {f.name}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Google Drive uploader")
    parser.add_argument("--folder", default=DEFAULT_FOLDER, required=not DEFAULT_FOLDER,
                        help="Drive folder ID")
    parser.add_argument("--mode", choices=["dir", "single"], default="dir")
    parser.add_argument("--source", default=str(EXTRACTED),
                        help="bronmap (default: extracted_docs/)")
    parser.add_argument("--file", help="bestandsnaam voor --mode single")
    parser.add_argument("--pattern", default="*.md")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    token = get_access_token()
    print(f"Token verkregen. Folder: {args.folder}")

    source = Path(args.source)
    if args.mode == "dir":
        upload_dir(token, args.folder, source, args.pattern, args.overwrite)
    elif args.mode == "single":
        if not args.file:
            print("FOUT: --file vereist")
            sys.exit(1)
        f = source / args.file
        content = f.read_text(encoding="utf-8")
        r = upload_file(token, args.folder, f.name, content)
        print(f"OK: {f.name} → {r.get('id','?')}")


if __name__ == "__main__":
    main()
