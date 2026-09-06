#!/usr/bin/env python3
"""Upload MailAccess reports to the dedicated Google Apps Script endpoint."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import sys
from pathlib import Path
from typing import Any

import requests

ALLOWED_FILES = (
    "report.json",
    "report.csv",
    "summary.md",
    "analysis.json",
    "metadata.json",
    "SHA256SUMS.txt",
)

MIME_TYPES = {
    ".json": "application/json",
    ".csv": "text/csv",
    ".md": "text/markdown",
    ".txt": "text/plain",
}

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 10
REQUEST_TIMEOUT = (15, 120)


def required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Environment variable {name} belum tersedia.")
    return value


def validate_webhook_url(url: str) -> None:
    if not url.startswith("https://script.google.com/macros/s/"):
        raise ValueError("APPS_SCRIPT_WEBHOOK_URL bukan URL Apps Script yang valid.")
    if not url.rstrip("/").endswith("/exec"):
        raise ValueError("APPS_SCRIPT_WEBHOOK_URL harus berakhir dengan /exec.")


def validate_job_id(job_id: str) -> None:
    allowed = set("0123456789abcdefABCDEF-")
    if not 20 <= len(job_id) <= 50 or any(ch not in allowed for ch in job_id):
        raise ValueError("Job ID tidak valid.")


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def resolve_job_id(report_folder: Path) -> str:
    metadata_path = report_folder / "metadata.json"
    folder_job_id = report_folder.name

    if not metadata_path.is_file():
        validate_job_id(folder_job_id)
        return folder_job_id

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata_job_id = str(metadata.get("jobId", "")).strip()
    validate_job_id(metadata_job_id)

    if metadata_job_id != folder_job_id:
        raise ValueError("Job ID metadata tidak cocok dengan nama folder laporan.")

    return metadata_job_id


def validate_report(report_folder: Path) -> None:
    report_path = report_folder / "report.json"
    if not report_path.is_file():
        raise FileNotFoundError("report.json tidak ditemukan.")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("Struktur report.json harus berupa object JSON.")

    status = str(report.get("status", "")).lower()
    if status not in {"complete", "completed"}:
        raise ValueError(f"Status report.json belum selesai: {status or 'kosong'}.")


def build_file_payload(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"Symlink tidak diizinkan: {path.name}")
    if not path.is_file():
        raise FileNotFoundError(f"File tidak ditemukan: {path.name}")

    content = path.read_bytes()
    if not content:
        raise ValueError(f"File kosong: {path.name}")
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(f"File melebihi 8 MB: {path.name}")

    mime_type = MIME_TYPES.get(path.suffix.lower())
    if not mime_type:
        mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

    return {
        "name": path.name,
        "mimeType": mime_type,
        "encoding": "base64",
        "size": len(content),
        "sha256": sha256_hex(content),
        "content": base64.b64encode(content).decode("ascii"),
    }


def build_upload_payload(report_folder: Path, callback_secret: str) -> dict[str, Any]:
    if not report_folder.is_dir():
        raise NotADirectoryError(f"Folder laporan tidak ditemukan: {report_folder}")

    job_id = resolve_job_id(report_folder)
    validate_report(report_folder)

    paths = [report_folder / name for name in ALLOWED_FILES if (report_folder / name).exists()]
    if not paths:
        raise ValueError("Tidak ada file laporan yang dapat dikirim.")
    if len(paths) > MAX_FILES:
        raise ValueError("Jumlah file laporan melebihi batas.")

    available_names = {path.name for path in paths}
    required_names = {"report.json", "metadata.json", "analysis.json"}
    missing = sorted(required_names - available_names)
    if missing:
        raise ValueError("File wajib belum tersedia: " + ", ".join(missing))

    return {
        "action": "email_upload",
        "jobId": job_id,
        "githubRunId": os.environ.get("GITHUB_RUN_ID", "").strip(),
        "githubRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", "").strip(),
        "repository": os.environ.get("GITHUB_REPOSITORY", "").strip(),
        "callbackSecret": callback_secret,
        "files": [build_file_payload(path) for path in paths],
    }


def build_failure_payload(job_id: str, message: str, callback_secret: str) -> dict[str, Any]:
    validate_job_id(job_id)
    clean_message = " ".join(message.split()).strip()
    if not clean_message:
        clean_message = "Workflow Email OSINT Audit gagal."

    return {
        "action": "email_failed",
        "jobId": job_id,
        "githubRunId": os.environ.get("GITHUB_RUN_ID", "").strip(),
        "githubRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", "").strip(),
        "repository": os.environ.get("GITHUB_REPOSITORY", "").strip(),
        "callbackSecret": callback_secret,
        "error": clean_message[:1000],
    }


def post_payload(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(
        url,
        json=payload,
        headers={
            "Accept": "application/json",
            "User-Agent": "mnytc-mailaccess-audit/1.0",
        },
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )

    response.raise_for_status()

    try:
        data = response.json()
    except requests.JSONDecodeError as exc:
        preview = response.text[:300].replace("\n", " ")
        raise RuntimeError(f"Apps Script tidak mengembalikan JSON: {preview}") from exc

    if not isinstance(data, dict):
        raise RuntimeError("Respons Apps Script bukan object JSON.")
    if data.get("ok") is not True:
        raise RuntimeError(str(data.get("error") or "Apps Script menolak permintaan."))

    return data


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kirim laporan MailAccess ke Apps Script.")
    parser.add_argument("report_folder", nargs="?", help="Folder laporan untuk mode upload.")
    parser.add_argument("failure_job_id", nargs="?", help="Job ID untuk mode gagal.")
    parser.add_argument("failure_message", nargs="?", help="Pesan untuk mode gagal.")
    parser.add_argument("--failed", action="store_true", help="Kirim status email_failed.")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    webhook_url = required_environment("APPS_SCRIPT_WEBHOOK_URL")
    callback_secret = required_environment("CALLBACK_SECRET")
    validate_webhook_url(webhook_url)

    if len(callback_secret) < 32:
        raise ValueError("CALLBACK_SECRET harus memiliki minimal 32 karakter.")

    if args.failed:
        # Mendukung pemanggilan: --failed JOB_ID "pesan"
        job_id = args.report_folder or ""
        message = args.failure_job_id or args.failure_message or "Workflow Email OSINT Audit gagal."
        payload = build_failure_payload(job_id, message, callback_secret)
        result = post_payload(webhook_url, payload)
        print("Status kegagalan berhasil dikirim.")
        print("Job ID:", result.get("jobId", job_id))
        return 0

    if not args.report_folder:
        raise ValueError("Folder laporan wajib diberikan.")

    folder = Path(args.report_folder).resolve(strict=True)
    payload = build_upload_payload(folder, callback_secret)
    file_names = [item["name"] for item in payload["files"]]

    print("Mengirim laporan MailAccess.")
    print("Job ID:", payload["jobId"])
    print("Jumlah file:", len(file_names))
    print("File:", ", ".join(file_names))

    result = post_payload(webhook_url, payload)
    print("Laporan berhasil diterima Apps Script.")
    print("Status:", result.get("status", "completed"))
    print("Duplikat:", bool(result.get("duplicate", False)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Proses dibatalkan.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)