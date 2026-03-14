import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import time
from datetime import datetime

import jwt
import requests
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

# =========================
# 1) Cấu hình hệ thống
# =========================
# Nạp biến môi trường từ .env
load_dotenv()

APP_ID = os.getenv("GITHUB_APP_ID")
PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH")
SONAR_URL = os.getenv("SONAR_URL")
SONAR_TOKEN = os.getenv("SONAR_TOKEN")
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
SONAR_API_URL = os.getenv("SONAR_API_URL", "http://localhost:80")
LOG_FILE = "scans.json"

app = FastAPI(title="Punssama Dashboard v4")


# =========================
# 2) Utility / Security
# =========================
def remove_readonly(func, path, _):
    """Xử lý file read-only khi xóa workspace trên Windows."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def verify_signature(payload: bytes, signature: str | None) -> bool:
    """Xác thực chữ ký webhook GitHub bằng HMAC-SHA256."""
    if not WEBHOOK_SECRET or not signature:
        return False

    try:
        sha_name, signature_val = signature.split("=", 1)
    except ValueError:
        return False

    if sha_name != "sha256":
        return False

    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=payload, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature_val)


def to_docker_mount_path(path: str) -> str:
    """Convert path Windows sang dạng Docker mount path (/c/...)."""
    normalized = os.path.abspath(path).replace("\\", "/")
    if len(normalized) > 1 and normalized[1] == ":":
        drive = normalized[0].lower()
        normalized = f"/{drive}{normalized[2:]}"
    return normalized


# =========================
# 3) GitHub App auth
# =========================
def get_installation_access_token(installation_id: int) -> str | None:
    """Dùng private key ký JWT rồi đổi lấy installation access token."""
    if not APP_ID or not PRIVATE_KEY_PATH:
        return None

    with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as key_file:
        private_key = key_file.read()

    jwt_payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + 10 * 60,
        "iss": APP_ID,
    }

    try:
        encoded_jwt = jwt.encode(jwt_payload, private_key, algorithm="RS256")
    except NotImplementedError as exc:
        raise RuntimeError(
            "Thiếu backend RS256. Cài: pip install 'PyJWT[crypto]' cryptography"
        ) from exc

    token_url = (
        f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    )
    headers = {
        "Authorization": f"Bearer {encoded_jwt}",
        "Accept": "application/vnd.github+json",
    }

    response = requests.post(token_url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("token")


# =========================
# 4) Sonar + Log dashboard
# =========================
def get_sonar_metrics(project_key: str) -> tuple[dict | None, str]:
    """Lấy metrics từ SonarQube; trả về (metrics, status)."""
    if not SONAR_TOKEN:
        print("[X] Thiếu SONAR_TOKEN, không thể lấy metrics")
        return None, "ERROR"

    url = f"{SONAR_API_URL}/api/measures/component"
    params = {
        "component": project_key,
        "metricKeys": "bugs,vulnerabilities,code_smells,alert_status",
    }

    try:
        # Chờ SonarQube ingest kết quả scan
        time.sleep(5)
        response = requests.get(url, params=params, auth=(SONAR_TOKEN, ""), timeout=15)
        response.raise_for_status()

        measures = response.json().get("component", {}).get("measures", [])
        metrics = {item["metric"]: item.get("value", "0") for item in measures}
        status = metrics.get("alert_status", "ERROR")
        return metrics, status
    except Exception as error:
        print(f"[X] Lỗi lấy metrics SonarQube: {error}")
        return None, "ERROR"


def log_scan(repo_name: str, status: str, metrics: dict) -> None:
    """Lưu lịch sử scan để dashboard đọc qua /api/scans."""
    entry = {
        "repo": repo_name,
        "time": datetime.now().strftime("%H:%M:%S %d/%m/%Y"),
        "status": "PASSED" if status == "OK" else "FAILED",
        "bugs": metrics.get("bugs", 0),
        "vulnerabilities": metrics.get("vulnerabilities", 0),
        "smells": metrics.get("code_smells", 0),
    }

    data: list[dict] = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []

    data.insert(0, entry)
    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(data[:50], file, ensure_ascii=False, indent=2)


# =========================
# 5) Pipeline chính
# =========================
def run_analysis_pipeline(repo_url: str, repo_name: str, installation_id: int) -> None:
    """
    Flow pipeline:
    1) Dọn workspace cũ
    2) Lấy installation token
    3) Clone repo
    4) Chạy SonarScanner
    5) Lấy metrics và lưu dashboard log
    6) Dọn workspace
    """
    workspace_dir = os.path.abspath(f"./workspaces/{repo_name}")

    try:
        if os.path.exists(workspace_dir):
            shutil.rmtree(workspace_dir, onerror=remove_readonly)

        installation_token = get_installation_access_token(installation_id)
        if not installation_token:
            raise RuntimeError("Không lấy được installation token từ GitHub App")

        clone_url = repo_url.replace(
            "https://", f"https://x-access-token:{installation_token}@", 1
        )

        print(f"[*] Đang clone dự án: {repo_name}")
        subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, workspace_dir],
            check=True,
        )

        print(f"[*] Kích hoạt SonarScanner cho {repo_name}")
        docker_path = to_docker_mount_path(workspace_dir)
        scan_cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{docker_path}:/usr/src",
            "--network",
            "host",
            "sonarsource/sonar-scanner-cli",
            f"-Dsonar.projectKey={repo_name}",
            f"-Dsonar.host.url={SONAR_URL}",
            f"-Dsonar.login={SONAR_TOKEN}",
            "-Dsonar.scm.disabled=true",
        ]
        subprocess.run(scan_cmd, check=True)

        metrics, status = get_sonar_metrics(repo_name)
        if metrics:
            log_scan(repo_name, status, metrics)

        print(f"[V] Đã cập nhật dashboard cho {repo_name}")
    except Exception as error:
        print(f"[X] Lỗi pipeline với {repo_name}: {error}")
    finally:
        if os.path.exists(workspace_dir):
            shutil.rmtree(workspace_dir, onerror=remove_readonly)
            print(f"[*] Đã dọn dẹp workspace: {repo_name}")


# =========================
# 6) Routes
# =========================
@app.get("/")
async def index():
    """Trả file dashboard UI."""
    return FileResponse("index.html")


@app.get("/api/scans")
async def api_scans():
    """API đọc lịch sử quét cho dashboard."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return []
    return []


@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """Nhận GitHub webhook, verify và queue scan job."""
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    if not verify_signature(raw_body, signature):
        raise HTTPException(status_code=401, detail="Invalid Signature")

    payload = await request.json()
    event = request.headers.get("X-GitHub-Event", "unknown")

    print(f"--- SỰ KIỆN MỚI: {event.upper()} ---")

    if event in ["push", "pull_request"]:
        repo = payload.get("repository", {})
        repo_name = repo.get("name")
        repo_url = repo.get("clone_url")
        installation_id = payload.get("installation", {}).get("id")

        if not repo_name or not repo_url or not installation_id:
            raise HTTPException(status_code=400, detail="Missing webhook payload data")

        background_tasks.add_task(
            run_analysis_pipeline,
            repo_url,
            repo_name,
            installation_id,
        )
        return {"status": "queued", "repo": repo_name}

    return {"status": "ignored", "event": event}


if __name__ == "__main__":
    import uvicorn

    os.makedirs("./workspaces", exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=5000)
