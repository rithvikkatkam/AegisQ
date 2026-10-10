#!/usr/bin/env python3
"""
AegisQ one-click launcher
=========================

Open this file in VS Code and press the Run button (or F5) -- that's it.

What it does, in order (each step is skipped when it is already done):

  1. Creates backend/venv (needs Python 3.11+) and installs requirements.txt
  2. Makes sure backend/data/aegisq.db exists (copies pipeline/aegisq.db)
  3. Trains the two ML models if their .joblib artifacts are missing
  4. Runs `npm install` if frontend/node_modules is missing
  5. Starts the FastAPI backend, and the Vite frontend
  6. Waits until both answer, then opens the site in your browser

Press Ctrl+C (or the red Stop button in VS Code) to shut everything down.

Only the Python standard library is used, so this file runs with any Python 3.8+.

Options:
  --no-browser        don't open the browser automatically
  --retrain           retrain both ML models even if artifacts already exist
  --setup-only        do steps 1-4 and exit (no servers)
  --skip-install      don't run pip / npm (offline use)
  --no-venv           use the Python that is running this script instead of backend/venv
  --reload            auto-restart the backend when backend code changes
  --backend-port N    preferred backend port  (default 8000)
  --frontend-port N   preferred frontend port (default 5173)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
PIPELINE = ROOT / "pipeline"
VENV = BACKEND / "venv"
DB_FILE = BACKEND / "data" / "aegisq.db"

IS_WIN = os.name == "nt"
MIN_PY = (3, 11)  # numpy 2.3 / scikit-learn 1.8 (see backend/requirements.txt)
HOST = "127.0.0.1"

ML_MODELS = [
    # (label, training script, artifact it produces, required?)
    ("risk forecast", "ml/train.py", "ml/risk_forecast_model.joblib", True),
    ("attack-loss", "ml/train_attack_loss.py", "ml/attack_loss_model.joblib", False),
]


# ----------------------------------------------------------------------------
# Pretty output
# ----------------------------------------------------------------------------
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

_USE_COLOR = sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))
if IS_WIN and _USE_COLOR:
    os.system("")  # enables ANSI escape codes in the Windows console

_COLORS = {"red": 31, "green": 32, "yellow": 33, "blue": 34, "magenta": 35, "cyan": 36, "dim": 90}
_print_lock = threading.Lock()


def paint(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{_COLORS[color]}m{text}\033[0m"


def say(tag: str, message: str, color: str = "cyan") -> None:
    with _print_lock:
        print(f"{paint(f'[{tag}]', color)} {message}", flush=True)


def info(msg: str) -> None:
    say("aegisq", msg, "cyan")


def warn(msg: str) -> None:
    say("aegisq", paint("WARNING: ", "yellow") + msg, "yellow")


def fail(msg: str, code: int = 1) -> "None":
    say("aegisq", paint("ERROR: ", "red") + msg, "red")
    sys.exit(code)


# ----------------------------------------------------------------------------
# Python / venv / dependencies
# ----------------------------------------------------------------------------
def probe_python(cmd: list) -> tuple | None:
    """Return (major, minor) for an interpreter command, or None if unusable."""
    try:
        out = subprocess.run(
            cmd + ["-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
            capture_output=True, text=True, timeout=20,
        )
        if out.returncode != 0:
            return None
        major, minor = out.stdout.strip().split(".")
        return int(major), int(minor)
    except Exception:  # noqa: BLE001
        return None


def find_python() -> list:
    """Find an interpreter that is new enough to install the pinned requirements."""
    candidates = [[sys.executable]]
    if IS_WIN:
        candidates += [["py", f"-3.{m}"] for m in (13, 12, 11)] + [["python"], ["python3"]]
    else:
        candidates += [[f"python3.{m}"] for m in (13, 12, 11)] + [["python3"], ["python"]]
    seen = set()
    for cmd in candidates:
        if cmd[0] != sys.executable and shutil.which(cmd[0]) is None:
            continue
        key = tuple(cmd)
        if key in seen:
            continue
        seen.add(key)
        ver = probe_python(cmd)
        if ver and ver >= MIN_PY:
            return cmd
    fail(
        f"Python {MIN_PY[0]}.{MIN_PY[1]}+ is required (the pinned numpy/scikit-learn need it) "
        "but none was found.\n         Install it from https://www.python.org/downloads/ and run again."
    )


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")


def ensure_venv(args) -> str:
    """Return the path of the interpreter the backend should run with."""
    if args.no_venv:
        info(f"Using current interpreter: {sys.executable}")
        return sys.executable

    vpy = venv_python()
    if vpy.exists() and probe_python([str(vpy)]):
        return str(vpy)

    if VENV.exists():
        warn("backend/venv exists but is unusable here (created on another OS or moved). Recreating it.")
        shutil.rmtree(VENV, ignore_errors=True)

    base = find_python()
    info(f"Creating virtual environment in backend/venv (using {' '.join(base)}) ...")
    result = subprocess.run(base + ["-m", "venv", str(VENV)])
    if result.returncode != 0 or not venv_python().exists():
        fail("Could not create the virtual environment. On Debian/Ubuntu try: sudo apt install python3-venv")
    return str(venv_python())


def run_checked(cmd: list, cwd: Path, what: str, env: dict | None = None) -> None:
    """Run a command with its output streamed straight to the terminal."""
    result = subprocess.run(cmd, cwd=str(cwd), env=env)
    if result.returncode != 0:
        fail(f"{what} failed (exit code {result.returncode}). See the output above.")


def ensure_dependencies(py: str, args) -> None:
    req = BACKEND / "requirements.txt"
    stamp = BACKEND / ".aegisq-deps.sha256"
    digest = hashlib.sha256(req.read_bytes()).hexdigest()

    imports_ok = subprocess.run(
        [py, "-c", "import fastapi, uvicorn, pydantic, sklearn, pandas, numpy, joblib, dotenv, anthropic"],
        capture_output=True,
    ).returncode == 0
    stamp_ok = stamp.exists() and stamp.read_text().strip() == digest

    if imports_ok and (stamp_ok or not stamp.exists()):
        stamp.write_text(digest)
        info("Python dependencies OK.")
        return
    if args.skip_install:
        warn("Python dependencies look incomplete but --skip-install was given; continuing.")
        return

    info("Installing Python dependencies (first run takes a few minutes) ...")
    run_checked([py, "-m", "pip", "install", "--disable-pip-version-check", "-r", str(req)],
                BACKEND, "pip install")
    stamp.write_text(digest)


# ----------------------------------------------------------------------------
# Data + ML
# ----------------------------------------------------------------------------
def db_has_data(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        conn = sqlite3.connect(str(path))
        try:
            return conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] > 0
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def ensure_database() -> None:
    if db_has_data(DB_FILE):
        info("Database OK (backend/data/aegisq.db).")
        return
    bundled = PIPELINE / "aegisq.db"
    if db_has_data(bundled):
        DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bundled, DB_FILE)
        info("Copied pipeline/aegisq.db -> backend/data/aegisq.db")
        return
    warn("No dataset found. The backend will seed a tiny 5-asset demo fixture. "
         "Run pipeline/build_pipeline.py to generate the full dataset.")


def ensure_models(py: str, args) -> None:
    for label, script, artifact, required in ML_MODELS:
        artifact_path = BACKEND / artifact
        if artifact_path.exists() and not args.retrain:
            info(f"ML model OK: {label}.")
            continue
        info(f"Training {label} model ({script}) ...")
        result = subprocess.run([py, script], cwd=str(BACKEND), capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        lines = [ln for ln in (result.stdout or "").splitlines() if ln.strip()]
        if result.returncode == 0 and artifact_path.exists():
            for ln in lines[:6]:  # header + metrics
                say("ml", ln, "magenta")
        else:
            tail = (result.stderr or "").strip().splitlines()[-8:] or lines[-8:]
            for ln in tail:
                say("ml", ln, "red")
            msg = f"Training the {label} model failed."
            if required:
                warn(msg + " Forecast endpoints will return MODEL_NOT_FOUND until it is trained "
                     "(run the 'AegisQ: Retrain ML models' launch config after fixing the error).")
            else:
                warn(msg + " The rest of the app still works.")


# ----------------------------------------------------------------------------
# Frontend
# ----------------------------------------------------------------------------
def ensure_frontend(args) -> str:
    npm = shutil.which("npm")
    node = shutil.which("node")
    if not npm or not node:
        fail("Node.js (with npm) is required for the frontend.\n"
             "         Install the LTS version from https://nodejs.org and run again.")
    try:
        ver = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip()
        major = int(ver.lstrip("v").split(".")[0])
        if major < 20:
            warn(f"Node {ver} detected; the frontend (Vite 8) wants Node 20.19+ or 22.12+.")
    except Exception:  # noqa: BLE001
        pass

    vite_bin = FRONTEND / "node_modules" / ".bin" / ("vite.cmd" if IS_WIN else "vite")
    if vite_bin.exists():
        info("Frontend dependencies OK.")
        return npm
    if args.skip_install:
        warn("frontend/node_modules is missing but --skip-install was given; continuing.")
        return npm
    info("Installing frontend dependencies (npm install) ...")
    run_checked([npm, "install"], FRONTEND, "npm install")
    return npm


# ----------------------------------------------------------------------------
# Process management
# ----------------------------------------------------------------------------
def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0 if IS_WIN else 1)
        try:
            s.bind((HOST, port))
            return True
        except OSError:
            return False


def pick_port(preferred: int, name: str) -> int:
    for port in range(preferred, preferred + 25):
        if port_is_free(port):
            if port != preferred:
                warn(f"Port {preferred} is busy, using {port} for the {name} instead.")
            return port
    fail(f"No free port found near {preferred} for the {name}.")


class Service:
    def __init__(self, tag: str, color: str, cmd: list, cwd: Path, env: dict):
        self.tag, self.color, self.cmd, self.cwd, self.env = tag, color, cmd, cwd, env
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        kwargs = {}
        if IS_WIN:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True  # own process group -> we can kill the whole tree
        self.proc = subprocess.Popen(
            self.cmd, cwd=str(self.cwd), env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1, **kwargs,
        )
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            say(self.tag, line.rstrip(), self.color)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return
        try:
            if IS_WIN:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               capture_output=True)
            else:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        except Exception:  # noqa: BLE001
            proc.kill()


def http_up(url: str) -> bool:
    try:
        urllib.request.urlopen(url, timeout=2).close()
        return True
    except urllib.error.HTTPError:
        return True  # server answered (any status) -> it is up
    except Exception:  # noqa: BLE001
        return False


def wait_until_up(url: str, service: Service, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not service.alive():
            return False
        if http_up(url):
            return True
        time.sleep(0.4)
    return False


def show_ml_status(backend_url: str) -> None:
    for label, path in (("risk forecast", "/api/ml/status"), ("attack-loss", "/api/ml/attack-loss/status")):
        try:
            with urllib.request.urlopen(backend_url + path, timeout=5) as resp:
                data = json.load(resp)
            if data.get("trained"):
                metrics = data.get("metrics") or {}
                r2 = metrics.get("r2")
                extra = f" (R2 = {r2:.3f})" if isinstance(r2, (int, float)) else ""
                say("ml", f"{label} model: loaded{extra}", "magenta")
            else:
                say("ml", f"{label} model: NOT trained", "yellow")
        except Exception:  # noqa: BLE001
            pass


def has_api_key() -> bool:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True
    for env_file in (BACKEND / ".env", ROOT / ".env"):
        if env_file.exists():
            for line in env_file.read_text(errors="ignore").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "ANTHROPIC_API_KEY" and value.strip().strip("'\""):
                    return True
    return False


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Set up and run AegisQ (backend + ML + frontend).")
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--retrain", action="store_true")
    p.add_argument("--setup-only", action="store_true")
    p.add_argument("--skip-install", action="store_true")
    p.add_argument("--no-venv", action="store_true")
    p.add_argument("--reload", action="store_true")
    p.add_argument("--backend-port", type=int, default=8000)
    p.add_argument("--frontend-port", type=int, default=5173)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    print(paint("\n  AegisQ - cyber-risk quantification\n", "cyan"), flush=True)

    # ---- setup -------------------------------------------------------------
    py = ensure_venv(args)
    ensure_dependencies(py, args)
    ensure_database()
    ensure_models(py, args)
    npm = ensure_frontend(args)

    if args.setup_only:
        info("Setup finished (--setup-only).")
        return 0

    if not has_api_key():
        info("Optional: put ANTHROPIC_API_KEY in .env (see .env.example) to enable the AI query box.")

    # ---- launch ------------------------------------------------------------
    bport = pick_port(args.backend_port, "backend")
    fport = pick_port(args.frontend_port, "frontend")
    backend_url = f"http://{HOST}:{bport}"
    frontend_url = f"http://{HOST}:{fport}"

    backend_env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    frontend_env = dict(os.environ, VITE_API_BASE_URL=backend_url)

    backend_cmd = [py, "-m", "uvicorn", "main:app", "--host", HOST, "--port", str(bport)]
    if args.reload:
        backend_cmd += ["--reload", "--reload-dir", ".", "--reload-exclude", "venv/*"]
    frontend_cmd = [npm, "run", "dev", "--", "--host", HOST, "--port", str(fport), "--strictPort"]

    backend = Service("backend", "blue", backend_cmd, BACKEND, backend_env)
    frontend = Service("frontend", "green", frontend_cmd, FRONTEND, frontend_env)
    services = [backend, frontend]

    stop_flag = threading.Event()

    def request_stop(*_):
        stop_flag.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, request_stop)

    exit_code = 0
    try:
        info("Starting backend ...")
        backend.start()
        if not wait_until_up(backend_url + "/api/health", backend, timeout=90):
            if stop_flag.is_set():
                return 0
            fail("The backend did not come up. Check the [backend] output above.")
        info(f"Backend ready: {backend_url}  (API docs: {backend_url}/docs)")
        show_ml_status(backend_url)

        info("Starting frontend ...")
        frontend.start()
        if not wait_until_up(frontend_url, frontend, timeout=90):
            if stop_flag.is_set():
                return 0
            fail("The frontend did not come up. Check the [frontend] output above.\n"
                 "         If frontend/node_modules was copied from another OS, delete it and run again.")

        print("", flush=True)
        say("aegisq", paint(f"AegisQ is running ->  {frontend_url}", "green"), "green")
        say("aegisq", paint("Press Ctrl+C (or the Stop button) to shut everything down.", "dim"), "dim")
        print("", flush=True)
        if not args.no_browser:
            webbrowser.open(frontend_url)

        while not stop_flag.is_set():
            for svc in services:
                if not svc.alive():
                    code = svc.proc.returncode if svc.proc else "?"
                    warn(f"The {svc.tag} stopped unexpectedly (exit code {code}). Shutting down.")
                    exit_code = 1
                    stop_flag.set()
                    break
            time.sleep(0.5)
    finally:
        info("Shutting down ...")
        for svc in reversed(services):
            svc.stop()
        info("Bye.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
