"""Tool installer — download ProjectDiscovery binaries to ~/.driln/bin.

Downloads pre-built releases of subfinder, httpx, and nuclei from
GitHub. Archives are extracted and binaries placed into ``~/.driln/bin``
which is added to ``$PATH`` at scan time.
"""

from __future__ import annotations

import io
import os
import platform
import shutil
import ssl
import stat
import tarfile
import zipfile
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import structlog

logger = structlog.get_logger()

BIN_DIR = Path.home() / ".driln" / "bin"

# ── Tool definitions ────────────────────────────────────────────

TOOLS = {
    "subfinder": {
        "repo": "projectdiscovery/subfinder",
        "version": "v2.7.1",
        "binary": "subfinder",
    },
    "httpx": {
        "repo": "projectdiscovery/httpx",
        "version": "v1.6.10",
        "binary": "httpx",
    },
    "nuclei": {
        "repo": "projectdiscovery/nuclei",
        "version": "v3.3.7",
        "binary": "nuclei",
    },
}


# ── SSL context ─────────────────────────────────────────────────


def _get_ssl_context() -> ssl.SSLContext:
    """Create an SSL context that works on macOS and Linux.

    Strategy:
    1. Try certifi (if installed) — most reliable on macOS.
    2. Fall back to system default context.
    3. Last resort: unverified context with warning.
    """
    # Try certifi first (best option for macOS)
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass

    # Try system default
    try:
        ctx = ssl.create_default_context()
        return ctx
    except ssl.SSLError:
        pass

    # Refuse to download with no SSL verification — supply chain risk
    raise RuntimeError(
        "Cannot create a verified SSL context. "
        "Install certifi to fix: pip install certifi"
    )


# ── Platform detection ──────────────────────────────────────────


def _get_platform() -> tuple[str, str]:
    """Return (os_name, arch) matching GitHub release naming."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"darwin": "macOS", "linux": "linux", "windows": "windows"}
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }

    os_name = os_map.get(system)
    arch = arch_map.get(machine)

    if os_name is None or arch is None:
        raise RuntimeError(f"Unsupported platform: {system}/{machine}")

    return os_name, arch


def _build_download_url(tool_name: str) -> str:
    """Build the GitHub release download URL for a tool."""
    info = TOOLS[tool_name]
    repo = info["repo"]
    version = info["version"]
    binary = info["binary"]
    os_name, arch = _get_platform()

    ver_num = version.lstrip("v")
    filename = f"{binary}_{ver_num}_{os_name}_{arch}.zip"

    return (
        f"https://github.com/{repo}/releases/download/{version}/{filename}"
    )


# ── Download & extract ──────────────────────────────────────────


def _download_and_extract(url: str, tool_name: str, binary_name: str) -> Path:
    """Download a release archive and extract the binary to BIN_DIR."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    ssl_ctx = _get_ssl_context()
    req = Request(url, headers={"User-Agent": "driln-installer/1.0"})
    try:
        with urlopen(req, timeout=120, context=ssl_ctx) as resp:
            data = resp.read()
    except URLError as e:
        raise RuntimeError(f"Failed to download {tool_name}: {e}") from e

    # Extract binary from archive
    binary_path = BIN_DIR / binary_name

    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.namelist():
                if os.path.basename(member) == binary_name:
                    binary_path.write_bytes(zf.read(member))
                    break
            else:
                raise RuntimeError(
                    f"Binary '{binary_name}' not found in archive"
                )
    elif url.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf.getmembers():
                if os.path.basename(member.name) == binary_name:
                    f = tf.extractfile(member)
                    if f is None:
                        raise RuntimeError(
                            f"Cannot read '{binary_name}' from archive"
                        )
                    binary_path.write_bytes(f.read())
                    break
            else:
                raise RuntimeError(
                    f"Binary '{binary_name}' not found in archive"
                )
    else:
        raise RuntimeError(f"Unknown archive format: {url}")

    # Make executable
    binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return binary_path


# ── Report helper ───────────────────────────────────────────────


def _report(tool_name: str, success: bool, message: str) -> None:
    """Log installation result."""
    if success:
        logger.info("tool_installed", tool=tool_name, message=message)
    else:
        logger.warning("tool_install_failed", tool=tool_name, message=message)


# ── nmap check ──────────────────────────────────────────────────


def check_nmap() -> dict[str, object]:
    """Check if nmap is available in PATH.

    Returns a dict with 'installed' (bool) and 'hint' (str or None).
    nmap is a system package — can't be downloaded as a GitHub release.
    """
    if shutil.which("nmap"):
        return {"installed": True, "hint": None}

    system = platform.system().lower()
    if system == "darwin":
        hint = "brew install nmap"
    elif system == "linux":
        hint = "sudo apt install nmap  # or: sudo yum install nmap"
    else:
        hint = "Download from https://nmap.org/download.html"

    return {"installed": False, "hint": hint}


# ── Public API ──────────────────────────────────────────────────


def install_all() -> dict[str, bool]:
    """Download and install all tools. Returns {name: success}."""
    results: dict[str, bool] = {}

    for tool_name, tool_info in TOOLS.items():
        binary_name = tool_info["binary"]

        # Skip if already on PATH
        if shutil.which(binary_name):
            _report(tool_name, True, "Already installed (found in PATH)")
            results[tool_name] = True
            continue

        # Skip if already in BIN_DIR
        if (BIN_DIR / binary_name).exists():
            _report(tool_name, True, f"Already in {BIN_DIR}")
            results[tool_name] = True
            continue

        try:
            url = _build_download_url(tool_name)
            path = _download_and_extract(url, tool_name, binary_name)
            _report(tool_name, True, f"Downloaded to {path}")
            results[tool_name] = True
        except Exception as e:
            _report(tool_name, False, str(e))
            results[tool_name] = False

    return results
