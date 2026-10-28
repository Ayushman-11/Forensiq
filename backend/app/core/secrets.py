"""
Secrets manager module for Forensiq.
Supports:
1. File-based secret directory (Kubernetes secrets / Docker secrets / Vault agent mounted files)
   via FORENSIQ_SECRETS_DIR.
2. Direct environment variables (local dev / cloud provider env injection).
3. Secret fallback chains.
"""

from pathlib import Path
from typing import Optional
import os


def load_secret_from_file_or_env(
    secret_name: str,
    default: str = "",
    secrets_dir: Optional[str] = None,
) -> str:
    """
    Attempts to read secret from:
    1. A mounted secret file at `<secrets_dir>/<secret_name>` (e.g. /run/secrets or /etc/secrets)
    2. Environment variable FORENSIQ_<SECRET_NAME> or <SECRET_NAME>
    3. Fallback default value.
    """
    # 1. Check directory mount (e.g., Vault Agent, Kubernetes Secret volume, Docker secret)
    base_dir = secrets_dir or os.getenv("FORENSIQ_SECRETS_DIR")
    if base_dir:
        candidate_file = Path(base_dir) / secret_name
        if candidate_file.is_file():
            try:
                content = candidate_file.read_text(encoding="utf-8").strip()
                if content:
                    return content
            except OSError:
                pass

    # 2. Check environment variable variants
    env_keys = [
        f"FORENSIQ_{secret_name.upper()}",
        secret_name.upper(),
        secret_name,
    ]
    for key in env_keys:
        val = os.getenv(key)
        if val is not None and val != "":
            return val

    return default

